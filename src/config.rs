//! Optional config-file fallback for VT's environment-based configuration.
//!
//! VT is configured through environment variables (`VT_PASSKEY_URL`,
//! `VT_PASSKEY_TOKEN`, the `VT_GIT_SSH_*` pair, …). This module adds a
//! *fallback* layer: a flat TOML file at `~/.config/vt/config.toml` (override
//! with `$VT_CONFIG`) whose `VT_*` keys are loaded into the process environment
//! **only when the matching env var is not already set**. Environment
//! variables therefore always win; the file is pure fallback.
//!
//! It hydrates `std::env` before clap parses or any configuration is read.
//! Client transports and `vt doctor` then share an immutable `ResolvedConfig`
//! snapshot; the remaining subsystems retain their existing env interfaces.
//!
//! Scope guard: only keys matching `^VT_[A-Z0-9_]+$` are honoured, so the file
//! cannot inject arbitrary unrelated environment variables.

mod client;
pub(crate) use client::{
    worker_url_is_secure, ClientRoute, PasskeyState, ResolvedConfig, RoutingError,
    CLIENT_CONFIG_KEYS,
};

use std::path::{Path, PathBuf};

/// Resolve the config-file path: `$VT_CONFIG` if set and non-empty, otherwise
/// `~/.config/vt/config.toml`. Returns `None` when neither `$VT_CONFIG` nor a
/// home directory can be determined.
pub fn config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("VT_CONFIG") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    std::env::home_dir().map(|h| h.join(".config").join("vt").join("config.toml"))
}

/// True for keys we allow a config file to populate: VT-namespaced uppercase
/// identifiers only. Prevents the file from setting arbitrary env vars.
fn is_allowed_key(key: &str) -> bool {
    key.starts_with("VT_")
        && key.len() > 3
        && key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// The config file's permission bits when they are too loose (group/other
/// accessible), else `None`. Single owner of the 0o077 policy — consumed by
/// the load-time warning below and by `vt doctor`, so the two can't drift.
pub fn insecure_config_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o077 != 0).then_some(mode & 0o7777)
}

/// Best-effort permission check: the file holds secrets (`VT_PASSKEY_TOKEN`),
/// so warn (don't fail) if it is group/other accessible.
fn warn_if_world_readable(path: &Path) {
    if let Some(mode) = insecure_config_mode(path) {
        tracing::warn!(
            "{} is accessible to group/other (mode {:o}); it holds secrets — run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        );
    }
}

/// Load the config file and, for each allowed `VT_*` key that is **not already
/// present in the environment**, set it. Env vars always take precedence.
///
/// Silent no-op when the file is absent (the common case). Parse / read errors
/// are logged at `warn` and otherwise ignored so a malformed file never bricks
/// the CLI — the env-var path still works.
///
/// Returns the keys it populated from the file, so `vt doctor` can attribute
/// each effective value to `env` vs `config.toml` (a key present in the
/// environment but absent from this list was set by the caller).
///
/// # Safety
/// Must be called before any threads are spawned (i.e. before the tokio runtime
/// is built), because it mutates the process environment via
/// [`std::env::set_var`]. `main()` calls it at the very top, single-threaded.
/// Read and TOML-parse the config file once. `None` when the file is absent
/// (silent — the common case) or unreadable/malformed (warned). Shared read
/// path for `hydrate_env_from_file` and `load_agent_file_config` so the file
/// is opened and parsed through one place with one error policy.
fn read_config_table() -> Option<(PathBuf, toml::Table)> {
    let path = config_path()?;
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!("could not read {}: {}", path.display(), e);
            return None;
        }
    };
    match contents.parse::<toml::Table>() {
        Ok(table) => Some((path, table)),
        Err(e) => {
            tracing::warn!(
                "ignoring malformed config {}: {}",
                path.display(),
                describe_toml_error(&contents, &e)
            );
            None
        }
    }
}

/// Position + message only. The error's `Display` quotes the offending source
/// line, which for a config file may be a token assignment; that must never
/// reach the log.
fn describe_toml_error(contents: &str, e: &toml::de::Error) -> String {
    let at = match e.span() {
        Some(span) => {
            let before = &contents[..span.start.min(contents.len())];
            let line = before.matches('\n').count() + 1;
            let col = before.rsplit('\n').next().map_or(0, str::len) + 1;
            format!("line {line} column {col}: ")
        }
        None => String::new(),
    };
    format!("{at}{}", e.message())
}

pub fn hydrate_env_from_file() -> Vec<String> {
    let Some((path, table)) = read_config_table() else {
        return Vec::new();
    };
    warn_if_world_readable(&path);

    let mut populated = Vec::new();

    for (key, value) in &table {
        // Structured sections (TOML tables / arrays) are not env-var
        // candidates — skip them silently so a future section can never
        // produce warning spam on every `vt` invocation.
        if value.is_table() || value.is_array() {
            continue;
        }
        if !is_allowed_key(key) {
            tracing::warn!("ignoring non-VT key in {}: {}", path.display(), key);
            continue;
        }
        // Env var wins — only fall back to the file when unset.
        if std::env::var_os(key).is_some() {
            continue;
        }
        let Some(s) = value.as_str() else {
            tracing::warn!(
                "ignoring {} in {}: value must be a string",
                key,
                path.display()
            );
            continue;
        };
        std::env::set_var(key, s);
        populated.push(key.clone());
    }
    populated
}

// ---------------------------------------------------------------------------
// Writing top-level keys (`vt enroll` persists VT_PASSKEY_URL / VT_PASSKEY_TOKEN)

/// Set top-level `KEY = "value"` entries in the config file, creating it (mode
/// 600) when absent. Goes through `toml_edit` (the parser `toml` already
/// uses) so the hand-edited file keeps its comments and layout: an existing
/// top-level key is replaced in place, a new one lands in the top-level region
/// before the first `[section]`. Only `is_allowed_key` names are accepted.
pub fn upsert_config_values(pairs: &[(&str, &str)]) -> anyhow::Result<PathBuf> {
    use anyhow::Context;
    let path = config_path()
        .context("cannot determine config path (no $VT_CONFIG and no home directory)")?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let updated =
        upsert_toml(&existing, pairs).with_context(|| format!("update {}", path.display()))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    write_private(&path, &updated)?;
    Ok(path)
}

/// Write through a same-directory temp file + rename so a crash never leaves a
/// half-written config, with the file private from the first byte.
fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
    let result = (|| -> anyhow::Result<()> {
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// A file that does not parse is refused rather than overwritten: the operator
/// fixes it by hand, `vt enroll` never guesses at its contents.
fn upsert_toml(existing: &str, pairs: &[(&str, &str)]) -> anyhow::Result<String> {
    for (key, _) in pairs {
        anyhow::ensure!(
            is_allowed_key(key),
            "refusing to write non-VT config key {key}"
        );
    }
    let mut doc: toml_edit::DocumentMut = existing.parse()?;
    for (key, value) in pairs {
        doc[key] = toml_edit::value(*value);
    }
    Ok(doc.to_string())
}

// ---------------------------------------------------------------------------
// [agent] section — file defaults for `vt ssh agent` flags

/// Optional `[agent]` table in the same config file: startup *defaults* for
/// `vt ssh agent`, so a supervisor (the VT.app shell) can spawn the agent
/// without hardcoding flags (docs/app-bundle.md#agent-defaults-and-menu-overrides). Explicit
/// CLI flags always override these; the env-over-file invariant is untouched
/// because no key here is an env var (`hydrate_env_from_file` skips tables).
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct AgentFileConfig {
    /// `--timeout`
    pub timeout: Option<u64>,
    /// `--ssh-auth-cache-duration` (0 = Fresh)
    pub ssh_auth_cache_duration: Option<u64>,
    /// `--decrypt-auth-cache-duration` (0 = Fresh)
    pub decrypt_auth_cache_duration: Option<u64>,
    /// Cache-hit transparency notifications (`--no-cache-hit-notify` inverts)
    pub cache_hit_notify: Option<bool>,
    /// `--run-allow` allowlist (comma-separated, same grammar as the flag).
    /// Not a secret — agent policy. Lets a supervisor (VT.app) keep run@vt
    /// enabled without hardcoding the list.
    pub run_allow: Option<String>,
}

/// Read the `[agent]` section. Absent file/section or a malformed table all
/// degrade to defaults with a warning — same "never brick the CLI" stance as
/// `hydrate_env_from_file`, and reusing its read/parse path.
pub fn load_agent_file_config() -> AgentFileConfig {
    let Some((path, table)) = read_config_table() else {
        return AgentFileConfig::default();
    };
    let Some(agent) = table.get("agent") else {
        return AgentFileConfig::default();
    };
    match agent.clone().try_into() {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                "ignoring malformed [agent] section in {}: {}",
                path.display(),
                e
            );
            AgentFileConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `VT_CONFIG` is process-global; the tests that set it run in parallel,
    /// so they take this lock for the whole set/remove span.
    static VT_CONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn upsert_replaces_top_level_key_and_keeps_comments_and_sections() {
        let existing = "# header\n# VT_PASSKEY_TOKEN = \"old-commented\"\nVT_PASSKEY_URL = \"https://a\"\nVT_PASSKEY_TOKEN = \"old\"\n\n[agent]\ntimeout = 60\n";
        let out = upsert_toml(
            existing,
            &[("VT_PASSKEY_TOKEN", "vt1.x.y"), ("VT_BACKEND", "auto")],
        )
        .unwrap();
        assert_eq!(
            out,
            "# header\n# VT_PASSKEY_TOKEN = \"old-commented\"\nVT_PASSKEY_URL = \"https://a\"\nVT_PASSKEY_TOKEN = \"vt1.x.y\"\nVT_BACKEND = \"auto\"\n\n[agent]\ntimeout = 60\n"
        );
        // A key that only exists under a section is NOT the top-level key.
        let sectioned = "[agent]\nVT_PASSKEY_TOKEN = \"inner\"\n";
        let out = upsert_toml(sectioned, &[("VT_PASSKEY_TOKEN", "t")]).unwrap();
        assert_eq!(
            out,
            "VT_PASSKEY_TOKEN = \"t\"\n[agent]\nVT_PASSKEY_TOKEN = \"inner\"\n"
        );
        // Non-VT key and a file that no longer parses are both refused.
        assert!(upsert_toml("", &[("PATH", "x")]).is_err());
        assert!(upsert_toml("VT_A = \"unterminated\n", &[("VT_B", "x")]).is_err());
    }

    #[test]
    fn upsert_round_trips_through_a_real_toml_parse() {
        // Escaping is the serializer's job; the proof is that a real parser
        // reads back exactly what was written, whatever the value contains.
        let hard = "a\"b\\c\n\t\u{1}\u{7f}#not-a-comment 'q' \"\"\"";
        let out = upsert_toml("VT_KEEP = \"k\"\n", &[("VT_X", hard), ("VT_KEEP", "k2")]).unwrap();
        let table: toml::Table = out.parse().unwrap();
        assert_eq!(table["VT_X"].as_str(), Some(hard));
        assert_eq!(table["VT_KEEP"].as_str(), Some("k2"));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn upsert_config_values_creates_private_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vt-cfg-test-{}", std::process::id()));
        let path = dir.join("config.toml");
        let _guard = VT_CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("VT_CONFIG", &path);
        let written = upsert_config_values(&[("VT_PASSKEY_URL", "https://w")]).unwrap();
        assert_eq!(written, path);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "VT_PASSKEY_URL = \"https://w\"\n"
        );
        std::env::remove_var("VT_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_config_warning_omits_source_text() {
        // A token assignment on the offending line must not be echoed.
        let contents = "VT_PASSKEY_TOKEN = \"vt1.secret-token-value\" trailing\nVT_B = \"x\"\n";
        let e = contents.parse::<toml::Table>().unwrap_err();
        assert!(
            e.to_string().contains("vt1.secret-token-value"),
            "precondition: Display leaks"
        );
        let msg = describe_toml_error(contents, &e);
        assert!(!msg.contains("vt1.secret-token-value"), "{msg}");
        assert!(!msg.contains("VT_PASSKEY_TOKEN"), "{msg}");
        assert!(msg.starts_with("line 1 column "), "{msg}");
    }

    #[test]
    fn allowed_keys() {
        assert!(is_allowed_key("VT_PASSKEY_TOKEN"));
        assert!(is_allowed_key("VT_GIT_SSH_PRIVATE_KEY"));
        assert!(!is_allowed_key("VT_")); // too short
        assert!(!is_allowed_key("PATH"));
        assert!(!is_allowed_key("vt_backend")); // lowercase
        assert!(!is_allowed_key("VT_backend")); // mixed
        assert!(!is_allowed_key("VTBACKEND")); // missing underscore prefix shape
    }

    #[test]
    fn hydrate_skips_structured_sections_and_loads_vt_keys() {
        use std::io::Write;
        // Unique dir/keys so this parallel test doesn't collide with others.
        let dir = std::env::temp_dir().join(format!("vt-cfg-hydrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        // A VT_* string key alongside a structured [agent]/[[rules]] section.
        write!(
            f,
            "VT_HYDRATE_TEST_KEY = \"value1\"\n\n[agent]\nx = 1\n\n[[rules]]\ncommand = \"gh\"\n"
        )
        .unwrap();
        drop(f);

        let _guard = VT_CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("VT_HYDRATE_TEST_KEY");
        std::env::set_var("VT_CONFIG", &path);
        hydrate_env_from_file();
        // The flat VT_ key loads; the tables are silently skipped (no panic/spam).
        assert_eq!(
            std::env::var("VT_HYDRATE_TEST_KEY").ok().as_deref(),
            Some("value1")
        );

        std::env::remove_var("VT_CONFIG");
        std::env::remove_var("VT_HYDRATE_TEST_KEY");
        std::fs::remove_dir_all(&dir).ok();
    }
}
