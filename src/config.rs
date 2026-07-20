//! Optional config-file fallback for VT's environment-based configuration.
//!
//! VT has historically been configured purely through environment variables
//! (`VT_AUTH`, `VT_PASSKEY_URL`, `VT_PASSKEY_TOKEN`, the `VT_GIT_SSH_*` pair,
//! …). This module adds a *fallback* layer: a flat TOML file at
//! `~/.config/vt/config.toml` (override with `$VT_CONFIG`) whose `VT_*` keys
//! are loaded into the process environment **only when the matching env var is
//! not already set**. Environment variables therefore always win; the file is
//! pure fallback.
//!
//! It works by hydrating `std::env` *before* clap parses and before any
//! `std::env::var("VT_…")` read happens. That keeps the rest of the codebase
//! (including clap's `env = "VT_AUTH"`) unchanged — every existing read
//! transparently picks up the file value when the env var is absent.
//!
//! Scope guard: only keys matching `^VT_[A-Z0-9_]+$` are honoured, so the file
//! cannot inject arbitrary unrelated environment variables.

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
    dirs::home_dir().map(|h| h.join(".config").join("vt").join("config.toml"))
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
#[cfg(unix)]
pub fn insecure_config_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o077 != 0).then_some(mode & 0o7777)
}

#[cfg(not(unix))]
pub fn insecure_config_mode(_path: &Path) -> Option<u32> {
    None
}

/// Best-effort permission check: the file holds secrets (`VT_AUTH`,
/// `VT_PASSKEY_TOKEN`), so warn (don't fail) if it is group/other accessible.
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
pub fn hydrate_env_from_file() -> Vec<String> {
    let Some(path) = config_path() else {
        return Vec::new();
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!("could not read {}: {}", path.display(), e);
            return Vec::new();
        }
    };
    warn_if_world_readable(&path);

    let table: toml::Table = match contents.parse() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("ignoring malformed config {}: {}", path.display(), e);
            return Vec::new();
        }
    };
    let mut populated = Vec::new();

    for (key, value) in &table {
        // Structured sections (TOML tables / arrays) are not env-var
        // candidates — skip them silently so a future section can never
        // produce warning spam on every `vt` invocation. (Hook rules live in
        // their own file; see `load_hook_config`.)
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
// Transport-path routing preference (VT_BACKEND)
// ---------------------------------------------------------------------------

/// Routing preference between the two transport paths, read from
/// `VT_BACKEND` (env var, or config.toml via the hydration above).
///
/// Historically the selector was implicit: `VT_AUTH` present → try the SSH
/// agent first. With the config-file fallback, `VT_AUTH` presence is ambient
/// (a copied config.toml silently enables agent probing), so `VT_BACKEND`
/// makes the intent explicit per host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    /// Try the SSH agent when `VT_AUTH` is set; fall back to the passkey
    /// ceremony on recoverable errors. The historical (and default) behavior.
    #[default]
    Auto,
    /// SSH agent only — never fall back to the passkey ceremony. Errors out
    /// when the agent is unreachable instead of silently paging the phone.
    Agent,
    /// Passkey ceremony only — never probe the agent socket, even when
    /// `VT_AUTH` is set (e.g. a config.toml shared with agent-reaching hosts).
    Passkey,
}

impl Backend {
    /// Parse a `VT_BACKEND` value. Empty/whitespace counts as unset (`Auto`);
    /// anything else must match exactly, so a typo fails loudly instead of
    /// silently routing to the wrong path.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Backend::Auto),
            "agent" => Ok(Backend::Agent),
            "passkey" => Ok(Backend::Passkey),
            other => Err(format!(
                "invalid VT_BACKEND '{}': expected auto, agent, or passkey",
                other
            )),
        }
    }

    /// Read `VT_BACKEND` from the environment (already hydrated from the
    /// config file). Unset → `Auto`.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("VT_BACKEND") {
            Err(_) => Ok(Backend::Auto),
            Ok(v) => Self::parse(&v).map_err(|e| anyhow::anyhow!(e)),
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Auto => write!(f, "auto"),
            Backend::Agent => write!(f, "agent"),
            Backend::Passkey => write!(f, "passkey"),
        }
    }
}

// ---------------------------------------------------------------------------
// Agent config (dedicated file: ~/.config/vt/agent.toml)
// ---------------------------------------------------------------------------
//
// Consumed by the `vt hook` subcommand (see `src/hook.rs`). Kept in its OWN
// file, separate from the secret-bearing config.toml, so the rules + env-var
// values can be synced to a repo while plaintext secrets never leave the host.
// Top-level `[[rules]]` (+ optional `[env]`):
//
//     [[rules]]
//     command  = "gh"                       # matched against argv[0] basename
//     env_vars = ["GH_TOKEN", "GITHUB_TOKEN"]
//
//     [[rules]]
//     command = "gh"
//     args    = ["auth", "token"]           # subcommand-level deny
//     block   = true

/// One whitelist entry. A command is matched by the *basename* of its leading
/// program token (so `python`, `/usr/bin/python`, and `./python` all match a
/// rule whose `command = "python"`).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct HookRule {
    /// Program to match (matched by basename against the command's argv[0]).
    pub command: String,
    /// Optional leading-argument prefix that must match (the tokens right after
    /// the program) for this rule to apply. Empty = match any invocation of
    /// `command`. Lets a rule target a subcommand, e.g.
    /// `command = "gh"`, `args = ["auth", "token"]` matches `gh auth token …`.
    #[serde(default)]
    pub args: Vec<String>,
    /// Optional "contains any" guard: when non-empty, the invocation's args
    /// must include at least one of these tokens (anywhere) for the rule to
    /// apply. Use it to match a flag that has no fixed position or has short/
    /// long aliases, e.g. `command = "glab"`, `args = ["auth","status"]`,
    /// `args_any = ["-t","--show-token"]` blocks `glab auth status --show-token`
    /// but leaves a plain `glab auth status` untouched.
    #[serde(default)]
    pub args_any: Vec<String>,
    /// Env-var names that should be decrypted via `vt inject` when this command
    /// runs AND the var's value starts with `vt://`. Empty → nothing to inject
    /// (the rule becomes a no-op unless `block` is set).
    #[serde(default)]
    pub env_vars: Vec<String>,
    /// When true, the command is denied outright (no execution).
    #[serde(default)]
    pub block: bool,
    /// Optional human reason surfaced to the agent (deny) or recorded in the
    /// vt audit row (inject). Defaults are synthesized when absent.
    pub reason: Option<String>,
}

/// Centrally-managed env-var VALUES the hook can supply to matched commands,
/// so the agent doesn't have to export them. Values are normally `vt://`
/// ciphertext (decrypted on use). `default` applies in every working
/// directory; `dirs` overrides per directory (longest path prefix of the
/// command's CWD wins). TOML:
///
///     [env.default]
///     GH_TOKEN = "vt://0default…"
///
///     [env.dirs."/home/me/work/projA"]
///     GH_TOKEN = "vt://0projA…"
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct EnvConfig {
    /// Values applied in all PWDs.
    #[serde(default)]
    pub default: std::collections::BTreeMap<String, String>,
    /// Per-directory overrides, keyed by absolute path. The longest key that is
    /// a prefix of the command's CWD wins.
    #[serde(default)]
    pub dirs: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

/// The hook-rules file: a top-level array of `[[rules]]` plus an optional
/// `[env]` section supplying values for the vars those rules name.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct HookConfig {
    #[serde(default)]
    pub rules: Vec<HookRule>,
    #[serde(default)]
    pub env: EnvConfig,
}

/// Resolve the agent-config file path: `$VT_AGENT_CONFIG` if set and non-empty,
/// otherwise `~/.config/vt/agent.toml` (falling back to the legacy
/// `~/.config/vt/hook.toml` if only that exists).
///
/// This is a SEPARATE file from `config.toml` (the `VT_*` secret store) on
/// purpose: `config.toml` holds secrets and must never be synced to a repo,
/// whereas the agent's command rules + env-var values carry no plaintext
/// secrets and are meant to be shared/synced (symlink `agent.toml` into a
/// dotfiles repo, or point `$VT_AGENT_CONFIG` at a checked-in file).
pub fn agent_config_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("VT_AGENT_CONFIG") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    let dir = dirs::home_dir()?.join(".config").join("vt");
    let primary = dir.join("agent.toml");
    // Legacy fallback: use hook.toml only if agent.toml doesn't exist yet.
    let legacy = dir.join("hook.toml");
    if !primary.exists() && legacy.exists() {
        return Some(legacy);
    }
    Some(primary)
}

/// Load the agent config (command rules + env-var values) from the dedicated
/// file. Absent file → empty config (the hook then defaults every command to
/// *accept*). Malformed file → warn + empty config so a typo can never wedge
/// the agent.
pub fn load_agent_config() -> HookConfig {
    let Some(path) = agent_config_path() else {
        return HookConfig::default();
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HookConfig::default(),
        Err(e) => {
            tracing::warn!("vt hook: could not read {}: {}", path.display(), e);
            return HookConfig::default();
        }
    };
    match toml::from_str::<HookConfig>(&contents) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                "vt hook: ignoring malformed agent config {}: {}",
                path.display(),
                e
            );
            HookConfig::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_parse() {
        assert_eq!(Backend::parse("auto"), Ok(Backend::Auto));
        assert_eq!(Backend::parse("agent"), Ok(Backend::Agent));
        assert_eq!(Backend::parse("passkey"), Ok(Backend::Passkey));
        // Case-insensitive + trimmed; empty counts as unset.
        assert_eq!(Backend::parse(" Passkey "), Ok(Backend::Passkey));
        assert_eq!(Backend::parse(""), Ok(Backend::Auto));
        assert_eq!(Backend::parse("  "), Ok(Backend::Auto));
        // Typos fail loudly instead of silently routing to the wrong path.
        assert!(Backend::parse("pass-key").is_err());
        assert!(Backend::parse("cf").is_err());
    }

    #[test]
    fn allowed_keys() {
        assert!(is_allowed_key("VT_AUTH"));
        assert!(is_allowed_key("VT_PASSKEY_TOKEN"));
        assert!(is_allowed_key("VT_GIT_SSH_PRIVATE_KEY"));
        assert!(!is_allowed_key("VT_")); // too short
        assert!(!is_allowed_key("PATH"));
        assert!(!is_allowed_key("vt_auth")); // lowercase
        assert!(!is_allowed_key("VT_auth")); // mixed
        assert!(!is_allowed_key("VTAUTH")); // missing underscore prefix shape
    }

    // The agent-config schema is deserialized by serde; a field/shape mismatch
    // would silently fail-open to "no rules". These lock the wiring.
    #[test]
    fn agent_config_deserializes_full_schema() {
        let toml = r#"
[[rules]]
command  = "gh"
env_vars = ["GH_TOKEN"]

[[rules]]
command  = "gh"
args     = ["auth", "token"]
block    = true
reason   = "no token reveal"

[[rules]]
command  = "glab"
args     = ["auth", "status"]
args_any = ["-t", "--show-token"]
block    = true

[env.default]
GH_TOKEN = "vt://0default"

[env.dirs."/work/projA"]
GH_TOKEN = "vt://0projA"
"#;
        let cfg: HookConfig = toml::from_str(toml).expect("valid agent config parses");
        assert_eq!(cfg.rules.len(), 3);
        // rule 0: inject
        assert_eq!(cfg.rules[0].command, "gh");
        assert_eq!(cfg.rules[0].env_vars, vec!["GH_TOKEN"]);
        assert!(!cfg.rules[0].block);
        // rule 1: subcommand block with reason
        assert_eq!(cfg.rules[1].args, vec!["auth", "token"]);
        assert!(cfg.rules[1].block);
        assert_eq!(cfg.rules[1].reason.as_deref(), Some("no token reveal"));
        // rule 2: args_any flag guard
        assert_eq!(cfg.rules[2].args_any, vec!["-t", "--show-token"]);
        // env values
        assert_eq!(cfg.env.default.get("GH_TOKEN").map(String::as_str), Some("vt://0default"));
        assert_eq!(
            cfg.env.dirs.get("/work/projA").and_then(|m| m.get("GH_TOKEN")).map(String::as_str),
            Some("vt://0projA")
        );
    }

    #[test]
    fn empty_and_minimal_configs_default_cleanly() {
        let empty: HookConfig = toml::from_str("").unwrap();
        assert!(empty.rules.is_empty() && empty.env.default.is_empty());
        // a rule with only `command` uses defaults for the rest
        let min: HookConfig = toml::from_str("[[rules]]\ncommand = \"gh\"\n").unwrap();
        assert_eq!(min.rules.len(), 1);
        assert!(min.rules[0].args.is_empty() && !min.rules[0].block && min.rules[0].reason.is_none());
    }

    #[test]
    fn unquoted_value_is_a_parse_error() {
        // Documents the footgun: a shell-style unquoted value breaks the file.
        // `load_agent_config` catches this and returns default (fail-open).
        assert!(toml::from_str::<HookConfig>("[env.default]\nGH_TOKEN=vt://x\n").is_err());
    }

    #[test]
    fn hydrate_skips_structured_sections_and_loads_vt_keys() {
        use std::io::Write;
        // Unique dir/keys so this parallel test doesn't collide with others.
        let dir = std::env::temp_dir().join(format!("vt-cfg-hydrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        // A VT_* string key alongside a structured [hook]/[[rules]] section.
        write!(
            f,
            "VT_HYDRATE_TEST_KEY = \"value1\"\n\n[hook]\nx = 1\n\n[[rules]]\ncommand = \"gh\"\n"
        )
        .unwrap();
        drop(f);

        std::env::remove_var("VT_HYDRATE_TEST_KEY");
        std::env::set_var("VT_CONFIG", &path);
        hydrate_env_from_file();
        // The flat VT_ key loads; the tables are silently skipped (no panic/spam).
        assert_eq!(std::env::var("VT_HYDRATE_TEST_KEY").ok().as_deref(), Some("value1"));

        std::env::remove_var("VT_CONFIG");
        std::env::remove_var("VT_HYDRATE_TEST_KEY");
        std::fs::remove_dir_all(&dir).ok();
    }
}
