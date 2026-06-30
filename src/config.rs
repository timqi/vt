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

/// Best-effort permission check: the file holds secrets (`VT_AUTH`,
/// `VT_PASSKEY_TOKEN`), so warn (don't fail) if it is group/other accessible.
#[cfg(unix)]
fn warn_if_world_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                "{} is accessible to group/other (mode {:o}); it holds secrets — run: chmod 600 {}",
                path.display(),
                mode & 0o7777,
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_world_readable(_path: &Path) {}

/// Load the config file and, for each allowed `VT_*` key that is **not already
/// present in the environment**, set it. Env vars always take precedence.
///
/// Silent no-op when the file is absent (the common case). Parse / read errors
/// are logged at `warn` and otherwise ignored so a malformed file never bricks
/// the CLI — the env-var path still works.
///
/// # Safety
/// Must be called before any threads are spawned (i.e. before the tokio runtime
/// is built), because it mutates the process environment via
/// [`std::env::set_var`]. `main()` calls it at the very top, single-threaded.
pub fn hydrate_env_from_file() {
    let Some(path) = config_path() else {
        return;
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            tracing::warn!("could not read {}: {}", path.display(), e);
            return;
        }
    };
    warn_if_world_readable(&path);

    let table: toml::Table = match contents.parse() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("ignoring malformed config {}: {}", path.display(), e);
            return;
        }
    };

    for (key, value) in &table {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
