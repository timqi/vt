//! Immutable client configuration after config-file hydration and clap parsing.
//! Validation stays lazy: doctor and commands without authentication still run
//! with an incomplete or invalid routing setup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const CLIENT_CONFIG_KEYS: &[&str] = &[
    "VT_BACKEND",
    "VT_PASSKEY_URL",
    "VT_PASSKEY_TOKEN",
    "VT_GIT_SSH_PRIVATE_KEY",
    "VT_GIT_SSH_PUB",
    "VT_AGENT_CONFIG",
    "VT_PASSKEY_UV",
];

/// Transport route decided by `VT_BACKEND` alone (env var, or config.toml via
/// hydration). The agent socket is the kernel-owned boundary, so nothing a
/// client holds makes it more or less trustworthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRoute {
    /// SSH agent only — never fall back to the passkey ceremony. Errors out
    /// when the agent is unreachable instead of silently paging the phone.
    Agent,
    /// Try the SSH agent socket when it exists; fall back to the passkey
    /// ceremony on recoverable errors (socket missing, non-vt agent, agent
    /// cannot deliver). The default.
    Auto,
    /// Passkey ceremony only — never probe the agent socket (e.g. hosts where
    /// `$SSH_AUTH_SOCK` is an unrelated ssh-agent).
    Passkey,
}

impl ClientRoute {
    /// Parse a `VT_BACKEND` value. Empty/whitespace counts as unset (`Auto`);
    /// anything else must match exactly, so a typo fails loudly instead of
    /// silently routing to the wrong path.
    fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "agent" => Ok(Self::Agent),
            "passkey" => Ok(Self::Passkey),
            other => Err(format!(
                "invalid VT_BACKEND '{}': expected auto, agent, or passkey",
                other
            )),
        }
    }

    pub fn uses_agent(self) -> bool {
        matches!(self, Self::Agent | Self::Auto)
    }

    pub fn allows_passkey_fallback(self) -> bool {
        self == Self::Auto
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasskeyState {
    Configured,
    MissingToken,
    MissingUrl,
    Unconfigured,
}

impl std::fmt::Display for PasskeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configured => "configured",
            Self::MissingToken => "incomplete (VT_PASSKEY_TOKEN unset)",
            Self::MissingUrl => "incomplete (VT_PASSKEY_URL unset)",
            Self::Unconfigured => "unconfigured",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingError {
    InvalidBackend(String),
    PasskeyUrlMissing,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBackend(message) => f.write_str(message),
            Self::PasskeyUrlMissing => f.write_str("VT_BACKEND=passkey requires VT_PASSKEY_URL + VT_PASSKEY_TOKEN for the phone passkey ceremony"),
        }
    }
}

impl std::error::Error for RoutingError {}

// Intentionally no Debug: this snapshot includes bearer tokens and may include
// a misconfigured plaintext SSH private key in its diagnostic values.
#[derive(Clone)]
pub struct ResolvedConfig {
    /// Requested WebAuthn user-verification level for the phone ceremony
    /// (`--uv`, else `VT_PASSKEY_UV`, else the file). Advisory: the Worker
    /// applies `max(its policy, this)`, so it can only ever ask for MORE
    /// verification than the deployment already requires.
    passkey_uv: Option<String>,
    values: BTreeMap<&'static str, Result<String, std::env::VarError>>,
    pub file_populated_keys: Vec<String>,
    pub config_path: Option<PathBuf>,
    socket: Option<String>,
    home: Option<PathBuf>,
}

impl ResolvedConfig {
    pub fn capture(uv: Option<String>, file_populated_keys: Vec<String>) -> Self {
        Self::from_lookup(
            uv,
            file_populated_keys,
            |key| std::env::var(key),
            super::config_path(),
            std::env::home_dir(),
        )
    }

    fn from_lookup(
        uv: Option<String>,
        file_populated_keys: Vec<String>,
        mut lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
        config_path: Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> Self {
        let values: BTreeMap<_, _> = CLIENT_CONFIG_KEYS
            .iter()
            .map(|&key| (key, lookup(key)))
            .collect();
        // The flag wins, else the env/file value.
        let passkey_uv = uv
            .or_else(|| {
                values
                    .get("VT_PASSKEY_UV")
                    .and_then(|value| value.as_ref().ok())
                    .cloned()
            })
            .filter(|v| !v.is_empty());
        Self {
            passkey_uv,
            values,
            file_populated_keys,
            config_path,
            socket: lookup("SSH_AUTH_SOCK").ok(),
            home,
        }
    }

    #[cfg(test)]
    pub(crate) fn resolve(
        file_populated_keys: Vec<String>,
        mut lookup: impl FnMut(&str) -> Option<String>,
        config_path: Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> Self {
        Self::from_lookup(
            None,
            file_populated_keys,
            |key| lookup(key).ok_or(std::env::VarError::NotPresent),
            config_path,
            home,
        )
    }

    fn raw_value(&self, key: &str) -> Result<&str, std::env::VarError> {
        self.values
            .get(key)
            .ok_or(std::env::VarError::NotPresent)?
            .as_deref()
            .map_err(Clone::clone)
    }

    pub fn value(&self, key: &str) -> Option<&str> {
        self.raw_value(key).ok()
    }

    /// Lazy: an invalid or incomplete `VT_BACKEND` setup is reported here,
    /// never at construction, so `doctor` can describe it.
    pub fn route(&self) -> Result<ClientRoute, RoutingError> {
        let route = ClientRoute::parse(self.value("VT_BACKEND").unwrap_or_default())
            .map_err(RoutingError::InvalidBackend)?;
        if route == ClientRoute::Passkey && self.value("VT_PASSKEY_URL").is_none() {
            return Err(RoutingError::PasskeyUrlMissing);
        }
        Ok(route)
    }

    pub fn passkey_state(&self) -> PasskeyState {
        match (
            self.value("VT_PASSKEY_URL").is_some(),
            self.value("VT_PASSKEY_TOKEN").is_some(),
        ) {
            (true, true) => PasskeyState::Configured,
            (true, false) => PasskeyState::MissingToken,
            (false, true) => PasskeyState::MissingUrl,
            (false, false) => PasskeyState::Unconfigured,
        }
    }

    pub fn passkey_config(&self) -> anyhow::Result<crate::cf::CfConfig<'_>> {
        use anyhow::{bail, Context};
        let worker_url = self
            .raw_value("VT_PASSKEY_URL")
            .context("VT_PASSKEY_URL not set")?;
        let worker_auth = self
            .raw_value("VT_PASSKEY_TOKEN")
            .context("VT_PASSKEY_TOKEN not set")?;
        if worker_url.trim().is_empty() {
            bail!("VT_PASSKEY_URL is empty");
        }
        if worker_auth.trim().is_empty() {
            bail!("VT_PASSKEY_TOKEN is empty");
        }
        if !worker_url_is_secure(worker_url) {
            bail!("VT_PASSKEY_URL must be https:// (got {worker_url})");
        }
        Ok(crate::cf::CfConfig {
            worker_url,
            worker_auth,
            uv: self.passkey_uv.as_deref(),
        })
    }

    pub fn socket_label(&self) -> &str {
        self.socket
            .as_deref()
            .unwrap_or("~/.ssh/vt.sock (default; $SSH_AUTH_SOCK unset)")
    }

    pub fn socket_path(&self) -> anyhow::Result<PathBuf> {
        match &self.socket {
            Some(socket) => Ok(Path::new(socket).to_owned()),
            None => self
                .home
                .as_ref()
                .map(|home| home.join(".ssh").join("vt.sock"))
                .ok_or_else(|| anyhow::anyhow!("Cannot determine home dir")),
        }
    }
}

/// The host token rides on every Worker request, so the transport must be
/// TLS. Plain `http://` is allowed only to loopback (local Worker dev); the
/// host is compared whole so `localhost.example` does not pass.
pub(crate) fn worker_url_is_secure(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or_default();
    host == "localhost"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::VarError;

    fn config(values: &[(&str, &str)]) -> ResolvedConfig {
        ResolvedConfig::resolve(
            Vec::new(),
            |key| {
                values
                    .iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| (*value).to_owned())
            },
            None,
            Some(PathBuf::from("/test-home")),
        )
    }

    #[test]
    fn backend_parse() {
        assert_eq!(ClientRoute::parse("auto"), Ok(ClientRoute::Auto));
        assert_eq!(ClientRoute::parse("agent"), Ok(ClientRoute::Agent));
        assert_eq!(ClientRoute::parse("passkey"), Ok(ClientRoute::Passkey));
        // Case-insensitive + trimmed; empty counts as unset.
        assert_eq!(ClientRoute::parse(" Passkey "), Ok(ClientRoute::Passkey));
        assert_eq!(ClientRoute::parse(""), Ok(ClientRoute::Auto));
        assert_eq!(ClientRoute::parse("  "), Ok(ClientRoute::Auto));
        // Typos fail loudly instead of silently routing to the wrong path.
        assert!(ClientRoute::parse("pass-key").is_err());
        assert!(ClientRoute::parse("cf").is_err());
    }

    #[test]
    fn routing_matrix_is_backend_only_with_lazy_worker_validation() {
        for backend in ["auto", "agent", "passkey"] {
            for url in [None, Some(""), Some("https://worker.invalid")] {
                for token in [None, Some(""), Some("token")] {
                    let mut values = vec![("VT_BACKEND", backend)];
                    if let Some(url) = url {
                        values.push(("VT_PASSKEY_URL", url));
                    }
                    if let Some(token) = token {
                        values.push(("VT_PASSKEY_TOKEN", token));
                    }
                    let cfg = config(&values);
                    let expected = match backend {
                        "passkey" if url.is_none() => Err(RoutingError::PasskeyUrlMissing),
                        "agent" => Ok(ClientRoute::Agent),
                        "passkey" => Ok(ClientRoute::Passkey),
                        _ => Ok(ClientRoute::Auto),
                    };
                    assert_eq!(
                        cfg.route(),
                        expected,
                        "backend={backend}, url={url:?}, token={token:?}"
                    );
                    assert_eq!(
                        cfg.passkey_config().is_ok(),
                        url.is_some_and(|s| !s.is_empty()) && token.is_some_and(|s| !s.is_empty())
                    );
                }
            }
        }
        // Plaintext transport is refused even with a token: the URL would
        // downgrade the challenge and WebSocket carrying the host token.
        for url in [
            "http://worker.invalid",
            "http://localhost.evil.invalid/",
            "http://127.evil.invalid",
            "ftp://worker.invalid",
        ] {
            let cfg = config(&[("VT_PASSKEY_URL", url), ("VT_PASSKEY_TOKEN", "token")]);
            let err = cfg.passkey_config().err().map(|e| e.to_string());
            assert!(
                err.as_deref()
                    .is_some_and(|e| e.contains("must be https://")),
                "{url}: {err:?}"
            );
        }
        for url in ["http://localhost:8787", "http://127.0.0.1:8787/"] {
            let cfg = config(&[("VT_PASSKEY_URL", url), ("VT_PASSKEY_TOKEN", "token")]);
            assert!(cfg.passkey_config().is_ok(), "{url}");
        }
        // A retired VT_AUTH value is inert: it neither routes nor is captured.
        let cfg = config(&[("VT_AUTH", "stale"), ("VT_BACKEND", "auto")]);
        assert_eq!(cfg.route(), Ok(ClientRoute::Auto));
        assert_eq!(cfg.value("VT_AUTH"), None);
    }

    #[test]
    fn snapshot_is_immutable_and_preserves_empty_environment_values() {
        let mut values = BTreeMap::from([
            ("VT_BACKEND", "auto".to_owned()),
            ("VT_PASSKEY_URL", "https://worker.invalid".to_owned()),
            ("VT_PASSKEY_TOKEN", "file-token".to_owned()),
            ("SSH_AUTH_SOCK", "/original.sock".to_owned()),
        ]);
        let cfg = ResolvedConfig::resolve(
            vec!["VT_PASSKEY_TOKEN".into()],
            |key| values.get(key).cloned(),
            Some(PathBuf::from("/config.toml")),
            None,
        );
        values.insert("VT_PASSKEY_TOKEN", "changed".into());
        values.insert("SSH_AUTH_SOCK", "/changed.sock".into());
        assert_eq!(cfg.passkey_config().unwrap().worker_auth, "file-token");
        assert_eq!(cfg.socket_path().unwrap(), Path::new("/original.sock"));
        assert_eq!(cfg.file_populated_keys, ["VT_PASSKEY_TOKEN"]);
        assert_eq!(
            config(&[("SSH_AUTH_SOCK", "")]).socket_path().unwrap(),
            Path::new("")
        );
    }

    #[test]
    fn passkey_uv_prefers_the_flag_and_stays_absent_when_unset() {
        let uv = |flag: Option<&str>, env: Option<&str>| {
            ResolvedConfig::from_lookup(
                flag.map(str::to_owned),
                Vec::new(),
                |key| match key {
                    "VT_PASSKEY_URL" => Ok("https://worker.invalid".to_owned()),
                    "VT_PASSKEY_TOKEN" => Ok("token".to_owned()),
                    "VT_PASSKEY_UV" => env.map(str::to_owned).ok_or(VarError::NotPresent),
                    _ => Err(VarError::NotPresent),
                },
                None,
                None,
            )
            .passkey_config()
            .unwrap()
            .uv
            .map(str::to_owned)
        };
        assert_eq!(uv(None, None), None);
        assert_eq!(uv(None, Some("preferred")), Some("preferred".to_owned()));
        assert_eq!(uv(Some("required"), None), Some("required".to_owned()));
        // The flag wins over the env/file value.
        assert_eq!(
            uv(Some("required"), Some("discouraged")),
            Some("required".to_owned())
        );
        // An empty value is "unset", not a request the worker has to parse.
        assert_eq!(uv(None, Some("")), None);
    }

    #[test]
    fn non_unicode_values_preserve_lazy_environment_errors() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        let cfg = ResolvedConfig::from_lookup(
            None,
            Vec::new(),
            |key| match key {
                "VT_BACKEND" | "VT_PASSKEY_URL" => {
                    Err(std::env::VarError::NotUnicode(invalid.clone()))
                }
                _ => Err(std::env::VarError::NotPresent),
            },
            None,
            None,
        );
        assert_eq!(cfg.route(), Ok(ClientRoute::Auto));
        assert!(cfg.value("VT_PASSKEY_URL").is_none());
        let error = cfg.passkey_config().err().unwrap();
        assert_eq!(
            error.downcast_ref::<std::env::VarError>(),
            Some(&std::env::VarError::NotUnicode(invalid))
        );
    }

    #[test]
    fn invalid_configuration_is_captured_without_failing_unrelated_commands() {
        let cfg = config(&[("VT_BACKEND", "typo")]);
        assert!(matches!(cfg.route(), Err(RoutingError::InvalidBackend(_))));
        assert_eq!(
            config(&[]).socket_path().unwrap(),
            Path::new("/test-home/.ssh/vt.sock")
        );
        let missing = ResolvedConfig::resolve(Vec::new(), |_| None, None, None);
        assert!(missing.socket_path().is_err());
        assert_eq!(missing.passkey_state(), PasskeyState::Unconfigured);
    }
}
