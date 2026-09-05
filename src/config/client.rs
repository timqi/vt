//! Immutable client configuration after config-file hydration and clap parsing.
//! Validation stays lazy: doctor and commands without authentication still run
//! with an incomplete or invalid routing setup.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::Backend;

pub const CLIENT_CONFIG_KEYS: &[&str] = &[
    "VT_BACKEND",
    "VT_AUTH",
    "VT_PASSKEY_URL",
    "VT_PASSKEY_TOKEN",
    "VT_GIT_SSH_PRIVATE_KEY",
    "VT_GIT_SSH_PUB",
    "VT_AGENT_CONFIG",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientRoute {
    Agent,
    AutoAgent,
    Passkey,
    AutoPasskey,
}

impl ClientRoute {
    pub fn uses_agent(self) -> bool {
        matches!(self, Self::Agent | Self::AutoAgent)
    }

    pub fn allows_passkey_fallback(self) -> bool {
        self == Self::AutoAgent
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
    AgentAuthMissing,
    PasskeyUrlMissing,
    NoPath,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBackend(message) => f.write_str(message),
            Self::AgentAuthMissing => f.write_str("VT_BACKEND=agent requires VT_AUTH for the SSH agent path"),
            Self::PasskeyUrlMissing => f.write_str("VT_BACKEND=passkey requires VT_PASSKEY_URL + VT_PASSKEY_TOKEN for the phone passkey ceremony"),
            Self::NoPath => f.write_str("no decryption path configured — set VT_AUTH for the SSH agent path, or VT_PASSKEY_URL + VT_PASSKEY_TOKEN for the phone passkey ceremony"),
        }
    }
}

impl std::error::Error for RoutingError {}

// Intentionally no Debug: this snapshot includes bearer tokens and may include
// a misconfigured plaintext SSH private key in its diagnostic values.
#[derive(Clone)]
pub struct ResolvedConfig {
    auth_token: String,
    values: BTreeMap<&'static str, Result<String, std::env::VarError>>,
    pub file_populated_keys: Vec<String>,
    pub config_path: Option<PathBuf>,
    socket: Option<String>,
    home: Option<PathBuf>,
}

impl ResolvedConfig {
    pub fn capture(auth: Option<String>, file_populated_keys: Vec<String>) -> Self {
        Self::from_lookup(
            auth,
            file_populated_keys,
            |key| std::env::var(key),
            super::config_path(),
            dirs::home_dir(),
        )
    }

    fn from_lookup(
        auth: Option<String>,
        file_populated_keys: Vec<String>,
        mut lookup: impl FnMut(&str) -> Result<String, std::env::VarError>,
        config_path: Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> Self {
        let values: BTreeMap<_, _> = CLIENT_CONFIG_KEYS
            .iter()
            .map(|&key| (key, lookup(key)))
            .collect();
        let auth_token = auth
            .or_else(|| {
                values
                    .get("VT_AUTH")
                    .and_then(|value| value.as_ref().ok())
                    .cloned()
            })
            .unwrap_or_default();
        Self {
            auth_token,
            values,
            file_populated_keys,
            config_path,
            socket: lookup("SSH_AUTH_SOCK").ok(),
            home,
        }
    }

    #[cfg(test)]
    pub(crate) fn resolve(
        auth: Option<String>,
        file_populated_keys: Vec<String>,
        mut lookup: impl FnMut(&str) -> Option<String>,
        config_path: Option<PathBuf>,
        home: Option<PathBuf>,
    ) -> Self {
        Self::from_lookup(
            auth,
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

    pub fn auth_token(&self) -> &str {
        &self.auth_token
    }

    pub fn route(&self) -> Result<ClientRoute, RoutingError> {
        let backend = Backend::parse(self.value("VT_BACKEND").unwrap_or_default())
            .map_err(RoutingError::InvalidBackend)?;
        let has_auth = !self.auth_token.is_empty();
        let has_url = self.value("VT_PASSKEY_URL").is_some();
        match backend {
            Backend::Agent if !has_auth => Err(RoutingError::AgentAuthMissing),
            Backend::Passkey if !has_url => Err(RoutingError::PasskeyUrlMissing),
            _ if !has_auth && !has_url => Err(RoutingError::NoPath),
            Backend::Agent => Ok(ClientRoute::Agent),
            Backend::Passkey => Ok(ClientRoute::Passkey),
            Backend::Auto if has_auth => Ok(ClientRoute::AutoAgent),
            Backend::Auto => Ok(ClientRoute::AutoPasskey),
        }
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
        Ok(crate::cf::CfConfig {
            worker_url,
            worker_auth,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(auth: Option<&str>, values: &[(&str, &str)]) -> ResolvedConfig {
        ResolvedConfig::resolve(
            auth.map(str::to_owned),
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
    fn routing_matrix_preserves_pins_and_lazy_worker_validation() {
        for backend in ["auto", "agent", "passkey"] {
            for auth in [None, Some(""), Some("auth")] {
                for url in [None, Some(""), Some("https://worker.invalid")] {
                    for token in [None, Some(""), Some("token")] {
                        let mut values = vec![("VT_BACKEND", backend)];
                        if let Some(url) = url {
                            values.push(("VT_PASSKEY_URL", url));
                        }
                        if let Some(token) = token {
                            values.push(("VT_PASSKEY_TOKEN", token));
                        }
                        let cfg = config(auth, &values);
                        let has_auth = auth.is_some_and(|s| !s.is_empty());
                        let expected = match backend {
                            "agent" if !has_auth => Err(RoutingError::AgentAuthMissing),
                            "passkey" if url.is_none() => Err(RoutingError::PasskeyUrlMissing),
                            _ if !has_auth && url.is_none() => Err(RoutingError::NoPath),
                            "agent" => Ok(ClientRoute::Agent),
                            "passkey" => Ok(ClientRoute::Passkey),
                            _ if has_auth => Ok(ClientRoute::AutoAgent),
                            _ => Ok(ClientRoute::AutoPasskey),
                        };
                        assert_eq!(
                            cfg.route(),
                            expected,
                            "backend={backend}, auth={auth:?}, url={url:?}, token={token:?}"
                        );
                        assert_eq!(
                            cfg.passkey_config().is_ok(),
                            url.is_some_and(|s| !s.is_empty())
                                && token.is_some_and(|s| !s.is_empty())
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn snapshot_preserves_cli_precedence_and_empty_environment_values() {
        let mut values = BTreeMap::from([
            ("VT_AUTH", "env-auth".to_owned()),
            ("VT_BACKEND", "auto".to_owned()),
            ("VT_PASSKEY_URL", "https://worker.invalid".to_owned()),
            ("VT_PASSKEY_TOKEN", "file-token".to_owned()),
            ("SSH_AUTH_SOCK", "/original.sock".to_owned()),
        ]);
        let cfg = ResolvedConfig::resolve(
            Some("cli-auth".into()),
            vec!["VT_PASSKEY_TOKEN".into()],
            |key| values.get(key).cloned(),
            Some(PathBuf::from("/config.toml")),
            None,
        );
        values.insert("VT_PASSKEY_TOKEN", "changed".into());
        values.insert("SSH_AUTH_SOCK", "/changed.sock".into());
        assert_eq!(cfg.auth_token(), "cli-auth");
        assert_eq!(cfg.value("VT_AUTH"), Some("env-auth"));
        assert_eq!(cfg.passkey_config().unwrap().worker_auth, "file-token");
        assert_eq!(cfg.socket_path().unwrap(), Path::new("/original.sock"));
        assert_eq!(cfg.file_populated_keys, ["VT_PASSKEY_TOKEN"]);
        assert_eq!(
            config(Some(""), &[("VT_AUTH", "env")]).route(),
            Err(RoutingError::NoPath)
        );
        assert_eq!(
            config(None, &[("VT_AUTH", "env")]).route(),
            Ok(ClientRoute::AutoAgent)
        );
        assert_eq!(
            config(None, &[("SSH_AUTH_SOCK", "")])
                .socket_path()
                .unwrap(),
            Path::new("")
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_values_preserve_lazy_environment_errors() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        let cfg = ResolvedConfig::from_lookup(
            Some("auth".into()),
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
        assert_eq!(cfg.route(), Ok(ClientRoute::AutoAgent));
        assert!(cfg.value("VT_PASSKEY_URL").is_none());
        let error = cfg.passkey_config().err().unwrap();
        assert_eq!(
            error.downcast_ref::<std::env::VarError>(),
            Some(&std::env::VarError::NotUnicode(invalid))
        );
    }

    #[test]
    fn invalid_configuration_is_captured_without_failing_unrelated_commands() {
        let cfg = config(None, &[("VT_BACKEND", "typo")]);
        assert!(matches!(cfg.route(), Err(RoutingError::InvalidBackend(_))));
        assert_eq!(
            config(None, &[]).socket_path().unwrap(),
            Path::new("/test-home/.ssh/vt.sock")
        );
        let missing = ResolvedConfig::resolve(None, Vec::new(), |_| None, None, None);
        assert!(missing.socket_path().is_err());
        assert_eq!(missing.passkey_state(), PasskeyState::Unconfigured);
    }
}
