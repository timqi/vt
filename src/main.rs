// Server-side modules consume most cross-platform symbols (`do_encrypt`,
// session classifiers, etc.). On non-macOS targets the server tree is
// cfg-gated out, so those symbols look unused. Suppress the noise rather
// than sprinkle `#[allow(dead_code)]` across `core` items.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::client::VTClient;

/// VT_AUTH is optional. When set, the CLI tries the SSH-agent path first
/// (macOS Touch ID). When unset, it skips the agent and goes straight to the
/// CF passkey ceremony (which itself requires VT_PASSKEY_URL + VT_PASSKEY_TOKEN).
fn require_auth(auth: &Option<String>) -> Result<String> {
    Ok(auth.clone().unwrap_or_default())
}

/// Build the agent's audit-push config from the `--audit-*` flags. Returns a
/// disabled config (audit push is a no-op) when `--audit-url` is unset,
/// `--no-audit-push` is given, or `--audit-key` is empty. `agent_id` is the
/// machine hostname; the agent derives its per-host audit subkey from the master
/// (`--audit-key`, == VT_AUTH_CF) + that hostname ONCE here at startup, so the
/// raw master is not retained — only the 32-byte subkey lives in the config.
#[cfg(target_os = "macos")]
fn build_audit_push_config(
    audit_url: &Option<String>,
    audit_key: &Option<String>,
    no_audit_push: bool,
) -> server_macos::audit::AuditPushConfig {
    use server_macos::audit::AuditPushConfig;

    let Some(url) = audit_url else {
        return AuditPushConfig::disabled();
    };
    if no_audit_push {
        return AuditPushConfig::disabled();
    }
    let master = match audit_key {
        Some(k) if !k.trim().is_empty() => k.trim(),
        _ => {
            tracing::warn!("audit push disabled: --audit-key not set");
            return AuditPushConfig::disabled();
        }
    };
    // agent_id = hostname. The Worker re-derives HKDF(VT_AUTH_CF, hostname) to
    // verify, so the wire stays per-host-keyed and the Worker is unchanged.
    let hostname = client::get_hostname();
    // Derive the per-host subkey once; pass the Zeroizing<[u8;32]> straight in so
    // no plain heap copy of the key ever exists.
    let key = audit::derive_agent_audit_key(master.as_bytes(), &hostname);
    AuditPushConfig::new(url.clone(), key, hostname)
}

mod audit;
mod cf;
mod client;
mod config;
mod core;
mod hook;
#[cfg(target_os = "macos")]
mod server_macos;
mod ssh_sign;
mod tty;

#[derive(Parser)]
#[command(
    author,
    version = env!("VT_VERSION"),
    about = "a simple kms. no plain, explicit auth everywhere"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "VT_AUTH",
        hide_env = true,
        help = "SSH-agent auth token (macOS, optional). When unset the CLI uses the CF passkey ceremony (env: VT_AUTH)"
    )]
    auth: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, PartialEq)]
enum Commands {
    /// Show version information
    Version,
    /// Diagnose config sources, transport routing, and agent cache behavior.
    /// Read-only: asks a reachable vt agent (via diag@vt) how it classifies
    /// this connection and why it is or isn't cacheable
    Doctor,
    /// Will read plain text and output encrypted message for you.
    /// With stdin piped (not a terminal) the plaintext is read from stdin —
    /// one trailing newline stripped — and no prompt is shown
    Create {
        #[arg(
            long = "type",
            value_name = "raw|totp",
            help = "Secret type. Required to answer the prompt non-interactively; defaults to raw when stdin is piped"
        )]
        secret_type: Option<String>,
    },
    /// Decrypt an existing vt protocol as plaintext
    Read {
        #[arg(help = "A string in vt protocol format, e.g. vt://mac/0xxxx")]
        vt: String,

        #[arg(long, help = "Reason shown in the bio auth prompt")]
        reason: Option<String>,
    },
    /// Decrypt vt:// in a file (in place, restored after --timeout) and/or
    /// env/argv, then exec the given command.
    Inject {
        #[arg(
            short = 'r',
            long = "replace-file",
            help = "File whose vt:// records are decrypted in place; restored after --timeout"
        )]
        replace_file: Option<String>,

        #[arg(
            short = 't',
            long,
            default_value = "2",
            value_parser = clap::value_parser!(u32).range(1..),
            help = "Seconds before the backup is restored over the decrypted file (>= 1)"
        )]
        timeout: u32,

        #[arg(long, help = "Reason shown in the bio auth prompt")]
        reason: Option<String>,

        #[arg(
            long = "only-env",
            value_delimiter = ',',
            help = "Restrict env-var vt:// decryption to these names (comma-separated). When omitted, every env var whose value contains vt:// is decrypted. Used by `vt hook` to scope a command to exactly the secrets its rule names."
        )]
        only_env: Option<Vec<String>>,

        #[arg(
            long,
            conflicts_with_all = ["replace_file", "reason", "only_env", "args"],
            help = "Restore ciphertext for any file left decrypted by a crashed or rebooted restore supervisor (sweeps the injection state dir). Run at login/boot. Needs no auth — it only moves the ciphertext backup back over the target."
        )]
        recover: bool,

        #[arg(
            trailing_var_arg = true,
            help = "Additional arguments to pass to the spawned process"
        )]
        args: Vec<String>,
    },

    /// Re-encrypt legacy `vt://mac/...` URLs in files as the v2 envelope
    /// format. Without `--no-dry-run` only previews what would change.
    /// One Touch ID covers the whole batch (decrypt); re-encrypt is silent.
    Rewrap {
        #[arg(required = true, help = "Files to scan and rewrite")]
        files: Vec<std::path::PathBuf>,
        #[arg(
            long,
            help = "Actually decrypt, re-encrypt, and rewrite files. Without this flag the command only previews the URLs it would migrate."
        )]
        no_dry_run: bool,
        #[arg(
            long,
            help = "Leave a <file>.vt-rewrap-backup copy next to each rewritten file. Off by default."
        )]
        backup: bool,
    },

    /// AI-agent command hook. Reads an agent's proposed shell command and,
    /// per the `[[rules]]` whitelist in ~/.config/vt/agent.toml, accepts it,
    /// blocks it, or rewrites it to run under `vt inject` so vt:// secrets in
    /// the environment are transparently decrypted. See `docs/hook.md`.
    #[command(subcommand)]
    Hook(HookCommands),

    /// Trigger bio auth via the vt SSH agent (for use with PAM, sudo, etc.)
    Auth {
        #[arg(long, help = "Reason shown in the bio auth prompt")]
        reason: Option<String>,
    },

    /// Ask the local vt SSH agent to run an allowlisted program on this Mac
    /// after Touch ID. Typically invoked from a remote host via a forwarded
    /// SSH agent socket — e.g. `vt run -- zed ssh://g1/path` from a remote
    /// shell pops Zed open locally pointed at the remote folder. Fire and
    /// forget; no stdout/stderr/exit-code is returned. Touch ID is required
    /// for every call (no caching).
    Run {
        #[arg(long, help = "Reason shown in the Touch ID prompt")]
        reason: Option<String>,

        #[arg(
            trailing_var_arg = true,
            required = true,
            help = "Program and arguments to run on the agent's machine, e.g. `zed ssh://g1/path`"
        )]
        argv: Vec<String>,
    },

    /// (Mac only) Initialize passcode and passphrase in the keychain
    #[cfg(target_os = "macos")]
    Init,
    /// (Mac only) Manage master secret
    #[cfg(target_os = "macos")]
    #[command(subcommand)]
    Secret(SecretCommands),
    /// SSH agent + key management (agent/add/list/... are macOS-only;
    /// keygen/connect are cross-platform)
    #[command(subcommand)]
    Ssh(SshCommands),
    /// (Mac only) Manage FIDO2 (YubiKey) credentials for Touch ID fallback
    #[cfg(target_os = "macos")]
    #[command(subcommand)]
    Fido2(Fido2Commands),
}

#[derive(Subcommand, PartialEq)]
pub enum HookCommands {
    /// Process a Claude Code PreToolUse event (JSON on stdin) and emit the
    /// decision JSON on stdout. Wire it as a PreToolUse hook for the Bash tool.
    Claude,
    /// Dry-run: print what the hook would do (ACCEPT / BLOCK / REWRITE) for the
    /// given command, without executing anything.
    Check {
        #[arg(
            trailing_var_arg = true,
            required = true,
            help = "The command to evaluate, e.g. `vt hook check gh pr list`"
        )]
        command: Vec<String>,
    },
    /// Exec-gateway: evaluate <argv> against the rules and then exec it
    /// unchanged, exec it under `vt inject`, or refuse it (non-zero exit).
    /// Intended for shell shims/wrappers — see `vt hook install-shims`.
    Exec {
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            help = "Program and args to gate, e.g. `vt hook exec -- gh pr list`"
        )]
        argv: Vec<String>,
    },
    /// Generate PATH shims (symlinks to vt, one per command in
    /// ~/.config/vt/agent.toml) that route through the exec-gateway, then print
    /// the line to prepend to PATH. Works in interactive shells, scripts, and
    /// non-interactive (agent) shells.
    InstallShims {
        #[arg(
            long,
            help = "Directory to write shims into (default: ~/.local/share/vt/shims)"
        )]
        dir: Option<String>,
    },
}

#[cfg(target_os = "macos")]
#[derive(Subcommand, PartialEq)]
pub enum Fido2Commands {
    /// Register a new YubiKey. Requires Touch ID or password first.
    Register {
        #[arg(short = 'l', long = "label", help = "Human label for this credential")]
        label: Option<String>,
    },
    /// List registered YubiKey credentials
    List,
    /// Remove a credential by short-id prefix
    Remove {
        #[arg(help = "Short-id prefix (shown in `vt fido2 list`)")]
        short_id: String,
    },
    /// Remove all credentials
    RemoveAll,
}

#[cfg(target_os = "macos")]
#[derive(Subcommand, PartialEq)]
pub enum SecretCommands {
    /// Export the encrypted master secret
    Export,
    /// Import an encrypted master secret
    Import,
    /// Rotate the passcode for the master secret
    RotatePasscode,
    /// Migrate the master-key wrap to the path-independent v2 derivation
    /// (or back to v1 with --to-v1 before rolling back to an old binary)
    Rebind {
        #[arg(
            long,
            help = "Absolute path of the vt binary that wrote the store, for v1 stores bound to a location this binary no longer occupies. The old binary need not exist — only the path string enters the derivation."
        )]
        old_bin_path: Option<String>,
        #[arg(
            long,
            help = "Rewrap back to the legacy v1 derivation bound to THIS binary's current path (escape hatch before downgrading vt)"
        )]
        to_v1: bool,
    },
}

#[derive(Subcommand, PartialEq)]
pub enum SshCommands {
    /// Generate a portable Ed25519 SSH identity stored as a vt:// record
    /// (cross-platform). Prints the OpenSSH public key for GitHub.
    Keygen {
        #[arg(short = 'l', long = "label", help = "Label/comment for the key")]
        label: Option<String>,
        #[arg(
            short = 'c',
            long = "comment",
            help = "OpenSSH comment (overrides --label)"
        )]
        comment: Option<String>,
        #[arg(
            long = "key-file",
            help = "Where to write the vt:// record (default ~/.config/vt/git-ssh); .pub written alongside"
        )]
        key_file: Option<String>,
    },
    /// Git SSH driver (cross-platform). Set `GIT_SSH_COMMAND="vt ssh connect"`.
    /// Signs with the vt:// identity via an ephemeral in-process agent + system ssh.
    Connect {
        #[arg(
            long = "forward-real-agent",
            default_value_t = false,
            help = "Forward the ephemeral agent to the remote (agent forwarding) and relay decrypt@vt / encrypt@vt / auth@vt / sign@vt / diag@vt to the UPSTREAM real vt agent; run@vt and every other extension are refused. Lets `vt read` / `vt inject` / a nested `vt ssh connect` on the remote use this host's Touch ID instead of paging the phone. Must precede the ssh arguments."
        )]
        forward_real_agent: bool,
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            help = "Arguments passed through to the system ssh (host + remote command)"
        )]
        args: Vec<String>,
    },
    /// Start the SSH agent (listens on ~/.ssh/vt.sock)
    #[cfg(target_os = "macos")]
    Agent {
        // The three duration knobs are `Option` so "flag passed" is
        // distinguishable from "compiled default": effective value is
        // flag > config.toml `[agent]` > built-in default
        // (docs/app-bundle.md §4).
        #[arg(
            short = 't',
            long = "timeout",
            help = "Idle timeout in seconds before clearing keys from memory and revoking all grants (default 7200 = 2h; config.toml [agent].timeout overrides the default). Screen lock and sleep/wake revoke far sooner regardless; lower this on hosts without reliable auto-lock."
        )]
        timeout: Option<u64>,
        #[arg(
            long = "ssh-auth-cache-duration",
            help = "Sign approval reuse duration in seconds; 0 (default) = prompt every time. Grants are activity-scoped: raw ssh signs bind to the session-bind-verified destination server (repeated one-shot git/ssh calls to the same host reuse one approval); local sign@vt and ssh-keygen signing bind to the caller's git workspace; forwarded/relay traffic is confined per connection and never rides local approvals. Strict TTL, no sliding refresh; screen lock, sleep/wake, agent lock, and idle timeout revoke all grants immediately. config.toml [agent].ssh_auth_cache_duration overrides the default."
        )]
        auth_cache_duration: Option<u64>,
        #[arg(
            long = "decrypt-auth-cache-duration",
            help = "Decrypt approval reuse duration in seconds; 0 (default) = prompt every time. Only v2 envelope URLs are cache-eligible; legacy items always prompt. Grants bind to the caller's git workspace (kernel-derived), or per relay connection when forwarded. Kept separate from the sign duration because a cached decrypt grant releases per-record DEK material. config.toml [agent].decrypt_auth_cache_duration overrides the default."
        )]
        decrypt_auth_cache_duration: Option<u64>,
        #[arg(
            long = "no-cache-hit-notify",
            default_value_t = false,
            help = "Disable the system notification fired when a cached grant satisfies sign/decrypt without a Touch ID prompt. Also configurable as [agent].cache_hit_notify in config.toml."
        )]
        no_cache_hit_notify: bool,
        #[arg(
            long = "no-legacy-decrypt",
            default_value_t = false,
            help = "Reject legacy v0/v1 vt:// URLs on decrypt@vt; only v2 envelope URLs are accepted. Use this once you've migrated all stored secrets to the v2 format."
        )]
        no_legacy_decrypt: bool,
        #[arg(
            long = "run-allow",
            help = "Comma-separated allowlist for `run@vt` (e.g. `zed,code,/Applications/Zed.app/Contents/MacOS/cli`). Bare names match argv[0] without `/` and are resolved via the agent's own PATH; entries containing `/` must be absolute and match argv[0] post-canonicalization. Unset falls back to config.toml [agent].run_allow, then empty (run@vt disabled)."
        )]
        run_allow: Option<String>,
        #[arg(
            long = "audit-url",
            help = "Worker base URL for agent audit push, e.g. https://vt-passkey.example.com. Unset (the default) disables audit push."
        )]
        audit_url: Option<String>,
        #[arg(
            long = "audit-key",
            help = "Worker master key for agent audit push (VT_AUTH_CF, == VT_PASSKEY_TOKEN). The agent derives its per-host audit subkey from this + the hostname on startup. NOTE: on the command line → visible in the process list; avoid on shared hosts. Unset (the default) disables audit push."
        )]
        audit_key: Option<String>,
        #[arg(
            long = "no-audit-push",
            default_value_t = false,
            help = "Disable audit push even when --audit-url is set."
        )]
        no_audit_push: bool,
        #[arg(
            long = "ui-token-fd",
            help = "File descriptor to read the 32-byte ui-status@vt token from at startup (inherited pipe). Set only by the VT.app shell supervisor — a pipe, never an env var (visible in `ps e`) or a file. Without it, ui-status@vt refuses every request."
        )]
        ui_token_fd: Option<i32>,
    },
    /// Add an SSH private key to the keychain
    #[cfg(target_os = "macos")]
    Add {
        #[arg(short = 'f', long = "file", help = "Path to the SSH private key file")]
        file: Option<String>,
        #[arg(
            short = 'c',
            long = "comment",
            help = "Comment for the key (overrides key's embedded comment)"
        )]
        comment: Option<String>,
    },
    /// List stored SSH keys
    #[cfg(target_os = "macos")]
    List,
    /// Remove an SSH key by fingerprint
    #[cfg(target_os = "macos")]
    Remove {
        #[arg(help = "Fingerprint (or prefix) of the key to remove")]
        fingerprint: String,
    },
    /// Remove all stored SSH keys
    #[cfg(target_os = "macos")]
    RemoveAll,
    /// Change the comment of a stored SSH key
    #[cfg(target_os = "macos")]
    Comment {
        #[arg(help = "Fingerprint (or prefix) of the key to update")]
        fingerprint: String,
        #[arg(short = 'c', long = "comment", help = "New comment for the key")]
        comment: String,
    },
    /// Show the public key for a stored SSH key
    #[cfg(target_os = "macos")]
    Show {
        #[arg(help = "Fingerprint (or prefix) of the key to show")]
        fingerprint: String,
    },
}

async fn run(cli: Cli, file_populated_keys: Vec<String>) -> Result<()> {
    match &cli.command {
        Commands::Version => {
            println!("vt {}", env!("VT_VERSION"));
            println!("commit {} ({})", env!("VT_GIT_SHA"), env!("VT_COMMIT_DATE"));
            Ok(())
        }
        Commands::Doctor => {
            let auth = require_auth(&cli.auth)?;
            return client::doctor(&auth, &file_populated_keys).await;
        }
        #[cfg(target_os = "macos")]
        Commands::Init => server_macos::admin::init(),
        #[cfg(target_os = "macos")]
        Commands::Secret(secret_command) => match secret_command {
            SecretCommands::Export => server_macos::admin::export_secret().await,
            SecretCommands::Import => server_macos::admin::import_secret().await,
            SecretCommands::RotatePasscode => server_macos::admin::rotate_passcode().await,
            SecretCommands::Rebind {
                old_bin_path,
                to_v1,
            } => server_macos::admin::rebind(old_bin_path.clone(), *to_v1).await,
        },
        Commands::Ssh(ssh_command) => match ssh_command {
            SshCommands::Keygen {
                label,
                comment,
                key_file,
            } => {
                let auth = require_auth(&cli.auth)?;
                let vt_client = VTClient::new(auth)?;
                ssh_sign::keygen(vt_client, label.clone(), comment.clone(), key_file.clone()).await
            }
            SshCommands::Connect {
                forward_real_agent,
                args,
            } => {
                let auth = require_auth(&cli.auth)?;
                let vt_client = VTClient::new(auth)?;
                ssh_sign::connect(vt_client, args.clone(), *forward_real_agent).await
            }
            #[cfg(target_os = "macos")]
            SshCommands::Agent {
                timeout,
                auth_cache_duration,
                decrypt_auth_cache_duration,
                no_cache_hit_notify,
                no_legacy_decrypt,
                run_allow,
                audit_url,
                audit_key,
                no_audit_push,
                ui_token_fd,
            } => {
                use server_macos::ssh_agent::{AuthCacheTtls, RunAllowlist};
                let audit_push = build_audit_push_config(audit_url, audit_key, *no_audit_push);
                // flag > config.toml [agent] > built-in default
                // (docs/app-bundle.md §4).
                let file_cfg = config::load_agent_file_config();
                let run_allow_spec = run_allow.clone().or(file_cfg.run_allow).unwrap_or_default();
                let run_allow = RunAllowlist::parse(&run_allow_spec)
                    .map_err(|e| anyhow::anyhow!("run-allow: {}", e))?;
                // Floor the idle timeout at 60s: unlike the cache durations,
                // idle `0` is NOT a "Fresh" special case — it would make the
                // sweeper busy-loop (check_interval = min(60, timeout) = 0).
                // Guards the config / CLI / UserDefaults-restart paths.
                let timeout = timeout
                    .or(file_cfg.timeout)
                    .unwrap_or(server_macos::ssh_agent::DEFAULT_IDLE_TIMEOUT_SECS)
                    .max(60);
                let sign_secs = auth_cache_duration
                    .or(file_cfg.ssh_auth_cache_duration)
                    .unwrap_or(0);
                let decrypt_secs = decrypt_auth_cache_duration
                    .or(file_cfg.decrypt_auth_cache_duration)
                    .unwrap_or(0);
                let notify_cache_hits =
                    !*no_cache_hit_notify && file_cfg.cache_hit_notify.unwrap_or(true);
                let ui_token = match ui_token_fd {
                    Some(fd) => {
                        use std::io::Read;
                        use std::os::unix::io::FromRawFd;
                        // SAFETY: the fd number was handed to us by the
                        // spawning supervisor explicitly for this purpose;
                        // we take ownership exactly once, read 32 bytes,
                        // and drop (close) it before the agent serves.
                        let mut pipe = unsafe { std::fs::File::from_raw_fd(*fd) };
                        let mut token = [0u8; 32];
                        pipe.read_exact(&mut token)
                            .map_err(|e| anyhow::anyhow!("--ui-token-fd {fd}: {e}"))?;
                        Some(token)
                    }
                    None => None,
                };
                server_macos::ssh_agent::start_ssh_agent(
                    timeout,
                    AuthCacheTtls {
                        sign_secs,
                        decrypt_secs,
                    },
                    *no_legacy_decrypt,
                    run_allow,
                    std::sync::Arc::new(audit_push),
                    notify_cache_hits,
                    ui_token,
                )
                .await
            }
            #[cfg(target_os = "macos")]
            SshCommands::Add { file, comment } => {
                server_macos::ssh_cli::ssh_add(file.clone(), comment.clone())
            }
            #[cfg(target_os = "macos")]
            SshCommands::List => server_macos::ssh_cli::ssh_list(),
            #[cfg(target_os = "macos")]
            SshCommands::Remove { fingerprint } => server_macos::ssh_cli::ssh_remove(fingerprint),
            #[cfg(target_os = "macos")]
            SshCommands::RemoveAll => server_macos::ssh_cli::ssh_remove_all(),
            #[cfg(target_os = "macos")]
            SshCommands::Comment {
                fingerprint,
                comment,
            } => server_macos::ssh_cli::ssh_comment(fingerprint, comment),
            #[cfg(target_os = "macos")]
            SshCommands::Show { fingerprint } => server_macos::ssh_cli::ssh_show(fingerprint),
        },
        #[cfg(target_os = "macos")]
        Commands::Fido2(cmd) => match cmd {
            Fido2Commands::Register { label } => {
                server_macos::fido2_cli::fido2_register(label.clone())
            }
            Fido2Commands::List => server_macos::fido2_cli::fido2_list(),
            Fido2Commands::Remove { short_id } => server_macos::fido2_cli::fido2_remove(short_id),
            Fido2Commands::RemoveAll => server_macos::fido2_cli::fido2_remove_all(),
        },
        Commands::Create { secret_type } => {
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::create(vt_client, secret_type.as_deref()).await
        }
        Commands::Read { vt, reason } => {
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::read(vt_client, vt.to_string(), reason.as_deref()).await
        }
        Commands::Auth { reason } => {
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::auth(vt_client, reason.as_deref().unwrap_or("bio auth requested")).await
        }
        Commands::Run { reason, argv } => {
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::run(vt_client, argv.clone(), reason.as_deref()).await
        }
        Commands::Rewrap {
            files,
            no_dry_run,
            backup,
        } => {
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::rewrap(vt_client, files.clone(), *no_dry_run, *backup).await
        }
        Commands::Inject {
            replace_file,
            timeout,
            reason,
            only_env,
            recover,
            args,
        } => {
            // Recovery only moves the ciphertext backup back over the target —
            // no decryption, so no VT_AUTH required.
            if *recover {
                return client::inject_recover();
            }
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::inject(
                vt_client,
                replace_file.clone(),
                *timeout,
                reason.as_deref(),
                only_env.clone(),
                args.clone(),
            )
            .await
        }
        Commands::Hook(cmd) => hook::run(cmd),
    }
}

fn main() {
    // The inject supervisor is dispatched here, *before* tokio / tracing /
    // clap load. It runs in the spawned child of `vt inject -r ...` and only
    // needs to sleep, unlink a tmp file, and rename a backup over the target.
    // Avoiding tokio shaves ~MB of RSS off a process that sleeps for seconds.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.get(1).and_then(|s| s.to_str()) == Some(client::SUPERVISOR_SUBCOMMAND) {
        std::process::exit(client::supervisor_main(&args[2..]));
    }

    // Multi-call (busybox-style) dispatch: when invoked via a `vt hook
    // install-shims` symlink whose name isn't `vt` (e.g. `gh`), act as the
    // exec-gateway for that command. Runs before clap (argv[0] isn't `vt`).
    if let Some(name) = args
        .first()
        .map(std::path::Path::new)
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
    {
        if name != "vt" && !name.is_empty() {
            std::process::exit(hook::shim_main(name, &args[1..]));
        }
    }

    let log_level = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| {
            if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "info".to_string()
            }
        })
        .parse::<tracing::Level>()
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(true)
        .with_line_number(true)
        .with_writer(std::io::stderr)
        .compact()
        .init();

    // Fallback layer: populate any unset VT_* env var from
    // ~/.config/vt/config.toml (override path via $VT_CONFIG). Env vars always
    // win. Must run before Cli::parse() (clap reads VT_AUTH from env) and while
    // still single-threaded (before the tokio runtime is built).
    let file_populated_keys = config::hydrate_env_from_file();

    let cli = Cli::parse();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    if let Err(e) = rt.block_on(run(cli, file_populated_keys)) {
        // Walk the error chain to find a `VtClientError`. The agent's
        // structured `ErrKind` maps to a stable exit code; transport
        // failures and any other error chain default to exit 1.
        let code = e
            .chain()
            .find_map(|src| src.downcast_ref::<client::VtClientError>())
            .map(|v| v.exit_code())
            .unwrap_or(1);
        // User-facing: one clean line on stderr. anyhow's alternate
        // Display (`{:#}`) joins the chain with `: ` separators — for
        // VtClientError it's just the typed message; for other anyhow
        // chains (e.g. "Failed to read file: <path>: No such file...")
        // it's the conventional CLI shape. The full Debug chain stays
        // on the tracing pipeline at debug level for troubleshooting.
        eprintln!("{:#}", e);
        tracing::debug!("error chain: {:?}", e);
        std::process::exit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_connect(argv: &[&str]) -> (bool, Vec<String>) {
        let cli = Cli::try_parse_from(argv).expect("argv must parse");
        match cli.command {
            Commands::Ssh(SshCommands::Connect {
                forward_real_agent,
                args,
            }) => (forward_real_agent, args),
            _ => panic!("expected ssh connect"),
        }
    }

    // `--forward-real-agent` must parse as OUR flag when it precedes the
    // trailing ssh args (the `git config core.sshCommand "vt ssh connect
    // --forward-real-agent"` shape), and the hyphenated ssh options after it
    // must still pass through verbatim.
    #[test]
    fn connect_forward_flag_parses_before_trailing_args() {
        let (fwd, args) = parse_connect(&[
            "vt",
            "ssh",
            "connect",
            "--forward-real-agent",
            "-p",
            "2222",
            "host",
            "cmd",
        ]);
        assert!(fwd);
        assert_eq!(args, vec!["-p", "2222", "host", "cmd"]);
    }

    // Default is OFF and plain usage is unchanged.
    #[test]
    fn connect_forward_flag_defaults_off() {
        let (fwd, args) = parse_connect(&["vt", "ssh", "connect", "host", "git-upload-pack"]);
        assert!(!fwd);
        assert_eq!(args, vec!["host", "git-upload-pack"]);
    }
}
