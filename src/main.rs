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

mod cf;
mod client;
mod core;
#[cfg(target_os = "macos")]
mod server_macos;
mod tty;

#[derive(Parser)]
#[command(
    author,
    version,
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
    /// Will read plain text and output encrypted message for you
    Create,
    /// Decrypt an existing vt protocol as plaintext
    Read {
        #[arg(help = "A string in vt protocol format, e.g. vt://mac/0xxxx")]
        vt: String,

        #[arg(long, help = "Reason shown in the bio auth prompt")]
        reason: Option<String>,
    },
    /// Read env/file and decrypt vt protocol, output to output-file or standard output
    Inject {
        #[arg(
            short = 'r',
            long = "replace-file",
            help = "Path to the file to replace with the decrypted vt protocol"
        )]
        replace_file: Option<String>,

        #[arg(short = 'i', long = "input-file", help = "Path to the input file")]
        input_file: Option<String>,

        #[arg(short = 'o', long = "output-file", help = "Path to the output file")]
        output_file: Option<String>,

        #[arg(
            short = 't',
            long,
            default_value = "2",
            help = "Timeout for deleting output_file after the spawned process in seconds"
        )]
        timeout: u32,

        #[arg(long, help = "Reason shown in the bio auth prompt")]
        reason: Option<String>,

        #[arg(
            trailing_var_arg = true,
            help = "Additional arguments to pass to the spawned process"
        )]
        args: Vec<String>,
    },

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
    /// (Mac only) SSH agent and key management
    #[cfg(target_os = "macos")]
    #[command(subcommand)]
    Ssh(SshCommands),
    /// (Mac only) Manage FIDO2 (YubiKey) credentials for Touch ID fallback
    #[cfg(target_os = "macos")]
    #[command(subcommand)]
    Fido2(Fido2Commands),
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
    RotatePasscode {
        #[arg(long, help = "Absolute path to the new vt binary")]
        bin_absolute_path: Option<String>,
    },
}

#[cfg(target_os = "macos")]
#[derive(Subcommand, PartialEq)]
pub enum SshCommands {
    /// Start the SSH agent (listens on ~/.ssh/vt.sock)
    Agent {
        #[arg(
            short = 't',
            long = "timeout",
            default_value_t = server_macos::ssh_agent::DEFAULT_IDLE_TIMEOUT_SECS,
            help = "Idle timeout in seconds before clearing keys from memory"
        )]
        timeout: u64,
        #[arg(
            long = "ssh-auth-cache-mode",
            default_value = "none",
            help = "Sign auth cache mode: none, per-session, or per-app"
        )]
        auth_cache_mode: server_macos::ssh_agent::AuthCacheMode,
        #[arg(
            long = "ssh-auth-cache-duration",
            default_value_t = server_macos::ssh_agent::DEFAULT_AUTH_CACHE_DURATION_SECS,
            help = "Sign auth cache duration in seconds"
        )]
        auth_cache_duration: u64,
        #[arg(
            long = "decrypt-auth-cache-mode",
            default_value = "none",
            help = "Decrypt auth cache mode: none, per-session, or per-app. Only v2 envelope URLs are cache-eligible; legacy items always prompt."
        )]
        decrypt_auth_cache_mode: server_macos::ssh_agent::AuthCacheMode,
        #[arg(
            long = "decrypt-auth-cache-duration",
            default_value_t = server_macos::ssh_agent::DEFAULT_DECRYPT_AUTH_CACHE_DURATION_SECS,
            help = "Decrypt auth cache duration in seconds (strict TTL, no sliding refresh)"
        )]
        decrypt_auth_cache_duration: u64,
        #[arg(
            long = "no-legacy-decrypt",
            default_value_t = false,
            help = "Reject legacy v0/v1 vt:// URLs on decrypt@vt; only v2 envelope URLs are accepted. Use this once you've migrated all stored secrets to the v2 format."
        )]
        no_legacy_decrypt: bool,
        #[arg(
            long = "run-allow",
            default_value = "",
            help = "Comma-separated allowlist for `run@vt` (e.g. `zed,code,/Applications/Zed.app/Contents/MacOS/cli`). Bare names match argv[0] without `/` and are resolved via the agent's own PATH; entries containing `/` must be absolute and match argv[0] post-canonicalization. Empty (the default) disables run@vt entirely."
        )]
        run_allow: String,
    },
    /// Add an SSH private key to the keychain
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
    List,
    /// Remove an SSH key by fingerprint
    Remove {
        #[arg(help = "Fingerprint (or prefix) of the key to remove")]
        fingerprint: String,
    },
    /// Remove all stored SSH keys
    RemoveAll,
    /// Change the comment of a stored SSH key
    Comment {
        #[arg(help = "Fingerprint (or prefix) of the key to update")]
        fingerprint: String,
        #[arg(short = 'c', long = "comment", help = "New comment for the key")]
        comment: String,
    },
    /// Show the public key for a stored SSH key
    Show {
        #[arg(help = "Fingerprint (or prefix) of the key to show")]
        fingerprint: String,
    },
}

async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Version => {
            println!("vt {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        #[cfg(target_os = "macos")]
        Commands::Init => server_macos::admin::init(),
        #[cfg(target_os = "macos")]
        Commands::Secret(secret_command) => match secret_command {
            SecretCommands::Export => server_macos::admin::export_secret().await,
            SecretCommands::Import => server_macos::admin::import_secret().await,
            SecretCommands::RotatePasscode { bin_absolute_path } => {
                server_macos::admin::rotate_passcode(bin_absolute_path.clone()).await
            }
        },
        #[cfg(target_os = "macos")]
        Commands::Ssh(ssh_command) => match ssh_command {
            SshCommands::Agent {
                timeout,
                auth_cache_mode,
                auth_cache_duration,
                decrypt_auth_cache_mode,
                decrypt_auth_cache_duration,
                no_legacy_decrypt,
                run_allow,
            } => {
                use server_macos::ssh_agent::{AuthCacheConfig, RunAllowlist};
                let run_allow = RunAllowlist::parse(run_allow)
                    .map_err(|e| anyhow::anyhow!("--run-allow: {}", e))?;
                server_macos::ssh_agent::start_ssh_agent(
                    *timeout,
                    AuthCacheConfig {
                        mode: *auth_cache_mode,
                        ttl_secs: *auth_cache_duration,
                    },
                    AuthCacheConfig {
                        mode: *decrypt_auth_cache_mode,
                        ttl_secs: *decrypt_auth_cache_duration,
                    },
                    *no_legacy_decrypt,
                    run_allow,
                )
                .await
            }
            SshCommands::Add { file, comment } => server_macos::ssh_cli::ssh_add(file.clone(), comment.clone()),
            SshCommands::List => server_macos::ssh_cli::ssh_list(),
            SshCommands::Remove { fingerprint } => server_macos::ssh_cli::ssh_remove(fingerprint),
            SshCommands::RemoveAll => server_macos::ssh_cli::ssh_remove_all(),
            SshCommands::Comment {
                fingerprint,
                comment,
            } => server_macos::ssh_cli::ssh_comment(fingerprint, comment),
            SshCommands::Show { fingerprint } => server_macos::ssh_cli::ssh_show(fingerprint),
        },
        #[cfg(target_os = "macos")]
        Commands::Fido2(cmd) => match cmd {
            Fido2Commands::Register { label } => server_macos::fido2_cli::fido2_register(label.clone()),
            Fido2Commands::List => server_macos::fido2_cli::fido2_list(),
            Fido2Commands::Remove { short_id } => server_macos::fido2_cli::fido2_remove(short_id),
            Fido2Commands::RemoveAll => server_macos::fido2_cli::fido2_remove_all(),
        },
        Commands::Create => {
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::create(vt_client).await
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
        Commands::Inject {
            replace_file,
            input_file,
            output_file,
            timeout,
            reason,
            args,
        } => {
            let auth = require_auth(&cli.auth)?;
            let vt_client = VTClient::new(auth)?;
            client::inject(
                vt_client,
                replace_file.clone(),
                input_file.clone(),
                output_file.clone(),
                *timeout,
                reason.as_deref(),
                args.clone(),
            )
            .await
        }
    }
}

#[tokio::main]
async fn main() {
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
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
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
