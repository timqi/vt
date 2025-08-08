use clap::{Parser, Subcommand};

mod encrypt;
mod init;
mod inject;
mod run;
mod serve;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a https server which will interact with system keychain for encryption/decryption
    Serve {
        #[clap(long, default_value = "127.0.0.1")]
        host: String,
        #[clap(short, long, default_value = "8080")]
        port: u16,
    },
    /// Initialize a gpg keypair, a passphrase which will be used by server
    Init,
    /// Will read plain text and output encrypted message for you
    Encrypt,
    /// Replace encrypted environment variables as plaintext and run program
    Run,
    /// Replace encrypted string in a file with plaintext
    Inject,
}

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Serve { host, port } => {
            serve::run(host.to_string(), *port);
        }
        Commands::Init => {
            init::run();
        }
        Commands::Encrypt => {
            encrypt::run();
        }
        Commands::Run => {
            run::run();
        }
        Commands::Inject => {
            inject::run();
        }
    }
}