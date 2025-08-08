use clap::{Parser, Subcommand};

mod cli;
mod serve;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[clap(long, default_value = "127.0.0.1")]
        host: String,
        #[clap(short, long, default_value = "5757")]
        port: u16,
    },
    /// Initialize a gpg keypair, a passphrase which will be used by server
    Init,
    /// Will read plain text and output encrypted message for you
    Encrypt,
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
            cli::init();
        }
        Commands::Encrypt => {
            cli::encrypt();
        }
    }
}
