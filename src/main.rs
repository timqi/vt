use clap::{Parser, Subcommand};

mod cli;
mod security;
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
    /// Initialize passcode, passphrase which will be used by server
    Init,
    /// Will read plain text and output encrypted message for you
    Encrypt,
}

#[tokio::main]
async fn main() {
    let log_level = if cfg!(debug_assertions) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(log_level).init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Serve { host, port } => {
            serve::serve(host.to_string(), *port).await;
        }
        Commands::Init => {
            cli::init();
        }
        Commands::Encrypt => {
            cli::encrypt().await;
        }
    }
}
