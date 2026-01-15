use clap::{Parser, Subcommand};
use vantage::{server, client, crypto::Identity};
use anyhow::Result;
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "vantage", version = "3.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a persistent identity
    GenKey {
        #[arg(short, long, default_value = "vantage.id")]
        output: String,
    },
    /// Start the VANTAGE Hub Server
    Server {
        #[arg(long, default_value_t = 7878)]
        port: u16,
        #[arg(long, default_value = "vantage.id")]
        identity: String,
    },
    /// Connect to a VANTAGE Hub
    Client {
        #[arg(long)]
        address: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        peer_fingerprint: String,
        #[arg(long, default_value = "127.0.0.1:9050")]
        proxy: String,
        #[arg(long, default_value = "vantage.id")]
        identity: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::GenKey { output } => {
            let id = Identity::generate()?;
            id.save(&output)?;
            println!("✅ Identity generated: {}", output);
            println!("🔑 Fingerprint: {}", id.fingerprint());
        }
        Commands::Server { port, identity } => {
            server::run(port, identity).await?;
        }
        Commands::Client { address, username, peer_fingerprint, proxy, identity } => {
            client::run(address, username, peer_fingerprint, proxy, identity).await?;
        }
    }
    
    Ok(())
}
