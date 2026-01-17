use clap::{Parser, Subcommand};
use anyhow::Result;

mod client;
mod server;
mod network;
mod crypto;
mod protocol;
mod tui;

// Global constants
pub const WIRE_PACKET_SIZE: usize = 4096;
pub const PQ_TAG_SIZE: usize = 16; 
pub const PLAINTEXT_SIZE: usize = 4064; 
pub const HANDSHAKE_TIMEOUT_SEC: u64 = 30;
pub const READ_TIMEOUT_SEC: u64 = 300;
pub const DEFAULT_SOCKS_PROXY: &str = "127.0.0.1:9050";
pub const DEFAULT_ID_FILE: &str = "vantage.id";

#[derive(Parser)]
#[command(name = "vantage")]
#[command(about = "VANTAGE: Post-Quantum Secure Chat over Tor", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start in Server (Listener) Mode
    Server {
        #[arg(short, long, default_value_t = 7878)]
        port: u16,
        #[arg(long, default_value = DEFAULT_ID_FILE)]
        identity: String,
    },
    /// Start in Client (Connect) Mode
    Client {
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        peer_fingerprint: String,
        #[arg(long, default_value = DEFAULT_SOCKS_PROXY)]
        proxy: String,
        #[arg(long, default_value = DEFAULT_ID_FILE)]
        identity: String,
        #[arg(short, long, default_value = "public")]
        group: String,
        
        // Temp Flag for Auto-Generation
        #[arg(long)]
        temp: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { port, identity } => {
            server::run(port, identity).await?;
        }
        Commands::Client { address, username, peer_fingerprint, proxy, identity, group, temp } => {
            client::run(address, username, peer_fingerprint, proxy, identity, group, temp).await?;
        }
    }

    Ok(())
}
