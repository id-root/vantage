pub mod crypto;
pub mod protocol;
pub mod network;
pub mod server;
pub mod client;
pub mod tui; 

// Global Shared Constants
pub const WIRE_PACKET_SIZE: usize = 4096;
pub const TAG_SIZE: usize = 16; 
pub const PLAINTEXT_SIZE: usize = WIRE_PACKET_SIZE - TAG_SIZE;

pub const READ_TIMEOUT_SEC: u64 = 300;
pub const HANDSHAKE_TIMEOUT_SEC: u64 = 30;
pub const DEFAULT_SOCKS_PROXY: &str = "127.0.0.1:9050";
pub const DEFAULT_ID_FILE: &str = "vantage.id";
