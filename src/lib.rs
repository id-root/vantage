pub mod crypto;
pub mod protocol;
pub mod network;
pub mod client;
pub mod server;
pub mod tui;
pub mod onion;
pub mod vault;

// Re-export constants
pub const WIRE_PACKET_SIZE: usize = 4096;
pub const PQ_TAG_SIZE: usize = 16; 
pub const PLAINTEXT_SIZE: usize = 4064; 
pub const HANDSHAKE_TIMEOUT_SEC: u64 = 30;
pub const READ_TIMEOUT_SEC: u64 = 300;
pub const DEFAULT_SOCKS_PROXY: &str = "127.0.0.1:9050";
pub const DEFAULT_ID_FILE: &str = "vantage.id";
