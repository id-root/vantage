use serde::{Serialize, Deserialize};
use crate::PLAINTEXT_SIZE;
use anyhow::{Result, bail};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use chrono::{DateTime, Utc};

#[derive(Serialize, Deserialize)]
pub struct VantagePacket {
    pub payload: Vec<u8>,
    pub nonce: [u8; 32],
    pub padding: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WireMessage {
    Heartbeat,
    
    Join { 
        username: String,
        did: String,
        // ⭐ NEW: Group Handle (e.g., "#hackers")
        group: String 
    },
    // ⭐ NEW: Gossip Message (Server tells Client who else is here)
    PeerList {
        peers: Vec<String> 
    },
    
    Chat { 
        sender: String,
        content: String,
        timestamp: DateTime<Utc>
    },
    System {
        content: String
    },
    PQInit {
        public_key: Vec<u8> 
    },
    PQFinish {
        ciphertext: Vec<u8> 
    },
    FileOffer {
        sender: String,
        file_name: String,
        file_size: u64,
        id: u32,
    },
    FileRequest {
        receiver: String,
        file_id: u32,
    },
    FileChunk {
        file_id: u32,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
    },
    AdminCommand {
        command: String,
        target: String,
    },
    DirectMessage {
        sender: String,
        target: String,
        content: String,
        timestamp: DateTime<Utc>,
    },
    VoicePacket {
        data: Vec<u8>,
    },
}

impl VantagePacket {
    pub fn new(payload: &[u8]) -> Result<Self> {
        let mut rng = ChaCha12Rng::from_entropy();
        let overhead = 64; 
        
        if payload.len() + overhead > PLAINTEXT_SIZE {
            bail!("Payload too large for constant-rate packet");
        }
        
        let padding_len = PLAINTEXT_SIZE - (payload.len() + overhead);
        
        Ok(Self {
            payload: payload.to_vec(),
            nonce: rng.gen(),
            padding: (0..padding_len).map(|_| rng.gen()).collect(),
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = bincode::serialize(self)?;
        if data.len() < PLAINTEXT_SIZE {
            data.resize(PLAINTEXT_SIZE, 0);
        } else if data.len() > PLAINTEXT_SIZE {
            data.truncate(PLAINTEXT_SIZE);
        }
        Ok(data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(data)?)
    }
}

// Feature 2: Protocol Mimicry
// Wrap encrypted packet (which is 4096 bytes) in fake HTTP.

pub struct HttpWrapper;

impl HttpWrapper {
    /// Wraps data in a fake HTTP POST request (Client -> Server)
    pub fn wrap_request(data: &[u8]) -> Vec<u8> {
        let headers = format!(
            "POST /api/v1/analytics/report HTTP/1.1\r\n\
             Host: analytics.google.com\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            data.len()
        );
        let mut packet = headers.into_bytes();
        packet.extend_from_slice(data);
        packet
    }

    /// Wraps data in a fake HTTP 200 OK response (Server -> Client)
    pub fn wrap_response(data: &[u8]) -> Vec<u8> {
        let headers = format!(
            "HTTP/1.1 200 OK\r\n\
             Server: gws\r\n\
             Date: {}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: keep-alive\r\n\
             \r\n",
             Utc::now().to_rfc2822(),
            data.len()
        );
        let mut packet = headers.into_bytes();
        packet.extend_from_slice(data);
        packet
    }
    
    // NOTE: Parsing logic is tricky because we might read partial headers or partial body.
    // However, the current network model uses `read_len_prefixed` or similar logic.
    // BUT `read_len_prefixed` reads 2 bytes length then data.
    // If we wrap in HTTP, we lose the length prefix or we must include it?
    // If we want to look like HTTP on the wire, we can't have a 2-byte length prefix BEFORE the HTTP headers.
    // The HTTP headers must be the FIRST bytes on the wire.
    // So `read_len_prefixed` in `network.rs` is incompatible with "look like HTTP".
    // We must modify `network.rs` to parse HTTP.
}
