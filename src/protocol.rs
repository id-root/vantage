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
    Join { 
        username: String 
    },
    Chat { 
        sender: String,
        content: String,
        timestamp: DateTime<Utc>
    },
    System {
        content: String
    },
    // --- FILE TRANSFER PROTOCOL ---
    // 1. Sender broadcasts this
    FileOffer {
        sender: String,
        file_name: String,
        file_size: u64,
        id: u32,
    },
    // 2. Receiver sends this to say "Yes"
    FileRequest {
        receiver: String,
        file_id: u32,
    },
    // 3. Sender streams these
    FileChunk {
        file_id: u32,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
    }
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
            bail!("Packet exceeded max plaintext size");
        }
        Ok(data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(data)?)
    }
}
