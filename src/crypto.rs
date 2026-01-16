use snow::{Builder, TransportState, HandshakeState};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use anyhow::{Result, Context, bail};
use base64::prelude::*;
use blake3::Hasher;
use crate::{WIRE_PACKET_SIZE, PQ_TAG_SIZE};

// PQ Imports
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, 
    aead::{Aead, KeyInit}
};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizableKeypair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    public_hex: String,
    private_hex: String,
}

pub struct Identity {
    pub keypair: ZeroizableKeypair,
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
        let kp = builder.generate_keypair()?;
        Ok(Self {
            keypair: ZeroizableKeypair {
                public: kp.public,
                private: kp.private,
            },
        })
    }

    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        if path.as_ref().exists() {
            let mut file = File::open(&path)?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let stored: StoredIdentity = serde_json::from_str(&contents)
                .context("Failed to parse identity file")?;
            Ok(Self {
                keypair: ZeroizableKeypair {
                    public: hex::decode(stored.public_hex)?,
                    private: hex::decode(stored.private_hex)?,
                },
            })
        } else {
            let id = Self::generate()?;
            id.save(path)?;
            Ok(id)
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let stored = StoredIdentity {
            public_hex: hex::encode(&self.keypair.public),
            private_hex: hex::encode(&self.keypair.private),
        };
        let json = serde_json::to_string_pretty(&stored)?;
        let mut file = File::create(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.keypair.public);
        BASE64_STANDARD.encode(hasher.finalize().as_bytes())
    }

    pub fn did(&self) -> String {
        let mut bytes = vec![0xec, 0x01]; 
        bytes.extend_from_slice(&self.keypair.public);
        let multibase = bs58::encode(bytes).into_string();
        format!("did:key:z{}", multibase)
    }
}

pub struct NoiseSession {
    pub transport: TransportState,
    pub buf: Vec<u8>,
    pub pq_cipher: Option<ChaCha20Poly1305>,
    
    // ⭐ FIX: SEPARATE NONCES FOR TX AND RX ⭐
    pub pq_send_nonce: u64,
    pub pq_recv_nonce: u64,
}

impl NoiseSession {
    pub fn new(handshake: HandshakeState) -> Result<Self> {
        let transport = handshake.into_transport_mode()?;
        Ok(Self { 
            transport, 
            buf: vec![0u8; 65535],
            pq_cipher: None,
            pq_send_nonce: 0,
            pq_recv_nonce: 0,
        })
    }
    
    pub fn upgrade_to_pq(&mut self, shared_secret: &[u8]) {
        let mut hasher = Hasher::new();
        hasher.update(b"VANTAGE_PQ_LAYER");
        hasher.update(shared_secret);
        let key_bytes = hasher.finalize();
        let key = Key::from_slice(key_bytes.as_bytes());
        self.pq_cipher = Some(ChaCha20Poly1305::new(key));
        // Reset both nonces on upgrade
        self.pq_send_nonce = 0;
        self.pq_recv_nonce = 0;
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // 1. Outer Layer (Noise)
        let len = self.transport.read_message(ciphertext, &mut self.buf)?;
        let noise_plain = self.buf[..len].to_vec();

        // 2. Inner Layer (PQ)
        if let Some(cipher) = &self.pq_cipher {
            let mut nonce_bytes = [0u8; 12];
            // ⭐ USE RECV NONCE ⭐
            nonce_bytes[4..].copy_from_slice(&self.pq_recv_nonce.to_be_bytes());
            self.pq_recv_nonce += 1;
            
            let nonce = Nonce::from_slice(&nonce_bytes);
            let inner_plain = cipher.decrypt(nonce, noise_plain.as_ref())
                .map_err(|_| anyhow::anyhow!("PQ Decryption Failed"))?;
            
            return Ok(inner_plain);
        } else {
            // Remove dummy padding if PQ is off
            if noise_plain.len() < PQ_TAG_SIZE {
                 bail!("Packet too short to contain padding");
            }
            let real_len = noise_plain.len() - PQ_TAG_SIZE;
            return Ok(noise_plain[..real_len].to_vec());
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // 1. Inner Layer (PQ)
        let data_to_send = if let Some(cipher) = &self.pq_cipher {
            let mut nonce_bytes = [0u8; 12];
            // ⭐ USE SEND NONCE ⭐
            nonce_bytes[4..].copy_from_slice(&self.pq_send_nonce.to_be_bytes());
            self.pq_send_nonce += 1;

            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher.encrypt(nonce, plaintext)
                .map_err(|_| anyhow::anyhow!("PQ Encryption Failed"))?
        } else {
            // Add dummy padding
            let mut padded = plaintext.to_vec();
            padded.resize(plaintext.len() + PQ_TAG_SIZE, 0);
            padded
        };

        // 2. Outer Layer (Noise)
        let len = self.transport.write_message(&data_to_send, &mut self.buf)?;
        
        if len != WIRE_PACKET_SIZE {
            bail!("Encryption failed to produce fixed-size packet");
        }
        Ok(self.buf[..len].to_vec())
    }
}
