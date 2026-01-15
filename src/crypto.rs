use snow::{Builder, Keypair, TransportState, HandshakeState};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use anyhow::{Result, Context, bail};
use base64::prelude::*;
use blake3::Hasher;
use crate::WIRE_PACKET_SIZE;

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
}

pub struct NoiseSession {
    pub transport: TransportState,
    pub buf: Vec<u8>,
}

impl NoiseSession {
    pub fn new(handshake: HandshakeState) -> Result<Self> {
        let transport = handshake.into_transport_mode()?;
        Ok(Self { transport, buf: vec![0u8; 65535] })
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let len = self.transport.read_message(ciphertext, &mut self.buf)?;
        Ok(self.buf[..len].to_vec())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let len = self.transport.write_message(plaintext, &mut self.buf)?;
        if len != WIRE_PACKET_SIZE {
            bail!("Encryption failed to produce fixed-size packet");
        }
        Ok(self.buf[..len].to_vec())
    }
}
