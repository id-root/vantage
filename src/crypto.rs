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
// Feature 1 Imports
use argon2::{
    password_hash::rand_core::{OsRng, RngCore},
    Argon2
};
// D1: Anomaly Detection time tracking
use chrono::Timelike;

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
    metadata: String, // "ops" or "casual"
}

// Identity file constants
const SALT_LEN: usize = 32;
const SLOT_SIZE: usize = 1024;
// Identity file: Salt + Slot 1 + Slot 2
// Total size = 32 + 1024 + 1024 = 2080
const ID_FILE_SIZE: usize = SALT_LEN + 2 * SLOT_SIZE;

pub struct Identity {
    pub keypair: ZeroizableKeypair,
    pub profile_type: String, // "ops" or "casual"
}

impl Identity {
    pub fn generate(profile_type: &str) -> Result<Self> {
        let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
        let kp = builder.generate_keypair()?;
        Ok(Self {
            keypair: ZeroizableKeypair {
                public: kp.public,
                private: kp.private,
            },
            profile_type: profile_type.to_string(),
        })
    }

    /// Tries to load the identity from the file using the provided password.
    /// It attempts to decrypt both slots.
    pub fn load<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        if !path.as_ref().exists() {
             bail!("Identity file not found");
        }
        let mut file = File::open(&path)?;
        let mut data = vec![0u8; ID_FILE_SIZE];
        file.read_exact(&mut data).context("Identity file corrupt or too short")?;

        let salt = &data[..SALT_LEN];
        let slot1 = &data[SALT_LEN..SALT_LEN+SLOT_SIZE];
        let slot2 = &data[SALT_LEN+SLOT_SIZE..];

        // Derive key from password and salt
        let key = Self::derive_key(password, salt)?;
        let cipher = ChaCha20Poly1305::new(&key);
        // Derive nonce from password hash to ensure uniqueness
        let mut nonce_material = [0u8; 12];
        let mut h = Hasher::new();
        h.update(password.as_bytes());
        h.update(b"NONCE_DOMAIN"); // Domain separation
        h.update(salt); // Include salt for extra entropy
        nonce_material.copy_from_slice(&h.finalize().as_bytes()[..12]);
        let nonce = Nonce::from_slice(&nonce_material);

        // Try decrypt Slot 1
        if let Ok(plaintext) = cipher.decrypt(nonce, slot1) {
             // Trim trailing zeros/junk
             let len = plaintext.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
             if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&plaintext[..len]) {
                 return Ok(Self {
                     keypair: ZeroizableKeypair {
                         public: hex::decode(stored.public_hex)?,
                         private: hex::decode(stored.private_hex)?,
                     },
                     profile_type: stored.metadata,
                 });
             }
        }

        // Try decrypt Slot 2
        if let Ok(plaintext) = cipher.decrypt(nonce, slot2) {
             let len = plaintext.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
             if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&plaintext[..len]) {
                 return Ok(Self {
                     keypair: ZeroizableKeypair {
                         public: hex::decode(stored.public_hex)?,
                         private: hex::decode(stored.private_hex)?,
                     },
                     profile_type: stored.metadata,
                 });
             }
        }

        bail!("Invalid password or corrupted identity file");
    }

    pub fn setup_dual<P: AsRef<Path>>(path: P, pass_ops: &str, pass_casual: &str) -> Result<()> {
        let ops_id = Self::generate("ops")?;
        let casual_id = Self::generate("casual")?;

        // Generate random salt
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        // Derive keys
        let key_ops = Self::derive_key(pass_ops, &salt)?;
        let key_casual = Self::derive_key(pass_casual, &salt)?;

        // Encrypt Ops -> Slot 1
        let ops_stored = StoredIdentity {
            public_hex: hex::encode(&ops_id.keypair.public),
            private_hex: hex::encode(&ops_id.keypair.private),
            metadata: ops_id.profile_type,
        };
        let ops_json = serde_json::to_vec(&ops_stored)?;
        let cipher_ops = ChaCha20Poly1305::new(&key_ops);
        // Derive nonce from password hash
        let mut nonce_material = [0u8; 12];
        let mut h = Hasher::new();
        h.update(pass_ops.as_bytes());
        h.update(b"NONCE_DOMAIN");
        h.update(&salt);
        nonce_material.copy_from_slice(&h.finalize().as_bytes()[..12]);
        let nonce_ops = Nonce::from_slice(&nonce_material);

        let ciphertext_ops = cipher_ops.encrypt(nonce_ops, ops_json.as_slice())
            .map_err(|_| anyhow::anyhow!("Encryption failed for Ops ID"))?;

        if ciphertext_ops.len() > SLOT_SIZE {
            bail!("Ops Identity too large for slot");
        }
        let mut slot1 = vec![0u8; SLOT_SIZE];
        slot1[..ciphertext_ops.len()].copy_from_slice(&ciphertext_ops);
        // Fill rest with random? Actually, better to fill with random BEFORE copying encrypted data to avoid distinguishing size?
        // Wait, encrypt produces ciphertext. If we pad the plaintext with random junk, we get random ciphertext.
        // But here we have variable size ciphertext.
        // To hide size, we should probably pad the JSON before encryption?
        // Or just pad the slot with random bytes?
        // If we just pad the slot, an attacker can distinguish ciphertext from random padding.
        // But both look random.
        // EXCEPT the tag is at the end of ciphertext.
        // If we decrypt, we process bytes.
        // ChaCha20Poly1305 decrypt needs exact ciphertext.
        // So we should probably store length? Or try to decrypt everything?
        // If we encrypt, the result is `ciphertext + tag`.
        // If we pad AFTER the tag, the decryptor needs to know where the tag ends.
        // Standard approach: Pad plaintext to fixed size, then encrypt.
        // Let's pad plaintext to `SLOT_SIZE - TAG_SIZE` (1024 - 16 = 1008).
        
        // Revised encrypt logic:
        let plaintext_ops = ops_json;
        if plaintext_ops.len() > 1008 { bail!("Identity too big"); }
        // Pad with 0s? Or PKCS7? Or random?
        // JSON ends with '}'. We can pad with spaces if JSON. Or binary padding.
        // Since we serialize to vec, we can just append random bytes?
        // But JSON parser needs to ignore them.
        // `serde_json::from_slice` ignores trailing whitespace? Not sure about trailing binary garbage.
        // Better: Store `length` (u16) + `JSON`.
        // Even better: Pad with 0x00 and assume JSON ends earlier?
        // Let's verify `serde_json::from_slice` behavior. It stops after valid JSON?
        // Usually yes.
        // But to be safe, let's just encrypt the JSON. The output size tells us how big it is.
        // The remaining bytes in the 1024 slot should be random.
        // An attacker sees 1024 bytes.
        // If 200 bytes are ciphertext (high entropy) and 800 bytes are 0s (low entropy), they know size.
        // So we must fill the rest with random.
        // But random bytes vs ciphertext bytes are indistinguishable.
        // EXCEPT if we try to decrypt the whole 1024 bytes, it will fail tag check if we included the random padding in the "ciphertext" passed to decrypt.
        // So we need to know the ciphertext length.
        // We can hide the length by encoding it in the first 2 bytes (encrypted).
        // OR: We pad the PLAINTEXT to fixed size (1008 bytes) with 0s (or random, if we have a length prefix).
        // Then encrypt 1008 bytes -> 1024 bytes ciphertext.
        // Decrypt 1024 bytes -> 1008 bytes plaintext.
        // Parse JSON from plaintext.
        
        let mut padded_ops = plaintext_ops;
        padded_ops.resize(1008, 0); // Pad with zeros. JSON parser should handle it or we trim?
        // Serde JSON might fail if trailing nulls.
        // Let's strip nulls after decrypt.
        
        let ciphertext_ops = cipher_ops.encrypt(nonce_ops, padded_ops.as_slice())
             .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
        // ciphertext_ops should be 1008 + 16 = 1024.
        
        // Encrypt Casual -> Slot 2
        let casual_stored = StoredIdentity {
             public_hex: hex::encode(&casual_id.keypair.public),
             private_hex: hex::encode(&casual_id.keypair.private),
             metadata: casual_id.profile_type,
        };
        let casual_json = serde_json::to_vec(&casual_stored)?;
        let mut padded_casual = casual_json;
        padded_casual.resize(1008, 0);
        
        let cipher_casual = ChaCha20Poly1305::new(&key_casual);
        let mut nonce_material_casual = [0u8; 12];
        let mut h = Hasher::new();
        h.update(pass_casual.as_bytes());
        h.update(b"NONCE_DOMAIN");
        h.update(&salt);
        nonce_material_casual.copy_from_slice(&h.finalize().as_bytes()[..12]);
        let nonce_casual = Nonce::from_slice(&nonce_material_casual);

        let ciphertext_casual = cipher_casual.encrypt(nonce_casual, padded_casual.as_slice())
             .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        // Write to file
        let mut file = File::create(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }
        
        file.write_all(&salt)?;
        file.write_all(&ciphertext_ops)?;
        file.write_all(&ciphertext_casual)?;
        
        Ok(())
    }

    fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
        let mut output_key_material = [0u8; 32];
        let params = argon2::Params::default(); // Argon2id, default cost
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params
        );
        argon2.hash_password_into(password.as_bytes(), salt, &mut output_key_material)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
        Ok(*Key::from_slice(&output_key_material))
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
    pub pq_tx_cipher: Option<ChaCha20Poly1305>,
    pub pq_rx_cipher: Option<ChaCha20Poly1305>,
    
    // ⭐ FIX: SEPARATE NONCES FOR TX AND RX ⭐
    pub pq_send_nonce: u64,
    pub pq_recv_nonce: u64,
    
    // C2: PQ Key Rotation - track message count
    #[allow(dead_code)]
    pub message_count: u64,
    #[allow(dead_code)]
    pub session_start: std::time::Instant,
}

// C2: Rekey thresholds
#[allow(dead_code)]
const REKEY_MESSAGE_THRESHOLD: u64 = 100;
#[allow(dead_code)]
const REKEY_TIME_THRESHOLD_SECS: u64 = 300; // 5 minutes

impl NoiseSession {
    pub fn new(handshake: HandshakeState) -> Result<Self> {
        let transport = handshake.into_transport_mode()?;
        Ok(Self { 
            transport, 
            buf: vec![0u8; 65535],
            pq_tx_cipher: None,
            pq_rx_cipher: None,
            pq_send_nonce: 0,
            pq_recv_nonce: 0,
            message_count: 0,
            session_start: std::time::Instant::now(),
        })
    }
    
    // C2: Check if session needs PQ key rotation
    #[allow(dead_code)]
    pub fn needs_rekey(&self) -> bool {
        self.pq_tx_cipher.is_some() && (
            self.message_count >= REKEY_MESSAGE_THRESHOLD ||
            self.session_start.elapsed().as_secs() >= REKEY_TIME_THRESHOLD_SECS
        )
    }
    
    // C2: Increment message counter
    #[allow(dead_code)]
    pub fn increment_message_count(&mut self) {
        self.message_count += 1;
    }
    
    pub fn upgrade_to_pq(&mut self, shared_secret: &[u8], is_initiator: bool) {
        // Derive Initiator Key
        let mut h_init = Hasher::new();
        h_init.update(b"ISOTOPE_PQ_INITIATOR");
        h_init.update(shared_secret);
        let k_init_bytes = h_init.finalize();
        let k_init = Key::from_slice(k_init_bytes.as_bytes());

        // Derive Responder Key
        let mut h_resp = Hasher::new();
        h_resp.update(b"ISOTOPE_PQ_RESPONDER");
        h_resp.update(shared_secret);
        let k_resp_bytes = h_resp.finalize();
        let k_resp = Key::from_slice(k_resp_bytes.as_bytes());

        let (tx_key, rx_key) = if is_initiator {
            (k_init, k_resp)
        } else {
            (k_resp, k_init)
        };

        self.pq_tx_cipher = Some(ChaCha20Poly1305::new(tx_key));
        self.pq_rx_cipher = Some(ChaCha20Poly1305::new(rx_key));

        // Reset both nonces on upgrade
        self.pq_send_nonce = 0;
        self.pq_recv_nonce = 0;
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // 1. Outer Layer (Noise)
        let len = self.transport.read_message(ciphertext, &mut self.buf)?;
        let noise_plain = self.buf[..len].to_vec();

        // 2. Inner Layer (PQ)
        if let Some(cipher) = &self.pq_rx_cipher {
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
        let data_to_send = if let Some(cipher) = &self.pq_tx_cipher {
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

// A1: Secure Memory Wiping - Zeroize sensitive data on drop
impl Drop for NoiseSession {
    fn drop(&mut self) {
        // Zeroize the buffer containing potential plaintext/ciphertext
        self.buf.zeroize();
        // Zeroize nonces
        self.pq_send_nonce = 0;
        self.pq_recv_nonce = 0;
        // Cipher keys are internal to ChaCha20Poly1305, we drop them
        self.pq_tx_cipher = None;
        self.pq_rx_cipher = None;
    }
}

// =============================================================================
// Z2: HSM INTEGRATION - Hardware Security Module Trait
// =============================================================================
//
// Design:
// - Abstract trait for hardware key storage (YubiKey, TPM, HSM)
// - Keys never leave secure hardware
// - Sign/decrypt operations happen inside HSM
// - Software implementation provided as fallback

/// Trait for Hardware Security Module integration
#[allow(dead_code)]
pub trait HsmProvider: Send + Sync {
    /// Get the public key stored in HSM
    fn get_public_key(&self) -> Result<Vec<u8>>;
    
    /// Sign data using HSM-stored private key
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt data using HSM-stored private key
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    
    /// Check if HSM is available and initialized
    fn is_available(&self) -> bool;
}

/// Software fallback HSM implementation
#[allow(dead_code)]
pub struct SoftwareHsm {
    keypair: Option<ZeroizableKeypair>,
}

impl SoftwareHsm {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self { keypair: None }
    }
    
    #[allow(dead_code)]
    pub fn load_keypair(&mut self, keypair: ZeroizableKeypair) {
        self.keypair = Some(keypair);
    }
}

impl Default for SoftwareHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmProvider for SoftwareHsm {
    fn get_public_key(&self) -> Result<Vec<u8>> {
        self.keypair.as_ref()
            .map(|k| k.public.clone())
            .context("No keypair loaded")
    }
    
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        // In real HSM, signing happens inside hardware
        // Here we just hash as placeholder
        let mut hasher = Hasher::new();
        hasher.update(data);
        if let Some(kp) = &self.keypair {
            hasher.update(&kp.private);
        }
        Ok(hasher.finalize().as_bytes().to_vec())
    }
    
    fn decrypt(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Placeholder - real HSM would use private key internally
        bail!("Software HSM decrypt not implemented - use real HSM")
    }
    
    fn is_available(&self) -> bool {
        self.keypair.is_some()
    }
}

// =============================================================================
// C3: DENIABLE AUTHENTICATION
// =============================================================================
//
// Design:
// - Ring signatures: prove you're part of a group without revealing which member
// - DAKE (Deniable Authenticated Key Exchange)
// - No transcript can prove who participated

/// Generates a ring signature that proves membership in a group
/// without revealing which member signed
#[allow(dead_code)]
pub fn ring_sign(
    message: &[u8],
    my_private: &[u8],
    ring_public_keys: &[Vec<u8>],
) -> Vec<u8> {
    // Simplified ring signature placeholder
    // Real implementation would use Linkable Ring Signatures
    let mut hasher = Hasher::new();
    hasher.update(b"ISOTOPE_RING_SIG");
    hasher.update(message);
    hasher.update(my_private);
    for pk in ring_public_keys {
        hasher.update(pk);
    }
    hasher.finalize().as_bytes().to_vec()
}

/// Verify a ring signature is valid for the group
#[allow(dead_code)]
pub fn ring_verify(
    message: &[u8],
    signature: &[u8],
    ring_public_keys: &[Vec<u8>],
) -> bool {
    // Placeholder - real verification would check cryptographic proof
    !signature.is_empty() && !ring_public_keys.is_empty() && !message.is_empty()
}

// =============================================================================
// D1: ANOMALY DETECTION - Behavioral Analysis
// =============================================================================
//
// Design:
// - Track normal user behavior patterns
// - Detect deviations that might indicate compromise
// - Alert on suspicious activity patterns

/// Tracks user behavior for anomaly detection
#[derive(Default)]
#[allow(dead_code)]
pub struct BehaviorProfile {
    /// Average messages per session
    avg_messages_per_session: f64,
    /// Typical session duration in seconds
    avg_session_duration_secs: u64,
    /// Typical active hours (0-23)
    active_hours: [u32; 24],
    /// Total sessions tracked
    sessions_counted: u32,
    /// Current session state
    current_session_messages: u32,
    current_session_start: Option<std::time::Instant>,
}

/// Type of anomaly detected
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AnomalyType {
    /// Unusual message volume
    HighMessageVolume { current: u32, expected: f64 },
    /// Login at unusual hour
    UnusualActiveHour { hour: u8 },
    /// Session abnormally long
    ExtendedSession { duration_secs: u64, expected: u64 },
    /// Rapid commands (possible automation)
    RapidCommands { commands_per_min: u32 },
}

impl BehaviorProfile {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Start tracking a new session
    #[allow(dead_code)]
    pub fn start_session(&mut self) {
        self.current_session_messages = 0;
        self.current_session_start = Some(std::time::Instant::now());
        
        // Track active hour
        let hour = chrono::Local::now().hour() as usize;
        if hour < 24 {
            self.active_hours[hour] += 1;
        }
    }
    
    /// Record a message sent
    #[allow(dead_code)]
    pub fn record_message(&mut self) {
        self.current_session_messages += 1;
    }
    
    /// End session and update profile
    #[allow(dead_code)]
    pub fn end_session(&mut self) {
        if self.sessions_counted > 0 {
            let total_messages = self.avg_messages_per_session * self.sessions_counted as f64;
            self.avg_messages_per_session = 
                (total_messages + self.current_session_messages as f64) / (self.sessions_counted + 1) as f64;
            
            if let Some(start) = self.current_session_start {
                let duration = start.elapsed().as_secs();
                let total_duration = self.avg_session_duration_secs * self.sessions_counted as u64;
                self.avg_session_duration_secs = 
                    (total_duration + duration) / (self.sessions_counted + 1) as u64;
            }
        } else {
            self.avg_messages_per_session = self.current_session_messages as f64;
            if let Some(start) = self.current_session_start {
                self.avg_session_duration_secs = start.elapsed().as_secs();
            }
        }
        self.sessions_counted += 1;
    }
    
    /// Check for anomalies in current session
    #[allow(dead_code)]
    pub fn check_anomalies(&self) -> Vec<AnomalyType> {
        let mut anomalies = Vec::new();
        
        // Check message volume (>3x average is anomalous)
        if self.sessions_counted >= 5 {
            let expected = self.avg_messages_per_session * 3.0;
            if self.current_session_messages as f64 > expected {
                anomalies.push(AnomalyType::HighMessageVolume {
                    current: self.current_session_messages,
                    expected: self.avg_messages_per_session,
                });
            }
        }
        
        // Check unusual active hour
        let current_hour = chrono::Local::now().hour() as usize;
        if current_hour < 24 && self.sessions_counted >= 10 {
            let hour_activity = self.active_hours[current_hour];
            let avg_activity: u32 = self.active_hours.iter().sum::<u32>() / 24;
            if hour_activity == 0 && avg_activity > 2 {
                anomalies.push(AnomalyType::UnusualActiveHour { 
                    hour: current_hour as u8 
                });
            }
        }
        
        // Check extended session
        if let Some(start) = self.current_session_start {
            let duration = start.elapsed().as_secs();
            if self.sessions_counted >= 5 && duration > self.avg_session_duration_secs * 3 {
                anomalies.push(AnomalyType::ExtendedSession {
                    duration_secs: duration,
                    expected: self.avg_session_duration_secs,
                });
            }
        }
        
        anomalies
    }
}
