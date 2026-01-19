#![allow(dead_code)]

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as DhPublicKey, StaticSecret};
use chacha20poly1305::{ChaCha20Poly1305, Key, AeadCore, aead::{Aead, KeyInit}};
use anyhow::{Result, bail};

/// Represents a node in the circuit.
/// The `pk` is the X25519 Public Key of the node.
/// The `addr` is the network address (e.g., "1.2.3.4:8000") of the node.
#[derive(Clone)]
pub struct Hop {
    pub pk: [u8; 32],
    pub addr: String,
}

/// A circuit consists of an ordered list of hops (Entry, Middle, Exit).
pub struct Circuit {
    pub hops: Vec<Hop>,
}

impl Circuit {
    /// Creates a new circuit from a list of hops.
    pub fn new(hops: Vec<Hop>) -> Self {
        Self { hops }
    }
}

/// Builds an onion packet for the given payload and circuit.
/// 
/// The function performs iterative encryption:
/// 1. Encrypts payload for Exit.
/// 2. Wraps it with routing info for Exit and encrypts for Middle.
/// 3. Wraps it with routing info for Middle and encrypts for Entry.
///
/// Returns the final bytes to be sent to the Entry node.
/// The output format is: `Ephemeral_PK (32 bytes) || Encrypted_Onion_Layer`
pub fn build_onion_packet(payload: Vec<u8>, hops: &[Hop]) -> Result<Vec<u8>> {
    if hops.is_empty() {
        bail!("Circuit must have at least one hop");
    }

    // Generate an ephemeral keypair for this circuit/packet
    // Note: We use StaticSecret here to allow reusing the secret for multiple DH operations (one per hop).
    // Even though it's called "StaticSecret", we generate a new random one for each packet, so it is ephemeral.
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let client_public = DhPublicKey::from(&client_secret);

    // Pre-calculate shared secrets.
    let mut shared_secrets = Vec::new();
    for hop in hops {
        let node_pk = DhPublicKey::from(hop.pk);
        let shared = client_secret.diffie_hellman(&node_pk);
        shared_secrets.push(shared);
    }

    // Start with the innermost payload (message)
    let mut current_payload = payload;

    // Iterate backwards (Exit -> Middle -> Entry)
    for (i, _hop) in hops.iter().enumerate().rev() {
        let shared_secret = &shared_secrets[i];
        
        // Derive Encryption Key from Shared Secret
        // We use BLAKE3 or similar to hash the shared secret into a 32-byte key.
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ONION_LAYER_KEY");
        hasher.update(shared_secret.as_bytes());
        let key_bytes = hasher.finalize();
        let key = Key::from_slice(key_bytes.as_bytes());
        let cipher = ChaCha20Poly1305::new(key);

        // Derive Nonce (random or deterministic?)
        // Since we send a fresh packet each time, random nonce is safer but we need to transmit it.
        // Format: Nonce (12 bytes) || Ciphertext (incl tag)
        // OR: Payload structure: `Next_Hop_Addr_Len (2 bytes) || Next_Hop_Addr || Inner_Payload`
        // Wait, the "Next Hop" info is for the CURRENT node to forward to the NEXT node.
        // Exit node has no next hop.
        
        // Prepare plaintext for this layer
        let plaintext = if i == hops.len() - 1 {
            // Exit node sees the raw payload
            current_payload
        } else {
            // Intermediate node sees: Next_Hop_Addr || Inner_Payload
            // We need to encode the address.
            // Let's use a simple framing: Length(u16) + Address(utf8) + Data
            let next_hop = &hops[i+1];
            let addr_bytes = next_hop.addr.as_bytes();
            let addr_len = addr_bytes.len() as u16;
            
            let mut buf = Vec::new();
            buf.extend_from_slice(&addr_len.to_be_bytes());
            buf.extend_from_slice(addr_bytes);
            buf.extend_from_slice(&current_payload);
            buf
        };

        // Encrypt
        // Generate a random 12-byte nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); 
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed at hop {}: {}", i, e))?;

        // Prepend Nonce to ciphertext so the recipient can decrypt
        let mut layer = Vec::new();
        layer.extend_from_slice(nonce.as_slice());
        layer.extend_from_slice(&ciphertext);
        
        current_payload = layer;
    }

    // Final packet: Ephemeral Public Key || Outer Layer
    let mut final_packet = Vec::new();
    final_packet.extend_from_slice(client_public.as_bytes());
    final_packet.extend_from_slice(&current_payload);

    Ok(final_packet)
}
