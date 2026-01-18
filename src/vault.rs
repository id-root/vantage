use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::collections::HashMap;
use chacha20poly1305::{
    XChaCha20Poly1305, Key, XNonce, AeadCore,
    aead::{Aead, KeyInit}
};
use anyhow::{Result, anyhow, bail, Context};
use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};

/// The Vault is an encrypted virtual filesystem stored in a single file.
/// It uses a simplified block-based approach.
/// 
/// Structure:
/// - Header: Salt (32 bytes)
/// - Blocks: 4KB encrypted blocks.
/// 
/// Block 0 is reserved for the File Allocation Table / Metadata.
/// 
/// Encryption:
/// We use XChaCha20Poly1305 for random nonces (24 bytes).
/// 
/// For random access `read/write`, we treat each block as an independent message.
/// `Nonce = Random(24 bytes)` stored at start of block.
/// 4KB Block on disk = 24 bytes Nonce + Ciphertext (Data + 16 byte Tag).
/// Usable Data Size per Block = 4096 - 24 - 16 = 4056 bytes.
/// 
/// Block Size: 4096 bytes.
/// Nonce: 24 bytes.
/// Tag: 16 bytes.
/// Payload capacity: 4056 bytes.
/// 
/// Metadata Block (Block 0):
/// Contains a serialized `Directory` struct.

const BLOCK_SIZE: usize = 4096;
const NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const PAYLOAD_SIZE: usize = BLOCK_SIZE - NONCE_SIZE - TAG_SIZE; // 4056
const HEADER_SALT_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Default, Clone)]
struct Directory {
    files: HashMap<String, FileEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct FileEntry {
    size: u64,
    blocks: Vec<u64>, // List of block indices
}

pub struct Vault {
    file: File,
    key: Key, // 32 bytes
    directory: Directory,
    total_blocks: u64,
}

impl Vault {
    /// Opens an existing vault or creates a new one.
    pub fn open<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let path = path.as_ref();
        let exists = path.exists();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        if !exists {
            // Initialize new vault
            let mut salt = [0u8; HEADER_SALT_SIZE];
            OsRng.fill_bytes(&mut salt);
            file.write_all(&salt)?;
            
            // Derive key
            let key = Self::derive_key(password, &salt);
            
            // Create empty directory
            let dir = Directory::default();
            let mut vault = Self {
                file,
                key,
                directory: dir,
                total_blocks: 1, // Block 0 is reserved for metadata
            };
            
            // Write directory to Block 0
            vault.write_metadata()?;
            return Ok(vault);
        }

        // Read Salt
        let mut salt = [0u8; HEADER_SALT_SIZE];
        if file.read_exact(&mut salt).is_err() {
            bail!("Vault file too short");
        }

        let key = Self::derive_key(password, &salt);
        let mut vault = Self {
            file,
            key,
            directory: Directory::default(),
            total_blocks: 0, // Will calculate
        };

        // Read Metadata
        vault.read_metadata()?;
        
        // Calculate total blocks
        let metadata = vault.file.metadata()?;
        let len = metadata.len();
        if len < HEADER_SALT_SIZE as u64 {
             bail!("Corrupted vault");
        }
        vault.total_blocks = (len - HEADER_SALT_SIZE as u64) / BLOCK_SIZE as u64;

        Ok(vault)
    }

    fn derive_key(password: &str, salt: &[u8]) -> Key {
        let mut output_key_material = [0u8; 32];
        let params = argon2::Params::default();
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params
        );
        argon2.hash_password_into(password.as_bytes(), salt, &mut output_key_material)
            .expect("Key derivation failed");
        *Key::from_slice(&output_key_material)
    }
    
    // Revised logic helpers
    fn prepare_block(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut padded = data.to_vec();
        if padded.len() > PAYLOAD_SIZE {
             bail!("Data exceeds block capacity");
        }
        // Pad with zeros (or random)
        padded.resize(PAYLOAD_SIZE, 0); 
        
        let cipher = XChaCha20Poly1305::new(&self.key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); 
        let ciphertext = cipher.encrypt(&nonce, padded.as_ref())
            .map_err(|_| anyhow!("Encryption failed"))?;
            
        let mut block = Vec::with_capacity(BLOCK_SIZE);
        block.extend_from_slice(nonce.as_slice());
        block.extend_from_slice(&ciphertext);
        
        Ok(block)
    }

    fn open_block(&self, block: &[u8]) -> Result<Vec<u8>> {
         if block.len() != BLOCK_SIZE {
             bail!("Block size mismatch");
         }
         let nonce = XNonce::from_slice(&block[..NONCE_SIZE]);
         let ciphertext = &block[NONCE_SIZE..];
         
         let cipher = XChaCha20Poly1305::new(&self.key);
         let plaintext = cipher.decrypt(nonce, ciphertext)
             .map_err(|_| anyhow!("Decryption failed (Integrity Check)"))?;
             
         Ok(plaintext)
    }

    fn read_metadata(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(HEADER_SALT_SIZE as u64))?;
        let mut block = vec![0u8; BLOCK_SIZE];
        if let Err(_) = self.file.read_exact(&mut block) {
            // If empty file (just created), metadata might not exist yet?
            // open() creates it.
            bail!("Could not read metadata block");
        }
        
        let plaintext = self.open_block(&block)?;
        
        // Deserialize. Remove trailing zeros?
        // JSON needs to be trimmed. `serde_json` might handle it or we store length.
        // We stored length? No.
        // `bincode` is better for binary.
        // But we padded with 0. 0 is valid in bincode?
        // Let's interpret as serialized data.
        // We can store the length in the first 4 bytes of plaintext.
        let len_bytes: [u8; 4] = plaintext[..4].try_into()?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        if len > plaintext.len() - 4 {
            bail!("Corrupt metadata length");
        }
        
        let dir_data = &plaintext[4..4+len];
        self.directory = bincode::deserialize(dir_data)?;
        
        Ok(())
    }

    fn write_metadata(&mut self) -> Result<()> {
        let data = bincode::serialize(&self.directory)?;
        if data.len() > PAYLOAD_SIZE - 4 {
             bail!("Directory too large for single block (TODO: Implement multi-block directory)");
        }
        
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&(data.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&data);
        
        let block = self.prepare_block(&plaintext)?;
        
        self.file.seek(SeekFrom::Start(HEADER_SALT_SIZE as u64))?;
        self.file.write_all(&block)?;
        Ok(())
    }
    
    fn allocate_block(&mut self) -> Result<u64> {
        // Simple append strategy for now.
        // In real FS, we scan for free blocks.
        // Here we just append to end of file.
        // `total_blocks` tracks the file size.
        // Blocks are 0-indexed relative to payload area.
        // Block 0 is metadata.
        // Block 1 is first data block.
        
        self.file.seek(SeekFrom::End(0))?;
        let index = self.total_blocks;
        
        // Write a dummy block or just reserve index?
        // We need to write *something* eventually.
        self.total_blocks += 1;
        Ok(index)
    }

    pub fn write_file(&mut self, filename: &str, data: &[u8]) -> Result<()> {
        // Chunk data
        let mut blocks = Vec::new();
        
        for chunk in data.chunks(PAYLOAD_SIZE) {
            let block_data = self.prepare_block(chunk)?;
            let block_idx = self.allocate_block()?;
            
            // Write to disk
            // Offset = Header + Block_Idx * Block_Size
            let offset = HEADER_SALT_SIZE as u64 + block_idx * BLOCK_SIZE as u64;
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(&block_data)?;
            
            blocks.push(block_idx);
        }
        
        // Update Directory
        self.directory.files.insert(filename.to_string(), FileEntry {
            size: data.len() as u64,
            blocks,
        });
        
        self.write_metadata()?;
        Ok(())
    }

    pub fn read_file(&mut self, filename: &str) -> Result<Vec<u8>> {
        let entry = self.directory.files.get(filename).context("File not found")?.clone();
        
        let mut file_data = Vec::with_capacity(entry.size as usize);
        
        for &block_idx in &entry.blocks {
            let offset = HEADER_SALT_SIZE as u64 + block_idx * BLOCK_SIZE as u64;
            self.file.seek(SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; BLOCK_SIZE];
            self.file.read_exact(&mut buf)?;
            
            let plaintext = self.open_block(&buf)?;
            file_data.extend_from_slice(&plaintext);
        }
        
        // Truncate to actual size
        file_data.truncate(entry.size as usize);
        Ok(file_data)
    }
    
    pub fn list_files(&self) -> Vec<String> {
        self.directory.files.keys().cloned().collect()
    }
}
