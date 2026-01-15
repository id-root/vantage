use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{VantagePacket, WireMessage};
use crate::network::{read_len_prefixed, write_len_prefixed};
use crate::{WIRE_PACKET_SIZE, HANDSHAKE_TIMEOUT_SEC, READ_TIMEOUT_SEC};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use dashmap::DashMap;
use std::sync::{Arc, Mutex};
use anyhow::Result;
use snow::Builder;
use tracing::{info, warn};
use base64::prelude::*;
use blake3::Hasher;
use chrono::Utc;

pub async fn run(port: u16, identity_path: String) -> Result<()> {
    let id = Identity::load_or_create(&identity_path)?;
    info!("🚀 Server Online. Fingerprint: {}", id.fingerprint());

    let users = Arc::new(DashMap::new());
    let (tx, _rx) = broadcast::channel::<WireMessage>(100);

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    info!("👂 Listening on 127.0.0.1:{}", port);

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("📞 Connection from {}", addr);
        
        let id_clone = Identity::load_or_create(&identity_path)?;
        let tx_clone = tx.clone();
        let rx_clone = tx.subscribe();
        let users_clone = users.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, id_clone, tx_clone, rx_clone, users_clone).await {
                warn!("Client disconnected: {}", e);
            }
        });
    }
}

async fn handle_client(
    mut stream: TcpStream,
    id: Identity,
    tx: broadcast::Sender<WireMessage>,
    mut rx: broadcast::Receiver<WireMessage>,
    users: Arc<DashMap<String, String>>,
) -> Result<()> {
    // 1. Handshake
    let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
    let mut handshake = builder.local_private_key(&id.keypair.private).build_responder()?;
    let mut buf = vec![0u8; 65535];

    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_len_prefixed(&mut stream)).await??;
    handshake.read_message(&msg, &mut buf)?;
    
    let len = handshake.write_message(&[], &mut buf)?;
    write_len_prefixed(&mut stream, &buf[..len]).await?;
    
    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_len_prefixed(&mut stream)).await??;
    handshake.read_message(&msg, &mut buf)?;

    let session = Arc::new(Mutex::new(NoiseSession::new(handshake)?));
    
    let remote_static = session.lock().unwrap().transport.get_remote_static().unwrap().to_vec();
    let mut h = Hasher::new(); h.update(&remote_static);
    let fp = BASE64_STANDARD.encode(h.finalize().as_bytes());

    // 2. Auth/Join
    let username: String; // Fixed: Declare without assigning dummy value
    {
        let mut wire_buf = vec![0u8; WIRE_PACKET_SIZE];
        timeout(Duration::from_secs(READ_TIMEOUT_SEC), stream.read_exact(&mut wire_buf)).await??;
        
        let decrypted = session.lock().unwrap().decrypt(&wire_buf)?;
        let packet = VantagePacket::from_bytes(&decrypted)?;
        
        if let Ok(WireMessage::Join { username: u }) = serde_json::from_slice(&packet.payload) {
            username = u.chars().filter(|c| c.is_alphanumeric()).collect();
            users.insert(fp.clone(), username.clone());
            info!("User Joined: {} ({})", username, fp);
            let _ = tx.send(WireMessage::System { content: format!("{} joined the chat", username) });
        } else {
            anyhow::bail!("Expected JOIN packet");
        }
    }

    // 3. Chat Loop
    let (mut reader, mut writer) = stream.into_split();
    let sess_read = session.clone();
    let sess_write = session.clone();
    let my_fp = fp.clone();
    let my_username = username.clone();

    // Read Task
    let tx_inner = tx.clone();
    tokio::spawn(async move {
        let mut wire = [0u8; WIRE_PACKET_SIZE];
        loop {
            if timeout(Duration::from_secs(READ_TIMEOUT_SEC), reader.read_exact(&mut wire)).await.is_err() { break; }
            
            let res = { sess_read.lock().unwrap().decrypt(&wire) };
            if let Ok(plain) = res {
                if let Ok(pkt) = VantagePacket::from_bytes(&plain) {
                    if let Ok(msg) = serde_json::from_slice::<WireMessage>(&pkt.payload) {
                        // Forward all messages (Chat, FileOffer, etc) to broadcast
                        // But enforce sender username validation
                        match msg {
                            WireMessage::Chat { content, .. } => {
                                let _ = tx_inner.send(WireMessage::Chat { 
                                    sender: my_username.clone(), 
                                    content, 
                                    timestamp: Utc::now() 
                                });
                            },
                            // Allow File protocol messages to pass through
                            WireMessage::FileOffer { file_name, file_size, id, .. } => {
                                let _ = tx_inner.send(WireMessage::FileOffer { 
                                    sender: my_username.clone(), file_name, file_size, id 
                                });
                            },
                            WireMessage::FileRequest { file_id, receiver } => {
                                // Only allow request if receiver name matches logged in user
                                if receiver == my_username {
                                    let _ = tx_inner.send(WireMessage::FileRequest { file_id, receiver });
                                }
                            },
                            WireMessage::FileChunk { file_id, chunk_index, total_chunks, data } => {
                                let _ = tx_inner.send(WireMessage::FileChunk { file_id, chunk_index, total_chunks, data });
                            },
                            _ => {}
                        }
                    }
                }
            } else { break; }
        }
        let _ = tx_inner.send(WireMessage::System { content: format!("{} left", my_username) });
    });

    // Write Task
    loop {
        match rx.recv().await {
            Ok(msg) => {
                let should_send = match &msg {
                    WireMessage::Chat { sender, .. } => sender != &username,
                    WireMessage::FileOffer { sender, .. } => sender != &username,
                    _ => true,
                };

                if should_send {
                    let json = serde_json::to_vec(&msg)?;
                    if let Ok(pkt) = VantagePacket::new(&json) {
                        let bytes = pkt.to_bytes()?;
                        let enc = { sess_write.lock().unwrap().encrypt(&bytes) };
                        if let Ok(data) = enc {
                            if writer.write_all(&data).await.is_err() { break; }
                        }
                    }
                }
            },
            Err(_) => break,
        }
    }
    
    users.remove(&my_fp);
    Ok(())
}
