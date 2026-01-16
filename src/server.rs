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
use std::net::SocketAddr;
use anyhow::Result;
use snow::Builder;
use tracing::{warn, error};
use base64::prelude::*;
use blake3::Hasher;
use chrono::Utc;
use crossterm::style::Stylize; 

use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, Ciphertext, SharedSecret};

struct UserSession {
    username: String,
    group: String,
}

fn print_banner(port: u16, fingerprint: &str) {
    print!("\x1B[2J\x1B[1;1H"); 
    println!("{}", r#"
██╗   ██╗ █████╗ ███╗   ██╗████████╗ █████╗  ██████╗ ███████╗
██║   ██║██╔══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝
██║   ██║███████║██╔██╗ ██║   ██║   ███████║██║  ███╗█████╗  
╚██╗ ██╔╝██╔══██║██║╚██╗██║   ██║   ██╔══██║██║   ██║██╔══╝  
 ╚████╔╝ ██║  ██║██║ ╚████║   ██║   ██║  ██║╚██████╔╝███████╗
  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"#.blue().bold());
    
    println!("   {} {}", "► VERSION:".dim(), "3.0.0 (PQ-Native)".cyan());
    println!("   {} {}", "► LISTEN :".dim(), format!("127.0.0.1:{}", port).yellow());
    println!("   {} {}", "► SERVER :".dim(), fingerprint.green());
    println!("   {} {}", "► STATUS :".dim(), "ONLINE & SECURE".green().bold());
    println!("{}", "──────────────────────────────────────────────────────────────".dim());
    println!();
}

fn log_event(addr: SocketAddr, icon: &str, title: &str, details: String) {
    let time = Utc::now().format("%H:%M:%S").to_string().dim();
    println!("{} {} | {} {:<5} | {}", 
        time, 
        addr.to_string().dim(), 
        icon, 
        title, 
        details
    );
}

pub async fn run(port: u16, identity_path: String) -> Result<()> {
    let id = Identity::load_or_create(&identity_path)?;
    let fp = id.fingerprint();
    print_banner(port, &fp);

    let users = Arc::new(DashMap::new());
    let (tx, _rx) = broadcast::channel::<WireMessage>(100);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let id_clone = Identity::load_or_create(&identity_path)?;
                let tx_clone = tx.clone();
                let rx_clone = tx.subscribe();
                let users_clone = users.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, id_clone, tx_clone, rx_clone, users_clone, addr).await {
                        if !e.to_string().contains("closed normally") {
                             warn!("{} | ❌ Error: {}", addr, e);
                        }
                    }
                });
            }
            Err(e) => error!("Listener Accept Error: {}", e),
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    id: Identity,
    tx: broadcast::Sender<WireMessage>,
    mut rx: broadcast::Receiver<WireMessage>,
    users: Arc<DashMap<String, UserSession>>, 
    addr: std::net::SocketAddr,
) -> Result<()> {
    // Noise Handshake
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

    // PQ KEM
    let (pk, sk) = keypair();
    let pq_init = WireMessage::PQInit { public_key: pk.as_bytes().to_vec() };
    let data = bincode::serialize(&pq_init)?;
    let pkt = VantagePacket::new(&data)?;
    let bytes = pkt.to_bytes()?;
    let enc = { session.lock().unwrap().encrypt(&bytes)? };
    
    let len = (enc.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&enc).await?;

    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(READ_TIMEOUT_SEC), stream.read_exact(&mut len_buf)).await??;
    let packet_len = u16::from_be_bytes(len_buf) as usize;
    
    let mut wire_buf = vec![0u8; packet_len];
    timeout(Duration::from_secs(READ_TIMEOUT_SEC), stream.read_exact(&mut wire_buf)).await??;
    
    let decrypted = session.lock().unwrap().decrypt(&wire_buf)?;
    let packet = VantagePacket::from_bytes(&decrypted)?;

    if let Ok(WireMessage::PQFinish { ciphertext }) = bincode::deserialize(&packet.payload) {
        let ct = Ciphertext::from_bytes(&ciphertext).unwrap();
        let ss = decapsulate(&ct, &sk);
        session.lock().unwrap().upgrade_to_pq(ss.as_bytes());
    } else {
        anyhow::bail!("Expected PQFinish");
    }

    // Join
    let username: String;
    let user_did: String;
    let group: String;
    {
        timeout(Duration::from_secs(READ_TIMEOUT_SEC), stream.read_exact(&mut len_buf)).await??;
        let packet_len = u16::from_be_bytes(len_buf) as usize;
        let mut wire_buf = vec![0u8; packet_len];
        timeout(Duration::from_secs(READ_TIMEOUT_SEC), stream.read_exact(&mut wire_buf)).await??;
        
        let decrypted = session.lock().unwrap().decrypt(&wire_buf)?;
        let packet = VantagePacket::from_bytes(&decrypted)?;
        
        if let Ok(WireMessage::Join { username: u, did: d, group: g }) = bincode::deserialize(&packet.payload) {
            username = u.chars().filter(|c| c.is_alphanumeric()).collect();
            user_did = d;
            group = g;
            
            users.insert(fp.clone(), UserSession { 
                username: username.clone(), 
                group: group.clone() 
            });

            log_event(addr, "🟢", "JOINED", format!("{} @ {}", username.clone().bold(), group.clone().cyan()));
            
            let _ = tx.send(WireMessage::Join { 
                username: username.clone(), 
                did: user_did.clone(),
                group: group.clone()
            });
            let _ = tx.send(WireMessage::PeerList { peers: vec![] });
        } else {
            anyhow::bail!("Expected JOIN");
        }
    }

    let (mut reader, mut writer) = stream.into_split();
    let sess_read = session.clone();
    let sess_write = session.clone();
    
    let my_fp = fp.clone();
    let my_username = username.clone();
    let my_group = group.clone();
    let tx_inner = tx.clone();
    let users_inner = users.clone(); 

    tokio::select! {
        // Reader
        _ = async {
            let mut len_buf = [0u8; 2];
            let mut wire = [0u8; WIRE_PACKET_SIZE];
            loop {
                if timeout(Duration::from_secs(READ_TIMEOUT_SEC), reader.read_exact(&mut len_buf)).await.is_err() { break; }
                let _len = u16::from_be_bytes(len_buf) as usize;
                if _len == 0 || _len > WIRE_PACKET_SIZE { break; }

                if timeout(Duration::from_secs(READ_TIMEOUT_SEC), reader.read_exact(&mut wire[0.._len])).await.is_err() { break; }
                
                let res = { sess_read.lock().unwrap().decrypt(&wire[0.._len]) };
                if let Ok(plain) = res {
                    if let Ok(pkt) = VantagePacket::from_bytes(&plain) {
                        if let Ok(msg) = bincode::deserialize::<WireMessage>(&pkt.payload) {
                            match msg {
                                WireMessage::Heartbeat => { },
                                WireMessage::Chat { content, .. } => {
                                    let _ = tx_inner.send(WireMessage::Chat { 
                                        sender: my_username.clone(), content, timestamp: Utc::now() 
                                    });
                                },
                                WireMessage::FileOffer { file_name, file_size, id, .. } => {
                                    log_event(addr, "📎", "FILE", format!("{} offered '{}' ({} B)", my_username.clone(), file_name, file_size));
                                    let _ = tx_inner.send(WireMessage::FileOffer { 
                                        sender: my_username.clone(), file_name, file_size, id 
                                    });
                                },
                                // ⭐ FIX: Removed "if receiver == my_username" check.
                                // We must allow the request to route to the actual file owner.
                                WireMessage::FileRequest { file_id, receiver } => {
                                    // Log it only if verbose, or if it's suspicious
                                    // log_event(addr, "🚀", "REQ", format!("Request for {}", file_id));
                                    let _ = tx_inner.send(WireMessage::FileRequest { file_id, receiver });
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
        } => {},

        // Writer
        _ = async {
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        let should_send = match &msg {
                            WireMessage::Join { group, .. } => group == &my_group,
                            WireMessage::Chat { sender, .. } => {
                                 users_inner.iter().find(|u| u.value().username == *sender)
                                    .map(|u| u.value().group == my_group)
                                    .unwrap_or(false)
                            },
                            WireMessage::FileOffer { sender, .. } => {
                                 users_inner.iter().find(|u| u.value().username == *sender)
                                    .map(|u| u.value().group == my_group)
                                    .unwrap_or(false)
                            },
                            // ⭐ FILTER: Only send FileRequest to the actual receiver
                            WireMessage::FileRequest { receiver, .. } => receiver == &my_username,
                            WireMessage::Heartbeat => false,
                            WireMessage::PeerList { .. } => true, 
                            _ => true,
                        };

                        if should_send {
                            let msg_to_send = if let WireMessage::PeerList { .. } = msg {
                                let fresh_list: Vec<String> = users_inner.iter()
                                    .filter(|r| r.value().group == my_group && r.key() != &my_fp)
                                    .map(|r| r.value().username.clone())
                                    .collect();
                                WireMessage::PeerList { peers: fresh_list }
                            } else {
                                msg
                            };

                            if let Ok(data) = bincode::serialize(&msg_to_send) {
                                if let Ok(pkt) = VantagePacket::new(&data) {
                                    if let Ok(bytes) = pkt.to_bytes() {
                                        let enc = { sess_write.lock().unwrap().encrypt(&bytes) };
                                        if let Ok(data) = enc {
                                            let len = (data.len() as u16).to_be_bytes();
                                            if writer.write_all(&len).await.is_err() { break; }
                                            if writer.write_all(&data).await.is_err() { break; }
                                            let _ = writer.flush().await;
                                        }
                                    }
                                }
                            }
                        }
                    },
                    Err(_) => break,
                }
            }
        } => {}
    }
    
    users.remove(&my_fp);
    log_event(addr, "🔴", "LEFT", format!("{}", my_username.clone().dim()));
    let _ = tx.send(WireMessage::PeerList { peers: vec![] });
    let _ = tx.send(WireMessage::System { content: format!("{} left", my_username) });
    anyhow::bail!("Connection closed normally");
}
