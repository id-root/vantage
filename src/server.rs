use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{IsotopePacket, WireMessage};
use crate::network::{read_packet, write_packet_as_server};
use crate::{HANDSHAKE_TIMEOUT_SEC, READ_TIMEOUT_SEC};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use dashmap::DashMap;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use anyhow::Result;
use snow::Builder;
use tracing::{warn, error};

use base64::prelude::*;
use blake3::Hasher;
use chrono::Utc;
use std::time::Instant;
use std::net::IpAddr;
use serde::{Serialize, Deserialize};
use std::fs::File;

use crossterm::style::Stylize; 

use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{PublicKey, Ciphertext, SharedSecret};

struct UserSession {
    username: String,
    group: String,
}

// Mailbox: username -> (message, expiry_time)
struct StoredMessage {
    msg: WireMessage,
    expires_at: Option<Instant>,
}
type Mailbox = DashMap<String, Vec<StoredMessage>>;
// Blacklist: username -> reason
type Blacklist = DashMap<String, String>;
// Admins: fingerprint -> bool
type Admins = DashMap<String, bool>;

struct ServerState {
    users: Arc<DashMap<String, UserSession>>,
    mailbox: Arc<Mailbox>,
    blacklist: Arc<Blacklist>,
    admins: Arc<Admins>,
    admin_rate_limit: Arc<DashMap<String, Instant>>,
    connection_attempts: Arc<DashMap<IpAddr, (u32, Instant)>>,
}

#[derive(Serialize, Deserialize, Default)]
struct DiskState {
    blacklist: Vec<(String, String)>,
    admins: Vec<(String, bool)>,
}

fn load_disk_state() -> DiskState {
    if let Ok(file) = File::open("server_state.json") {
        let reader = std::io::BufReader::new(file);
        serde_json::from_reader(reader).unwrap_or_default()
    } else {
        DiskState::default()
    }
}

fn save_disk_state(state: &ServerState) {
    let disk_state = DiskState {
        blacklist: state.blacklist.iter().map(|r| (r.key().clone(), r.value().clone())).collect(),
        admins: state.admins.iter().map(|r| (r.key().clone(), *r.value())).collect(),
    };
    if let Ok(file) = File::create("server_state.json") {
        let writer = std::io::BufWriter::new(file);
        let _ = serde_json::to_writer_pretty(writer, &disk_state);
    }
}

fn print_banner(port: u16, fingerprint: &str) {
    print!("\x1B[2J\x1B[1;1H"); 
    println!("{}", r#"
██╗███████╗ ██████╗ ████████╗ ██████╗ ██████╗ ███████╗
██║██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
██║███████╗██║   ██║   ██║   ██║   ██║██████╔╝█████╗  
██║╚════██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══╝  
██║███████║╚██████╔╝   ██║   ╚██████╔╝██║     ███████╗
╚═╝╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚══════╝
"#.blue().bold());
    
    println!("   {} {}", "► VERSION:".dim(), "4.0.0 (MILITARY-GRADE)".cyan());
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
    // Server currently uses single identity, but Identity::load requires password.
    // For server automation, maybe read from env or prompt?
    // The prompt requires modifying main.rs to pass password. 
    // Since we updated Identity, we need to update this call.
    // But `Identity::load_or_create` is gone.
    // We should probably rely on main.rs passing the loaded Identity or handle it here.
    // However, `server::run` takes `identity_path`.
    // We will assume for now we can prompt for password or use a default one for server if not interactive?
    // But "Blue/Red" is primarily a client-side feature for "operative safety".
    // Server likely runs in a secure environment.
    // Let's prompt for password if file exists, or setup if not.
    // But wait, `run` is async. Prompting blocks?
    // Let's just ask for password here.
    
    // Check if file exists to decide prompt
    let id = if std::path::Path::new(&identity_path).exists() {
        println!("Enter password for server identity:");
        let pass = rpassword::read_password()?;
        Identity::load(&identity_path, &pass)?
    } else {
        println!("Creating new server identity...");
        println!("Set password:");
        let pass = rpassword::read_password()?;
        println!("Confirm password:");
        let confirm = rpassword::read_password()?;
        if pass != confirm {
            anyhow::bail!("Passwords do not match");
        }
        // For server, we might not need dual profile, but our Identity struct enforces it or we can just use same password for both slots?
        // Or we can just use "casual" slot as dummy.
        // Let's just use the same password for both to simplify server setup, or ask for a dummy one.
        println!("Set duress password (optional, press enter to skip/use same):");
        let duress = rpassword::read_password()?;
        let duress = if duress.is_empty() { &pass } else { &duress };
        
        Identity::setup_dual(&identity_path, &pass, duress)?;
        Identity::load(&identity_path, &pass)?
    };

    let fp = id.fingerprint();
    print_banner(port, &fp);

    let disk = load_disk_state();
    let blacklist_map = DashMap::new();
    for (k, v) in disk.blacklist { blacklist_map.insert(k, v); }
    let admin_map = DashMap::new();
    for (k, v) in disk.admins { admin_map.insert(k, v); }

    let state = Arc::new(ServerState {
        users: Arc::new(DashMap::new()),
        mailbox: Arc::new(DashMap::new()),
        blacklist: Arc::new(blacklist_map),
        admins: Arc::new(admin_map),
        admin_rate_limit: Arc::new(DashMap::new()),
        connection_attempts: Arc::new(DashMap::new()),
    });
    
    // Auto-add server identity as admin
    state.admins.insert(fp.clone(), true);

    let (tx, _rx) = broadcast::channel::<WireMessage>(100);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    
    // We need to pass the loaded identity (keypair) to the handler.
    // But `Identity` is not Clone because ZeroizableKeypair is not Clone (it zeroes on drop).
    // We can't easily clone `Identity`.
    // We should probably just share the Keypair or clone the bytes if needed.
    // `ZeroizableKeypair` fields are Vec<u8>, so we can clone them if we access them.
    // But `Identity` struct holds them.
    // Let's make `Identity` cloneable? No, `ZeroizeOnDrop` makes it tricky.
    // But we can extract the keys once and wrap them in Arc?
    // Or just re-load from file? But that requires password again.
    // The previous code re-loaded from file: `let id_clone = Identity::load_or_create(&identity_path)?;`
    // This is bad for performance and security (requires password).
    // We should load it ONCE and share it.
    // Let's wrap Identity in Arc.
    let id = Arc::new(id);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                // Connection Throttling
                let ip = addr.ip();
                let mut allowed = true;
                let mut attempts = state.connection_attempts.entry(ip).or_insert((0, Instant::now()));
                if attempts.1.elapsed() > Duration::from_secs(60) {
                    *attempts = (1, Instant::now());
                } else {
                    attempts.0 += 1;
                    if attempts.0 > 20 { 
                        allowed = false;
                    }
                }
                drop(attempts);

                if !allowed {
                    warn!("{} | ⚠️ Throttled (DoS Protection)", addr);
                    continue;
                }

                // We need a fresh copy of keypair for each handshake? 
                // `handle_client` takes `id: Identity`.
                // Handshake needs `&id.keypair.private`.
                // So we can pass `Arc<Identity>`.
                let id_clone = id.clone();
                let tx_clone = tx.clone();
                let rx_clone = tx.subscribe();
                let state_clone = state.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, id_clone, tx_clone, rx_clone, state_clone, addr).await {
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
    id: Arc<Identity>,
    tx: broadcast::Sender<WireMessage>,
    mut rx: broadcast::Receiver<WireMessage>,
    state: Arc<ServerState>, 
    addr: std::net::SocketAddr,
) -> Result<()> {
    // Noise Handshake
    let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
    let mut handshake = builder.local_private_key(&id.keypair.private).build_responder()?;
    let mut buf = vec![0u8; 65535];

    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
    handshake.read_message(&msg, &mut buf)?;
    
    let len = handshake.write_message(&[], &mut buf)?;
    write_packet_as_server(&mut stream, &buf[..len]).await?;
    
    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
    handshake.read_message(&msg, &mut buf)?;

    let session = Arc::new(Mutex::new(NoiseSession::new(handshake)?));
    
    let remote_static = session.lock().unwrap().transport.get_remote_static().unwrap().to_vec();
    let mut h = Hasher::new(); h.update(&remote_static);
    let fp = BASE64_STANDARD.encode(h.finalize().as_bytes());

    // PQ KEM
    let (pk, sk) = keypair();
    let pq_init = WireMessage::PQInit { public_key: pk.as_bytes().to_vec() };
    log_event(addr, "🔐", "PQ KEM", "Sending PQInit...".to_string());
    let data = bincode::serialize(&pq_init)?;
    let pkt = IsotopePacket::new(&data)?;
    let bytes = pkt.to_bytes()?;
    let enc = { session.lock().unwrap().encrypt(&bytes)? };
    
    write_packet_as_server(&mut stream, &enc).await?;

    let wire_buf = timeout(Duration::from_secs(READ_TIMEOUT_SEC), read_packet(&mut stream)).await??;
    
    let decrypted = session.lock().unwrap().decrypt(&wire_buf)?;
    let packet = IsotopePacket::from_bytes(&decrypted)?;

    if let Ok(WireMessage::PQFinish { ciphertext }) = bincode::deserialize(&packet.payload) {
        // [FIX] Safe Kyber ciphertext parsing
        let ct = Ciphertext::from_bytes(&ciphertext)
            .map_err(|_| anyhow::anyhow!("Invalid Kyber ciphertext"))?;
        let ss = decapsulate(&ct, &sk);
        // Server is Responder -> false
        session.lock().unwrap().upgrade_to_pq(ss.as_bytes(), false);
    } else {
        anyhow::bail!("Expected PQFinish");
    }

    // Join
    let username: String;
    let user_did: String;
    let group: String;
    {
        let wire_buf = timeout(Duration::from_secs(READ_TIMEOUT_SEC), read_packet(&mut stream)).await??;
        
        let decrypted = session.lock().unwrap().decrypt(&wire_buf)?;
        let packet = IsotopePacket::from_bytes(&decrypted)?;
        
        if let Ok(WireMessage::Join { username: u, did: d, group: g }) = bincode::deserialize(&packet.payload) {
            username = u.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(32)
                .collect();
            
            if username.is_empty() {
                anyhow::bail!("Invalid username");
            }
            user_did = d;
            group = g;
            
            // Check Blacklist
            if let Some(reason) = state.blacklist.get(&username) {
                log_event(addr, "🚫", "BANNED", format!("{} tried to join (Reason: {})", username, reason.value()));
                // Send system message? Can't really, just disconnect for now.
                anyhow::bail!("User Banned");
            }

            state.users.insert(fp.clone(), UserSession { 
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

            // DELIVER OFFLINE MESSAGES (O2: Filter expired TTL)
            if let Some((_, stored_msgs)) = state.mailbox.remove(&username) {
                let now = Instant::now();
                let original_count = stored_msgs.len();
                let valid_msgs: Vec<_> = stored_msgs.into_iter()
                    .filter(|sm| sm.expires_at.map_or(true, |exp| exp > now))
                    .collect();
                
                let expired = original_count - valid_msgs.len();
                if expired > 0 {
                    log_event(addr, "🗑️", "TTL", format!("Discarded {} expired messages", expired));
                }
                
                log_event(addr, "📬", "MAILBOX", format!("Delivered {} messages to {}", valid_msgs.len(), username));
                for sm in valid_msgs {
                    // Send directly to this socket
                    let data = bincode::serialize(&sm.msg)?;
                    let pkt = IsotopePacket::new(&data)?;
                    let enc = session.lock().unwrap().encrypt(&pkt.to_bytes()?)?;
                    write_packet_as_server(&mut stream, &enc).await?;
                }
            }
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
    let state_inner = state.clone();

    tokio::select! {
        // Reader
        _ = async {
            loop {
                let wire_res = timeout(Duration::from_secs(READ_TIMEOUT_SEC), read_packet(&mut reader)).await;
                if wire_res.is_err() { break; }
                let wire_res = wire_res.unwrap();
                if wire_res.is_err() { break; }
                let wire = wire_res.unwrap();
                
                let res = { sess_read.lock().unwrap().decrypt(&wire) };
                if let Ok(plain) = res {
                    if let Ok(pkt) = IsotopePacket::from_bytes(&plain) {
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
                                    // [FIX] V4: Validate chunk size
                                    if data.len() > 64 * 1024 {
                                         // Silently drop or log
                                         continue;
                                    }
                                    let _ = tx_inner.send(WireMessage::FileChunk { file_id, chunk_index, total_chunks, data });
                                },
                                WireMessage::Version { .. } => {}, // Ignore version for now
                                WireMessage::DirectMessage { sender: _, ref target, ref content, ref timestamp, ttl } => {
                                    // RECONSTRUCT message to prevent spoofing
                                    let safe_msg = WireMessage::DirectMessage {
                                        sender: my_username.clone(),
                                        target: target.clone(),
                                        content: content.clone(),
                                        timestamp: *timestamp,
                                        ttl,
                                    };
                                    
                                    // Check if target is online
                                    let is_online = state_inner.users.iter().any(|u| u.value().username == *target);
                                    if is_online {
                                        let _ = tx_inner.send(safe_msg);
                                    } else {
                                        let target_clone = target.clone(); 
                                        // O2: Store in Mailbox with TTL
                                        let expires_at = ttl.map(|secs| Instant::now() + Duration::from_secs(secs));
                                        let stored = StoredMessage { msg: safe_msg, expires_at };
                                        let mut box_entry = state_inner.mailbox.entry(target_clone.clone()).or_insert(Vec::new());
                                        box_entry.push(stored); 
                                        
                                        log_event(addr, "📥", "SAVED", format!("Message for {} (TTL: {:?})", target_clone, ttl));
                                    }
                                },
                                WireMessage::AdminCommand { command, target } => {
                                    if state_inner.admins.contains_key(&my_fp) {
                                        // [FIX] V7: Rate limiting
                                        let now = std::time::Instant::now();
                                        let mut allowed = true;
                                        if let Some(mut last) = state_inner.admin_rate_limit.get_mut(&my_fp) {
                                            if last.elapsed() < Duration::from_secs(2) {
                                                log_event(addr, "⚠️", "RATE", "Admin rate limit hit".into());
                                                allowed = false;
                                            } else {
                                                *last = now;
                                            }
                                        } else {
                                            state_inner.admin_rate_limit.insert(my_fp.clone(), now);
                                        }

                                        if allowed {
                                            log_event(addr, "⚡", "ADMIN", format!("{} executed {} on {}", my_username, command, target));
                                            
                                            if command == "kick" {
                                                let _ = tx_inner.send(WireMessage::System { content: format!("{} was kicked by admin.", target) });
                                            // The kicked user will receive this system message and should disconnect themselves, 
                                            // or we rely on the server effectively severing the link.
                                            // We can signal other threads to drop connections where username matches.
                                            // But we don't have handle to other streams here easily.
                                            // For now, we rely on the client honoring the kick or just the broadcast message.
                                            // Wait, the KICK command should probably be broadcasted so the VICTIM receives it and quits.
                                            let _ = tx_inner.send(WireMessage::AdminCommand { command, target });
                                        } else if command == "ban" {
                                            state_inner.blacklist.insert(target.clone(), "Banned by Admin".to_string());
                                            save_disk_state(&state_inner);
                                            let _ = tx_inner.send(WireMessage::System { content: format!("{} was BANNED by admin.", target) });
                                            let _ = tx_inner.send(WireMessage::AdminCommand { command: "kick".to_string(), target });
                                        }
                                        }
                                    } else {
                                        log_event(addr, "⚠️", "AUTH", format!("{} tried admin command but is not admin", my_username));
                                    }
                                },
                                WireMessage::VoicePacket { data: _ } => {
                                    let _ = tx_inner.send(msg);
                                }
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
                                 state_inner.users.iter().find(|u| u.value().username == *sender)
                                    .map(|u| u.value().group == my_group)
                                    .unwrap_or(false)
                            },
                            WireMessage::FileOffer { sender, .. } => {
                                 sender != &my_username &&
                                 state_inner.users.iter().find(|u| u.value().username == *sender)
                                    .map(|u| u.value().group == my_group)
                                    .unwrap_or(false)
                            },
                            // ⭐ FILTER: Only send FileRequest to the actual receiver
                            WireMessage::FileRequest { receiver, .. } => receiver == &my_username,
                            
                            // Direct Message Routing
                            WireMessage::DirectMessage { target, .. } => target == &my_username,
                            
                            // Admin/Voice Broadcast to Group
                            WireMessage::VoicePacket { .. } => true, // Broadcast to all for now, logic can be refined
                            WireMessage::AdminCommand { .. } => {
                                true
                            },

                            WireMessage::Heartbeat => false,
                            WireMessage::PeerList { .. } => true, 
                            _ => true,
                        };

                        // Check if we need to disconnect (Server-side Kick Enforcement)
                        if let WireMessage::AdminCommand { command, target } = &msg {
                            if command == "kick" && target == &my_username {
                                // We are the target of a kick. Send the message first, then break.
                                // Send logic is below. We set a flag or just break after sending?
                                // If we break loop here, we might not send the packet.
                                // Let's fall through to send, then check again.
                            }
                        }

                        if should_send {
                            let msg_to_send = if let WireMessage::PeerList { .. } = msg {
                                let fresh_list: Vec<String> = state_inner.users.iter()
                                    .filter(|r| r.value().group == my_group && r.key() != &my_fp)
                                    .map(|r| r.value().username.clone())
                                    .collect();
                                WireMessage::PeerList { peers: fresh_list }
                            } else {
                                msg.clone()
                            };

                            if let Ok(data) = bincode::serialize(&msg_to_send) {
                                if let Ok(pkt) = IsotopePacket::new(&data) {
                                    if let Ok(bytes) = pkt.to_bytes() {
                                        let enc = { sess_write.lock().unwrap().encrypt(&bytes) };
                                        if let Ok(data) = enc {
                                            if write_packet_as_server(&mut writer, &data).await.is_err() { break; }
                                        }
                                    }
                                }
                            }
                        }

                        // Enforce Kick
                        if let WireMessage::AdminCommand { command, target } = &msg {
                            if command == "kick" && target == &my_username {
                                // Wait a tiny bit to ensure flush?
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                break;
                            }
                        }
                    },
                    Err(_) => break,
                }
            }
        } => {}
    }
    
    state.users.remove(&my_fp);
    log_event(addr, "🔴", "LEFT", format!("{}", my_username.clone().dim()));
    let _ = tx.send(WireMessage::PeerList { peers: vec![] });
    let _ = tx.send(WireMessage::System { content: format!("{} left", my_username) });
    anyhow::bail!("Connection closed normally");
}
