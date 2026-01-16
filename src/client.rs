use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{VantagePacket, WireMessage};
use crate::network::{connect_socks5, parse_onion_address, read_len_prefixed, write_len_prefixed};
use crate::{WIRE_PACKET_SIZE, HANDSHAKE_TIMEOUT_SEC};
use crate::tui::{AppState, ui};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use anyhow::{Result, bail};
use snow::Builder;
use base64::prelude::*;
use blake3::Hasher;
use chrono::Utc;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tui_input::backend::crossterm::EventHandler;

use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret, PublicKey};

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; 

enum InternalEvent {
    NetworkMessage(WireMessage),
    Input(String),
    Progress(String, f64),
}

fn nuke_everything(identity_path: &str) {
    if Path::new(identity_path).exists() {
        if let Ok(metadata) = fs::metadata(identity_path) {
            let len = metadata.len();
            if let Ok(mut file) = OpenOptions::new().write(true).open(identity_path) {
                let zeros = vec![0u8; len as usize];
                let _ = file.write_all(&zeros);
                let _ = file.sync_all(); 
            }
            let _ = fs::remove_file(identity_path);
        }
    }
    
    if let Ok(entries) = fs::read_dir("downloads") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(mut file) = OpenOptions::new().write(true).open(&path) {
                     let _ = file.write_all(&vec![0u8; 1024]); 
                }
                let _ = fs::remove_file(&path);
            }
        }
        let _ = fs::remove_dir_all("downloads");
    }
}

fn expand_path(input: &str) -> PathBuf {
    let input = input.trim();
    if input.starts_with("~") {
        if let Ok(home) = std::env::var("HOME") {
            let without_tilde = input.trim_start_matches('~');
            let path_str = if without_tilde.starts_with('/') {
                format!("{}{}", home, without_tilde)
            } else {
                format!("{}/{}", home, without_tilde)
            };
            return PathBuf::from(path_str);
        }
    }
    PathBuf::from(input)
}

pub async fn run(
    address: String,
    username: String,
    peer_fp: String,
    proxy: String,
    identity: String,
    group: String, 
    temp: bool, 
) -> Result<()> {
    fs::create_dir_all("downloads")?;

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let id = if temp {
        Identity::generate()?
    } else {
        Identity::load_or_create(&identity)?
    };
    
    // ⭐ FIX: Pass 'group' to AppState constructor
    let mut app = AppState::new(username.clone(), id.fingerprint()[0..8].to_string(), group.clone());
    app.status = "CONNECTING...".to_string();
    if temp { app.add_log("⚠️ USING TEMP IDENTITY".to_string()); }
    terminal.draw(|f| ui(f, &app))?;

    let (host, port) = parse_onion_address(&address)?;
    let proxy_addr: SocketAddr = proxy.parse()?;
    
    let mut stream = match connect_socks5(proxy_addr, &host, port).await {
        Ok(s) => s,
        Err(e) => {
            disable_raw_mode()?;
            execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
            println!("Connection failed: {}", e);
            return Ok(());
        }
    };

    // --- HANDSHAKE ---
    app.status = "HANDSHAKING...".to_string();
    terminal.draw(|f| ui(f, &app))?;

    let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
    let mut handshake = builder.local_private_key(&id.keypair.private).build_initiator()?;
    let mut buf = vec![0u8; 65535];

    let len = handshake.write_message(&[], &mut buf)?;
    write_len_prefixed(&mut stream, &buf[..len]).await?;
    
    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_len_prefixed(&mut stream)).await??;
    handshake.read_message(&msg, &mut buf)?;
    
    let len = handshake.write_message(&[], &mut buf)?;
    write_len_prefixed(&mut stream, &buf[..len]).await?;

    let session = Arc::new(Mutex::new(NoiseSession::new(handshake)?));

    let remote = session.lock().unwrap().transport.get_remote_static().unwrap().to_vec();
    let mut h = Hasher::new(); h.update(&remote);
    let server_fp = BASE64_STANDARD.encode(h.finalize().as_bytes());
    if server_fp != peer_fp { bail!("Fingerprint mismatch"); }

    app.status = "SECURED (NOISE)".to_string();
    app.encryption_level = "NOISE: AES-256".to_string(); 

    // --- PQ ---
    app.status = "NEGOTIATING QUANTUM...".to_string();
    terminal.draw(|f| ui(f, &app))?;

    let mut wire_buf = vec![0u8; WIRE_PACKET_SIZE];
    let mut len_buf = [0u8; 2];
    
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), stream.read_exact(&mut len_buf)).await??;
    let packet_len = u16::from_be_bytes(len_buf) as usize;
    timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), stream.read_exact(&mut wire_buf[0..packet_len])).await??;
    
    let decrypted = session.lock().unwrap().decrypt(&wire_buf[0..packet_len])?;
    let packet = VantagePacket::from_bytes(&decrypted)?;
    
    if let Ok(WireMessage::PQInit { public_key }) = bincode::deserialize(&packet.payload) {
        let pk = PublicKey::from_bytes(&public_key).unwrap();
        let (ss, ct) = encapsulate(&pk);

        let pq_msg = WireMessage::PQFinish { ciphertext: ct.as_bytes().to_vec() };
        let data = bincode::serialize(&pq_msg)?;
        let pkt = VantagePacket::new(&data)?;
        let enc = session.lock().unwrap().encrypt(&pkt.to_bytes()?)?;
        
        let len = (enc.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&enc).await?;

        session.lock().unwrap().upgrade_to_pq(ss.as_bytes());
        
        app.encryption_level = "🛡️ KYBER-1024".to_string();
        app.add_log("QUANTUM SHIELD ESTABLISHED".to_string());
    } else {
        bail!("Expected PQInit");
    }

    // --- JOIN ---
    let join_msg = WireMessage::Join { 
        username: username.clone(), 
        did: id.did(),
        group: group.clone()
    };
    let data = bincode::serialize(&join_msg)?;
    let pkt = VantagePacket::new(&data)?;
    let enc = session.lock().unwrap().encrypt(&pkt.to_bytes()?)?;
    let len = (enc.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&enc).await?;

    app.status = "ONLINE".to_string();
    
    let (mut reader, mut writer) = stream.into_split();
    let (tx_net, mut rx_net) = mpsc::channel::<WireMessage>(100);
    let (tx_logic, mut rx_logic) = mpsc::channel::<InternalEvent>(100);

    let sess_read = session.clone();
    let sess_write = session.clone();
    
    let tx_heartbeat = tx_net.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if tx_heartbeat.send(WireMessage::Heartbeat).await.is_err() {
                break;
            }
        }
    });

    let tx_logic_net = tx_logic.clone();
    tokio::spawn(async move {
        let mut len_buf = [0u8; 2];
        let mut wire = [0u8; WIRE_PACKET_SIZE];
        loop {
            if reader.read_exact(&mut len_buf).await.is_err() { break; }
            let _len = u16::from_be_bytes(len_buf) as usize;
            if _len == 0 || _len > WIRE_PACKET_SIZE { break; }

            if reader.read_exact(&mut wire[0.._len]).await.is_err() { break; }
            
            let res = { sess_read.lock().unwrap().decrypt(&wire[0.._len]) };
            if let Ok(plain) = res {
                if let Ok(pkt) = VantagePacket::from_bytes(&plain) {
                    if let Ok(msg) = bincode::deserialize(&pkt.payload) {
                        if !matches!(msg, WireMessage::Heartbeat) {
                            let _ = tx_logic_net.send(InternalEvent::NetworkMessage(msg)).await;
                        }
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some(msg) = rx_net.recv().await {
            if let Ok(data) = bincode::serialize(&msg) {
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
    });

    let mut upload_queue: HashMap<u32, PathBuf> = HashMap::new();
    let mut download_whitelist: HashSet<u32> = HashSet::new();
    let mut active_downloads: HashMap<u32, (String, u32)> = HashMap::new(); 
    let mut pending_offers: HashMap<u32, (String, String)> = HashMap::new(); 
    
    loop {
        terminal.draw(|f| ui(f, &app))?;

        if crossterm::event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Enter => {
                        let input: String = app.input.value().into();
                        if !input.is_empty() {
                            let _ = tx_logic.send(InternalEvent::Input(input)).await;
                            app.input.reset();
                        }
                    },
                    KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        disable_raw_mode()?;
                        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                        println!("\n\x1b[31;1m🚨 PANIC INITIATED. NUKING DATA...\x1b[0m");
                        nuke_everything(&identity);
                        std::process::exit(0);
                    },
                    KeyCode::Esc => break, 
                    _ => { app.input.handle_event(&Event::Key(key)); }
                }
            }
        }

        if let Ok(event) = rx_logic.try_recv() {
            match event {
                InternalEvent::Progress(filename, pct) => {
                    if pct >= 1.0 {
                        app.file_progress = None;
                        app.add_log(format!("TRANSFER COMPLETE: {}", filename));
                    } else {
                        app.file_progress = Some((filename, pct));
                    }
                },
                InternalEvent::Input(raw_cmd) => {
                    let cmd = raw_cmd.trim();

                    if cmd.starts_with("/send") {
                        let path_part = cmd.trim_start_matches("/send").trim();
                        let path = expand_path(path_part);

                        if let Ok(metadata) = fs::metadata(&path) {
                            if path.is_file() {
                                let size = metadata.len();
                                if size > MAX_FILE_SIZE {
                                    app.add_log(format!("⚠️ FILE TOO LARGE ({} MB)", size/1024/1024));
                                } else {
                                    let id = rand::random::<u32>();
                                    let name = path.file_name().unwrap().to_str().unwrap().to_string();
                                    upload_queue.insert(id, path);
                                    app.add_log(format!("OFFERED: {} (ID: {})", name, id));
                                    let _ = tx_net.send(WireMessage::FileOffer {
                                        sender: username.clone(), file_name: name, file_size: size, id
                                    }).await;
                                }
                            } else {
                                app.add_log("ERROR: INVALID FILE".to_string());
                            }
                        } else {
                             app.add_log(format!("ERROR: PATH NOT FOUND {:?}", path));
                        }
                    } else if cmd.starts_with("/get ") {
                        if let Ok(id) = cmd.trim_start_matches("/get ").parse::<u32>() {
                            if let Some((_, sender_name)) = pending_offers.get(&id) {
                                app.add_log(format!("ACCEPTING ID {} from {}", id, sender_name));
                                download_whitelist.insert(id);
                                let _ = tx_net.send(WireMessage::FileRequest { 
                                    receiver: sender_name.clone(), 
                                    file_id: id 
                                }).await;
                            } else {
                                app.add_log(format!("UNKNOWN FILE ID: {}", id));
                            }
                        }
                    } else if cmd == "/quit" {
                        break;
                    } else if cmd == "/nuke" {
                        disable_raw_mode()?;
                        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                        println!("\n\x1b[31;1m🚨 PANIC INITIATED VIA COMMAND. NUKING DATA...\x1b[0m");
                        nuke_everything(&identity);
                        std::process::exit(0);
                    } else {
                        let _ = tx_net.send(WireMessage::Chat {
                            sender: username.clone(), content: cmd.to_string(), timestamp: Utc::now()
                        }).await;
                    }
                },
                InternalEvent::NetworkMessage(msg) => {
                    match msg {
                        WireMessage::Join { username, .. } => {
                            app.add_log(format!("JOIN: {}", username));
                        },
                        WireMessage::PeerList { peers } => {
                            app.peers = peers;
                        },
                        WireMessage::Chat { sender, content, .. } => {
                            app.add_msg(sender, content);
                        },
                        WireMessage::System { content } => {
                            app.add_log(format!("SYSTEM: {}", content));
                        },
                        WireMessage::FileOffer { sender, file_name, file_size: _, id, .. } => {
                            if sender != username {
                                let safe_name = Path::new(&file_name).file_name().unwrap_or_default().to_string_lossy().into_owned();
                                pending_offers.insert(id, (safe_name.clone(), sender.clone()));
                                app.add_log(format!("FILE: {} sent '{}'. Type /get {}", sender, safe_name, id));
                            }
                        },
                        WireMessage::FileRequest { file_id, receiver } => {
                            if let Some(path) = upload_queue.get(&file_id) {
                                app.add_log(format!("UPLOADING to {}...", receiver));
                                
                                let tx_progress = tx_logic.clone();
                                let file_name_display = path.file_name().unwrap_or_default().to_string_lossy().to_string();

                                if let Ok(mut file) = File::open(path) {
                                    let mut buffer = Vec::new();
                                    if let Ok(_) = file.read_to_end(&mut buffer) {
                                        let tx_clone = tx_net.clone();
                                        let chunk_size = 1024; 
                                        let total = (buffer.len() as f64 / chunk_size as f64).ceil() as u32;
                                        
                                        tokio::spawn(async move {
                                            for (i, chunk) in buffer.chunks(chunk_size).enumerate() {
                                                let _ = tx_clone.send(WireMessage::FileChunk {
                                                    file_id, chunk_index: i as u32, total_chunks: total, data: chunk.to_vec(),
                                                }).await;
                                                
                                                if i % 10 == 0 {
                                                    let pct = (i as f64) / (total as f64);
                                                    let _ = tx_progress.send(InternalEvent::Progress(file_name_display.clone(), pct)).await;
                                                }
                                                tokio::time::sleep(Duration::from_millis(5)).await;
                                            }
                                            let _ = tx_progress.send(InternalEvent::Progress(file_name_display, 1.0)).await;
                                        });
                                    }
                                }
                            }
                        },
                        WireMessage::FileChunk { file_id, chunk_index, total_chunks, data } => {
                            if download_whitelist.contains(&file_id) {
                                if !active_downloads.contains_key(&file_id) {
                                    let name = pending_offers.get(&file_id)
                                        .map(|(n, _)| n.clone())
                                        .unwrap_or_else(|| format!("file_{}.bin", file_id));
                                    active_downloads.insert(file_id, (name, 0));
                                }
                                if let Some((name, progress)) = active_downloads.get_mut(&file_id) {
                                    let path = format!("downloads/{}", name);
                                    let mut f = OpenOptions::new().create(true).append(true).open(&path).ok();
                                    if let Some(ref mut file) = f {
                                        let _ = file.write_all(&data);
                                    }
                                    *progress = chunk_index;
                                    
                                    let pct = chunk_index as f64 / total_chunks as f64;
                                    app.file_progress = Some((name.clone(), pct));
                                    
                                    if chunk_index == total_chunks - 1 {
                                        app.add_log(format!("DOWNLOAD COMPLETE: {}", name));
                                        app.file_progress = None; 
                                        download_whitelist.remove(&file_id);
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                },
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}
