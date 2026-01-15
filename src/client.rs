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

// TUI Imports
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tui_input::backend::crossterm::EventHandler;

// Internal Events to coordinate UI, Network, and Logic
enum InternalEvent {
    NetworkMessage(WireMessage),
    Input(String),
}

pub async fn run(
    address: String,
    username: String,
    peer_fp: String,
    proxy: String,
    identity: String,
) -> Result<()> {
    fs::create_dir_all("downloads")?;

    // --- SETUP TERMINAL ---
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // --- CONNECT ---
    let mut app = AppState::new(username.clone());
    app.status = "Connecting to Tor...".to_string();
    terminal.draw(|f| ui(f, &app))?;

    let id = Identity::load_or_create(&identity)?;
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
    app.status = "Handshaking...".to_string();
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

    // Verify
    let remote = session.lock().unwrap().transport.get_remote_static().unwrap().to_vec();
    let mut h = Hasher::new(); h.update(&remote);
    let server_fp = BASE64_STANDARD.encode(h.finalize().as_bytes());
    if server_fp != peer_fp { bail!("Fingerprint mismatch"); }

    // Join
    let join_msg = WireMessage::Join { username: username.clone() };
    let json = serde_json::to_vec(&join_msg)?;
    let pkt = VantagePacket::new(&json)?;
    let enc = session.lock().unwrap().encrypt(&pkt.to_bytes()?)?;
    stream.write_all(&enc).await?;

    app.status = format!("Connected to {}", server_fp[0..8].to_string());
    
    // --- MAIN LOGIC ---
    let (mut reader, mut writer) = stream.into_split();
    let (tx_net, mut rx_net) = mpsc::channel::<WireMessage>(100); // Outgoing to Network
    let (tx_logic, mut rx_logic) = mpsc::channel::<InternalEvent>(100); // Internal Logic Bus

    let sess_read = session.clone();
    let sess_write = session.clone();
    
    // 1. Network Reader (Incoming -> Logic)
    let tx_logic_net = tx_logic.clone();
    tokio::spawn(async move {
        let mut wire = [0u8; WIRE_PACKET_SIZE];
        loop {
            if reader.read_exact(&mut wire).await.is_err() { break; }
            let res = { sess_read.lock().unwrap().decrypt(&wire) };
            if let Ok(plain) = res {
                if let Ok(pkt) = VantagePacket::from_bytes(&plain) {
                    if let Ok(msg) = serde_json::from_slice(&pkt.payload) {
                        let _ = tx_logic_net.send(InternalEvent::NetworkMessage(msg)).await;
                    }
                }
            }
        }
    });

    // 2. Network Writer (Logic -> Outgoing)
    tokio::spawn(async move {
        while let Some(msg) = rx_net.recv().await {
            if let Ok(json) = serde_json::to_vec(&msg) {
                if let Ok(pkt) = VantagePacket::new(&json) {
                    if let Ok(bytes) = pkt.to_bytes() {
                        let enc = { sess_write.lock().unwrap().encrypt(&bytes) };
                        if let Ok(data) = enc {
                            let _ = writer.write_all(&data).await;
                        }
                    }
                }
            }
        }
    });

    // 4. MAIN STATE LOOP
    let mut upload_queue: HashMap<u32, PathBuf> = HashMap::new();
    let mut download_whitelist: HashSet<u32> = HashSet::new(); // IDs we agreed to download
    let mut active_downloads: HashMap<u32, (String, u32)> = HashMap::new(); // ID -> (Name, Progress)

    loop {
        terminal.draw(|f| ui(f, &app))?;

        // A. Handle User Input (Non-blocking check)
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
                    KeyCode::Esc => break, // Exit
                    _ => { 
                        app.input.handle_event(&Event::Key(key)); 
                    }
                }
            }
        }

        // B. Handle Logic Events
        if let Ok(event) = rx_logic.try_recv() {
            match event {
                // --- USER TYPED SOMETHING ---
                InternalEvent::Input(cmd) => {
                    if cmd.starts_with("/send ") {
                        let path_str = cmd.trim_start_matches("/send ");
                        let path = Path::new(path_str).to_path_buf();
                        if path.exists() {
                            let id = rand::random::<u32>();
                            let size = fs::metadata(&path)?.len();
                            let name = path.file_name().unwrap().to_str().unwrap().to_string();
                            
                            upload_queue.insert(id, path);
                            
                            app.messages.push(format!("📡 Offering file: {} (ID: {})", name, id));
                            tx_net.send(WireMessage::FileOffer {
                                sender: username.clone(),
                                file_name: name,
                                file_size: size,
                                id,
                            }).await?;
                        } else {
                            app.messages.push("❌ File not found.".to_string());
                        }
                    } else if cmd.starts_with("/get ") {
                        if let Ok(id) = cmd.trim_start_matches("/get ").parse::<u32>() {
                            app.messages.push(format!("✅ Accepting file ID {}", id));
                            download_whitelist.insert(id);
                            tx_net.send(WireMessage::FileRequest { 
                                receiver: username.clone(), 
                                file_id: id 
                            }).await?;
                        }
                    } else if cmd == "/quit" {
                        break;
                    } else {
                        app.messages.push(format!("[You] {}", cmd));
                        tx_net.send(WireMessage::Chat {
                            sender: username.clone(),
                            content: cmd,
                            timestamp: Utc::now()
                        }).await?;
                    }
                },

                // --- NETWORK MESSAGE ARRIVED ---
                InternalEvent::NetworkMessage(msg) => {
                    match msg {
                        // FIX: Added missing Join handler
                        WireMessage::Join { username } => {
                            app.messages.push(format!("[*] {} joined the channel", username));
                        },
                        WireMessage::Chat { sender, content, .. } => {
                            app.messages.push(format!("[{}] {}", sender, content));
                        },
                        WireMessage::System { content } => {
                            app.messages.push(format!("[*] {}", content));
                        },
                        WireMessage::FileOffer { sender, file_name, file_size, id } => {
                            if sender != username {
                                app.messages.push(format!("📎 {} offered '{}' ({} bytes).", sender, file_name, file_size));
                                app.messages.push(format!("   Type '/get {}' to download.", id));
                            }
                        },
                        WireMessage::FileRequest { file_id, receiver } => {
                            if let Some(path) = upload_queue.get(&file_id) {
                                app.messages.push(format!("🚀 {} accepted file. Sending...", receiver));
                                
                                if let Ok(mut file) = File::open(path) {
                                    let mut buffer = Vec::new();
                                    file.read_to_end(&mut buffer)?;
                                    
                                    let tx_clone = tx_net.clone();
                                    let chunk_size = 3000;
                                    let total = (buffer.len() as f64 / chunk_size as f64).ceil() as u32;
                                    let buf_clone = buffer.clone();
                                    
                                    tokio::spawn(async move {
                                        for (i, chunk) in buf_clone.chunks(chunk_size).enumerate() {
                                            let _ = tx_clone.send(WireMessage::FileChunk {
                                                file_id,
                                                chunk_index: i as u32,
                                                total_chunks: total,
                                                data: chunk.to_vec(),
                                            }).await;
                                            tokio::time::sleep(Duration::from_millis(20)).await;
                                        }
                                    });
                                }
                            }
                        },
                        WireMessage::FileChunk { file_id, chunk_index, total_chunks, data } => {
                            if download_whitelist.contains(&file_id) {
                                if !active_downloads.contains_key(&file_id) {
                                    active_downloads.insert(file_id, (format!("file_{}.bin", file_id), 0));
                                }
                                
                                if let Some((name, progress)) = active_downloads.get_mut(&file_id) {
                                    let path = format!("downloads/{}", name);
                                    let mut f = OpenOptions::new().create(true).append(true).open(&path).ok();
                                    if let Some(ref mut file) = f {
                                        let _ = file.write_all(&data);
                                    }
                                    *progress = chunk_index;
                                    app.file_progress = Some((name.clone(), (chunk_index as f64 / total_chunks as f64)));

                                    if chunk_index == total_chunks - 1 {
                                        app.messages.push(format!("✅ Download Complete: {}", name));
                                        app.file_progress = None;
                                        download_whitelist.remove(&file_id);
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}
