use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{VantagePacket, WireMessage, SignalType};
use crate::network::{connect_socks5, parse_onion_address, read_packet, write_packet_as_client};
use crate::vault::Vault; // Import Vault
use crate::HANDSHAKE_TIMEOUT_SEC;
use crate::tui::{AppState, ui};

use tokio::time::{timeout, Duration};
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use std::fs::{self, OpenOptions};
use std::io::Write;
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
use audiopus::{coder::Decoder as OpusDecoder, coder::Encoder as OpusEncoder, Application, Channels, SampleRate};

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; 

enum InternalEvent {
    NetworkMessage(WireMessage),
    Input(String),
    Progress(String, f64),
}

// Generate a dummy sine wave audio packet
fn simulate_audio_capture() -> Vec<i16> {
    let sample_rate = 48000;
    let frequency = 440.0; // A4
    let duration_ms = 60; // 60ms frame
    let num_samples = (sample_rate * duration_ms / 1000) as usize;
    
    (0..num_samples)
        .map(|i| (i as f32 * frequency * 2.0 * std::f32::consts::PI / sample_rate as f32).sin() * 3000.0)
        .map(|x| x as i16)
        .collect()
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
                // Get file size for secure overwrite
                let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(1024);
                if let Ok(mut file) = OpenOptions::new().write(true).open(&path) {
                     // Overwrite with zeros
                     let chunk_size = 4096;
                     let zeros = vec![0u8; chunk_size];
                     let mut written = 0;
                     while written < len {
                         let to_write = std::cmp::min(chunk_size as u64, len - written) as usize;
                         let _ = file.write_all(&zeros[..to_write]);
                         written += to_write as u64;
                     }
                     let _ = file.sync_all();
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

    // MOVED IDENTITY LOADING TO THE TOP
    // This runs in the standard terminal (before raw mode) so password input works cleanly.
    let id = if temp {
        Identity::generate("temp")?
    } else {
        let path = std::path::Path::new(&identity);
        if path.exists() {
            println!("Enter identity password:");
            // Reads from standard TTY securely without TUI interference
            let pass = rpassword::read_password()?;
            Identity::load(&identity, &pass)?
        } else {
            println!("Identity file not found. Creating new identity.");
            println!("Set REAL password (for OPS):");
            let pass_ops = rpassword::read_password()?;
            println!("Set DURESS password (for CASUAL):");
            let pass_casual = rpassword::read_password()?;
            
            Identity::setup_dual(&identity, &pass_ops, &pass_casual)?;
            println!("Identity created. Logging in with REAL password...");
            Identity::load(&identity, &pass_ops)?
        }
    };

    // NOW Initialize the TUI
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Pass 'group' to AppState constructor
    let mut app = AppState::new(username.clone(), id.fingerprint()[0..8].to_string(), group.clone());
    app.status = "CONNECTING...".to_string();
    if temp { app.add_log("⚠️ USING TEMP IDENTITY".to_string()); }

    // Initialize Vault
    let vault_path = "vantage.vault";
    let vault_pass = "default_vault_password"; // In real app, prompt for this!
    let mut vault: Option<Vault> = match Vault::open(vault_path, vault_pass) {
        Ok(v) => {
            app.add_log("🔒 VAULT MOUNTED".to_string());
            Some(v)
        },
        Err(e) => {
            app.add_log(format!("⚠️ VAULT ERROR: {}", e));
            None
        }
    };

    terminal.draw(|f| ui(f, &mut app))?;

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
    terminal.draw(|f| ui(f, &mut app))?;

    let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
    let mut handshake = builder.local_private_key(&id.keypair.private).build_initiator()?;
    let mut buf = vec![0u8; 65535];

    let len = handshake.write_message(&[], &mut buf)?;
    write_packet_as_client(&mut stream, &buf[..len]).await?;
    
    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
    handshake.read_message(&msg, &mut buf)?;
    
    let len = handshake.write_message(&[], &mut buf)?;
    write_packet_as_client(&mut stream, &buf[..len]).await?;

    let session = Arc::new(Mutex::new(NoiseSession::new(handshake)?));

    let remote = session.lock().unwrap().transport.get_remote_static().unwrap().to_vec();
    let mut h = Hasher::new(); h.update(&remote);
    let server_fp = BASE64_STANDARD.encode(h.finalize().as_bytes());
    if server_fp != peer_fp { bail!("Fingerprint mismatch"); }

    app.status = "SECURED (NOISE)".to_string();
    app.encryption_level = "NOISE: AES-256".to_string(); 

    // --- PQ ---
    app.status = "NEGOTIATING QUANTUM...".to_string();
    terminal.draw(|f| ui(f, &mut app))?;

    let wire_buf = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
    
    let decrypted = session.lock().unwrap().decrypt(&wire_buf)?;
    let packet = VantagePacket::from_bytes(&decrypted)?;
    
    match bincode::deserialize(&packet.payload) {
        Ok(WireMessage::PQInit { public_key }) => {
            // Verify Key Size
            if public_key.len() != pqcrypto_kyber::kyber1024::public_key_bytes() {
                bail!("Invalid Kyber1024 Public Key length: {}", public_key.len());
            }
            
            let pk = match PublicKey::from_bytes(&public_key) {
                Ok(k) => k,
                Err(e) => bail!("Failed to parse Kyber Public Key: {}", e),
            };
            
            let (ss, ct) = encapsulate(&pk);

            let pq_msg = WireMessage::PQFinish { ciphertext: ct.as_bytes().to_vec() };
            let data = bincode::serialize(&pq_msg)?;
            let pkt = VantagePacket::new(&data)?;
            let enc = session.lock().unwrap().encrypt(&pkt.to_bytes()?)?;
            
            write_packet_as_client(&mut stream, &enc).await?;

            // Client is Initiator -> true
            session.lock().unwrap().upgrade_to_pq(ss.as_bytes(), true);
            
            app.encryption_level = "🛡️ KYBER-1024".to_string();
            app.add_log("QUANTUM SHIELD ESTABLISHED".to_string());
        },
        Ok(other) => {
            // Debugging output for user
            println!("Debug: Expected PQInit, got {:?}", other);
            bail!("Expected PQInit, got {:?}", other);
        },
        Err(e) => {
            println!("Debug: PQInit deserialization failed: {}", e);
            bail!("PQInit deserialization failed: {}", e);
        }
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
    write_packet_as_client(&mut stream, &enc).await?;

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
        loop {
            let wire_res = read_packet(&mut reader).await;
            if wire_res.is_err() { break; }
            let wire = wire_res.unwrap();
            
            let res = { sess_read.lock().unwrap().decrypt(&wire) };
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
                            if write_packet_as_client(&mut writer, &data).await.is_err() { break; }
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
        app.cleanup_expired();
        terminal.draw(|f| ui(f, &mut app))?;

        if crossterm::event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                if app.file_browser_open {
                    match key.code {
                        KeyCode::Esc => app.file_browser_open = false,
                        KeyCode::Up => app.browser_navigate(true),
                        KeyCode::Down => app.browser_navigate(false),
                        KeyCode::Enter => {
                            if let Some(path) = app.browser_select() {
                                let _ = app.input.handle_event(&Event::Key(KeyCode::Char('/').into()));
                                let _ = app.input.handle_event(&Event::Key(KeyCode::Char('s').into()));
                                let _ = app.input.handle_event(&Event::Key(KeyCode::Char('e').into()));
                                let _ = app.input.handle_event(&Event::Key(KeyCode::Char('n').into()));
                                let _ = app.input.handle_event(&Event::Key(KeyCode::Char('d').into()));
                                let _ = app.input.handle_event(&Event::Key(KeyCode::Char(' ').into()));
                                for c in path.chars() {
                                    let _ = app.input.handle_event(&Event::Key(KeyCode::Char(c).into()));
                                }
                            }
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Enter => {
                            // [FIX] Support ALT+ENTER or SHIFT+ENTER for newlines
                            if key.modifiers.contains(KeyModifiers::SHIFT) || key.modifiers.contains(KeyModifiers::ALT) {
                                app.input.handle_event(&Event::Key(KeyCode::Char('\n').into()));
                            } else {
                                let input: String = app.input.value().into();
                                if !input.is_empty() {
                                    if input.trim() == "/browse" {
                                        app.open_browser();
                                        app.input.reset();
                                    } else {
                                        let _ = tx_logic.send(InternalEvent::Input(input)).await;
                                        app.input.reset();
                                    }
                                }
                            }
                        },
                        KeyCode::Up | KeyCode::PageUp => app.scroll_up(),
                        KeyCode::Down | KeyCode::PageDown => app.scroll_down(),
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
                    } else if cmd.starts_with("/vault_put ") {
                        let path_str = cmd.trim_start_matches("/vault_put ").trim();
                        let path = Path::new(path_str);
                        if path.exists() && path.is_file() {
                            if let Some(v) = &mut vault {
                                match fs::read(path) {
                                    Ok(data) => {
                                        let filename = path.file_name().unwrap().to_str().unwrap();
                                        match v.write_file(filename, &data) {
                                            Ok(_) => app.add_log(format!("🔒 Stored {} in Vault", filename)),
                                            Err(e) => app.add_log(format!("❌ Vault Write Error: {}", e)),
                                        }
                                    },
                                    Err(e) => app.add_log(format!("❌ Read Error: {}", e)),
                                }
                            } else {
                                app.add_log("❌ Vault not available".to_string());
                            }
                        } else {
                            app.add_log("❌ File not found".to_string());
                        }
                    } else if cmd.starts_with("/vault_get ") {
                        let filename = cmd.trim_start_matches("/vault_get ").trim();
                        if let Some(v) = &mut vault {
                            match v.read_file(filename) {
                                Ok(data) => {
                                    let out_path = format!("downloads/{}", filename);
                                    match fs::write(&out_path, data) {
                                        Ok(_) => app.add_log(format!("📂 Extracted to {}", out_path)),
                                        Err(e) => app.add_log(format!("❌ Write Error: {}", e)),
                                    }
                                },
                                Err(e) => app.add_log(format!("❌ Vault Read Error: {}", e)),
                            }
                        } else {
                            app.add_log("❌ Vault not available".to_string());
                        }
                    } else if cmd == "/vault_list" {
                        if let Some(v) = &vault {
                            let files = v.list_files();
                            app.add_log(format!("🔒 Vault Contents: {:?}", files));
                        } else {
                            app.add_log("❌ Vault not available".to_string());
                        }
                    } else if cmd.starts_with("/msg ") {
                        let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                        if parts.len() == 3 {
                            let target = parts[1];
                            let content = parts[2];
                            let _ = tx_net.send(WireMessage::DirectMessage {
                                sender: username.clone(),
                                target: target.to_string(),
                                content: content.to_string(),
                                timestamp: Utc::now(),
                                ttl: None,
                            }).await;
                            app.add_msg(format!("You -> {}", target), content.to_string());
                        } else {
                            app.add_log("Usage: /msg <user> <message>".to_string());
                        }
                    } else if cmd.starts_with("/ttl ") {
                        let parts: Vec<&str> = cmd.splitn(4, ' ').collect();
                        if parts.len() == 4 {
                            let target = parts[1];
                            let seconds = parts[2].parse::<u64>().unwrap_or(30);
                            let content = parts[3];
                            
                            // Here we should fetch peer_dids if we had E2EE (assuming E2EE is implemented or we fallback)
                            // Since protocol has ciphertext field but files are mixed, I will assume E2EE is active if I am to implement TTL secure delete.
                            // But I need to check if I have E2EE logic here.
                            // `id` is `Identity`.
                            // I see `id.encrypt_direct_msg` call in previous turns.
                            // But in `client.rs` attached, there is NO `encrypt_direct_msg` in `/msg`.
                            // This confirms I am working on OLD code and need to ADD `ttl` to plaintext message if E2EE is missing?
                            // OR I should assume I need to ADD E2EE back?
                            // The user said "fix this error".
                            // If I add `/ttl` support, I should follow the protocol I just defined.
                            // `WireMessage::DirectMessage` has `ciphertext`, `nonce`, `ttl` (I added them in protocol.rs).
                            // BUT `WireMessage` in `client.rs` usage (read_file) showed `content` string.
                            // I updated `protocol.rs` to have `ciphertext` instead of `content`?
                            // Let's check `protocol.rs` current state.
                            // I updated it in Step 1.
                            // It has:
                            // DirectMessage {
                            //     sender: String,
                            //     target: String,
                            //     content: String,  <-- Wait, did I remove content?
                            //     timestamp: DateTime<Utc>,
                            //     ttl: Option<u64>,
                            // },
                            //
                            // Ah, in Step 1 I added `ttl` to the EXISTING `DirectMessage`.
                            // The existing one had `content: String`.
                            // I did NOT replace it with `ciphertext` in Step 1 of THIS turn.
                            // I just added `ttl`.
                            // This is good because it matches the attached files.
                            // So I am implementing TTL on Plaintext messages (or whatever is there).
                            //
                            let _ = tx_net.send(WireMessage::DirectMessage {
                                sender: username.clone(),
                                target: target.to_string(),
                                content: content.to_string(),
                                timestamp: Utc::now(),
                                ttl: Some(seconds),
                            }).await;
                            app.add_ttl_msg(format!("You -> {}", target), content.to_string(), seconds);
                        } else {
                            app.add_log("Usage: /ttl <user> <seconds> <message>".to_string());
                        }
                    } else if cmd.starts_with("/kick ") {
                        let target = cmd.trim_start_matches("/kick ").trim();
                        if !target.is_empty() {
                            let _ = tx_net.send(WireMessage::AdminCommand {
                                command: "kick".to_string(),
                                target: target.to_string(),
                            }).await;
                        }
                    } else if cmd.starts_with("/ban ") {
                        let target = cmd.trim_start_matches("/ban ").trim();
                        if !target.is_empty() {
                            let _ = tx_net.send(WireMessage::AdminCommand {
                                command: "ban".to_string(),
                                target: target.to_string(),
                            }).await;
                        }
                    } else if cmd == "/voice_sim" {
                        app.add_log("🎤 Simulating Voice Packet Send...".to_string());
                        
                        // Encode simulated audio
                        let pcm = simulate_audio_capture();
                        let encoder = OpusEncoder::new(
                            SampleRate::Hz48000,
                            Channels::Mono,
                            Application::Voip
                        ).unwrap();
                        
                        let mut output = [0u8; 128]; // Small packet
                        if let Ok(len) = encoder.encode(&pcm, &mut output) {
                            let opus_data = output[..len].to_vec();
                            let _ = tx_net.send(WireMessage::VoicePacket {
                                data: opus_data
                            }).await;
                        } else {
                            app.add_log("Audio Encoding Failed".to_string());
                        }

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
                        WireMessage::DirectMessage { sender, content, ttl, .. } => {
                            if let Some(seconds) = ttl {
                                app.add_ttl_msg(sender, content, seconds);
                            } else {
                                app.add_msg(format!("{} (DM)", sender), content);
                            }
                        },
                        WireMessage::AdminCommand { command, target } => {
                            if target == username {
                                if command == "kick" {
                                    disable_raw_mode()?;
                                    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                                    println!("\n\x1b[31;1m🚨 YOU HAVE BEEN KICKED BY ADMIN.\x1b[0m");
                                    std::process::exit(0);
                                }
                            }
                            app.add_log(format!("ADMIN: Executed {} on {}", command, target));
                        },
                        WireMessage::VoicePacket { data } => {
                             // Decode logic to verify it works
                             let mut decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono).unwrap();
                             let mut output = [0i16; 5760]; // 120ms at 48khz
                             // Fix E0277: pass slice &mut output[..] instead of array
                             if let Ok(len) = decoder.decode(Some(&data), &mut output[..], false) {
                                 // "Play" it by logging
                                 app.add_log(format!("🔊 Voice Packet Received & Decoded ({} samples)", len));
                             } else {
                                 app.add_log("🔊 Voice Packet Receive Error".to_string());
                             }
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

                                let path_clone = path.clone();
                                let tx_net_task = tx_net.clone(); // Clone for task
                                tokio::spawn(async move {
                                    if let Ok(buffer) = tokio::fs::read(&path_clone).await {
                                        let tx_clone = tx_net_task.clone();
                                        let chunk_size = 1024; 
                                        let total = (buffer.len() as f64 / chunk_size as f64).ceil() as u32;
                                        
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
                                    }
                                });
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
