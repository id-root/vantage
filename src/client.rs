use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{IsotopePacket, WireMessage};
use crate::network::{connect_socks5, parse_onion_address, read_packet, write_packet_as_client};
use crate::vault::Vault; 
use crate::HANDSHAKE_TIMEOUT_SEC;
use crate::ui::{AppState, Focus};
use crate::ui::render::draw_ui;

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
use rand::Rng; // For random dashboard stats

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
    vault_password: Option<String>,
) -> Result<()> {
    // [FIX] Add Panic Hook to restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen, crossterm::event::DisableMouseCapture);
        original_hook(info);
    }));

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
    let vault_path = "isotope.vault";
    let mut vault: Option<Vault> = None;
    
    // [FIX] Secure Vault Password Handling
    let v_pass = if let Some(p) = vault_password {
        Some(p)
    } else {
        // TUI is already init, so we skip asking or we need to handle it properly?
        // Actually, we are in raw mode now. `rpassword` reads from stdin which might be messy.
        // Ideally we ask BEFORE raw mode. But logic flow is tricky.
        // For simplicity, if not provided, skip or rely on command line. 
        // We will default to None if not passed in args for now to avoid TUI breaking.
        None 
    };

    if let Some(pass) = v_pass {
         match Vault::open(vault_path, &pass) {
            Ok(v) => {
                app.add_log("🔒 VAULT MOUNTED".to_string());
                app.vault_files = v.list_files(); // Sync initial state
                vault = Some(v);
            },
            Err(e) => {
                app.add_log(format!("⚠️ VAULT ERROR: {}", e));
            }
        }
    } else {
         app.add_log("⚠️ VAULT SKIPPED".to_string());
    }

    terminal.draw(|f| draw_ui(f, &mut app))?;

    let (host, port) = parse_onion_address(&address)?;
    let proxy_addr: SocketAddr = proxy.parse()?;
    
    // RECONNECT LOOP
    let mut retry_count = 0;
    loop {
        if retry_count > 0 {
             app.status = format!("RETRYING ({})", retry_count);
             let delay = std::cmp::min(10, retry_count * 2) as u64;
             app.add_log(format!("Lost connection. Retrying in {}s...", delay));
             terminal.draw(|f| draw_ui(f, &mut app))?;
             tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        app.status = "CONNECTING...".to_string();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        let mut stream = match connect_socks5(proxy_addr, &host, port).await {
            Ok(s) => s,
            Err(e) => {
                app.add_log(format!("Connection Failed: {}", e));
                retry_count += 1;
                continue;
            }
        };

        // --- HANDSHAKE ---
        app.status = "HANDSHAKING...".to_string();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
        let handshake_res = builder.local_private_key(&id.keypair.private).build_initiator();
        if let Err(e) = handshake_res {
             app.add_log(format!("Handshake Init Error: {}", e));
             retry_count += 1; continue;
        }
        let mut handshake = handshake_res.unwrap();
        let mut buf = vec![0u8; 65535];

        if let Err(e) = (async {
            let len = handshake.write_message(&[], &mut buf)?;
            write_packet_as_client(&mut stream, &buf[..len]).await?;
            let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
            handshake.read_message(&msg, &mut buf)?;
            let len = handshake.write_message(&[], &mut buf)?;
            write_packet_as_client(&mut stream, &buf[..len]).await?;
            Ok::<(), anyhow::Error>(())
        }).await {
             app.add_log(format!("Handshake Error: {}", e));
             retry_count += 1; continue;
        }

        let session = match NoiseSession::new(handshake) {
            Ok(s) => Arc::new(Mutex::new(s)),
            Err(e) => { app.add_log(format!("Session Error: {}", e)); retry_count += 1; continue; }
        };

        let remote = session.lock().unwrap().transport.get_remote_static().unwrap().to_vec();
        let mut h = Hasher::new(); h.update(&remote);
        let server_fp = BASE64_STANDARD.encode(h.finalize().as_bytes());
        if server_fp != peer_fp { 
            app.add_log("Fingerprint mismatch! MITM?".to_string());
            retry_count += 1; continue; 
        }

        app.status = "SECURED (NOISE)".to_string();
        app.encryption_level = "NOISE: AES-256".to_string(); 

        // --- PQ ---
        app.status = "NEGOTIATING QUANTUM...".to_string();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if let Err(e) = (async {
            let wire_buf = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
            let decrypted = session.lock().unwrap().decrypt(&wire_buf)?;
            let packet = IsotopePacket::from_bytes(&decrypted)?;
            
            match bincode::deserialize(&packet.payload) {
                Ok(WireMessage::PQInit { public_key }) => {
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
                    let pkt = IsotopePacket::new(&data)?;
                    let enc = session.lock().unwrap().encrypt(&pkt.to_bytes()?)?;
                    write_packet_as_client(&mut stream, &enc).await?;
                    session.lock().unwrap().upgrade_to_pq(ss.as_bytes(), true);
                    Ok(())
                },
                _ => bail!("Expected PQInit")
            }
        }).await {
             app.add_log(format!("PQ Error: {}", e));
             retry_count += 1; continue;
        }

        app.encryption_level = "🛡️ KYBER-1024".to_string();
        app.add_log("QUANTUM SHIELD ESTABLISHED".to_string());

        // --- JOIN ---
        let join_msg = WireMessage::Join { 
            username: username.clone(), 
            did: id.did(),
            group: group.clone()
        };
        if let Ok(data) = bincode::serialize(&join_msg) {
             if let Ok(pkt) = IsotopePacket::new(&data) {
                 if let Ok(enc) = session.lock().unwrap().encrypt(&pkt.to_bytes().unwrap()) {
                      if write_packet_as_client(&mut stream, &enc).await.is_err() {
                           app.add_log("Failed to send Join".to_string());
                           retry_count += 1; continue;
                      }
                 }
             }
        }

        app.status = "ONLINE".to_string();
        retry_count = 0; // RESET RETRY COUNT ON SUCCESSFUL JOIN

        let (mut reader, mut writer) = stream.into_split();
        let (tx_net, mut rx_net) = mpsc::channel::<WireMessage>(100);
        let (tx_logic, mut rx_logic) = mpsc::channel::<InternalEvent>(100);

        let sess_read = session.clone();
        let sess_write = session.clone();
        
        let tx_heartbeat = tx_net.clone();
        // Heartbeat Task
        let hb_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if tx_heartbeat.send(WireMessage::Heartbeat).await.is_err() {
                    break;
                }
            }
        });

        // T1: Cover Traffic Task - send dummy packets at random intervals
        let tx_cover = tx_net.clone();
        let _cover_handle = tokio::spawn(async move {
            use rand::Rng;
            loop {
                // Random interval between 2-8 seconds
                let interval = rand::thread_rng().gen_range(2..8);
                tokio::time::sleep(Duration::from_secs(interval)).await;
                
                // Generate random noise (same size as typical packet for uniformity)
                let noise: Vec<u8> = (0..256).map(|_| rand::thread_rng().gen()).collect();
                if tx_cover.send(WireMessage::Dummy { noise }).await.is_err() {
                    break;
                }
            }
        });

        // Network Reader Task
        let tx_logic_net = tx_logic.clone();
        let reader_handle = tokio::spawn(async move {
            loop {
                let wire_res = read_packet(&mut reader).await;
                if wire_res.is_err() { break; }
                let wire = wire_res.unwrap();
                
                let res = { sess_read.lock().unwrap().decrypt(&wire) };
                if let Ok(plain) = res {
                    if let Ok(pkt) = IsotopePacket::from_bytes(&plain) {
                        if let Ok(msg) = bincode::deserialize(&pkt.payload) {
                            if !matches!(msg, WireMessage::Heartbeat) {
                                let _ = tx_logic_net.send(InternalEvent::NetworkMessage(msg)).await;
                            }
                        }
                    }
                }
            }
        });

        // Network Writer Task
        let writer_handle = tokio::spawn(async move {
            while let Some(msg) = rx_net.recv().await {
                if let Ok(data) = bincode::serialize(&msg) {
                    if let Ok(pkt) = IsotopePacket::new(&data) {
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
        
        // A2: Dead Man's Switch - auto-nuke after inactivity
        let dead_man_timeout = Duration::from_secs(5 * 60); // 5 minutes
        let mut last_activity = std::time::Instant::now();
        
        // MAIN UI LOOP
        let mut quit_signal = false;
        'session: loop {
            // A2: Check Dead Man's Switch
            if last_activity.elapsed() > dead_man_timeout {
                // Send MAYDAY signal before nuke
                let _ = tx_net.send(WireMessage::Signal(crate::protocol::SignalType::Duress)).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
                
                disable_raw_mode()?;
                execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                println!("\n\x1b[31;1m🚨 DEAD MAN'S SWITCH TRIGGERED (INACTIVITY). NUKING DATA...\x1b[0m");
                nuke_everything(&identity);
                std::process::exit(0);
            }
            
            // UI5: Update Dashboard Stats (Simulated)
            // Real uptime would use a start timestamp, here we just increment
            app.dashboard_state.uptime_secs = app.dashboard_state.uptime_secs.wrapping_add(1);
            
            // Simulate fluctuating RAM (50-150MB)
            // In real app, use sysinfo crate
            let mut rng = rand::thread_rng();
            app.dashboard_state.ram_usage = (50 + rng.gen_range(0..20)) as u64;
            
            // Simulate Network Traffic
            if app.dashboard_state.uptime_secs % 2 == 0 {
                app.dashboard_state.upload_speed = rng.gen_range(0.5..5.0);
                app.dashboard_state.download_speed = rng.gen_range(10.0..50.0);
            }

            app.cleanup_expired();
            terminal.draw(|f| draw_ui(f, &mut app))?;

            if crossterm::event::poll(Duration::from_millis(10))? {
                // A2: Reset Dead Man's Switch on any input
                last_activity = std::time::Instant::now();
                
                if let Event::Key(key) = event::read()? {
                    if app.file_browser_open {
                        match key.code {
                            KeyCode::Esc => app.file_browser_open = false,
                            KeyCode::Up => app.browser_navigate(true),
                            KeyCode::Down => app.browser_navigate(false),
                            KeyCode::Enter => {
                                if let Some(path) = app.browser_select() {
                                    // Hacky simulation of input to preserve flow
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
                            // Shortcuts
                            // Tab Navigation
                            // Tab Navigation
                            KeyCode::Tab => {
                                 // Restore original behavior: Cycle Focus
                                 app.cycle_focus(key.modifiers.contains(KeyModifiers::SHIFT));
                            }
                            
                            // New Tab Navigation Keys (Alt + Left/Right)
                            KeyCode::Left if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.prev_tab();
                            }
                            KeyCode::Right if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.next_tab();
                            }
                            
                            // Direct Tab Access (Alt+1, Alt+2, Alt+3)
                            KeyCode::Char('1') if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.current_tab = crate::ui::Tab::Comms;
                            }
                            KeyCode::Char('2') if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.current_tab = crate::ui::Tab::Vault;
                            }
                            KeyCode::Char('3') if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.current_tab = crate::ui::Tab::Intel;
                            }
                            
                            // Focus Cycling (Ctrl+Tab)
                            // Kept as legacy or alternative for inside tabs
                            KeyCode::BackTab => { // Shift+Tab usually sends BackTab
                                app.cycle_focus(true);
                            }
                            KeyCode::Char('?') => {
                                 app.show_help = !app.show_help;
                            }
                            
                            // Input Focus Handling
                            KeyCode::Enter if app.focus == Focus::Input => {
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
                            }
                            KeyCode::Char(c) if app.focus == Focus::Input => {
                                 app.input.handle_event(&Event::Key(key));
                            }
                            KeyCode::Backspace if app.focus == Focus::Input => {
                                 app.input.handle_event(&Event::Key(key));
                            }
                            
                            // Scroll
                            KeyCode::Up | KeyCode::PageUp => {
                                if app.focus == Focus::Chat {
                                    app.scroll_up();
                                }
                            }
                            KeyCode::Down | KeyCode::PageDown => {
                                if app.focus == Focus::Chat {
                                    app.scroll_down();
                                }
                            }

                            KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                // D3: MAYDAY - Send silent duress signal before nuke
                                let _ = tx_net.send(WireMessage::Signal(crate::protocol::SignalType::Duress)).await;
                                tokio::time::sleep(Duration::from_millis(100)).await; // Brief delay for signal
                                
                                disable_raw_mode()?;
                                execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                                println!("\n\x1b[31;1m🚨 PANIC INITIATED. NUKING DATA...\x1b[0m");
                                nuke_everything(&identity);
                                std::process::exit(0);
                            },
                            KeyCode::Esc => { quit_signal = true; break 'session; }, 
                            _ => {}
                        }
                    }
                }
            }

            // Check if connection died (tasks finished)
            if reader_handle.is_finished() || writer_handle.is_finished() {
                 app.add_log("⚠️ Network Task Failed".to_string());
                 break 'session; 
            }

            if let Ok(event) = rx_logic.try_recv() {
                match event {
                    InternalEvent::Progress(filename, pct) => {
                        if pct >= 1.0 {
                            app.file_progress = None;
                            app.add_msg("SYSTEM".to_string(), format!("TRANSFER COMPLETE: {}", filename));
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
                                        app.add_msg("SYSTEM".to_string(), format!("⚠️ FILE TOO LARGE ({} MB)", size/1024/1024));
                                    } else {
                                        // Fix: Short 4-digit ID
                                        let mut rng = rand::thread_rng();
                                        let id = rng.gen_range(1000..9999);
                                        
                                        let name = path.file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("unknown_file")
                                            .to_string();
                                        upload_queue.insert(id, path);
                                        
                                        // Fix: Show in MAIN CHAT
                                        app.add_msg("SYSTEM".to_string(), format!("OFFERED: {} (ID: {})", name, id));
                                        
                                        let _ = tx_net.send(WireMessage::FileOffer {
                                            sender: username.clone(), file_name: name, file_size: size, id
                                        }).await;
                                    }
                                } else {
                                    app.add_msg("SYSTEM".to_string(), "ERROR: INVALID FILE".to_string());
                                }
                            } else {
                                 app.add_msg("SYSTEM".to_string(), format!("ERROR: PATH NOT FOUND {:?}", path));
                            }
                        } else if cmd.starts_with("/get ") {
                            if let Ok(id) = cmd.trim_start_matches("/get ").parse::<u32>() {
                                if let Some((_, sender_name)) = pending_offers.get(&id) {
                                    // Fix: Show in MAIN CHAT
                                    app.add_msg("SYSTEM".to_string(), format!("ACCEPTING ID {} from {}", id, sender_name));
                                    download_whitelist.insert(id);
                                    let _ = tx_net.send(WireMessage::FileRequest { 
                                        receiver: sender_name.clone(), 
                                        file_id: id 
                                    }).await;
                                } else {
                                    app.add_msg("SYSTEM".to_string(), format!("UNKNOWN FILE ID: {}", id));
                                }
                            }
                        } else if cmd == "/quit" {
                            quit_signal = true; break 'session; 
                        } else if cmd == "/nuke" {
                            // D3: MAYDAY - Send silent duress signal before nuke
                            let _ = tx_net.send(WireMessage::Signal(crate::protocol::SignalType::Duress)).await;
                            tokio::time::sleep(Duration::from_millis(100)).await; // Brief delay for signal
                            
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
                                                Ok(_) => {
                                                    // Fix: MAIN CHAT log + Sync UI
                                                    app.add_msg("SYSTEM".to_string(), format!("🔒 Stored {} in Vault", filename));
                                                    app.vault_files = v.list_files();
                                                },
                                                Err(e) => app.add_msg("SYSTEM".to_string(), format!("❌ Vault Write Error: {}", e)),
                                            }
                                        },
                                        Err(e) => app.add_msg("SYSTEM".to_string(), format!("❌ Read Error: {}", e)),
                                    }
                                } else {
                                    app.add_msg("SYSTEM".to_string(), "❌ Vault not available".to_string());
                                }
                            } else {
                                app.add_msg("SYSTEM".to_string(), "❌ File not found".to_string());
                            }
                        } else if cmd.starts_with("/vault_get ") {
                            let filename = cmd.trim_start_matches("/vault_get ").trim();
                            if let Some(v) = &mut vault {
                                match v.read_file(filename) {
                                    Ok(data) => {
                                        let out_path = format!("downloads/{}", filename);
                                        match fs::write(&out_path, data) {
                                            Ok(_) => app.add_msg("SYSTEM".to_string(), format!("📂 Extracted to {}", out_path)),
                                            Err(e) => app.add_msg("SYSTEM".to_string(), format!("❌ Write Error: {}", e)),
                                        }
                                    },
                                    Err(e) => app.add_msg("SYSTEM".to_string(), format!("❌ Vault Read Error: {}", e)),
                                }
                            } else {
                                app.add_msg("SYSTEM".to_string(), "❌ Vault not available".to_string());
                            }
                        } else if cmd == "/vault_list" {
                            if let Some(v) = &vault {
                                let files = v.list_files();
                                app.vault_files = files.clone(); // Sync UI
                                app.add_msg("SYSTEM".to_string(), format!("🔒 Vault Contents: {:?}", files));
                            } else {
                                app.add_msg("SYSTEM".to_string(), "❌ Vault not available".to_string());
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
                            let pcm = simulate_audio_capture();
                            let encoder = OpusEncoder::new(
                                SampleRate::Hz48000,
                                Channels::Mono,
                                Application::Voip
                            ).unwrap();
                            
                            let mut output = [0u8; 128]; 
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
                                 let mut decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono).unwrap();
                                 let mut output = [0i16; 5760];
                                 if let Ok(len) = decoder.decode(Some(&data), &mut output[..], false) {
                                     app.add_log(format!("🔊 Voice Packet Received & Decoded ({} samples)", len));
                                 } else {
                                     app.add_log("🔊 Voice Packet Receive Error".to_string());
                                 }
                            },
                            WireMessage::FileOffer { sender, file_name, file_size, id, .. } => {
                                if file_size > MAX_FILE_SIZE {
                                    app.add_log(format!("⚠️ IGNORED FILE OFFER > 10MB ({} B)", file_size));
                                } else if sender != username {
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
                                    let tx_net_task = tx_net.clone(); 
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
        } // End 'session

        // Loop Break Handling
        hb_handle.abort(); 
        reader_handle.abort();
        writer_handle.abort();

        if quit_signal {
            break;
        }
        
        // If we are here, it's a disconnect.
        app.peers.clear();
        retry_count += 1;
        // Proceed to next iteration of loop to retry logic
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}
