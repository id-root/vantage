use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{VantagePacket, WireMessage};
use crate::network::{connect_socks5, parse_onion_address, read_len_prefixed, write_len_prefixed}; // Helpers
use crate::{WIRE_PACKET_SIZE, HANDSHAKE_TIMEOUT_SEC};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use tokio::time::{timeout, Duration};
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use anyhow::{Result, bail};
use snow::Builder;
use tracing::info;
use base64::prelude::*;
use blake3::Hasher;
use chrono::Utc;

pub async fn run(
    address: String,
    username: String,
    peer_fp: String,
    proxy: String,
    identity: String,
) -> Result<()> {
    let id = Identity::load_or_create(&identity)?;
    info!("🆔 My Fingerprint: {}", id.fingerprint());

    let (host, port) = parse_onion_address(&address)?;
    let proxy_addr: SocketAddr = proxy.parse()?;
    
    info!("🌍 Connecting to {} via Tor...", host);
    let mut stream = connect_socks5(proxy_addr, &host, port).await?;
    
    // --- Handshake (Framed) ---
    info!("🔒 Performing Handshake...");
    let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
    let mut handshake = builder.local_private_key(&id.keypair.private).build_initiator()?;
    let mut buf = vec![0u8; 65535];

    // -> e
    let len = handshake.write_message(&[], &mut buf)?;
    write_len_prefixed(&mut stream, &buf[..len]).await?;
    
    // <- e, ee, s, es
    let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_len_prefixed(&mut stream)).await??;
    handshake.read_message(&msg, &mut buf)?;
    
    // -> s, se
    let len = handshake.write_message(&[], &mut buf)?;
    write_len_prefixed(&mut stream, &buf[..len]).await?;

    let session = Arc::new(Mutex::new(NoiseSession::new(handshake)?));

    // Verify Server
    let remote = session.lock().unwrap().transport.get_remote_static().unwrap().to_vec();
    let mut h = Hasher::new(); h.update(&remote);
    let server_fp = BASE64_STANDARD.encode(h.finalize().as_bytes());
    
    if server_fp != peer_fp {
        bail!("Fingerprint Mismatch! Expected {}, Got {}", peer_fp, server_fp);
    }
    info!("✅ Verified Server.");

    // --- Join ---
    info!("👋 Joining as '{}'...", username);
    let join_msg = WireMessage::Join { username: username.clone() };
    let json = serde_json::to_vec(&join_msg)?;
    let pkt = VantagePacket::new(&json)?;
    let enc = session.lock().unwrap().encrypt(&pkt.to_bytes()?)?;
    stream.write_all(&enc).await?;

    println!("╔═════════════════════════════════════════════╗");
    println!("║       Connected! Type /quit to exit         ║");
    println!("╚═════════════════════════════════════════════╝");

    // --- Chat Loop ---
    let (mut reader, mut writer) = stream.into_split();
    let sess_read = session.clone();
    let sess_write = session.clone();
    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Console Input Task
    tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line).await.is_err() { break; }
        }
    });

    // Network Read Task
    tokio::spawn(async move {
        let mut wire = [0u8; WIRE_PACKET_SIZE];
        loop {
            if reader.read_exact(&mut wire).await.is_err() { break; }
            let res = { sess_read.lock().unwrap().decrypt(&wire) };
            if let Ok(plain) = res {
                if let Ok(pkt) = VantagePacket::from_bytes(&plain) {
                    match serde_json::from_slice(&pkt.payload) {
                        Ok(WireMessage::Chat { sender, content, .. }) => {
                            println!("\x1b[32m[{}]\x1b[0m {}", sender, content);
                        },
                        Ok(WireMessage::System { content }) => {
                            println!("\x1b[33m[*] {}\x1b[0m", content);
                        },
                        _ => {}
                    }
                }
            }
        }
        println!("Disconnected.");
        std::process::exit(0);
    });

    // Network Write Task
    while let Some(input) = rx.recv().await {
        if input.trim() == "/quit" { break; }
        
        print!("\x1b[1A\x1b[2K"); // Erase input line
        println!("\x1b[36m[You]\x1b[0m {}", input);

        let msg = WireMessage::Chat { 
            sender: username.clone(), 
            content: input, 
            timestamp: Utc::now() 
        };
        let json = serde_json::to_vec(&msg)?;
        if let Ok(pkt) = VantagePacket::new(&json) {
            if let Ok(bytes) = pkt.to_bytes() {
                let enc = { sess_write.lock().unwrap().encrypt(&bytes) };
                if let Ok(data) = enc {
                    writer.write_all(&data).await?;
                }
            }
        }
    }

    Ok(())
}
