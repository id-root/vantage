use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use anyhow::{Result, bail, Context};

pub async fn connect_socks5(proxy: SocketAddr, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await
        .context("Failed to connect to SOCKS5 proxy")?;
    
    // 1. Handshake (No Auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf != [0x05, 0x00] { bail!("SOCKS5 auth rejected"); }

    // 2. Connect Request
    let mut req = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
    req.extend(target_host.as_bytes());
    req.extend(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    // 3. Response
    let mut resp = vec![0u8; 10]; 
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 { 
        bail!("SOCKS5 connection failed. Error code: 0x{:02x}", resp[1]); 
    }

    Ok(stream)
}

pub fn parse_onion_address(addr: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        bail!("Address format must be hostname.onion:port");
    }
    let host = parts[0];
    let port = parts[1].parse::<u16>().context("Invalid port number")?;
    
    if !host.ends_with(".onion") {
        bail!("Host must be a .onion address");
    }
    Ok((host.to_string(), port))
}

// --- NEW HELPER FUNCTIONS ---

/// Writes data prefixed with a 2-byte Big Endian length
pub async fn write_len_prefixed(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    Ok(())
}

/// Reads a 2-byte length, then that many bytes
pub async fn read_len_prefixed(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
    
