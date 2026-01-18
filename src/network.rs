use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use anyhow::{Result, bail, Context};
use crate::protocol::HttpWrapper;

pub async fn connect_socks5(proxy: SocketAddr, target_host: &str, target_port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await
        .context("Failed to connect to SOCKS5 proxy")?;
    
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf != [0x05, 0x00] { bail!("SOCKS5 auth rejected"); }

    let mut req = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
    req.extend(target_host.as_bytes());
    req.extend(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    // Read response header: VER, REP, RSV, ATYP
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    
    if head[1] != 0x00 { 
        bail!("SOCKS5 connection failed. Error code: 0x{:02x}", head[1]); 
    }

    // Read bound address based on ATYP
    match head[3] {
        0x01 => { 
            // IPv4: 4 bytes IP + 2 bytes Port
            let mut addr = [0u8; 6];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            // Domain: 1 byte len + N bytes domain + 2 bytes Port
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            // IPv6: 16 bytes IP + 2 bytes Port
            let mut addr = [0u8; 18];
            stream.read_exact(&mut addr).await?;
        }
        _ => bail!("Unknown SOCKS5 ATYP: 0x{:02x}", head[3]),
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

// FEATURE 2: Protocol Mimicry

pub async fn write_http_request<W>(stream: &mut W, data: &[u8]) -> Result<()> 
where W: AsyncWriteExt + Unpin
{
    let packet = HttpWrapper::wrap_request(data);
    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn write_http_response<W>(stream: &mut W, data: &[u8]) -> Result<()> 
where W: AsyncWriteExt + Unpin
{
    let packet = HttpWrapper::wrap_response(data);
    stream.write_all(&packet).await?;
    stream.flush().await?;
    Ok(())
}

/// Reads an HTTP message (Request or Response) and extracts the body.
pub async fn read_http_message<R>(stream: &mut R) -> Result<Vec<u8>> 
where R: AsyncReadExt + Unpin
{
    // Read header byte by byte or in chunks until \r\n\r\n
    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    
    // Safety limit for headers
    let max_header_size = 4096;
    
    loop {
        if stream.read_exact(&mut byte).await.is_err() {
            bail!("Connection closed while reading headers");
        }
        header_buf.push(byte[0]);
        
        if header_buf.len() > max_header_size {
            bail!("HTTP Headers too large");
        }
        
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    
    let header_str = String::from_utf8_lossy(&header_buf);
    
    // Parse Content-Length
    let content_length = header_str.lines()
        .find(|line| line.to_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|val| val.trim().parse::<usize>().ok())
        .context("Missing or Invalid Content-Length")?;
        
    // Read body
    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body).await?;
    
    Ok(body)
}

pub async fn write_packet_as_client<W>(stream: &mut W, data: &[u8]) -> Result<()> 
where W: AsyncWriteExt + Unpin
{
    write_http_request(stream, data).await
}

pub async fn write_packet_as_server<W>(stream: &mut W, data: &[u8]) -> Result<()> 
where W: AsyncWriteExt + Unpin
{
    write_http_response(stream, data).await
}

pub async fn read_packet<R>(stream: &mut R) -> Result<Vec<u8>> 
where R: AsyncReadExt + Unpin
{
    read_http_message(stream).await
}
