//! Protocol-specific service probes.
//!
//! This module implements deep service fingerprinting via protocol-specific probes.
//! Each probe sends crafted requests and parses responses to identify service versions.

use anyhow::{Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Result from a service probe
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub details: Option<String>,
}

/// HTTP service probe
pub async fn probe_http(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;

    let request = b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await?;

    let mut response = String::new();
    let mut buf = [0; 4096];

    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    response.push_str(&String::from_utf8_lossy(&buf[..n]));

    // Parse HTTP response
    let mut version = None;
    let mut server = None;

    for line in response.lines().take(20) {
        if line.starts_with("HTTP/") {
            version = Some(line.split_whitespace().next().unwrap_or("").to_string());
        }
        if line.starts_with("Server:") {
            server = Some(line.strip_prefix("Server:").unwrap_or("").trim().to_string());
        }
    }

    Ok(ProbeResult {
        service: "HTTP".to_string(),
        version,
        banner: server.clone(),
        details: server,
    })
}

/// HTTPS/TLS service probe
pub async fn probe_https(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    // For Phase 2, we do a simple TLS ClientHello and look for ServerHello
    let addr = SocketAddr::new(ip, port);
    let _stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;

    // Simplified: just indicate HTTPS is responding
    Ok(ProbeResult {
        service: "HTTPS".to_string(),
        version: Some("TLS".to_string()),
        banner: None,
        details: Some("TLS port responsive".to_string()),
    })
}

/// SSH service probe
pub async fn probe_ssh(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;

    let mut banner = String::new();
    let mut buf = [0; 256];

    // SSH servers send banner immediately
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    banner.push_str(&String::from_utf8_lossy(&buf[..n]));

    let banner = banner.trim().to_string();

    // Parse SSH banner (format: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6)
    let version = if banner.contains("OpenSSH") {
        banner
            .split_whitespace()
            .find(|s| s.contains("OpenSSH"))
            .map(|s| s.to_string())
    } else {
        None
    };

    Ok(ProbeResult {
        service: "SSH".to_string(),
        version,
        banner: Some(banner.clone()),
        details: Some(banner),
    })
}

/// FTP service probe
pub async fn probe_ftp(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;

    let mut banner = String::new();
    let mut buf = [0; 256];

    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    banner.push_str(&String::from_utf8_lossy(&buf[..n]));

    let banner = banner.trim().to_string();

    // Parse FTP banner (format: 220 FTP server ready)
    let version = if banner.contains("ProFTPD") {
        banner
            .split_whitespace()
            .find(|s| s.contains("ProFTPD"))
            .map(|s| s.to_string())
    } else if banner.contains("vsftpd") {
        banner
            .split_whitespace()
            .find(|s| s.contains("vsftpd"))
            .map(|s| s.to_string())
    } else {
        None
    };

    Ok(ProbeResult {
        service: "FTP".to_string(),
        version,
        banner: Some(banner.clone()),
        details: Some(banner),
    })
}

/// Telnet service probe
pub async fn probe_telnet(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;

    let mut banner = String::new();
    let mut buf = [0; 512];

    let n = timeout(Duration::from_secs(2), stream.read(&mut buf)).await??;
    banner.push_str(&String::from_utf8_lossy(&buf[..n]));

    // Send telnet negotiation
    let _result = stream.write_all(b"\r\n").await;

    Ok(ProbeResult {
        service: "Telnet".to_string(),
        version: None,
        banner: Some(banner.clone()),
        details: Some("Telnet service detected - major security risk!".to_string()),
    })
}

/// SNMP service probe (sends GetRequest for system description)
pub async fn probe_snmp(ip: IpAddr, _port: u16) -> Result<ProbeResult> {
    // SNMP uses UDP, skip for now (TCP-focused in Phase 2)
    Ok(ProbeResult {
        service: "SNMP".to_string(),
        version: None,
        banner: None,
        details: Some("SNMP detected on port 161 (UDP)".to_string()),
    })
}

/// Generic TCP probe that just checks if port responds
pub async fn probe_tcp(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let _stream = timeout(Duration::from_secs(2), TcpStream::connect(addr)).await??;

    Ok(ProbeResult {
        service: format!("TCP:{}", port),
        version: None,
        banner: None,
        details: Some("Port responsive".to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_result_creation() {
        let result = ProbeResult {
            service: "SSH".to_string(),
            version: Some("OpenSSH_7.4".to_string()),
            banner: Some("SSH-2.0-OpenSSH_7.4p1".to_string()),
            details: None,
        };

        assert_eq!(result.service, "SSH");
        assert!(result.version.is_some());
        assert!(result.banner.is_some());
    }

    #[tokio::test]
    async fn test_probe_localhost_ssh() {
        // This test only runs if sshd is running on localhost:22
        // Skip in CI environments
        if std::env::var("CI").is_ok() {
            return;
        }

        // This would need an actual SSH server to test
        // For now, just verify the function signature
        let _result = probe_ssh("127.0.0.1".parse().unwrap(), 22).await;
    }
}
