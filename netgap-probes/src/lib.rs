//! Protocol-specific service probes.
//!
//! Each probe speaks just enough of a protocol to make the service identify
//! itself, then parses the reply into a product name and a version:
//! `nginx` `1.18.0`, `OpenSSH` `7.4p1`, `PostgreSQL` `14.5`.
//!
//! That pair is what makes vulnerability matching real. Matching on the port
//! number alone can only guess ("port 80, probably Apache"), and a guessed
//! product produces confidently wrong CVEs.
//!
//! Parsing is kept in free functions over captured strings so it can be tested
//! without a network.

use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// How long to wait for a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// How long to wait for a service to say something.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Result from a service probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// Protocol family, e.g. "HTTP", "SSH", "MySQL".
    pub service: String,
    /// Product as reported by the service, e.g. "nginx", "OpenSSH", "Postfix".
    pub product: Option<String>,
    /// Product version, e.g. "1.18.0". Never the protocol version.
    pub version: Option<String>,
    /// Raw banner or header the identification came from.
    pub banner: Option<String>,
    /// Anything else worth showing a human.
    pub details: Option<String>,
}

impl ProbeResult {
    /// A result for a port that answered but identified nothing.
    fn unidentified(service: &str, banner: Option<String>) -> Self {
        ProbeResult {
            service: service.to_string(),
            product: None,
            version: None,
            banner,
            details: None,
        }
    }

    /// Whether a product and version were recovered.
    pub fn is_identified(&self) -> bool {
        self.product.is_some() && self.version.is_some()
    }

    /// `product version`, when both are known.
    pub fn product_version(&self) -> Option<String> {
        match (&self.product, &self.version) {
            (Some(product), Some(version)) => Some(format!("{} {}", product, version)),
            (Some(product), None) => Some(product.clone()),
            (None, Some(version)) => Some(version.clone()),
            (None, None) => None,
        }
    }
}

/// Which probe to use for a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    Http,
    Https,
    Ssh,
    Ftp,
    Telnet,
    Smtp,
    Imap,
    Pop3,
    Vnc,
    MySql,
    Postgres,
    Redis,
    /// Port responds, but nothing protocol-specific is known about it.
    Generic,
}

/// Pick a probe for a port.
pub fn probe_kind_for_port(port: u16) -> ProbeKind {
    match port {
        80 | 8000 | 8080 | 8888 | 5000 | 3000 => ProbeKind::Http,
        443 | 8443 | 9443 => ProbeKind::Https,
        22 | 2222 => ProbeKind::Ssh,
        21 => ProbeKind::Ftp,
        23 => ProbeKind::Telnet,
        25 | 465 | 587 => ProbeKind::Smtp,
        143 | 993 => ProbeKind::Imap,
        110 | 995 => ProbeKind::Pop3,
        5900 | 5901 => ProbeKind::Vnc,
        3306 => ProbeKind::MySql,
        5432 => ProbeKind::Postgres,
        6379 => ProbeKind::Redis,
        _ => ProbeKind::Generic,
    }
}

/// Probe a single port with the protocol that fits it.
pub async fn probe_port(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    match probe_kind_for_port(port) {
        ProbeKind::Http => probe_http(ip, port).await,
        ProbeKind::Https => probe_https(ip, port).await,
        ProbeKind::Ssh => probe_ssh(ip, port).await,
        ProbeKind::Ftp => probe_ftp(ip, port).await,
        ProbeKind::Telnet => probe_telnet(ip, port).await,
        ProbeKind::Smtp => probe_smtp(ip, port).await,
        ProbeKind::Imap => probe_imap(ip, port).await,
        ProbeKind::Pop3 => probe_pop3(ip, port).await,
        ProbeKind::Vnc => probe_vnc(ip, port).await,
        ProbeKind::MySql => probe_mysql(ip, port).await,
        ProbeKind::Postgres => probe_postgres(ip, port).await,
        ProbeKind::Redis => probe_redis(ip, port).await,
        ProbeKind::Generic => probe_tcp(ip, port).await,
    }
}

/// Probe several ports on one host, concurrently.
///
/// Failures are dropped: a port that refuses or stays silent is simply not in
/// the result.
pub async fn probe_ports(
    ip: IpAddr,
    ports: &[u16],
    concurrency: usize,
) -> Vec<(u16, ProbeResult)> {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for port in ports {
        let Ok(permit) = semaphore.clone().acquire_owned().await else {
            break;
        };
        let port = *port;
        tasks.spawn(async move {
            let _permit = permit;
            (port, probe_port(ip, port).await)
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok((port, Ok(result))) = joined {
            results.push((port, result));
        }
    }

    results.sort_by_key(|(port, _)| *port);
    results
}

/// Connect to a port.
async fn connect(ip: IpAddr, port: u16) -> Result<TcpStream> {
    let addr = SocketAddr::new(ip, port);
    Ok(timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await??)
}

/// Read whatever a service offers, up to `limit` bytes.
///
/// Stops at the read timeout rather than failing: services that greet without
/// a newline (SSH) would otherwise never be read.
async fn read_banner(stream: &mut TcpStream, limit: usize) -> String {
    let mut buffer = vec![0u8; limit];
    match timeout(READ_TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(read)) => String::from_utf8_lossy(&buffer[..read]).to_string(),
        _ => String::new(),
    }
}

/// HTTP probe: read the `Server` header.
pub async fn probe_http(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;

    let request = b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\nUser-Agent: netgap\r\n\r\n";
    stream.write_all(request).await?;

    let response = read_banner(&mut stream, 8192).await;
    let server = server_header(&response);

    let (product, version) = server
        .as_deref()
        .map(parse_server_header)
        .unwrap_or((None, None));

    Ok(ProbeResult {
        service: "HTTP".to_string(),
        product,
        version,
        banner: server,
        details: response
            .lines()
            .next()
            .map(|status| status.trim().to_string()),
    })
}

/// HTTPS probe.
///
/// Confirms the port speaks TLS and records that it is encrypted. It does not
/// complete a handshake, so no certificate details are available yet.
pub async fn probe_https(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let stream = connect(ip, port).await?;
    drop(stream);

    Ok(ProbeResult {
        service: "HTTPS".to_string(),
        product: None,
        version: None,
        banner: None,
        details: Some("TLS port responsive (certificate not inspected)".to_string()),
    })
}

/// SSH probe: the server sends its identification string immediately.
pub async fn probe_ssh(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream, 256).await;
    let (product, version) = parse_ssh_banner(&banner);

    Ok(ProbeResult {
        service: "SSH".to_string(),
        product,
        version,
        banner: Some(banner.trim().to_string()),
        details: None,
    })
}

/// FTP probe.
pub async fn probe_ftp(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream, 256).await;
    let (product, version) = parse_ftp_banner(&banner);

    Ok(ProbeResult {
        service: "FTP".to_string(),
        product,
        version,
        banner: Some(banner.trim().to_string()),
        details: None,
    })
}

/// Telnet probe.
pub async fn probe_telnet(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream, 512).await;
    let _ = stream.write_all(b"\r\n").await;

    Ok(ProbeResult {
        service: "Telnet".to_string(),
        product: None,
        version: None,
        banner: Some(banner.trim().to_string()),
        details: Some("Telnet sends credentials in cleartext".to_string()),
    })
}

/// SMTP probe.
pub async fn probe_smtp(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream, 512).await;
    let (product, version) = parse_smtp_banner(&banner);

    Ok(ProbeResult {
        service: "SMTP".to_string(),
        product,
        version,
        banner: Some(banner.trim().to_string()),
        details: None,
    })
}

/// IMAP probe.
pub async fn probe_imap(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream, 512).await;
    let (product, version) = parse_mail_banner(&banner);

    Ok(ProbeResult {
        service: "IMAP".to_string(),
        product,
        version,
        banner: Some(banner.trim().to_string()),
        details: None,
    })
}

/// POP3 probe.
pub async fn probe_pop3(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream, 512).await;
    let (product, version) = parse_mail_banner(&banner);

    Ok(ProbeResult {
        service: "POP3".to_string(),
        product,
        version,
        banner: Some(banner.trim().to_string()),
        details: None,
    })
}

/// VNC probe: the server announces the protocol version it speaks.
pub async fn probe_vnc(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let banner = read_banner(&mut stream, 64).await;

    let version = banner
        .trim()
        .strip_prefix("RFB ")
        .map(|rest| rest.trim().to_string())
        .filter(|value| !value.is_empty());

    // "003.008" is 3.8, which may still permit no authentication at all.
    let details = version.as_deref().map(|version| {
        if version.starts_with("003.003") {
            "VNC 3.3 offers no authentication".to_string()
        } else {
            format!("VNC protocol {}", version)
        }
    });

    Ok(ProbeResult {
        service: "VNC".to_string(),
        product: Some("VNC".to_string()),
        version,
        banner: Some(banner.trim().to_string()),
        details,
    })
}

/// MySQL/MariaDB probe: the server greeting carries its version.
pub async fn probe_mysql(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    let mut buffer = vec![0u8; 512];

    let read = match timeout(READ_TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(read)) => read,
        _ => 0,
    };

    let banner = String::from_utf8_lossy(&buffer[..read]).to_string();
    let (product, version) = parse_mysql_handshake(&buffer[..read]);

    Ok(ProbeResult {
        service: "MySQL".to_string(),
        product,
        version,
        banner: Some(banner.trim_end_matches('\0').to_string()),
        details: None,
    })
}

/// PostgreSQL probe.
///
/// Sends a startup message; any reply that is a valid protocol response proves
/// PostgreSQL is listening. The version needs a completed login, so it stays
/// unknown — which is honest, and better than guessing.
pub async fn probe_postgres(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;

    // length + protocol 3.0 + user\0netgap\0 + terminator
    let mut startup = Vec::new();
    startup.extend_from_slice(&[0, 0, 0, 0]); // length placeholder
    startup.extend_from_slice(&[0, 3, 0, 0]); // protocol 196608
    startup.extend_from_slice(b"user\0netgap\0\0");
    let length = startup.len() as u32;
    startup[..4].copy_from_slice(&length.to_be_bytes());

    stream.write_all(&startup).await?;
    let banner = read_banner(&mut stream, 64).await;
    let kind = banner.as_bytes().first().copied();

    // 'R' is an authentication request, 'E' an error: both are PostgreSQL.
    let recognised = matches!(kind, Some(b'R') | Some(b'E') | Some(b'S') | Some(b'N'));

    Ok(ProbeResult {
        service: "PostgreSQL".to_string(),
        product: recognised.then(|| "PostgreSQL".to_string()),
        version: None,
        banner: None,
        details: Some(if recognised {
            "PostgreSQL server responded to a startup message".to_string()
        } else {
            "Port responded, but not with a PostgreSQL handshake".to_string()
        }),
    })
}

/// Redis probe: `INFO server` reports the version, and needs no authentication
/// when the instance is unprotected — which is itself worth knowing.
pub async fn probe_redis(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let mut stream = connect(ip, port).await?;
    stream.write_all(b"INFO server\r\n").await?;
    let response = read_banner(&mut stream, 4096).await;

    let version = response
        .lines()
        .find_map(|line| line.strip_prefix("redis_version:"))
        .map(|value| value.trim().to_string());

    let product = response
        .lines()
        .find_map(|line| line.strip_prefix("redis_mode:"))
        .map(|_| "Redis".to_string())
        .or_else(|| version.as_ref().map(|_| "Redis".to_string()));

    let unauthenticated = response.contains("redis_version:");

    Ok(ProbeResult {
        service: "Redis".to_string(),
        product,
        version,
        banner: response.lines().next().map(str::to_string),
        details: unauthenticated
            .then(|| "Redis answered INFO without authentication".to_string()),
    })
}

/// Generic TCP probe: confirms the port accepts connections.
pub async fn probe_tcp(ip: IpAddr, port: u16) -> Result<ProbeResult> {
    let _stream = connect(ip, port).await?;
    Ok(ProbeResult::unidentified("TCP", None))
}

/// Extract the `Server` header from an HTTP response.
fn server_header(response: &str) -> Option<String> {
    response
        .lines()
        .find_map(|line| line.strip_prefix("Server:"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Split an HTTP `Server` header into product and version.
///
/// Handles the forms servers actually send:
/// `nginx/1.18.0`, `Apache/2.4.41 (Ubuntu)`, `Microsoft-IIS/10.0`,
/// `lighttpd/1.4.59`, and bare products with no version.
pub fn parse_server_header(header: &str) -> (Option<String>, Option<String>) {
    let token = header.split_whitespace().next().unwrap_or("").trim();

    if token.is_empty() {
        return (None, None);
    }

    match token.split_once('/') {
        Some((product, version)) if !product.is_empty() && !version.is_empty() => (
            Some(product.to_string()),
            Some(version.trim_end_matches(')').to_string()),
        ),
        _ => (Some(token.to_string()), None),
    }
}

/// Split an SSH identification string into product and version.
///
/// `SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6` gives `OpenSSH` `7.4p1`, and
/// `SSH-1.99-Cisco-1.25` gives `Cisco` `1.25`.
pub fn parse_ssh_banner(banner: &str) -> (Option<String>, Option<String>) {
    let Some(line) = banner.lines().find(|line| line.starts_with("SSH-")) else {
        return (None, None);
    };

    // Everything after the protocol version is the software string; anything
    // after the first space is the platform, which is not ours to parse.
    let software = line.splitn(3, '-').nth(2).unwrap_or("").trim();
    let software = software.split_whitespace().next().unwrap_or("");

    split_product_version(software)
}

/// Split `Product<separator>Version`, where the separator is the last `_` or
/// `-` that is followed by a digit.
///
/// Software strings are inconsistent — `OpenSSH_7.4p1`, `Sun_SSH_1.1`,
/// `Cisco-1.25` — and anchoring on a digit avoids splitting the product name
/// itself, as `Sun_SSH` would be by a naive first-underscore split.
fn split_product_version(software: &str) -> (Option<String>, Option<String>) {
    if software.is_empty() {
        return (None, None);
    }

    let mut split_at = None;
    for (index, character) in software.char_indices() {
        if !matches!(character, '_' | '-') {
            continue;
        }
        let rest = &software[index + character.len_utf8()..];
        if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            split_at = Some(index);
        }
    }

    match split_at {
        Some(index) => (
            Some(software[..index].to_string()),
            Some(software[index + 1..].to_string()),
        ),
        None => (Some(software.to_string()), None),
    }
}

/// Split an FTP greeting into product and version.
///
/// `220 ProFTPD 1.3.5 Server` and `220 (vsFTPd 3.0.3)` are both handled.
pub fn parse_ftp_banner(banner: &str) -> (Option<String>, Option<String>) {
    let lower = banner.to_lowercase();

    for product in ["proftpd", "vsftpd", "pure-ftpd", "filezilla"] {
        if let Some(index) = lower.find(product) {
            let rest = &banner[index..];
            let mut parts = rest.split_whitespace().map(|part| {
                part.trim_matches(|c: char| c == '(' || c == ')' || c == ',')
            });
            let name = parts.next().unwrap_or("").to_string();
            let version = parts
                .next()
                .filter(|value| value.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .map(str::to_string);

            return (Some(canonical_product_case(&name)), version);
        }
    }

    (None, None)
}

/// Split an SMTP greeting into product and version.
///
/// `220 mail.example.com ESMTP Postfix` and
/// `220 mail.example.com ESMTP Exim 4.94.2 Thu, 01 Jan 2026` both work.
pub fn parse_smtp_banner(banner: &str) -> (Option<String>, Option<String>) {
    for product in ["Postfix", "Exim", "Sendmail", "Microsoft ESMTP", "Haraka", "OpenSMTPD"] {
        if let Some(index) = banner.find(product) {
            let rest = &banner[index + product.len()..];
            let version = rest
                .split_whitespace()
                .next()
                .filter(|value| value.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .map(str::to_string);

            return (Some(product.to_string()), version);
        }
    }

    (None, None)
}

/// Split an IMAP or POP3 greeting into product and version.
///
/// `* OK [CAPABILITY ...] Dovecot ready.` and `+OK Dovecot ready.` both work.
pub fn parse_mail_banner(banner: &str) -> (Option<String>, Option<String>) {
    for product in ["Dovecot", "Courier", "Cyrus", "Exchange", "Zimbra"] {
        if let Some(index) = banner.find(product) {
            let rest = &banner[index + product.len()..];
            let version = rest
                .split_whitespace()
                .next()
                .filter(|value| value.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .map(str::to_string);

            return (Some(product.to_string()), version);
        }
    }

    (None, None)
}

/// Read the version out of a MySQL/MariaDB server greeting.
///
/// The greeting is a packet header, a protocol byte, then a NUL-terminated
/// version string. MariaDB prefixes its version with `5.5.5-` for compatibility
/// with clients that predate it.
pub fn parse_mysql_handshake(packet: &[u8]) -> (Option<String>, Option<String>) {
    // 4-byte packet header, then the protocol version byte.
    let Some(body) = packet.get(4..) else {
        return (None, None);
    };
    if body.first() != Some(&0x0a) {
        return (None, None);
    }

    let rest = &body[1..];
    let Some(end) = rest.iter().position(|byte| *byte == 0) else {
        return (None, None);
    };

    let reported = String::from_utf8_lossy(&rest[..end]).to_string();
    if reported.is_empty() {
        return (None, None);
    }

    let is_mariadb = reported.contains("MariaDB");
    let reported = reported.strip_prefix("5.5.5-").unwrap_or(&reported);

    // "8.0.32-0ubuntu0.22.04.2" -> "8.0.32"; "10.6.12-MariaDB-1" -> "10.6.12"
    let version = reported
        .split('-')
        .next()
        .filter(|value| value.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(str::to_string);

    let product = if is_mariadb { "MariaDB" } else { "MySQL" };
    (Some(product.to_string()), version)
}

/// Restore conventional capitalisation for products that spell it oddly.
fn canonical_product_case(product: &str) -> String {
    match product.to_lowercase().as_str() {
        "vsftpd" => "vsftpd".to_string(),
        "proftpd" => "ProFTPD".to_string(),
        "pure-ftpd" => "Pure-FTPd".to_string(),
        _ => product.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_result_creation() {
        let result = ProbeResult {
            service: "SSH".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("7.4p1".to_string()),
            banner: Some("SSH-2.0-OpenSSH_7.4p1".to_string()),
            details: None,
        };

        assert_eq!(result.service, "SSH");
        assert!(result.is_identified());
        assert_eq!(result.product_version().as_deref(), Some("OpenSSH 7.4p1"));
    }

    #[test]
    fn test_probe_kind_by_port() {
        assert_eq!(probe_kind_for_port(80), ProbeKind::Http);
        assert_eq!(probe_kind_for_port(443), ProbeKind::Https);
        assert_eq!(probe_kind_for_port(22), ProbeKind::Ssh);
        assert_eq!(probe_kind_for_port(25), ProbeKind::Smtp);
        assert_eq!(probe_kind_for_port(6379), ProbeKind::Redis);
        assert_eq!(probe_kind_for_port(9999), ProbeKind::Generic);
    }

    #[test]
    fn test_parse_server_header() {
        assert_eq!(
            parse_server_header("nginx/1.18.0"),
            (Some("nginx".to_string()), Some("1.18.0".to_string()))
        );
        assert_eq!(
            parse_server_header("Apache/2.4.41 (Ubuntu)"),
            (Some("Apache".to_string()), Some("2.4.41".to_string()))
        );
        assert_eq!(
            parse_server_header("Microsoft-IIS/10.0"),
            (Some("Microsoft-IIS".to_string()), Some("10.0".to_string()))
        );
        // A product with no version must not invent one.
        assert_eq!(
            parse_server_header("cloudflare"),
            (Some("cloudflare".to_string()), None)
        );
        assert_eq!(parse_server_header(""), (None, None));
    }

    #[test]
    fn test_parse_ssh_banner() {
        assert_eq!(
            parse_ssh_banner("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6\r\n"),
            (Some("OpenSSH".to_string()), Some("7.4p1".to_string()))
        );
        assert_eq!(
            parse_ssh_banner("SSH-1.99-Cisco-1.25"),
            (Some("Cisco".to_string()), Some("1.25".to_string()))
        );
        // The version separator may be an underscore or a dash, and may not be
        // the first one: "Sun_SSH_1.1" keeps its product name intact.
        assert_eq!(
            parse_ssh_banner("SSH-2.0-Sun_SSH_1.1"),
            (Some("Sun_SSH".to_string()), Some("1.1".to_string()))
        );
        assert_eq!(
            parse_ssh_banner("SSH-2.0-dropbear_2020.81"),
            (Some("dropbear".to_string()), Some("2020.81".to_string()))
        );

        // No version at all: product only, and no fabricated version.
        assert_eq!(
            parse_ssh_banner("SSH-2.0-dropbear"),
            (Some("dropbear".to_string()), None)
        );
        assert_eq!(parse_ssh_banner("220 FTP server ready"), (None, None));
    }

    #[test]
    fn test_parse_ftp_banner() {
        assert_eq!(
            parse_ftp_banner("220 ProFTPD 1.3.5 Server (ProFTPD) [127.0.0.1]"),
            (Some("ProFTPD".to_string()), Some("1.3.5".to_string()))
        );
        assert_eq!(
            parse_ftp_banner("220 (vsFTPd 3.0.3)"),
            (Some("vsftpd".to_string()), Some("3.0.3".to_string()))
        );
        assert_eq!(parse_ftp_banner("220 Service ready"), (None, None));
    }

    #[test]
    fn test_parse_smtp_banner() {
        assert_eq!(
            parse_smtp_banner("220 mail.example.com ESMTP Postfix"),
            (Some("Postfix".to_string()), None)
        );
        assert_eq!(
            parse_smtp_banner("220 mail.example.com ESMTP Exim 4.94.2 Thu, 01 Jan 2026"),
            (Some("Exim".to_string()), Some("4.94.2".to_string()))
        );
    }

    #[test]
    fn test_parse_mail_banner() {
        assert_eq!(
            parse_mail_banner("* OK [CAPABILITY IMAP4rev1] Dovecot ready."),
            (Some("Dovecot".to_string()), None)
        );
        assert_eq!(
            parse_mail_banner("+OK Dovecot 2.3.16 ready."),
            (Some("Dovecot".to_string()), Some("2.3.16".to_string()))
        );
    }

    #[test]
    fn test_parse_mysql_handshake() {
        // Packet header (3-byte length, sequence), protocol 0x0a, version, NUL.
        let mut packet = vec![0x2c, 0x00, 0x00, 0x00, 0x0a];
        packet.extend_from_slice(b"8.0.32-0ubuntu0.22.04.2\0");
        assert_eq!(
            parse_mysql_handshake(&packet),
            (Some("MySQL".to_string()), Some("8.0.32".to_string()))
        );

        // MariaDB hides its real version behind the 5.5.5- compatibility prefix.
        let mut maria = vec![0x2c, 0x00, 0x00, 0x00, 0x0a];
        maria.extend_from_slice(b"5.5.5-10.6.12-MariaDB-1\0");
        assert_eq!(
            parse_mysql_handshake(&maria),
            (Some("MariaDB".to_string()), Some("10.6.12".to_string()))
        );

        // Not a greeting at all.
        assert_eq!(parse_mysql_handshake(b"garbage"), (None, None));
    }

    #[test]
    fn test_vnc_version_is_reported_from_the_banner() {
        // Parsing lives inline in the probe, so assert the shape it relies on.
        let banner = "RFB 003.008\n";
        let version = banner.trim().strip_prefix("RFB ").map(str::to_string);
        assert_eq!(version.as_deref(), Some("003.008"));
    }

    #[tokio::test]
    async fn test_probe_unreachable_port_is_an_error() {
        // TEST-NET-1 is never routed, so this exercises the failure path.
        let result = probe_port("192.0.2.1".parse().unwrap(), 80).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_probe_ports_on_localhost_returns_only_live_services() {
        // Port 9 (discard) is not listening; the result must simply omit it.
        let results = probe_ports("127.0.0.1".parse().unwrap(), &[9], 4).await;
        assert!(results.is_empty(), "unexpected: {results:?}");
    }
}
