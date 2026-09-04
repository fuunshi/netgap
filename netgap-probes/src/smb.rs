//! What a file-sharing service will do before anyone logs in.
//!
//! Two questions are answered by a NEGOTIATE exchange, which any client may
//! send and which needs no credentials:
//!
//! - **Does it still speak SMBv1?** A server that accepts the 1990s dialect is
//!   open to the worm class that made WannaCry and NotPetya famous — the
//!   exploit needs nothing but a reachable SMBv1 service.
//! - **Does it require message signing?** Without it, an attacker on the same
//!   network can relay a victim's authentication to this server and act as
//!   them, without ever seeing the password.
//!
//! Both are configuration facts the server states about itself, so the
//! confidence is exact rather than guessed. Neither test logs in, guesses a
//! password, or tries any exploit.
//!
//! The wire format is small enough to build by hand: an SMB2 header is 64
//! bytes, a NEGOTIATE body is 36, and the fields read back are at fixed
//! offsets. The packet construction and the parsers are separate so the
//! parsers can be tested against captured bytes.

use anyhow::{bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// How long to wait for a connection or a reply.
const TIMEOUT: Duration = Duration::from_secs(3);

/// The largest SMB message worth reading: the protocol caps a frame at 64 KiB.
const MAX_FRAME: usize = 64 * 1024;

/// Whether the server requires SMB signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signing {
    /// The server insists: an unsigned session is refused.
    Required,
    /// The server supports signing but accepts unsigned sessions, which is
    /// what makes relay possible.
    Optional,
    /// The server said it does not sign at all.
    Disabled,
    /// An SMBv1-only server does not reveal this until a session is set up.
    Unknown,
}

/// What the server negotiated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbInfo {
    pub smb1: bool,
    pub smb2: bool,
    /// The SMB2/3 dialect the server picked, e.g. "2.1".
    pub dialect: Option<String>,
    pub signing: Signing,
}

/// Ask a file server what it supports.
///
/// The two questions are asked on separate connections: a server that refuses
/// one negotiation may close the connection, and the answer that matters is
/// the refusal, not the closed socket.
pub async fn inspect(ip: IpAddr, port: u16) -> Result<SmbInfo> {
    let smb1 = negotiate_smb1_on(ip, port).await;
    let smb2 = negotiate_smb2_on(ip, port).await;

    if smb2.is_none() && smb1.is_none() {
        bail!("{ip}:{port} did not answer SMB negotiation");
    }

    let (dialect, signing) = match &smb2 {
        Some((dialect, mode)) => (Some(dialect_name(*dialect)), signing_from_mode(*mode)),
        None => (None, Signing::Unknown),
    };

    Ok(SmbInfo {
        smb1: smb1.unwrap_or(false),
        smb2: dialect.is_some(),
        dialect,
        signing,
    })
}

/// Connect, and answer whether the server accepted the SMB1 dialect.
async fn negotiate_smb1_on(ip: IpAddr, port: u16) -> Option<bool> {
    let mut stream = connect(ip, port).await?;
    stream.write_all(&smb1_negotiate_request()).await.ok()?;
    let reply = read_frame(&mut stream).await?;
    parse_smb1_negotiate(&reply)
}

/// Connect, and read the dialect and security mode of the SMB2 reply.
async fn negotiate_smb2_on(ip: IpAddr, port: u16) -> Option<(u16, u16)> {
    let mut stream = connect(ip, port).await?;
    stream.write_all(&smb2_negotiate_request()).await.ok()?;
    let reply = read_frame(&mut stream).await?;
    parse_smb2_negotiate(&reply)
}

/// Open a connection, or give up after the timeout.
async fn connect(ip: IpAddr, port: u16) -> Option<TcpStream> {
    timeout(TIMEOUT, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .ok()?
        .ok()
}

/// Read one NetBIOS-framed message.
///
/// The whole frame is returned, header included, because that is the offset
/// base the parsers below use — the same base a captured packet has.
async fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;

    // The first byte is the message type (0x00 for a session message) and the
    // other three are the length, big-endian.
    let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
    if length == 0 || length > MAX_FRAME {
        return None;
    }

    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    timeout(TIMEOUT, stream.read_exact(&mut frame[4..]))
        .await
        .ok()?
        .ok()?;
    Some(frame)
}

/// An SMB2 NEGOTIATE asking for 2.0.2, 2.1 and 3.0, with signing enabled.
pub fn smb2_negotiate_request() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&3u16.to_le_bytes()); // DialectCount
    body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&[0u8; 16]); // ClientGuid
    body.extend_from_slice(&[0u8; 8]); // ClientStartTime / negotiate contexts
    body.extend_from_slice(&0x0202u16.to_le_bytes()); // 2.0.2
    body.extend_from_slice(&0x0210u16.to_le_bytes()); // 2.1
    body.extend_from_slice(&0x0300u16.to_le_bytes()); // 3.0

    let mut message = Vec::new();
    // The protocol id reads as the bytes FE 53 4D 42 on the wire.
    message.extend_from_slice(&0xFE53_4D42u32.to_be_bytes());
    message.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    message.extend_from_slice(&1u16.to_le_bytes()); // CreditCharge
    message.extend_from_slice(&0u32.to_le_bytes()); // Status
    message.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    message.extend_from_slice(&1u16.to_le_bytes()); // Credits
    message.extend_from_slice(&0u32.to_le_bytes()); // Flags
    message.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    message.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    message.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    message.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    message.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    message.extend_from_slice(&[0u8; 16]); // Signature
    message.extend_from_slice(&body);
    frame(message)
}

/// An SMB1 NEGOTIATE offering the "NT LM 0.12" dialect.
pub fn smb1_negotiate_request() -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&[0xFF, b'S', b'M', b'B']);
    message.push(0x72); // SMB_COM_NEGOTIATE
    message.extend_from_slice(&[0, 0, 0, 0]); // Status
    message.push(0x18); // Flags: case-insensitive, canonical paths
    message.extend_from_slice(&[0, 0]); // Flags2
    message.extend_from_slice(&[0, 0]); // PIDHigh
    message.extend_from_slice(&[0u8; 8]); // Signature
    message.extend_from_slice(&[0, 0]); // Reserved
    message.extend_from_slice(&[0, 0]); // TID
    message.extend_from_slice(&[0, 0]); // PID
    message.extend_from_slice(&[0, 0]); // UID
    message.extend_from_slice(&[0, 0]); // MID
    message.push(0); // WordCount
    message.extend_from_slice(&12u16.to_le_bytes()); // ByteCount
    message.extend_from_slice(b"\x02NT LM 0.12\x00");
    frame(message)
}

/// Prefix a message with its NetBIOS session header.
fn frame(message: Vec<u8>) -> Vec<u8> {
    let length = message.len() as u32;
    let mut framed = Vec::with_capacity(message.len() + 4);
    framed.push(0x00);
    framed.extend_from_slice(&length.to_be_bytes()[1..]);
    framed.extend_from_slice(&message);
    framed
}

/// The dialect and security mode of an SMB2 NEGOTIATE response.
///
/// Offsets are from the start of the frame: 4 bytes of NetBIOS header, a
/// 64-byte SMB2 header, then the 65-byte negotiate response.
pub fn parse_smb2_negotiate(frame: &[u8]) -> Option<(u16, u16)> {
    if frame.len() < 4 + 64 + 6 {
        return None;
    }

    // Protocol id, then the command and status in the header.
    if frame[4..8] != [0xFE, b'S', b'M', b'B'] {
        return None;
    }
    let command = u16::from_le_bytes([frame[16], frame[17]]);
    let status = u32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]);
    if command != 0 || status != 0 {
        return None;
    }

    let body = &frame[4 + 64..];
    let structure_size = u16::from_le_bytes([body[0], body[1]]);
    if structure_size != 65 {
        return None;
    }

    let security_mode = u16::from_le_bytes([body[2], body[3]]);
    let dialect = u16::from_le_bytes([body[4], body[5]]);
    Some((dialect, security_mode))
}

/// Whether an SMB1 NEGOTIATE response accepted a dialect.
///
/// The response's first parameter word carries the index of the dialect the
/// server chose; `0xFFFF` means none of the offered dialects were accepted.
pub fn parse_smb1_negotiate(frame: &[u8]) -> Option<bool> {
    if frame.len() < 4 + 32 + 2 {
        return None;
    }
    if frame[4..8] != [0xFF, b'S', b'M', b'B'] {
        return None;
    }

    let command = frame[8];
    let status = u32::from_le_bytes([frame[9], frame[10], frame[11], frame[12]]);
    if command != 0x72 || status != 0 {
        return None;
    }

    let word_count = frame[4 + 32];
    if word_count == 0 {
        return Some(false);
    }

    let dialect_index = frame[4 + 33];
    Some(dialect_index != 0xFF)
}

/// The SMB dialect number as people write it.
pub fn dialect_name(dialect: u16) -> String {
    match dialect {
        0x0202 => "2.0.2".to_string(),
        0x0210 => "2.1".to_string(),
        0x0300 => "3.0".to_string(),
        0x0302 => "3.0.2".to_string(),
        0x0311 => "3.1.1".to_string(),
        other => format!("0x{other:04X}"),
    }
}

/// Security mode bits from an SMB2 negotiate response.
fn signing_from_mode(mode: u16) -> Signing {
    const SIGNING_ENABLED: u16 = 0x0001;
    const SIGNING_REQUIRED: u16 = 0x0002;

    if mode & SIGNING_REQUIRED != 0 {
        Signing::Required
    } else if mode & SIGNING_ENABLED != 0 {
        Signing::Optional
    } else {
        Signing::Disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smb2_response(security_mode: u16, dialect: u16, status: u32) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&0xFE53_4D42u32.to_be_bytes());
        message.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
        message.extend_from_slice(&1u16.to_le_bytes()); // CreditCharge
        message.extend_from_slice(&status.to_le_bytes());
        message.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
        message.extend_from_slice(&1u16.to_le_bytes()); // Credits
        message.extend_from_slice(&[0u8; 16]); // Flags, NextCommand, MessageId
        message.extend_from_slice(&[0u8; 4]); // Reserved
        message.extend_from_slice(&[0u8; 4]); // TreeId
        message.extend_from_slice(&[0u8; 8]); // SessionId
        message.extend_from_slice(&[0u8; 16]); // Signature
        assert_eq!(message.len(), 64);

        message.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
        message.extend_from_slice(&security_mode.to_le_bytes());
        message.extend_from_slice(&dialect.to_le_bytes());
        message.extend_from_slice(&[0u8; 55]); // rest of the response
        frame(message)
    }

    /// An SMB1 NEGOTIATE response carrying `dialect_index` in its first word.
    fn smb1_response_with(dialect_index: u8) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(17); // WordCount
        let mut words = [0u8; 34];
        words[0] = dialect_index;
        body.extend_from_slice(&words);
        body.extend_from_slice(&0u16.to_le_bytes()); // ByteCount

        let mut message = Vec::new();
        message.extend_from_slice(&[0xFF, b'S', b'M', b'B']);
        message.push(0x72); // Command: NEGOTIATE
        message.extend_from_slice(&[0, 0, 0, 0]); // Status: success
        message.push(0x98); // Flags
        message.extend_from_slice(&[0u8; 22]); // rest of the header
        assert_eq!(message.len(), 32);
        message.extend_from_slice(&body);
        frame(message)
    }

    fn smb1_response() -> Vec<u8> {
        smb1_response_with(0)
    }

    #[test]
    fn an_smb2_negotiate_response_is_read() {
        let reply = smb2_response(0x0003, 0x0300, 0);
        let (dialect, mode) = parse_smb2_negotiate(&reply).expect("parse");
        assert_eq!(dialect, 0x0300);
        assert_eq!(signing_from_mode(mode), Signing::Required);
        assert_eq!(dialect_name(dialect), "3.0");
    }

    #[test]
    fn signing_is_classified_from_the_mode_bits() {
        assert_eq!(signing_from_mode(0x0002), Signing::Required);
        // "enabled" means supported, not demanded — which is the relay case.
        assert_eq!(signing_from_mode(0x0001), Signing::Optional);
        assert_eq!(signing_from_mode(0x0000), Signing::Disabled);
    }

    #[test]
    fn an_error_response_is_not_a_negotiation() {
        let reply = smb2_response(0x0001, 0x0202, 0xC000_00FE);
        assert!(parse_smb2_negotiate(&reply).is_none());
    }

    #[test]
    fn an_smb1_accepting_response_is_recognised() {
        assert_eq!(parse_smb1_negotiate(&smb1_response_with(0)), Some(true));
    }

    #[test]
    fn an_smb1_refusal_is_not_support() {
        assert_eq!(parse_smb1_negotiate(&smb1_response_with(0xFF)), Some(false));
    }

    #[test]
    fn an_smb2_frame_is_not_read_as_smb1() {
        assert_eq!(
            parse_smb1_negotiate(&smb2_response(0x0001, 0x0202, 0)),
            None
        );
        assert!(parse_smb2_negotiate(&smb1_response()).is_none());
    }

    #[test]
    fn requests_are_framed_with_their_netbios_length() {
        let smb2 = smb2_negotiate_request();
        assert_eq!(smb2[0], 0x00);
        let length = u32::from_be_bytes([0, smb2[1], smb2[2], smb2[3]]) as usize;
        assert_eq!(length, smb2.len() - 4);
        // A 64-byte SMB2 header and the fixed 36-byte negotiate body, then
        // the six bytes of the three dialects offered.
        assert_eq!(length, 64 + 36 + 6);

        let smb1 = smb1_negotiate_request();
        let length = u32::from_be_bytes([0, smb1[1], smb1[2], smb1[3]]) as usize;
        assert_eq!(length, smb1.len() - 4);
        assert_eq!(length, 32 + 3 + 12);
    }

    #[tokio::test]
    async fn a_server_that_answers_both_dialects_is_described() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).await.is_err() {
                    continue;
                }
                let length = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
                let mut request = vec![0u8; length];
                if stream.read_exact(&mut request).await.is_err() {
                    continue;
                }

                // Dialect by what the client offered: our SMB1 request has a
                // different protocol id from the SMB2 one.
                let reply = if request.starts_with(&[0xFE, b'S', b'M', b'B']) {
                    smb2_response(0x0002, 0x0210, 0)
                } else {
                    smb1_response()
                };
                let _ = stream.write_all(&reply).await;
            }
        });

        let info = inspect(address.ip(), address.port())
            .await
            .expect("inspect");
        assert!(info.smb1);
        assert!(info.smb2);
        assert_eq!(info.dialect.as_deref(), Some("2.1"));
        assert_eq!(info.signing, Signing::Required);
    }
}
