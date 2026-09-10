//! Whether a MongoDB server lets anyone in.
//!
//! A MongoDB with no authentication enabled answers administrative commands to
//! any client that connects, and `listDatabases` is the one that settles it:
//! with authentication on, the server refuses that command until the client
//! has authenticated, and says so; with it off, the server simply lists the
//! databases. Asking for the list is the read-only way to tell the difference.
//!
//! Only database *names* would come back, and this code does not keep them —
//! the answer it cares about is whether the server answered at all.
//!
//! The wire protocol is `OP_MSG` with a BSON body, which MongoDB has supported
//! since 3.6. A server older than that is reported as unknown, not as open.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(3);

/// `OP_MSG`, the only command opcode modern servers accept.
const OP_MSG: i32 = 2013;

/// The largest reply worth reading.
const MAX_REPLY: usize = 8 * 1024 * 1024;

/// What the server allowed without a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// `listDatabases` was answered.
    Open,
    /// The server asked the client to authenticate first.
    Protected,
}

/// Ask whether the server needs a password.
pub async fn inspect(ip: IpAddr, port: u16) -> Result<Access> {
    let mut stream = timeout(TIMEOUT, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .map_err(|_| anyhow!("connecting to {ip}:{port} timed out"))??;

    // Servers expect a handshake before any other command.
    let hello = document(&[("hello", Value::Int32(1)), ("$db", Value::text("admin"))]);
    stream
        .write_all(&op_msg(1, &hello))
        .await
        .map_err(|error| anyhow!("{ip}:{port} closed before the handshake: {error}"))?;
    read_message(&mut stream)
        .await
        .ok_or_else(|| anyhow!("{ip}:{port} did not answer the handshake"))?;

    let list = document(&[
        ("listDatabases", Value::Int32(1)),
        ("$db", Value::text("admin")),
    ]);
    stream.write_all(&op_msg(2, &list)).await?;

    let reply = read_message(&mut stream)
        .await
        .ok_or_else(|| anyhow!("{ip}:{port} closed without answering listDatabases"))?;
    let body = reply_document(&reply)
        .ok_or_else(|| anyhow!("{ip}:{port} did not answer with an OP_MSG document"))?;

    classify(body)
}

/// Read the verdict from a `listDatabases` reply document.
pub fn classify(body: &[u8]) -> Result<Access> {
    match number(body, "ok") {
        Some(1.0) => Ok(Access::Open),
        Some(_) => {
            // An authorisation failure is the protected answer. Anything else
            // is a server that answered, but not the question that was asked.
            if has_field(body, "databases") {
                return Ok(Access::Open);
            }
            if let Some(message) = text(body, "errmsg") {
                if message.contains("requires authentication")
                    || message.contains("unauthorized")
                    || message.contains("not authorized")
                {
                    return Ok(Access::Protected);
                }
                bail!("the server refused listDatabases: {message}");
            }
            bail!("the server answered listDatabases without ok or errmsg");
        }
        None => bail!("the reply has no ok field"),
    }
}

/// Read one length-prefixed message.
async fn read_message(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;
    let length = i32::from_le_bytes(header);
    if length < 16 || length as usize > MAX_REPLY {
        return None;
    }

    let mut message = vec![0u8; length as usize];
    message[..4].copy_from_slice(&header);
    timeout(TIMEOUT, stream.read_exact(&mut message[4..]))
        .await
        .ok()?
        .ok()?;
    Some(message)
}

/// Wrap a BSON document in an `OP_MSG` for the given request id.
pub fn op_msg(request_id: i32, body: &[u8]) -> Vec<u8> {
    let total = 16 + 4 + 1 + body.len();
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&(total as i32).to_le_bytes());
    message.extend_from_slice(&request_id.to_le_bytes());
    message.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    message.extend_from_slice(&OP_MSG.to_le_bytes());
    message.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    message.push(0); // section kind: a body document
    message.extend_from_slice(body);
    message
}

/// The first body document of an `OP_MSG` reply.
pub fn reply_document(message: &[u8]) -> Option<&[u8]> {
    if message.len() < 21 {
        return None;
    }
    let length = i32::from_le_bytes([message[0], message[1], message[2], message[3]]);
    if length as usize != message.len() {
        return None;
    }
    let opcode = i32::from_le_bytes([message[12], message[13], message[14], message[15]]);
    if opcode != OP_MSG {
        return None;
    }

    // Skip the flags word, then walk the sections for one of kind 0.
    let mut cursor = 20;
    while cursor < message.len() {
        match message[cursor] {
            0 => {
                let body = &message[cursor + 1..];
                let size = i32::from_le_bytes(body.get(..4)?.try_into().ok()?);
                if size < 5 || size as usize > body.len() {
                    return None;
                }
                return Some(&body[..size as usize]);
            }
            // A kind-1 section carries a sequence size and an identifier.
            1 => {
                let size =
                    i32::from_le_bytes(message.get(cursor + 1..cursor + 5)?.try_into().ok()?);
                if size < 5 {
                    return None;
                }
                cursor += 1 + size as usize;
            }
            _ => return None,
        }
    }
    None
}

/// A BSON value, as much of it as this probe needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int32(i32),
    Text(String),
}

impl Value {
    fn text(value: &str) -> Value {
        Value::Text(value.to_string())
    }
}

/// Build a BSON document from the fields given.
pub fn document(fields: &[(&str, Value)]) -> Vec<u8> {
    let mut elements = Vec::new();
    for (name, value) in fields {
        match value {
            Value::Int32(number) => {
                elements.push(0x10);
                elements.extend_from_slice(name.as_bytes());
                elements.push(0);
                elements.extend_from_slice(&number.to_le_bytes());
            }
            Value::Text(text) => {
                elements.push(0x02);
                elements.extend_from_slice(name.as_bytes());
                elements.push(0);
                elements.extend_from_slice(&((text.len() + 1) as i32).to_le_bytes());
                elements.extend_from_slice(text.as_bytes());
                elements.push(0);
            }
        }
    }

    let total = 4 + elements.len() + 1;
    let mut document = Vec::with_capacity(total);
    document.extend_from_slice(&(total as i32).to_le_bytes());
    document.extend_from_slice(&elements);
    document.push(0);
    document
}

/// Whether a top-level field is present.
pub fn has_field(body: &[u8], wanted: &str) -> bool {
    field(body, wanted).is_some()
}

/// A top-level numeric field, as a double.
pub fn number(body: &[u8], wanted: &str) -> Option<f64> {
    for (name, kind, value) in elements(body) {
        if name != wanted {
            continue;
        }
        return match kind {
            0x01 => Some(f64::from_le_bytes(value.try_into().ok()?)),
            0x10 => Some(i32::from_le_bytes(value.try_into().ok()?) as f64),
            0x12 => Some(i64::from_le_bytes(value.try_into().ok()?) as f64),
            0x08 => Some(if value[0] != 0 { 1.0 } else { 0.0 }),
            _ => None,
        };
    }
    None
}

/// A top-level string field.
pub fn text(body: &[u8], wanted: &str) -> Option<String> {
    for (name, kind, value) in elements(body) {
        if name == wanted && kind == 0x02 {
            return string_value(value);
        }
    }
    None
}

/// One top-level field: its name, BSON type byte and raw value bytes.
fn field<'a>(body: &'a [u8], wanted: &str) -> Option<(u8, &'a [u8])> {
    elements(body)
        .find(|(name, _, _)| *name == wanted)
        .map(|(_, kind, value)| (kind, value))
}

/// Walk the top-level fields of a document.
fn elements(body: &[u8]) -> impl Iterator<Item = (&str, u8, &[u8])> {
    let mut cursor = 4;
    std::iter::from_fn(move || {
        let kind = *body.get(cursor)?;
        if kind == 0 {
            return None;
        }
        cursor += 1;

        let name_end = cursor + body.get(cursor..)?.iter().position(|byte| *byte == 0)?;
        let name = std::str::from_utf8(&body[cursor..name_end]).ok()?;
        cursor = name_end + 1;

        let (value, next) = value_at(body, cursor, kind)?;
        cursor = next;
        Some((name, kind, value))
    })
}

/// The value bytes at `cursor`, and where the next element starts.
fn value_at(body: &[u8], cursor: usize, kind: u8) -> Option<(&[u8], usize)> {
    let rest = body.get(cursor..)?;
    let (size, value) = match kind {
        0x01 => (8, 8), // double
        0x02 | 0x0D | 0x0E => {
            // string, JavaScript, symbol: length prefix, then the bytes
            let length = i32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
            if length < 1 {
                return None;
            }
            (0, 4 + length as usize)
        }
        0x03 | 0x04 => {
            // embedded document or array: its own length covers everything
            let length = i32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
            if length < 5 {
                return None;
            }
            (0, length as usize)
        }
        0x05 => {
            // binary: length, subtype, bytes
            let length = i32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
            if length < 0 {
                return None;
            }
            (0, 5 + length as usize)
        }
        0x06 | 0x0A | 0x7F | 0xFF => (0, 0),
        0x07 => (12, 12), // ObjectId
        0x08 => (1, 1),   // boolean
        0x09 => (8, 8),   // UTC datetime
        0x0B => {
            // regular expression: two cstrings
            let first = rest.iter().position(|byte| *byte == 0)?;
            let second = rest[first + 1..].iter().position(|byte| *byte == 0)?;
            (0, first + 1 + second + 1)
        }
        0x0C => {
            // DBPointer: string, then ObjectId
            let length = i32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
            if length < 1 {
                return None;
            }
            (0, 4 + length as usize + 12)
        }
        0x0F => {
            // code with scope: its own total length
            let length = i32::from_le_bytes(rest.get(..4)?.try_into().ok()?);
            if length < 4 {
                return None;
            }
            (0, length as usize)
        }
        0x10 => (4, 4),   // int32
        0x11 => (8, 8),   // timestamp
        0x12 => (8, 8),   // int64
        0x13 => (16, 16), // decimal128
        _ => return None,
    };

    let value = body.get(cursor..cursor + value)?;
    Some((value, cursor + size.max(value.len())))
}

/// A string value's contents, without its length prefix or terminator.
fn string_value(value: &[u8]) -> Option<String> {
    let length = i32::from_le_bytes(value.get(..4)?.try_into().ok()?) as usize;
    let bytes = value.get(4..4 + length.checked_sub(1)?)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(body: &[u8]) -> Vec<u8> {
        op_msg(42, body)
    }

    fn result_document(ok: i32, extra: &[(&str, Value)]) -> Vec<u8> {
        let mut fields: Vec<(&str, Value)> = vec![("ok", Value::Int32(ok))];
        for (name, value) in extra {
            fields.push((name, value.clone()));
        }
        document(&fields)
    }

    #[test]
    fn a_command_is_wrapped_in_an_op_msg() {
        let body = document(&[("hello", Value::Int32(1)), ("$db", Value::text("admin"))]);
        let message = op_msg(7, &body);

        let length = i32::from_le_bytes(message[..4].try_into().unwrap());
        assert_eq!(length as usize, message.len());
        assert_eq!(&message[4..8], &7i32.to_le_bytes());
        assert_eq!(&message[12..16], &OP_MSG.to_le_bytes());
        assert_eq!(message[20], 0);
        assert_eq!(&message[21..], body.as_slice());
    }

    #[test]
    fn a_document_is_length_prefixed_and_terminated() {
        let body = document(&[("ok", Value::Int32(1))]);
        let length = i32::from_le_bytes(body[..4].try_into().unwrap());
        assert_eq!(length as usize, body.len());
        assert_eq!(*body.last().unwrap(), 0);
        assert_eq!(body[4], 0x10);
        assert_eq!(&body[5..7], b"ok");
    }

    #[test]
    fn an_answered_list_databases_is_open() {
        let body = result_document(1, &[]);
        assert_eq!(classify(&body).expect("classify"), Access::Open);
    }

    #[test]
    fn a_refused_list_databases_is_protected() {
        let body = result_document(
            0,
            &[(
                "errmsg",
                Value::text("command listDatabases requires authentication"),
            )],
        );
        assert_eq!(classify(&body).expect("classify"), Access::Protected);
    }

    #[test]
    fn another_refusal_is_not_a_verdict() {
        let body = result_document(0, &[("errmsg", Value::text("not master"))]);
        assert!(classify(&body).is_err());
    }

    #[test]
    fn the_body_document_is_found_inside_an_op_msg() {
        let body = result_document(1, &[("totalSize", Value::Int32(1024))]);
        let message = reply(&body);
        assert_eq!(reply_document(&message), Some(body.as_slice()));

        // Something that is not OP_MSG is not this protocol.
        let mut wrong = message.clone();
        wrong[12..16].copy_from_slice(&2012i32.to_le_bytes());
        assert!(reply_document(&wrong).is_none());
    }

    #[tokio::test]
    async fn a_server_without_auth_answers_the_listing() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");

        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            // Handshake, then the listing.
            for body in [
                result_document(1, &[]),
                result_document(1, &[("databases", Value::Int32(0))]),
            ] {
                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let length = i32::from_le_bytes(header);
                let mut rest = vec![0u8; length as usize - 4];
                if stream.read_exact(&mut rest).await.is_err() {
                    return;
                }
                if stream.write_all(&reply(&body)).await.is_err() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        assert_eq!(
            inspect(address.ip(), address.port())
                .await
                .expect("inspect"),
            Access::Open
        );
    }
}
