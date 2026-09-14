//! Whether a device answers SNMP with the `public` community.
//!
//! SNMP v1 and v2c were built for a network where everyone was trusted: the
//! community string is a shared word sent in the clear, and `public` is the
//! factory default on a great many devices. A device that answers it will hand
//! out its description, its interface list and often its routing and ARP
//! tables to anyone who asks — the map an attacker needs first.
//!
//! The question is a single `GET` of the system description
//! (`1.3.6.1.2.1.1.1.0`), which every SNMP agent carries. Any well-formed
//! answer means the community was accepted; silence means it was not, or the
//! device filters UDP, and this cannot tell those apart.
//!
//! Nothing here writes, and no other community string is tried.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(1);

/// `sysDescr.0`, the one value every SMNP agent has.
const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

/// The community string a device keeps from its factory settings.
const COMMUNITY: &str = "public";

/// What the device did with the `public` community.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// The device answered, so it accepted the community.
    Open {
        /// What the device calls itself, when it said.
        description: Option<String>,
    },
    /// Nothing came back.
    Silent,
}

/// Ask the device what it calls itself, as the `public` community.
pub async fn inspect(ip: IpAddr, port: u16) -> Result<Access> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|error| anyhow!("could not open a UDP socket: {error}"))?;
    socket
        .connect(SocketAddr::new(ip, port))
        .await
        .map_err(|error| anyhow!("could not address {ip}:{port}: {error}"))?;

    // v2c is the modern default; a device that only speaks v1 is asked again.
    // One datagram each, because silence is the common answer and the wait is
    // paid on every device in the scan.
    for version in [1u8, 0u8] {
        let request = request(version, COMMUNITY, SYS_DESCR);
        let _ = socket.send(&request).await;

        let mut reply = [0u8; 1500];
        match timeout(TIMEOUT, socket.recv(&mut reply)).await {
            Ok(Ok(read)) => {
                if let Some((community, description)) = parse_response(&reply[..read]) {
                    // A reply for a different community is not our answer.
                    if community == COMMUNITY {
                        return Ok(Access::Open { description });
                    }
                }
            }
            Ok(Err(error)) => bail!("{ip}:{port} failed to answer: {error}"),
            // No answer: try the older version, then give up.
            Err(_) => {}
        }
    }

    Ok(Access::Silent)
}

/// Build a v1 (`version` 0) or v2c (`version` 1) `GET` for one OID.
pub fn request(version: u8, community: &str, oid: &[u32]) -> Vec<u8> {
    let request_id = integer(0x4e_4741); // "NGA"
    let error_status = integer(0);
    let error_index = integer(0);
    let mut varbind_contents = object_identifier(oid);
    varbind_contents.extend_from_slice(&tlv(0x05, &[]));
    let varbind = tlv(0x30, &varbind_contents);
    let varbinds = tlv(0x30, &varbind);
    let pdu = tlv(
        0xA0,
        &[&request_id[..], &error_status, &error_index, &varbinds].concat(),
    );

    tlv(
        0x30,
        &[
            &integer(version as i64)[..],
            &tlv(0x04, community.as_bytes()),
            &pdu,
        ]
        .concat(),
    )
}

/// The community and system description of an SNMP response.
pub fn parse_response(packet: &[u8]) -> Option<(String, Option<String>)> {
    let (tag, message, _) = read_tlv_at(packet, 0)?;
    if tag != 0x30 {
        return None;
    }

    let (tag, _version, next) = read_tlv_at(message, 0)?;
    if tag != 0x02 {
        return None;
    }
    let (tag, community, next) = read_tlv_at(message, next)?;
    if tag != 0x04 {
        return None;
    }
    let community = String::from_utf8_lossy(community).into_owned();

    let (tag, pdu, _) = read_tlv_at(message, next)?;
    if tag != 0xA2 {
        return None;
    }

    // request-id, error-status, error-index, then the varbind list.
    let (_, _, next) = read_tlv_at(pdu, 0)?;
    let (_, error_status, next) = read_tlv_at(pdu, next)?;
    let status = error_status.first().copied().unwrap_or(0);
    let (_, _, next) = read_tlv_at(pdu, next)?;
    let (tag, varbinds, _) = read_tlv_at(pdu, next)?;
    if tag != 0x30 {
        return None;
    }

    // A non-zero error status is still an answer: the device accepted the
    // community and then complained about the question.
    if status != 0 {
        return Some((community, None));
    }

    let (tag, varbind, _) = read_tlv_at(varbinds, 0)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _, next) = read_tlv_at(varbind, 0)?;
    let (tag, value, _) = read_tlv_at(varbind, next)?;

    let description = match tag {
        0x04 => {
            let text = String::from_utf8_lossy(value);
            Some(text.trim().to_string()).filter(|text| !text.is_empty())
        }
        _ => None,
    };

    Some((community, description))
}

/// One BER value, with the offset just past it.
fn read_tlv_at(data: &[u8], start: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *data.get(start)?;
    let mut cursor = start + 1;

    let first = *data.get(cursor)?;
    cursor += 1;
    let length = if first & 0x80 == 0 {
        first as usize
    } else {
        let bytes = (first & 0x7F) as usize;
        if bytes == 0 || bytes > 2 {
            return None;
        }
        let mut length = 0usize;
        for _ in 0..bytes {
            length = (length << 8) | *data.get(cursor)? as usize;
            cursor += 1;
        }
        length
    };

    let contents = data.get(cursor..cursor + length)?;
    Some((tag, contents, cursor + length))
}

/// A BER tag, length and contents.
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    length(contents.len(), &mut out);
    out.extend_from_slice(contents);
    out
}

fn length(value: usize, out: &mut Vec<u8>) {
    if value < 0x80 {
        out.push(value as u8);
    } else {
        let bytes = (value as u64).to_be_bytes();
        let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
}

/// A minimal two's-complement INTEGER.
fn integer(value: i64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    tlv(0x02, &bytes)
}

/// An OBJECT IDENTIFIER.
fn object_identifier(parts: &[u32]) -> Vec<u8> {
    let mut contents = Vec::new();
    if let Some(first) = parts.first() {
        let second = parts.get(1).copied().unwrap_or(0);
        contents.push((first * 40) as u8 + second as u8);
        for part in parts.iter().skip(2) {
            let mut chunk = [0u8; 5];
            let mut index = 4;
            let mut value = *part;
            chunk[index] = (value & 0x7F) as u8;
            while value > 0x7F {
                value >>= 7;
                index -= 1;
                chunk[index] = (value & 0x7F) as u8 | 0x80;
            }
            contents.extend_from_slice(&chunk[index..]);
        }
    }
    tlv(0x06, &contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_is_a_complete_snmp_message() {
        let packet = request(1, "public", SYS_DESCR);

        let (tag, message, _) = read_tlv_at(&packet, 0).expect("outer sequence");
        assert_eq!(tag, 0x30);

        let (tag, version, next) = read_tlv_at(message, 0).expect("version");
        assert_eq!(tag, 0x02);
        assert_eq!(version, &[1]);

        let (tag, community, next) = read_tlv_at(message, next).expect("community");
        assert_eq!(tag, 0x04);
        assert_eq!(community, b"public");

        // The PDU is a GetRequest carrying sysDescr.0.
        let (tag, pdu, _) = read_tlv_at(message, next).unwrap();
        assert_eq!(tag, 0xA0);

        let (_, _, next) = read_tlv_at(pdu, 0).unwrap(); // request-id
        let (_, _, next) = read_tlv_at(pdu, next).unwrap(); // error-status
        let (_, _, next) = read_tlv_at(pdu, next).unwrap(); // error-index
        let (tag, varbinds, _) = read_tlv_at(pdu, next).unwrap();
        assert_eq!(tag, 0x30);
        let (tag, varbind, _) = read_tlv_at(varbinds, 0).unwrap();
        assert_eq!(tag, 0x30);
        let (tag, oid, _) = read_tlv_at(varbind, 0).unwrap();
        assert_eq!(tag, 0x06);
        assert_eq!(oid, &[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]);
    }

    /// A response encoded by an independent ASN.1 library (pyasn1), so the
    /// parser is not only agreeing with this module's own writer.
    #[test]
    fn a_response_from_another_encoder_is_understood() {
        let packet = hex(
            "303a02010104067075626c6963a22d02014e0201000201003022302006082b0601020101010004144c696e75782066616b652d6167656e7420362e31",
        );
        let (community, description) = parse_response(&packet).expect("parse");
        assert_eq!(community, "public");
        assert_eq!(description.as_deref(), Some("Linux fake-agent 6.1"));
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn integers_and_lengths_keep_their_shape() {
        assert_eq!(integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(integer(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(integer(128), vec![0x02, 0x02, 0x00, 0x80]);

        let mut short = Vec::new();
        length(127, &mut short);
        assert_eq!(short, vec![0x7F]);

        let mut long = Vec::new();
        length(200, &mut long);
        assert_eq!(long, vec![0x81, 0xC8]);
    }

    /// A response as an agent would build it.
    fn response(community: &str, value: Option<&str>) -> Vec<u8> {
        let request_id = integer(7);
        let status = integer(0);
        let index = integer(0);
        let varbind_value = match value {
            Some(text) => tlv(0x04, text.as_bytes()),
            None => tlv(0x05, &[]),
        };
        let varbind = tlv(
            0x30,
            &[&object_identifier(SYS_DESCR)[..], &varbind_value].concat(),
        );
        let varbinds = tlv(0x30, &varbind);
        let pdu = tlv(
            0xA2,
            &[&request_id[..], &status, &index, &varbinds].concat(),
        );
        tlv(
            0x30,
            &[&integer(1)[..], &tlv(0x04, community.as_bytes()), &pdu].concat(),
        )
    }

    #[test]
    fn a_response_carries_the_device_description() {
        let packet = response("public", Some("Linux router 5.10.0"));
        let (community, description) = parse_response(&packet).expect("parse");
        assert_eq!(community, "public");
        assert_eq!(description.as_deref(), Some("Linux router 5.10.0"));
    }

    #[test]
    fn a_response_to_something_else_is_still_read() {
        let packet = response("public", None);
        let (community, description) = parse_response(&packet).expect("parse");
        assert_eq!(community, "public");
        assert_eq!(description, None);
    }

    #[test]
    fn a_packet_that_is_not_a_response_is_rejected() {
        assert!(parse_response(&[]).is_none());
        assert!(parse_response(&request(1, "public", SYS_DESCR)).is_none());
        assert!(parse_response(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_none());
    }

    #[tokio::test]
    async fn an_agent_that_answers_is_reported() {
        let agent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let address = agent.local_addr().expect("address");

        tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            let Ok((read, from)) = agent.recv_from(&mut buffer).await else {
                return;
            };
            // Only the v2c request gets an answer.
            if parse_response(&buffer[..read]).is_some() {
                return;
            }
            let reply = response("public", Some("Test agent"));
            let _ = agent.send_to(&reply, from).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        assert_eq!(
            inspect(address.ip(), address.port())
                .await
                .expect("inspect"),
            Access::Open {
                description: Some("Test agent".into())
            }
        );
    }

    #[tokio::test]
    async fn silence_is_not_a_verdict() {
        let agent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let address = agent.local_addr().expect("address");
        // The socket accepts the datagram and never answers.
        tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            let _ = agent.recv_from(&mut buffer).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        assert_eq!(
            inspect(address.ip(), address.port())
                .await
                .expect("inspect"),
            Access::Silent
        );
    }
}
