//! TLS inspection: what a service on a port actually negotiates, and what
//! certificate it presents.
//!
//! Connecting is done with rustls, configured to accept any certificate — this
//! is an inspection, not a trust decision, and a scanner that refused to look
//! at a self-signed certificate would learn nothing about the networks where
//! they are most common.
//!
//! Certificate fields are read with a small DER reader rather than an X.509
//! crate. Only four things are needed (subject, issuer, and the two validity
//! times), and the well-known crates for this pull in a parser stack the rest
//! of the tool has no use for.

use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long to allow for connecting, sending, and reading the reply.
const TLS_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap on how much of the server's reply to buffer.
const MAX_REPLY: usize = 16 * 1024;

/// What a TLS handshake revealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInspection {
    /// Protocol version the server chose, e.g. "TLSv1.2".
    pub protocol_version: String,
    /// Cipher suite the server chose.
    pub cipher_suite: String,
    /// Whether the server answered a TLS 1.0 hello, meaning it still accepts
    /// a protocol deprecated since 2021.
    pub supports_legacy_tls: bool,
    /// The leaf certificate, when one was presented.
    pub certificate: Option<CertificateInfo>,
}

impl TlsInspection {
    /// Whether the negotiated cipher suite offers forward secrecy.
    ///
    /// Static RSA suites do not: anyone who later obtains the server's private
    /// key can decrypt traffic that was recorded today.
    pub fn has_forward_secrecy(&self) -> bool {
        self.cipher_suite.starts_with("TLS_ECDHE")
            || self.cipher_suite.starts_with("TLS_DHE")
            || self.cipher_suite.starts_with("TLS13_")
    }

    /// A one-line summary for the scan output.
    pub fn summary(&self) -> String {
        match &self.certificate {
            Some(certificate) => format!(
                "{}, {}, {}",
                self.protocol_version,
                self.cipher_suite,
                certificate.summary()
            ),
            None => format!("{}, {}", self.protocol_version, self.cipher_suite),
        }
    }
}

/// Inspect a TLS service.
///
/// Reads the `ServerHello` and `Certificate` messages directly rather than
/// completing a handshake. That is deliberate: a real handshake requires
/// agreeing on a cipher suite, and the servers most worth inspecting —
/// consumer routers, printers, cameras — often offer only static-RSA suites
/// that modern TLS libraries refuse to negotiate. Reading two messages needs
/// no key exchange, so the certificate arrives regardless of what the server
/// would have negotiated.
///
/// The cost is that nothing is authenticated: this reports what the service
/// claims, which is the point.
pub async fn inspect(ip: IpAddr, port: u16) -> Result<TlsInspection> {
    // Prefer TLS 1.2: it keeps the Certificate message in the clear, which
    // TLS 1.3 does not. A server that only speaks something older answers
    // with an alert, so fall back rather than give up on it — a device stuck
    // on TLS 1.0 is one of the more interesting things to find.
    let (reply, negotiated_with) = match exchange(ip, port, LegacyVersion::Tls12).await {
        Ok(reply) if parse_server_hello(&collect_handshake_bytes(&reply)).is_some() => {
            (reply, LegacyVersion::Tls12)
        }
        _ => (
            exchange(ip, port, LegacyVersion::Tls10).await?,
            LegacyVersion::Tls10,
        ),
    };

    let handshake = collect_handshake_bytes(&reply);
    let (protocol_version, cipher_suite) = parse_server_hello(&handshake)
        .ok_or_else(|| anyhow!("server did not send a readable ServerHello"))?;

    let certificate =
        parse_certificate_message(&handshake).and_then(|der| parse_certificate(&der).ok());

    // If the 1.2 hello was refused but a 1.0 hello worked, the server is
    // legacy-only. Otherwise ask separately whether it still accepts 1.0.
    let supports_legacy_tls = negotiated_with == LegacyVersion::Tls10
        || match exchange(ip, port, LegacyVersion::Tls10).await {
            Ok(reply) => parse_server_hello(&collect_handshake_bytes(&reply)).is_some(),
            Err(_) => false,
        };

    Ok(TlsInspection {
        protocol_version,
        cipher_suite,
        supports_legacy_tls,
        certificate,
    })
}

/// Which protocol version to put in the ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyVersion {
    Tls10,
    Tls12,
}

impl LegacyVersion {
    fn as_u16(self) -> u16 {
        match self {
            LegacyVersion::Tls10 => 0x0301,
            LegacyVersion::Tls12 => 0x0303,
        }
    }
}

/// Send a ClientHello and read whatever comes back.
async fn exchange(ip: IpAddr, port: u16, version: LegacyVersion) -> Result<Vec<u8>> {
    let hello = build_client_hello(version, &ip.to_string());

    let mut stream = tokio::time::timeout(TLS_TIMEOUT, TcpStream::connect((ip, port)))
        .await
        .context("connecting for the TLS handshake")??;

    stream
        .write_all(&hello)
        .await
        .context("sending the ClientHello")?;

    let mut reply = Vec::new();
    let mut buffer = [0u8; 4096];

    // The certificate usually lands in the first few kilobytes, but it can be
    // split across records, so keep reading until it parses or the budget ends.
    loop {
        let read = match tokio::time::timeout(TLS_TIMEOUT, stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => read,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => break,
        };

        reply.extend_from_slice(&buffer[..read]);

        let handshake = collect_handshake_bytes(&reply);
        if parse_certificate_message(&handshake).is_some() || reply.len() >= MAX_REPLY {
            break;
        }
    }

    if reply.is_empty() {
        return Err(anyhow!("no reply to the ClientHello"));
    }

    Ok(reply)
}

/// Build a minimal ClientHello.
///
/// Offers both ECDHE and static-RSA suites so that older servers, which only
/// understand the latter, still answer.
fn build_client_hello(version: LegacyVersion, host: &str) -> Vec<u8> {
    // ECDHE suites first, then static RSA, then plain AES for old stacks.
    const CIPHER_SUITES: &[u16] = &[
        0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
        0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
    ];

    let mut body = Vec::new();
    body.extend_from_slice(&version.as_u16().to_be_bytes());
    body.extend_from_slice(&random_bytes());
    body.push(0); // no session id

    body.extend_from_slice(&((CIPHER_SUITES.len() * 2) as u16).to_be_bytes());
    for suite in CIPHER_SUITES {
        body.extend_from_slice(&suite.to_be_bytes());
    }

    body.extend_from_slice(&[0x01, 0x00]); // compression: null only

    let mut extensions = Vec::new();

    // server_name, so name-based servers answer rather than closing.
    if !host.is_empty() {
        // ServerNameList is length-prefixed, then each entry is a name type, a
        // length, and the name. Leaving out the list length makes strict
        // implementations — OpenSSL among them — reject the whole hello.
        let mut entry = vec![0x00]; // name_type = host_name
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host.as_bytes());

        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&entry);

        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&list);
    }

    extensions.extend_from_slice(&0x000Bu16.to_be_bytes()); // ec_point_formats
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&[0x03, 0x01, 0x00, 0x02]);

    extensions.extend_from_slice(&0x000Au16.to_be_bytes()); // supported_groups
    extensions.extend_from_slice(&6u16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&0x001Du16.to_be_bytes()); // x25519
    extensions.extend_from_slice(&0x0017u16.to_be_bytes()); // secp256r1

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01]; // ClientHello
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16]; // handshake
    record.extend_from_slice(&version.as_u16().to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// 32 random bytes for the ClientHello.
///
/// These do not need to be cryptographic — nothing is keyed on them, and the
/// handshake is never completed — but a fixed value makes some servers
/// suspicious, so mix in the clock and the process id.
fn random_bytes() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut bytes = [0u8; 32];
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
        ^ (std::process::id() as u128) << 64;

    let mut state = seed;
    for chunk in bytes.chunks_mut(8) {
        // xorshift128+ style mixing; not security, just spread.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let value = (state as u64).to_be_bytes();
        chunk.copy_from_slice(&value[..chunk.len()]);
    }

    bytes
}

/// Concatenate the payloads of every handshake record in a reply.
///
/// Handshake messages are not aligned to record boundaries, so they are
/// reassembled before being parsed.
fn collect_handshake_bytes(records: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::new();
    let mut offset = 0;

    while offset + 5 <= records.len() {
        let content_type = records[offset];
        let length = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
        let start = offset + 5;
        let end = start.saturating_add(length).min(records.len());

        if content_type == 0x16 {
            handshake.extend_from_slice(&records[start..end]);
        }

        // An alert (0x15) means the server refused; nothing more is coming.
        if content_type == 0x15 {
            break;
        }

        offset = end;
    }

    handshake
}

/// Read the version and cipher suite out of a ServerHello.
fn parse_server_hello(handshake: &[u8]) -> Option<(String, String)> {
    let mut offset = 0;

    while offset + 4 <= handshake.len() {
        let message_type = handshake[offset];
        let length = ((handshake[offset + 1] as usize) << 16)
            | ((handshake[offset + 2] as usize) << 8)
            | (handshake[offset + 3] as usize);
        let body = handshake.get(offset + 4..offset + 4 + length)?;

        if message_type == 0x02 {
            // version(2) random(32) session_id_len(1) session_id cipher(2)
            let version = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
            let session_id_len = *body.get(34)? as usize;
            let cipher_offset = 35 + session_id_len;
            let cipher = u16::from_be_bytes([
                *body.get(cipher_offset)?,
                *body.get(cipher_offset + 1)?,
            ]);

            return Some((protocol_version_name(version), cipher_suite_name(cipher)));
        }

        offset += 4 + length;
    }

    None
}

/// Extract the leaf certificate from a Certificate message.
fn parse_certificate_message(handshake: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;

    while offset + 4 <= handshake.len() {
        let message_type = handshake[offset];
        let length = ((handshake[offset + 1] as usize) << 16)
            | ((handshake[offset + 2] as usize) << 8)
            | (handshake[offset + 3] as usize);
        let body = handshake.get(offset + 4..offset + 4 + length)?;

        if message_type == 0x0B {
            // certificate_list_length(3), then certificate_length(3) + der
            let first_length = ((*body.get(3)? as usize) << 16)
                | ((*body.get(4)? as usize) << 8)
                | (*body.get(5)? as usize);
            return Some(body.get(6..6 + first_length)?.to_vec());
        }

        // Nothing before the certificate matters, and skipping past it would
        // mean guessing at encrypted content.
        if message_type == 0x02 {
            offset += 4 + length;
            continue;
        }

        offset += 4 + length;
    }

    None
}

/// Human-readable protocol version.
fn protocol_version_name(version: u16) -> String {
    match version {
        0x0301 => "TLSv1.0".to_string(),
        0x0302 => "TLSv1.1".to_string(),
        0x0303 => "TLSv1.2".to_string(),
        0x0304 => "TLSv1.3".to_string(),
        0x0300 => "SSLv3".to_string(),
        other => format!("0x{other:04X}"),
    }
}

/// Human-readable cipher suite, for the suites likely to be seen.
fn cipher_suite_name(suite: u16) -> String {
    match suite {
        0x1301 => "TLS13_AES_128_GCM_SHA256",
        0x1302 => "TLS13_AES_256_GCM_SHA384",
        0x1303 => "TLS13_CHACHA20_POLY1305_SHA256",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        other => return format!("0x{other:04X}"),
    }
    .to_string()
}

/// The parts of a certificate worth reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// Common Name of the subject, or a fallback rendering.
    pub subject: String,
    /// Common Name of the issuer.
    pub issuer: String,
    /// Validity start, as an ISO-8601 date.
    pub not_before: String,
    /// Validity end, as an ISO-8601 date.
    pub not_after: String,
    /// Whether the certificate is signed by itself.
    pub self_signed: bool,
    /// Days until expiry; negative when already expired.
    pub days_until_expiry: i64,
}

impl CertificateInfo {
    /// Whether the certificate is past its expiry date.
    pub fn is_expired(&self) -> bool {
        self.days_until_expiry < 0
    }

    /// Whether expiry is close enough to be worth flagging.
    pub fn expires_soon(&self) -> bool {
        (0..=30).contains(&self.days_until_expiry)
    }

    /// A short description for a table or a finding.
    pub fn summary(&self) -> String {
        let trust = if self.self_signed {
            "self-signed"
        } else {
            "CA-signed"
        };
        let expiry = if self.is_expired() {
            format!("expired {} day(s) ago", -self.days_until_expiry)
        } else {
            format!("expires in {} day(s)", self.days_until_expiry)
        };

        format!("{} ({}, {})", self.subject, trust, expiry)
    }
}

/// Read the fields we report out of a DER-encoded certificate.
///
/// Walks just far enough into the structure:
/// `Certificate -> TBSCertificate -> { issuer, validity, subject }`.
pub fn parse_certificate(der: &[u8]) -> Result<CertificateInfo> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (certificate, _) = read_tlv(der).ok_or_else(|| anyhow!("not a DER certificate"))?;
    if certificate.tag != TAG_SEQUENCE {
        return Err(anyhow!("certificate is not a SEQUENCE"));
    }

    let (tbs, _) = read_tlv(certificate.value).ok_or_else(|| anyhow!("missing tbsCertificate"))?;
    if tbs.tag != TAG_SEQUENCE {
        return Err(anyhow!("tbsCertificate is not a SEQUENCE"));
    }

    let mut rest = tbs.value;

    // [0] EXPLICIT version — optional, absent in v1 certificates.
    if let Some((field, tail)) = read_tlv(rest) {
        if field.tag == TAG_CONTEXT_0 {
            rest = tail;
        }
    }

    // serialNumber, then the signature algorithm.
    let (_, rest) = skip(rest)?;
    let (_, rest) = skip(rest)?;

    // issuer
    let (issuer_raw, rest) = take(rest, TAG_SEQUENCE, "issuer")?;
    // validity
    let (validity, rest) = take(rest, TAG_SEQUENCE, "validity")?;
    // subject
    let (subject_raw, _) = take(rest, TAG_SEQUENCE, "subject")?;

    let not_before = read_time(validity.value)?;
    let (_, after_validity) = read_tlv(validity.value).ok_or_else(|| anyhow!("missing notBefore"))?;
    let not_after = read_time(after_validity)?;

    let days_until_expiry =
        (not_after - chrono::Utc::now()).num_days();

    Ok(CertificateInfo {
        subject: display_name(subject_raw.value),
        issuer: display_name(issuer_raw.value),
        not_before: not_before.format("%Y-%m-%d").to_string(),
        not_after: not_after.format("%Y-%m-%d").to_string(),
        // A self-signed certificate names itself as its own issuer. Comparing
        // the raw encodings avoids having to render the whole distinguished
        // name in a canonical order.
        self_signed: subject_raw.value == issuer_raw.value,
        days_until_expiry,
    })
}

/// Parse the two `Time` values inside a `Validity` structure.
fn read_time(input: &[u8]) -> Result<chrono::DateTime<chrono::Utc>> {
    let (time, _) = read_tlv(input).ok_or_else(|| anyhow!("missing validity time"))?;
    let text = std::str::from_utf8(time.value).context("validity time is not text")?;
    let text = text.trim_end_matches('Z');

    // UTCTime is two-digit years, GeneralizedTime is four.
    let (format, text) = match time.tag {
        TAG_UTC_TIME => {
            if text.len() < 12 {
                return Err(anyhow!("UTCTime is too short: {text}"));
            }
            ("%y%m%d%H%M%S", text)
        }
        TAG_GENERALIZED_TIME => {
            if text.len() < 14 {
                return Err(anyhow!("GeneralizedTime is too short: {text}"));
            }
            ("%Y%m%d%H%M%S", text)
        }
        other => return Err(anyhow!("unexpected time tag 0x{other:02X}")),
    };

    let naive = chrono::NaiveDateTime::parse_from_str(text, format)
        .with_context(|| format!("parsing validity time '{text}'"))?;

    Ok(chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc))
}

/// A human-readable name for a distinguished name.
///
/// Prefers the commonName; plenty of certificates — including the default
/// ones shipped on consumer routers — carry only an organization, and an
/// empty column would be less useful than "Internet Widgits Pty Ltd".
fn display_name(rdn_sequence: &[u8]) -> String {
    attribute(rdn_sequence, OID_COMMON_NAME)
        .or_else(|| attribute(rdn_sequence, OID_ORGANIZATION))
        .or_else(|| attribute(rdn_sequence, OID_ORGANIZATIONAL_UNIT))
        .unwrap_or_else(|| "<unnamed>".to_string())
}

/// Find the commonName (OID 2.5.4.3) inside a DER-encoded Name.
///
/// Takes the *contents* of the name's SEQUENCE, which is a sequence of
/// RelativeDistinguishedNames, each a SET of AttributeTypeAndValue pairs.
fn attribute(rdn_sequence: &[u8], wanted: &[u8]) -> Option<String> {
    let mut rest = rdn_sequence;

    while let Some((rdn, tail)) = read_tlv(rest) {
        rest = tail;
        if rdn.tag != TAG_SET {
            continue;
        }

        let mut attributes = rdn.value;
        while let Some((attribute, next)) = read_tlv(attributes) {
            attributes = next;
            if attribute.tag != TAG_SEQUENCE {
                continue;
            }

            // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
            let Some((oid, value_rest)) = read_tlv(attribute.value) else {
                continue;
            };
            let Some((value, _)) = read_tlv(value_rest) else {
                continue;
            };

            if oid.value == wanted {
                return Some(String::from_utf8_lossy(value.value).to_string());
            }
        }
    }

    None
}

// DER tags used above.
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xA0;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
/// 2.5.4.3, encoded.
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// 2.5.4.10.
const OID_ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0A];
/// 2.5.4.11.
const OID_ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0B];

/// One tag-length-value element.
#[derive(Debug)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Read one TLV, returning it and whatever follows.
fn read_tlv(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first_length, rest) = rest.split_first()?;

    let (length, rest) = if first_length & 0x80 == 0 {
        (first_length as usize, rest)
    } else {
        // Long form: the low bits give the number of length bytes.
        let count = (first_length & 0x7F) as usize;
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let mut length = 0usize;
        for byte in &rest[..count] {
            length = (length << 8) | *byte as usize;
        }
        (length, &rest[count..])
    };

    if rest.len() < length {
        return None;
    }

    Some((
        Tlv {
            tag,
            value: &rest[..length],
        },
        &rest[length..],
    ))
}

/// Read one TLV, requiring a specific tag.
fn take<'a>(input: &'a [u8], tag: u8, what: &str) -> Result<(Tlv<'a>, &'a [u8])> {
    let (field, rest) = read_tlv(input).ok_or_else(|| anyhow!("truncated while reading {what}"))?;
    if field.tag != tag {
        return Err(anyhow!(
            "expected {what} to have tag 0x{tag:02X}, found 0x{:02X}",
            field.tag
        ));
    }
    Ok((field, rest))
}

/// Skip one TLV without interpreting it.
fn skip(input: &[u8]) -> Result<(&[u8], &[u8])> {
    let (_, rest) = read_tlv(input).ok_or_else(|| anyhow!("truncated field"))?;
    Ok((input, rest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    include!("cert_fixtures.rs");

    fn decode(base64_text: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(base64_text)
            .expect("fixture is valid base64")
    }

    /// Generated with `openssl req -x509`, CN=netgap-test.local, valid to 2036.
    fn self_signed() -> CertificateInfo {
        parse_certificate(&decode(SELF_SIGNED_CERT_DER_BASE64)).expect("parses")
    }

    /// Generated with `openssl x509 -req` against a local CA, CN=device.lan.
    fn ca_signed() -> CertificateInfo {
        parse_certificate(&decode(CA_SIGNED_CERT_DER_BASE64)).expect("parses")
    }

    #[test]
    fn test_client_hello_is_well_formed() {
        let hello = build_client_hello(LegacyVersion::Tls12, "example.test");

        // Record header: handshake, version, length matching the payload.
        assert_eq!(hello[0], 0x16);
        assert_eq!(u16::from_be_bytes([hello[1], hello[2]]), 0x0303);
        assert_eq!(
            u16::from_be_bytes([hello[3], hello[4]]) as usize,
            hello.len() - 5
        );

        // Handshake header: ClientHello, length matching the body.
        assert_eq!(hello[5], 0x01);
        let body_length = ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(body_length, hello.len() - 9);

        // The server_name extension must be present and correctly framed:
        // extension length, then a list length, then the name type.
        let name = b"example.test";
        // extension_data = list length (2) + name type (1) + name length (2) + name
        let extension = [
            0x00, 0x00, // extension type: server_name
            0x00, (name.len() + 5) as u8, // extension data length
            0x00, (name.len() + 3) as u8, // server_name_list length
            0x00, // name_type: host_name
            0x00, name.len() as u8, // name length
        ];
        let position = hello
            .windows(extension.len())
            .position(|window| window == extension)
            .expect("server_name extension is framed correctly");

        // And the name itself follows.
        assert_eq!(&hello[position + extension.len()..position + extension.len() + name.len()], name);
    }

    #[test]
    fn test_reads_subject_and_issuer_of_a_self_signed_certificate() {
        let certificate = self_signed();

        assert_eq!(certificate.subject, "netgap-test.local");
        assert_eq!(certificate.issuer, "netgap-test.local");
        assert!(certificate.self_signed);
    }

    #[test]
    fn test_reads_subject_and_issuer_of_a_ca_signed_certificate() {
        let certificate = ca_signed();

        assert_eq!(certificate.subject, "device.lan");
        assert_eq!(certificate.issuer, "Netgap Test CA");
        assert!(!certificate.self_signed);
    }

    #[test]
    fn test_reads_validity_dates() {
        let certificate = self_signed();

        assert_eq!(certificate.not_before, "2026-10-01");
        assert_eq!(certificate.not_after, "2036-09-28");
        // Ordered correctly, and far from expiring when the fixture was made.
        assert!(certificate.not_before < certificate.not_after);
        assert!(certificate.days_until_expiry > 3000);
        assert!(!certificate.is_expired());
        assert!(!certificate.expires_soon());
    }

    #[test]
    fn test_short_lived_certificate_is_flagged_as_expiring_soon() {
        // The CA-signed leaf is valid for 365 days, so it is not "soon" today;
        // fake an expiry window to exercise the branch.
        let mut certificate = ca_signed();
        certificate.days_until_expiry = 10;

        assert!(certificate.expires_soon());
        assert!(!certificate.is_expired());

        certificate.days_until_expiry = -1;
        assert!(certificate.is_expired());
        assert!(!certificate.expires_soon());
        assert!(certificate.summary().contains("expired"));
    }

    #[test]
    fn test_certificate_without_a_common_name_falls_back_to_the_organization() {
        // Some certificates carry only an organization; an empty subject would
        // be less useful than what they do say.
        // SET { SEQUENCE { OID 2.5.4.10, UTF8String "Test" } }
        let name = [
            0x31, 0x0D, // SET
            0x30, 0x0B, // AttributeTypeAndValue
            0x06, 0x03, 0x55, 0x04, 0x0A, // organizationName
            0x0C, 0x04, b'T', b'e', b's', b't',
        ];
        assert_eq!(display_name(&name), "Test");

        // A common name wins over the organization when both are present.
        let with_cn = [
            0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x04, b'T', b'e', b's', b't',
            0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x06, b'r', b'o', b'u', b't', b'e', b'r',
        ];
        assert_eq!(display_name(&with_cn), "router");

        // Nothing recognisable at all.
        assert_eq!(display_name(&[]), "<unnamed>");
    }

    #[test]
    fn test_summary_mentions_trust_and_expiry() {
        let summary = self_signed().summary();
        assert!(summary.contains("netgap-test.local"));
        assert!(summary.contains("self-signed"));
        assert!(summary.contains("expires in"));
    }

    #[test]
    fn test_rejects_input_that_is_not_a_certificate() {
        assert!(parse_certificate(b"not der at all").is_err());
        assert!(parse_certificate(&[]).is_err());
        // A valid TLV that is not a certificate body.
        assert!(parse_certificate(&[0x02, 0x01, 0x05]).is_err());
        // Truncated certificate.
        let der = decode(SELF_SIGNED_CERT_DER_BASE64);
        assert!(parse_certificate(&der[..der.len() / 2]).is_err());
    }

    #[test]
    fn test_tlv_reader_handles_both_length_forms() {
        // Short form.
        let (tlv, rest) = read_tlv(&[0x02, 0x01, 0x2A, 0xFF]).expect("short form");
        assert_eq!(tlv.tag, 0x02);
        assert_eq!(tlv.value, &[0x2A]);
        assert_eq!(rest, &[0xFF]);

        // Long form: 0x81 means one length byte.
        let mut input = vec![0x30, 0x81, 0x03];
        input.extend_from_slice(&[1, 2, 3]);
        let (tlv, rest) = read_tlv(&input).expect("long form");
        assert_eq!(tlv.value, &[1, 2, 3]);
        assert!(rest.is_empty());

        // A length longer than the data must not panic.
        assert!(read_tlv(&[0x30, 0x05, 0x01]).is_none());
    }

    #[test]
    fn test_utc_and_generalized_time_both_parse() {
        // UTCTime, the form most certificates use.
        let utc = [0x17, 0x0D, b'2', b'6', b'1', b'0', b'0', b'1', b'0', b'6', b'4', b'8', b'3', b'3', b'Z'];
        assert_eq!(read_time(&utc).expect("utc").format("%Y-%m-%d").to_string(), "2026-10-01");

        // GeneralizedTime, used past 2049.
        let generalized = [
            0x18, 0x0F, b'2', b'0', b'5', b'0', b'0', b'1', b'0', b'1', b'0', b'6', b'4', b'8',
            b'3', b'3', b'Z',
        ];
        assert_eq!(
            read_time(&generalized).expect("generalized").format("%Y-%m-%d").to_string(),
            "2050-01-01"
        );

        // A nonsense tag is an error, not a panic.
        assert!(read_time(&[0x02, 0x01, 0x00]).is_err());
    }

    /// Live inspection of a real TLS service. Ignored by default: it needs a
    /// reachable host presenting a certificate.
    #[tokio::test]
    #[ignore = "requires a reachable TLS service"]
    async fn test_live_inspection() {
        let target = std::env::var("NETGAP_TLS_TARGET").unwrap_or_else(|_| "192.168.111.1:443".to_string());
        let mut parts = target.split(':');
        let ip: IpAddr = parts.next().expect("host").parse().expect("valid ip");
        let port: u16 = parts.next().unwrap_or("443").parse().expect("valid port");

        let inspection = inspect(ip, port).await.expect("handshake");
        println!("{}", inspection.summary());
        assert!(!inspection.protocol_version.is_empty());
    }
}
