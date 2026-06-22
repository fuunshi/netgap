//! Finding every DHCP server on the network.
//!
//! A DHCP server hands out addresses *and* tells the client which gateway and
//! DNS server to use. A second one on the network can therefore point devices
//! at itself, which is how traffic gets quietly redirected — the rogue server
//! does not need to be clever, it just has to answer first.
//!
//! The check is active: send a DHCP DISCOVER and collect whoever answers. The
//! alternative — listening passively — only sees traffic when something else
//! triggers it, and on a quiet network that can be nothing for hours. Asking
//! gets an answer now.
//!
//! This needs privileges. A DHCP client binds UDP port 68, which is below 1024,
//! and sends to the broadcast address; there is no unprivileged way to do it.
//!
//! Sending a DISCOVER has a side effect worth stating: a server will hold the
//! offered address briefly, as it would for any device joining the network.
//! The probe reuses one client identity so repeated runs look like the same
//! device rather than a stream of new ones.

use crate::DiscoveryError;
use anyhow::{anyhow, Context, Result};
pub use pnet::util::MacAddr;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Parse a MAC address in the usual colon-separated form.
pub fn parse_mac(value: &str) -> Option<MacAddr> {
    value.trim().parse().ok()
}

/// The port a DHCP client listens on.
const CLIENT_PORT: u16 = 68;
/// The port DHCP servers listen on.
const SERVER_PORT: u16 = 67;

/// DHCP message types (RFC 2131).
const DHCPDISCOVER: u8 = 1;
/// Offers are what a scan collects; a REQUEST/ACK exchange is what a client
/// does after choosing one, which this never gets to.
const DHCPOFFER: u8 = 2;

/// Option codes.
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_HOSTNAME: u8 = 12;
const OPTION_END: u8 = 255;

/// The fixed part of a BOOTP message, before the options.
const BOOTP_HEADER_LEN: usize = 236;
/// The magic cookie that marks a BOOTP payload as DHCP.
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// A DHCP server that answered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DhcpServer {
    /// The address the server identifies itself with (option 54).
    pub server_id: Ipv4Addr,
    /// The address it offered us.
    pub offered: Option<Ipv4Addr>,
    /// What the server calls itself, if it said.
    pub hostname: Option<String>,
}

/// A parsed DHCP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpReply {
    pub message_type: u8,
    /// The server identifier option (54), which some servers omit.
    pub server_id: Option<Ipv4Addr>,
    /// The `siaddr` field, which older servers use instead of the option.
    pub header_server: Ipv4Addr,
    pub offered: Option<Ipv4Addr>,
    pub hostname: Option<String>,
}

impl DhcpReply {
    /// Whether this reply is a server offering an address.
    pub fn is_offer(&self) -> bool {
        self.message_type == DHCPOFFER
    }

    /// The server behind this reply.
    ///
    /// Falls back to the `siaddr` field when the server identifier option is
    /// absent, which older servers omit.
    pub fn server(&self) -> Option<DhcpServer> {
        let fallback = (!self.header_server.is_unspecified()).then_some(self.header_server);
        let server_id = self.server_id.or(fallback)?;
        Some(DhcpServer {
            server_id,
            offered: self.offered,
            hostname: self.hostname.clone(),
        })
    }
}

/// Build a DHCP DISCOVER.
///
/// The transaction id is derived from the client address rather than drawn at
/// random: servers key on it, and reusing one makes repeated scans look like
/// the same device asking again instead of a new device each time.
pub fn build_discover(client_mac: MacAddr, hostname: &str) -> Vec<u8> {
    let mut packet = vec![0u8; BOOTP_HEADER_LEN];

    packet[0] = 1; // op: BOOTREQUEST
    packet[1] = 1; // htype: Ethernet
    packet[2] = 6; // hlen
    packet[3] = 0; // hops

    packet[4..8].copy_from_slice(&transaction_id(client_mac).to_be_bytes());

    // Ask for the reply to be broadcast: we have no address yet for the server
    // to unicast to.
    packet[10..12].copy_from_slice(&0x8000u16.to_be_bytes());

    // chaddr: the client address, padded to sixteen bytes.
    let octets = client_mac.octets();
    packet[28..34].copy_from_slice(&octets);

    let mut options = vec![
        OPTION_MESSAGE_TYPE,
        1,
        DHCPDISCOVER,
        // Parameters worth having: subnet mask, router, DNS, domain name,
        // lease time, server identifier.
        55,
        5,
        1,
        3,
        6,
        15,
        54,
    ];

    if !hostname.is_empty() {
        let name = hostname.as_bytes();
        let name = &name[..name.len().min(255)];
        options.push(OPTION_HOSTNAME);
        options.push(name.len() as u8);
        options.extend_from_slice(name);
    }

    options.push(OPTION_END);

    packet.extend_from_slice(&MAGIC_COOKIE);
    packet.extend_from_slice(&options);
    packet
}

/// A transaction id that is stable for a given client.
fn transaction_id(client_mac: MacAddr) -> u32 {
    let octets = client_mac.octets();
    let mut id = 0x4E47_4150u32; // "NGAP"

    for octet in octets {
        id = id.rotate_left(5) ^ u32::from(octet);
    }

    id
}

/// Read a DHCP reply.
///
/// Returns `None` for anything that is not a well-formed DHCP message, so a
/// stray broadcast on the port does not look like a server.
pub fn parse_reply(packet: &[u8]) -> Option<DhcpReply> {
    if packet.len() < BOOTP_HEADER_LEN + MAGIC_COOKIE.len() {
        return None;
    }
    if packet[0] != 2 {
        // op 2 is BOOTREPLY; anything else is a request, not a reply.
        return None;
    }
    if packet[BOOTP_HEADER_LEN..BOOTP_HEADER_LEN + 4] != MAGIC_COOKIE {
        return None;
    }

    let offered = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let header_server = Ipv4Addr::new(packet[20], packet[21], packet[22], packet[23]);

    let mut message_type = None;
    let mut server_id = None;
    let mut hostname = None;

    let mut offset = BOOTP_HEADER_LEN + MAGIC_COOKIE.len();
    while offset < packet.len() {
        let option = packet[offset];
        offset += 1;

        if option == OPTION_END {
            break;
        }
        if option == 0 {
            // Padding.
            continue;
        }
        if offset >= packet.len() {
            break;
        }

        let length = packet[offset] as usize;
        offset += 1;

        // A malformed option ends the options rather than discarding the
        // reply: whatever was already read is still what the server said.
        let Some(value) = packet.get(offset..offset + length) else {
            break;
        };
        offset += length;

        match option {
            OPTION_MESSAGE_TYPE if length == 1 => message_type = Some(value[0]),
            OPTION_SERVER_IDENTIFIER if length == 4 => {
                server_id = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
            }
            OPTION_HOSTNAME => {
                hostname = Some(
                    String::from_utf8_lossy(value)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    Some(DhcpReply {
        message_type: message_type?,
        server_id,
        header_server,
        offered: (!offered.is_unspecified()).then_some(offered),
        hostname,
    })
}

/// Pull a DHCP reply out of a raw Ethernet frame.
///
/// Walks the frame the kernel would have: Ethernet, then IPv4, then UDP, then
/// the DHCP payload. Only frames addressed to the client port are considered,
/// so unrelated broadcast traffic on a busy network is ignored.
pub fn parse_frame(frame: &[u8]) -> Option<DhcpReply> {
    // Ethernet II: destination, source, ethertype.
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    // 0x0800 is IPv4; VLAN-tagged frames (0x8100) are not unwrapped.
    if ethertype != 0x0800 {
        return None;
    }

    let ip = &frame[14..];
    if ip.len() < 20 {
        return None;
    }

    let version = ip[0] >> 4;
    let header_length = ((ip[0] & 0x0F) as usize) * 4;
    if version != 4 || header_length < 20 || ip.len() < header_length {
        return None;
    }
    // Protocol 17 is UDP.
    if ip[9] != 17 {
        return None;
    }

    let udp = &ip[header_length..];
    if udp.len() < 8 {
        return None;
    }
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    if destination_port != CLIENT_PORT {
        return None;
    }

    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if length < 8 {
        return None;
    }
    let payload = udp.get(8..length.min(udp.len()))?;

    parse_reply(payload)
}

/// Which servers this probe considers legitimate.
///
/// The gateway is the expected answer on a home network, but a network may
/// have a dedicated server instead; anything else answering is the finding.
#[derive(Debug, Clone, Default)]
pub struct ExpectedServers {
    pub addresses: Vec<Ipv4Addr>,
}

impl ExpectedServers {
    pub fn new(addresses: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
        }
    }

    /// Whether an address is one of the expected servers.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        self.addresses.contains(&address)
    }

    /// Whether nothing is known about the network's servers.
    ///
    /// Without an expectation, an answer cannot be called unexpected; the
    /// result is still worth reporting, but as information.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

/// Sends DISCOVER messages and collects the servers that answer.
pub struct DhcpProbe {
    interface: String,
    timeout: Duration,
    client_port: u16,
    server_port: u16,
    target: Option<SocketAddr>,
}

impl DhcpProbe {
    pub fn new(interface: impl Into<String>, timeout: Duration) -> Self {
        Self {
            interface: interface.into(),
            timeout,
            client_port: CLIENT_PORT,
            server_port: SERVER_PORT,
            target: None,
        }
    }

    /// Aim the probe at a specific address, on an ephemeral client port.
    ///
    /// Exists for tests: the real probe binds port 68 and broadcasts, both of
    /// which need privileges, so an unprivileged test could not otherwise
    /// exercise any of this. Pointing it at a stand-in server on a high port
    /// runs the whole path — socket, DISCOVER, reply, parse — without them.
    #[cfg(test)]
    fn for_test(target: SocketAddr) -> Self {
        Self {
            interface: "lo".to_string(),
            timeout: Duration::from_secs(1),
            client_port: 0,
            server_port: target.port(),
            target: Some(target),
        }
    }

    /// Ask the network who provides DHCP.
    ///
    /// Needs root or `CAP_NET_BIND_SERVICE`: a DHCP client binds port 68.
    pub async fn discover_servers(&self, client_mac: MacAddr) -> Result<Vec<DhcpServer>> {
        let socket = self.open_socket()?;
        let local = socket
            .local_addr()
            .context("reading the probe socket address")?;
        let _ = local;

        // Open the capture *before* sending. A server can answer within
        // milliseconds, and anything that arrives before the socket is
        // listening is simply lost.
        let capture = self.open_capture();

        let discover = build_discover(client_mac, "netgap-probe");

        // Send to the probed interface's own subnet broadcast rather than the
        // limited broadcast address. The kernel routes a subnet broadcast out
        // that subnet's interface, so the probe goes where it was asked to,
        // without needing SO_BINDTODEVICE (which needs another capability).
        let target = self
            .target
            .unwrap_or_else(|| (self.broadcast_address(), self.server_port).into());

        socket
            .send_to(&discover, target)
            .await
            .context("broadcasting the DHCP DISCOVER")?;

        // Replies are read from a raw frame when possible. A host firewall
        // that drops inbound broadcast never lets the packet reach a UDP
        // socket, while a raw socket is tapped before that point — which is
        // why real DHCP clients read this way, and why a machine can hold a
        // lease while a UDP listener sees nothing.
        let servers = match capture {
            Ok(mut receiver) => self.read_capture(&mut *receiver),
            Err(_) => self.receive_via_socket(&socket).await?,
        };

        let mut servers = servers;
        servers.sort();
        Ok(servers)
    }

    /// Read replies from the client socket.
    ///
    /// The fallback path: correct, but a host firewall can stop the packet
    /// before it arrives.
    async fn receive_via_socket(&self, socket: &UdpSocket) -> Result<Vec<DhcpServer>> {
        let mut servers: Vec<DhcpServer> = Vec::new();
        let mut buffer = [0u8; 1024];
        let deadline = tokio::time::Instant::now() + self.timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            let Ok(Ok((read, _))) =
                tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await
            else {
                break;
            };

            let Some(reply) = parse_reply(&buffer[..read]) else {
                continue;
            };
            if !reply.is_offer() {
                continue;
            }

            if let Some(server) = reply.server() {
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }

        Ok(servers)
    }

    /// Open a packet socket on the interface being probed.
    ///
    /// Needs `CAP_NET_RAW` — the same privilege the ARP sweep uses — and is
    /// the path that survives a firewall, since packet sockets are tapped
    /// before netfilter sees anything. Returns an error when the channel
    /// cannot be opened, so the caller can fall back to the client socket.
    fn open_capture(&self) -> Result<Box<dyn pnet::datalink::DataLinkReceiver>> {
        use pnet::datalink::{self, Channel};

        // Tests point the probe at a stand-in server and have no interface to
        // listen on; they use the socket path.
        if self.target.is_some() {
            return Err(anyhow!("no raw capture for a targeted probe"));
        }

        let interface = datalink::interfaces()
            .into_iter()
            .find(|interface| interface.name == self.interface)
            .ok_or_else(|| anyhow!("interface '{}' not found", self.interface))?;

        let config = datalink::Config {
            read_timeout: Some(Duration::from_millis(100)),
            promiscuous: false,
            ..Default::default()
        };

        match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(_, receiver)) => Ok(receiver),
            Ok(_) => Err(anyhow!("unsupported datalink channel")),
            Err(error) => Err(crate::classify_channel_error(error)),
        }
    }

    /// Collect offers from captured frames until the budget runs out.
    fn read_capture(&self, receiver: &mut dyn pnet::datalink::DataLinkReceiver) -> Vec<DhcpServer> {
        use std::time::Instant;

        let mut servers: Vec<DhcpServer> = Vec::new();
        let deadline = Instant::now() + self.timeout;

        while Instant::now() < deadline {
            let Ok(frame) = receiver.next() else {
                // A read timeout is how the loop checks the clock, not a
                // reason to stop looking.
                continue;
            };

            let Some(reply) = parse_frame(frame) else {
                continue;
            };
            if !reply.is_offer() {
                continue;
            }

            if let Some(server) = reply.server() {
                if !servers.contains(&server) {
                    servers.push(server);
                }
            }
        }

        servers
    }

    /// The broadcast address of the interface being probed.
    ///
    /// Falls back to the limited broadcast address when the interface has no
    /// IPv4 network to derive one from.
    fn broadcast_address(&self) -> Ipv4Addr {
        pnet::datalink::interfaces()
            .into_iter()
            .find(|interface| interface.name == self.interface)
            .and_then(|interface| {
                interface.ips.into_iter().find_map(|ip| match ip {
                    pnet::ipnetwork::IpNetwork::V4(network) => Some(network.broadcast()),
                    _ => None,
                })
            })
            .unwrap_or(Ipv4Addr::BROADCAST)
    }

    /// Open the client socket.
    ///
    /// Binding a port below 1024 is what requires privilege; the failure is
    /// turned into a typed error so callers can offer the alternative rather
    /// than printing a bare permission message.
    fn open_socket(&self) -> Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("creating the DHCP probe socket")?;

        socket
            .set_reuse_address(true)
            .context("configuring the DHCP probe socket")?;
        socket
            .set_broadcast(true)
            .context("enabling broadcast on the DHCP probe socket")?;

        let address: SocketAddr = (Ipv4Addr::UNSPECIFIED, self.client_port).into();
        socket.bind(&address.into()).map_err(|error| match error.kind() {
            std::io::ErrorKind::PermissionDenied => anyhow!(DiscoveryError::PrivilegeRequired),
            std::io::ErrorKind::AddrInUse => anyhow!(
                "port {CLIENT_PORT} is already held by this machine's own DHCP client;                  an active lease cannot be probed for while it is, so run this on a                  machine that is not itself a DHCP client, or stop its client first"
            ),
            _ => anyhow!(error).context("binding the DHCP client port"),
        })?;

        let socket: std::net::UdpSocket = socket.into();
        socket
            .set_nonblocking(true)
            .context("setting the DHCP probe socket non-blocking")?;

        UdpSocket::from_std(socket).context("registering the DHCP probe socket")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_MAC: MacAddr = MacAddr(0x90, 0x61, 0x0C, 0xA3, 0x12, 0x94);

    /// Build a reply the way a server would, for the parser to read back.
    fn build_offer(server_id: &str, offered: &str, hostname: Option<&str>) -> Vec<u8> {
        let mut packet = vec![0u8; BOOTP_HEADER_LEN];

        packet[0] = 2; // op: BOOTREPLY
        packet[1] = 1;
        packet[2] = 6;
        packet[4..8].copy_from_slice(&transaction_id(CLIENT_MAC).to_be_bytes());

        let offered: Ipv4Addr = offered.parse().expect("valid ip");
        packet[16..20].copy_from_slice(&offered.octets());

        let server: Ipv4Addr = server_id.parse().expect("valid ip");
        packet[20..24].copy_from_slice(&server.octets());

        packet.extend_from_slice(&MAGIC_COOKIE);
        packet.extend_from_slice(&[OPTION_MESSAGE_TYPE, 1, DHCPOFFER]);
        packet.extend_from_slice(&[OPTION_SERVER_IDENTIFIER, 4]);
        packet.extend_from_slice(&server.octets());
        if let Some(hostname) = hostname {
            packet.push(OPTION_HOSTNAME);
            packet.push(hostname.len() as u8);
            packet.extend_from_slice(hostname.as_bytes());
        }
        packet.push(OPTION_END);

        packet
    }

    #[test]
    fn test_discover_is_a_well_formed_bootp_request() {
        let packet = build_discover(CLIENT_MAC, "netgap-probe");

        assert_eq!(packet[0], 1, "op is BOOTREQUEST");
        assert_eq!(packet[1], 1, "hardware type is Ethernet");
        assert_eq!(packet[2], 6, "hardware address length");
        assert_eq!(
            &packet[28..34],
            &CLIENT_MAC.octets(),
            "chaddr carries the client"
        );
        assert_eq!(&packet[236..240], &MAGIC_COOKIE);

        // The broadcast flag, so a server with no route to us still answers.
        assert_eq!(u16::from_be_bytes([packet[10], packet[11]]), 0x8000);

        // The message type option, which is what makes it a DISCOVER.
        let options = &packet[240..];
        assert_eq!(&options[..3], &[OPTION_MESSAGE_TYPE, 1, DHCPDISCOVER]);
        assert_eq!(*options.last().expect("an option"), OPTION_END);
    }

    #[test]
    fn test_discover_carries_the_hostname() {
        let packet = build_discover(CLIENT_MAC, "netgap-probe");
        let text = String::from_utf8_lossy(&packet[240..]).to_string();
        assert!(text.contains("netgap-probe"));

        // An empty hostname is left out rather than sent as an empty option.
        let without = build_discover(CLIENT_MAC, "");
        let text = String::from_utf8_lossy(&without[240..]).to_string();
        assert!(!text.contains('\0'));
        assert!(without.len() < packet.len());
    }

    #[test]
    fn test_transaction_id_is_stable_per_client() {
        let other = MacAddr(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        // Repeated scans should look like the same client asking again.
        assert_eq!(transaction_id(CLIENT_MAC), transaction_id(CLIENT_MAC));
        assert_ne!(transaction_id(CLIENT_MAC), transaction_id(other));
    }

    #[test]
    fn test_parses_an_offer() {
        let packet = build_offer("192.168.111.1", "192.168.111.50", Some("router"));
        let reply = parse_reply(&packet).expect("parses");

        assert!(reply.is_offer());
        assert_eq!(
            reply.server_id,
            Some("192.168.111.1".parse().expect("valid ip"))
        );
        assert_eq!(
            reply.offered,
            Some("192.168.111.50".parse().expect("valid ip"))
        );
        assert_eq!(reply.hostname.as_deref(), Some("router"));
    }

    #[test]
    fn test_server_falls_back_to_the_header_address() {
        // A reply with no server identifier option, as older servers send.
        let mut packet = build_offer("10.0.0.1", "10.0.0.50", None);
        let options_at = BOOTP_HEADER_LEN + 4;
        // Option 54 is six bytes: code, length, and four of address.
        packet.drain(options_at + 3..options_at + 9);

        let reply = parse_reply(&packet).expect("parses");
        assert_eq!(reply.server_id, None);

        let header: Ipv4Addr = "10.0.0.1".parse().expect("valid ip");
        assert_eq!(reply.server().expect("server").server_id, header);
    }

    #[test]
    fn test_ignores_anything_that_is_not_a_reply() {
        // A request, not a reply.
        let mut request = build_offer("192.168.1.1", "192.168.1.50", None);
        request[0] = 1;
        assert_eq!(parse_reply(&request), None);

        // Truncated, empty, and a lost magic cookie.
        assert_eq!(parse_reply(&[]), None);
        assert_eq!(parse_reply(&[0u8; 100]), None);
        let mut no_cookie = build_offer("192.168.1.1", "192.168.1.50", None);
        no_cookie[BOOTP_HEADER_LEN] = 0;
        assert_eq!(parse_reply(&no_cookie), None);
    }

    #[test]
    fn test_a_truncated_option_does_not_discard_what_was_read() {
        // A reply whose first option is unreadable has no message type, and so
        // is not a reply at all.
        let mut packet = build_offer("192.168.1.1", "192.168.1.50", None);
        packet.truncate(packet.len() - 3);
        packet[BOOTP_HEADER_LEN + 4] = OPTION_HOSTNAME;
        packet[BOOTP_HEADER_LEN + 5] = 200; // claims 200 bytes that are not there

        assert_eq!(parse_reply(&packet), None);

        // One that goes bad *after* the useful options keeps them: the server
        // said what it said, and discarding it would lose a real server.
        let mut packet = build_offer("192.168.1.1", "192.168.1.50", None);
        packet.pop(); // drop the end marker
        packet.extend_from_slice(&[OPTION_HOSTNAME, 200]); // and overclaim

        let reply = parse_reply(&packet).expect("the readable part still parses");
        assert_eq!(
            reply.server_id,
            Some("192.168.1.1".parse().expect("valid ip"))
        );
    }

    #[test]
    fn test_an_offer_without_a_type_is_not_a_reply() {
        let mut packet = build_offer("192.168.1.1", "192.168.1.50", None);
        packet[BOOTP_HEADER_LEN + 4] = OPTION_HOSTNAME; // no message type at all
        packet[BOOTP_HEADER_LEN + 5] = 1;
        packet[BOOTP_HEADER_LEN + 6] = b'x';

        assert_eq!(parse_reply(&packet), None);
    }

    /// Wrap a DHCP payload in the headers a real reply arrives with.
    fn ethernet_frame(payload: &[u8], protocol: u8, destination_port: u16) -> Vec<u8> {
        let mut frame = Vec::new();

        // Ethernet II: destination, source, ethertype 0x0800.
        frame.extend_from_slice(&[0xFF; 6]);
        frame.extend_from_slice(&[0x0E, 0x61, 0x23, 0x8B, 0x9B, 0x81]);
        frame.extend_from_slice(&[0x08, 0x00]);

        // IPv4, 20 bytes, no options.
        let udp_length = 8 + payload.len();
        let total_length = 20 + udp_length;
        frame.push(0x45); // version 4, header length 5 words
        frame.push(0);
        frame.extend_from_slice(&(total_length as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]); // identification
        frame.extend_from_slice(&[0, 0]); // flags and fragment offset
        frame.push(64); // ttl
        frame.push(protocol);
        frame.extend_from_slice(&[0, 0]); // header checksum, unchecked here
        frame.extend_from_slice(&[10, 99, 99, 1]); // source
        frame.extend_from_slice(&[255, 255, 255, 255]); // destination

        // UDP.
        frame.extend_from_slice(&67u16.to_be_bytes());
        frame.extend_from_slice(&destination_port.to_be_bytes());
        frame.extend_from_slice(&(udp_length as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]); // checksum

        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn test_parse_frame_reads_a_reply_off_the_wire() {
        let offer = build_offer("192.168.111.1", "192.168.111.50", Some("router"));
        let frame = ethernet_frame(&offer, 17, CLIENT_PORT);

        let reply = parse_frame(&frame).expect("parses");
        assert!(reply.is_offer());
        assert_eq!(
            reply.server().expect("server").server_id,
            "192.168.111.1".parse::<Ipv4Addr>().expect("valid ip")
        );
    }

    #[test]
    fn test_parse_frame_ignores_other_traffic() {
        let offer = build_offer("192.168.111.1", "192.168.111.50", None);

        // A reply to some other port is not ours.
        assert_eq!(parse_frame(&ethernet_frame(&offer, 17, 5353)), None);
        // Not UDP: 6 is TCP.
        assert_eq!(parse_frame(&ethernet_frame(&offer, 6, CLIENT_PORT)), None);
        // Not IPv4 at all.
        let mut frame = ethernet_frame(&offer, 17, CLIENT_PORT);
        frame[12] = 0x86;
        frame[13] = 0xDD; // IPv6
        assert_eq!(parse_frame(&frame), None);
    }

    #[test]
    fn test_parse_frame_survives_truncated_input() {
        let offer = build_offer("192.168.111.1", "192.168.111.50", None);
        let frame = ethernet_frame(&offer, 17, CLIENT_PORT);

        assert_eq!(parse_frame(&[]), None);
        assert_eq!(parse_frame(&frame[..10]), None);
        assert_eq!(parse_frame(&frame[..20]), None);
        assert_eq!(parse_frame(&frame[..40]), None);
        // Cut in the middle of the payload: nothing usable, no panic.
        assert_eq!(parse_frame(&frame[..frame.len() - 20]), None);
    }

    #[test]
    fn test_parse_frame_honours_the_ip_header_length() {
        // A frame carrying IP options must still find the UDP header: the
        // header length field says where it starts.
        let offer = build_offer("192.168.111.1", "192.168.111.50", None);
        let mut frame = ethernet_frame(&offer, 17, CLIENT_PORT);

        // Grow the header from 20 to 24 bytes and adjust both length fields.
        frame[14] = 0x46; // version 4, header length 6 words
        let extra = [0x01, 0x01, 0x01, 0x01]; // a no-op option, padded
        frame.splice(34..34, extra.iter().copied());

        let total = u16::from_be_bytes([frame[16], frame[17]]) + 4;
        frame[16..18].copy_from_slice(&total.to_be_bytes());

        let reply = parse_frame(&frame).expect("parses with IP options present");
        assert!(reply.is_offer());
    }

    /// The whole path — socket, DISCOVER, reply, parse — against a stand-in
    /// server on a high port, so it runs unprivileged.
    #[tokio::test]
    async fn test_probe_collects_a_server_that_answers() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
        let server_address = server.local_addr().expect("server address");

        let answer = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let (read, from) = server.recv_from(&mut buffer).await.expect("receive");

            // What arrives must be a well-formed request, not a copy of a reply.
            assert_eq!(buffer[0], 1, "the probe sends BOOTREQUEST");
            assert_eq!(&buffer[236..240], &MAGIC_COOKIE);
            assert!(
                parse_reply(&buffer[..read]).is_none(),
                "a request is not a reply"
            );

            let offer = build_offer("192.168.111.1", "192.168.111.50", Some("router"));
            server.send_to(&offer, from).await.expect("send offer");
        });

        let probe = DhcpProbe::for_test(server_address);
        let servers = probe.discover_servers(CLIENT_MAC).await.expect("probe");

        answer.await.expect("the stand-in server ran");

        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers[0].server_id,
            "192.168.111.1".parse::<Ipv4Addr>().expect("valid ip")
        );
        assert_eq!(servers[0].hostname.as_deref(), Some("router"));
    }

    /// Two servers answering is the case worth reporting, so both must come
    /// back rather than whichever replied first.
    #[tokio::test]
    async fn test_probe_reports_every_server_that_answers() {
        let stand_in = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = stand_in.local_addr().expect("address");

        // One socket plays both servers: the network is shared, so the probe
        // cannot tell them apart by who sent what, only by what each claims.
        let answer = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let (_, from) = stand_in.recv_from(&mut buffer).await.expect("receive");

            for (server, hostname) in [
                ("192.168.111.1", "router"),
                ("192.168.111.99", "not-the-router"),
            ] {
                let offer = build_offer(server, "192.168.111.60", Some(hostname));
                stand_in.send_to(&offer, from).await.expect("send");
            }
        });

        let probe = DhcpProbe::for_test(target);
        let servers = probe.discover_servers(CLIENT_MAC).await.expect("probe");

        answer.await.expect("the stand-in server ran");

        assert_eq!(
            servers.len(),
            2,
            "both answering servers should be reported"
        );
        assert_eq!(
            servers[0].server_id,
            "192.168.111.1".parse::<Ipv4Addr>().expect("valid ip"),
            "results are ordered by address, so the same network reads the same way twice"
        );
        assert_eq!(servers[1].hostname.as_deref(), Some("not-the-router"));
    }

    /// A server answering twice is still one server.
    #[tokio::test]
    async fn test_a_repeated_offer_is_not_a_second_server() {
        let stand_in = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = stand_in.local_addr().expect("address");

        let answer = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let (_, from) = stand_in.recv_from(&mut buffer).await.expect("receive");
            for _ in 0..3 {
                let offer = build_offer("192.168.111.1", "192.168.111.50", Some("router"));
                stand_in.send_to(&offer, from).await.expect("send");
            }
        });

        let probe = DhcpProbe::for_test(target);
        let servers = probe.discover_servers(CLIENT_MAC).await.expect("probe");
        answer.await.expect("the stand-in server ran");

        assert_eq!(servers.len(), 1);
    }

    /// A server that never answers must not hold the probe open.
    #[tokio::test]
    async fn test_probe_gives_up_when_nothing_answers() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = silent.local_addr().expect("address");

        let probe = DhcpProbe::for_test(target);
        let started = std::time::Instant::now();
        let servers = probe.discover_servers(CLIENT_MAC).await.expect("probe");

        assert!(servers.is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the probe must respect its timeout"
        );
    }

    #[test]
    fn test_expected_servers() {
        let expected = ExpectedServers::new(["192.168.1.1".parse().expect("valid ip")]);

        assert!(expected.contains("192.168.1.1".parse().expect("valid ip")));
        assert!(!expected.contains("192.168.1.99".parse().expect("valid ip")));
        assert!(!expected.is_empty());
        assert!(ExpectedServers::default().is_empty());
    }
}
