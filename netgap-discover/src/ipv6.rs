//! IPv6 host discovery.
//!
//! IPv6 has no ARP, and a `/64` cannot be swept — 2^64 addresses is not a list
//! anyone walks. What works instead is the kernel's neighbour table, which is
//! IPv6's equivalent of the ARP cache and fills in as traffic happens.
//!
//! So discovery is two steps:
//!
//! 1. Send an ICMPv6 echo to the all-nodes multicast address, which every IPv6
//!    host on the link receives. Most devices do not answer a multicast echo —
//!    that is a deliberate hardening — but the exchange makes the kernel
//!    resolve and record the neighbours that do react.
//! 2. Read the neighbour table.
//!
//! Both steps work unprivileged. The echo goes through a datagram ICMPv6
//! socket, which the kernel builds and checksums and which the `ping_group_range`
//! sysctl opens to ordinary users; the neighbour table is read through netlink,
//! the same source `ip -6 neigh` reads.
//!
//! The addresses this finds are usually link-local, which is worth stating
//! plainly: a `fe80::` address is reachable from this link and nowhere else. It
//! identifies a device; it does not reach it.

use anyhow::{anyhow, Context, Result};
use netgap_core::Device;
use std::net::Ipv6Addr;
use std::time::Duration;

/// The all-nodes multicast address: every IPv6 host on the link receives it.
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// How long to let the kernel settle before reading the table back.
///
/// Neighbour entries appear as the responses arrive, which is sub-millisecond
/// on a LAN; this is slack for a busy or wireless link, not a wait for a
/// timeout.
const SETTLE: Duration = Duration::from_millis(300);

/// How many echo requests to send. One is enough to be received; more give a
/// lossy wireless link several chances to carry it.
const ECHO_COUNT: u8 = 3;

/// One IPv6 neighbour the kernel knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Neighbour {
    pub address: Ipv6Addr,
    /// The hardware address, when the kernel has resolved one. An entry that
    /// has been solicited but not answered has none, and identifies nothing.
    pub mac: Option<String>,
}

impl Ipv6Neighbour {
    /// Whether this address is link-local (`fe80::/10`).
    pub fn is_link_local(&self) -> bool {
        (self.address.segments()[0] & 0xffc0) == 0xfe80
    }

    /// Whether this is a multicast address (`ff00::/8`).
    ///
    /// The kernel keeps an entry for every multicast group this machine has
    /// joined, with a synthetic MAC (`33:33:...`) derived from the address.
    /// They are memberships, not devices, and merging them would invent a
    /// handful of imaginary hosts on every scan.
    pub fn is_multicast(&self) -> bool {
        self.address.is_multicast()
    }

    /// Whether this entry identifies another machine.
    ///
    /// The table also holds this host's own addresses and its multicast
    /// memberships; neither is a device to report.
    pub fn is_a_device(&self) -> bool {
        !self.is_multicast() && !self.address.is_unspecified() && !self.address.is_loopback()
    }
}

/// What a merge did, so the caller can report it rather than guess.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeSummary {
    /// Devices already known that gained an IPv6 address.
    pub matched: usize,
    /// Devices only IPv6 revealed.
    pub added: usize,
}

/// Find IPv6 neighbours of one interface: stimulate, then read the table.
pub fn discover(interface_name: &str) -> Result<Vec<Ipv6Neighbour>> {
    stimulate(interface_name)?;
    std::thread::sleep(SETTLE);
    read_neighbours(interface_name)
}

/// Prompt the kernel to talk to every IPv6 host on the link.
///
/// Uses a datagram ICMPv6 socket, so the kernel builds the packet and its
/// checksum and a normal user may send it. This needs no raw socket, which is
/// why IPv6 discovery works unprivileged where ARP does not.
pub fn stimulate(interface_name: &str) -> Result<()> {
    let index = interface_index(interface_name)
        .ok_or_else(|| anyhow!("interface '{}' not found", interface_name))?;

    let socket = Icmpv6Socket::open().context("opening an ICMPv6 socket")?;
    let target = SockAddrIn6::multicast(ALL_NODES, index);

    // An echo request: type 128, code 0, checksum (the kernel fills it), then
    // an identifier and sequence. The identifier is fixed so repeated runs are
    // recognisable as the same prober.
    for sequence in 1u16..=ECHO_COUNT as u16 {
        let [high, low] = sequence.to_be_bytes();
        let request = [128u8, 0, 0, 0, 0x4E, 0x47, high, low];
        socket.send(&request, &target).with_context(|| {
            format!(
                "sending an IPv6 echo to all nodes on '{}'",
                interface_name
            )
        })?;

        if sequence < ECHO_COUNT as u16 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    Ok(())
}

/// Read the kernel's IPv6 neighbour table for one interface.
pub fn read_neighbours(interface_name: &str) -> Result<Vec<Ipv6Neighbour>> {
    let index = interface_index(interface_name)
        .ok_or_else(|| anyhow!("interface '{}' not found", interface_name))?;

    let neighbours = netlink::dump_neighbours(index)?;

    // The table holds multicast memberships and this host's own addresses
    // alongside real neighbours. Filtering here rather than in the parser keeps
    // the parser honest about what the kernel sent.
    Ok(neighbours
        .into_iter()
        .filter(Ipv6Neighbour::is_a_device)
        .collect())
}

/// Attach IPv6 addresses to the devices already found, and add the ones only
/// IPv6 revealed.
///
/// Matching is by hardware address, because that is the one identifier both
/// sides of the split — IPv4 discovery and the IPv6 neighbour table — agree on.
/// A device whose MAC is randomized still matches itself: the same random
/// address appears on both. A neighbour with no MAC (an unanswered solicitation)
/// is skipped, since there is nothing to attach it to.
///
/// `allow_new` says whether a neighbour matching no known device should become
/// one. It must be false when the caller scanned a range narrower than the
/// network: the neighbour table covers the whole link, and honouring it
/// unfiltered would report devices the user explicitly asked not to scan.
pub fn merge(
    devices: &mut Vec<Device>,
    neighbours: &[Ipv6Neighbour],
    allow_new: bool,
) -> MergeSummary {
    let mut summary = MergeSummary::default();

    for neighbour in neighbours {
        let Some(mac) = neighbour.mac.as_deref() else {
            continue;
        };
        let address = neighbour.address.to_string();

        let existing = devices.iter_mut().find(|device| {
            device
                .mac
                .as_deref()
                .is_some_and(|device_mac| device_mac.eq_ignore_ascii_case(mac))
        });

        match existing {
            Some(device) => {
                if !device.ipv6_addresses.contains(&address) {
                    device.ipv6_addresses.push(address);
                    summary.matched += 1;
                }
            }
            None if !allow_new => {}
            None => {
                // A device the IPv4 sweep never saw — asleep, firewalled
                // against TCP, or simply IPv6-only.
                let mut device = Device::new(std::net::IpAddr::V6(neighbour.address));
                device.mac = Some(mac.to_uppercase());
                device.ipv6_addresses.push(address);
                devices.push(device);
                summary.added += 1;
            }
        }
    }

    summary
}

/// Look up an interface index by name.
fn interface_index(name: &str) -> Option<u32> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // Safety: the pointer comes from a CString that is NUL-terminated and
    // outlives the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    (index != 0).then_some(index)
}

/// An `AF_INET6` datagram ICMPv6 socket, closed when dropped.
struct Icmpv6Socket(libc::c_int);

impl Icmpv6Socket {
    fn open() -> Result<Self> {
        // Safety: a plain socket call, checked before use.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET6,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_ICMPV6,
            )
        };

        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(error).context(
                "ICMPv6 sockets need a group in net.ipv4.ping_group_range (usually set by \
                 default); a container may not allow it",
            );
        }

        Ok(Icmpv6Socket(fd))
    }

    fn send(&self, payload: &[u8], target: &SockAddrIn6) -> Result<()> {
        // Safety: a valid buffer and address, on a socket this type owns.
        let written = unsafe {
            libc::sendto(
                self.0,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &target.0 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };

        if written < 0 {
            return Err(std::io::Error::last_os_error()).context("sending the echo");
        }

        Ok(())
    }
}

impl Drop for Icmpv6Socket {
    fn drop(&mut self) {
        // Safety: closing a descriptor this type owns, exactly once.
        unsafe { libc::close(self.0) };
    }
}

/// A `sockaddr_in6` wrapper, so the unsafe construction lives in one place.
struct SockAddrIn6(libc::sockaddr_in6);

impl SockAddrIn6 {
    fn multicast(address: Ipv6Addr, scope_id: u32) -> Self {
        // Safety: `sockaddr_in6` is a plain C struct that zeroes cleanly.
        let mut raw: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        raw.sin6_family = libc::AF_INET6 as u16;
        raw.sin6_port = 0;
        raw.sin6_addr = libc::in6_addr {
            s6_addr: address.octets(),
        };
        // A link-local multicast address is only meaningful on one link, so
        // the interface has to be named.
        raw.sin6_scope_id = scope_id;

        SockAddrIn6(raw)
    }
}

/// Reading the neighbour table through netlink.
mod netlink {
    use super::Ipv6Neighbour;
    use anyhow::{anyhow, Context, Result};
    use std::net::Ipv6Addr;
    use std::os::fd::RawFd;

    /// An `nlmsghdr`, which opens every netlink message.
    const NLMSG_HEADER_LEN: usize = 16;
    /// An `rtattr`, which opens every netlink attribute.
    const ATTRIBUTE_HEADER_LEN: usize = 4;
    /// An `ndmsg`, the neighbour-table payload.
    const NDMSG_LEN: usize = 12;

    const NETLINK_ROUTE: i32 = 0;
    const RTM_GETNEIGH: u16 = 30;
    const NLM_F_REQUEST: u16 = 1;
    /// `NLM_F_ROOT | NLM_F_MATCH` — asks for the whole table.
    const NLM_F_DUMP: u16 = 0x100 | 0x200;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const AF_INET6: u8 = 10;

    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;

    /// How long to wait for the kernel before giving up. A dump of a neighbour
    /// table is immediate; this only bounds a kernel that never answers.
    const RECEIVE_TIMEOUT: libc::timeval = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };

    /// Ask the kernel for one interface's IPv6 neighbours.
    pub fn dump_neighbours(interface_index: u32) -> Result<Vec<Ipv6Neighbour>> {
        let socket = NetlinkSocket::open()?;
        socket.set_receive_timeout(RECEIVE_TIMEOUT)?;
        socket.send(&build_request(interface_index))?;

        let mut neighbours = Vec::new();
        let mut buffer = vec![0u8; 32 * 1024];

        loop {
            let read = socket.receive(&mut buffer)?;
            if read == 0 {
                break;
            }

            let parsed = parse_dump(&buffer[..read], interface_index);

            if let Some(error) = parsed.error {
                // The kernel reports failures — an unprivileged container, a
                // missing table — as a netlink error message. Silence here
                // would read as "no IPv6 devices", which is a different and
                // much more reassuring answer.
                return Err(anyhow!(
                    "the kernel refused the neighbour lookup: {}",
                    std::io::Error::from_raw_os_error(error)
                ));
            }

            neighbours.extend(parsed.neighbours);

            if parsed.done {
                break;
            }
        }

        neighbours.sort_by_key(|neighbour| neighbour.address);
        neighbours.dedup_by_key(|neighbour| neighbour.address);
        Ok(neighbours)
    }

    /// A bound netlink socket, closed when dropped.
    struct NetlinkSocket(RawFd);

    impl NetlinkSocket {
        fn open() -> Result<Self> {
            // Safety: a plain socket call, checked before use.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    NETLINK_ROUTE,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("opening a netlink socket");
            }

            // Safety: `sockaddr_nl` is a plain C struct that zeroes cleanly.
            let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16;

            // Safety: a valid address of the right length, on a socket this
            // type owns and will close.
            let bound = unsafe {
                libc::bind(
                    fd,
                    &address as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if bound < 0 {
                let error = std::io::Error::last_os_error();
                // Safety: closing a descriptor that would otherwise leak.
                unsafe { libc::close(fd) };
                return Err(error).context("binding the netlink socket");
            }

            Ok(NetlinkSocket(fd))
        }

        fn set_receive_timeout(&self, timeout: libc::timeval) -> Result<()> {
            // Safety: a valid option of the size given, on a socket this type
            // owns.
            let set = unsafe {
                libc::setsockopt(
                    self.0,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &timeout as *const libc::timeval as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if set < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("setting the netlink receive timeout");
            }

            Ok(())
        }

        fn send(&self, message: &[u8]) -> Result<()> {
            // Safety: a valid buffer and length, on a socket this type owns.
            let written = unsafe {
                libc::send(
                    self.0,
                    message.as_ptr() as *const libc::c_void,
                    message.len(),
                    0,
                )
            };
            if written < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("sending the netlink request");
            }

            Ok(())
        }

        /// Read once. A timeout returns `Ok(0)`, which ends the dump the same
        /// way the kernel's own "done" does — better a partial table than a
        /// hang.
        fn receive(&self, buffer: &mut [u8]) -> Result<usize> {
            // Safety: a valid writable buffer, on a socket this type owns.
            let read = unsafe {
                libc::recv(
                    self.0,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                {
                    return Ok(0);
                }

                return Err(error).context("reading the netlink reply");
            }

            Ok(read as usize)
        }
    }

    impl Drop for NetlinkSocket {
        fn drop(&mut self) {
            // Safety: closing a descriptor this type owns, exactly once.
            unsafe { libc::close(self.0) };
        }
    }

    /// Build an `RTM_GETNEIGH` dump request for one interface.
    fn build_request(interface_index: u32) -> Vec<u8> {
        let total = NLMSG_HEADER_LEN + NDMSG_LEN;

        let mut message = Vec::with_capacity(total);
        message.extend_from_slice(&(total as u32).to_ne_bytes());
        message.extend_from_slice(&RTM_GETNEIGH.to_ne_bytes());
        message.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        message.extend_from_slice(&1u32.to_ne_bytes()); // sequence
        message.extend_from_slice(&0u32.to_ne_bytes()); // pid: the kernel

        // ndmsg, in the kernel's field order rather than the name order.
        message.push(AF_INET6);
        message.push(0);
        message.extend_from_slice(&0u16.to_ne_bytes());
        message.extend_from_slice(&(interface_index as i32).to_ne_bytes());
        message.extend_from_slice(&0u16.to_ne_bytes());
        message.push(0);
        message.push(0);

        message
    }

    /// What one netlink message's worth of dump yielded.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct ParsedDump {
        pub neighbours: Vec<Ipv6Neighbour>,
        /// An errno, when the kernel refused the request.
        pub error: Option<i32>,
        /// Whether this was the kernel's last message.
        pub done: bool,
    }

    /// Parse a netlink reply.
    ///
    /// Kept free of the socket so it can be tested against bytes.
    pub fn parse_dump(message: &[u8], interface_index: u32) -> ParsedDump {
        let mut parsed = ParsedDump::default();
        let mut offset = 0;

        while offset + NLMSG_HEADER_LEN <= message.len() {
            let header = &message[offset..offset + NLMSG_HEADER_LEN];
            let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
            let kind = u16::from_ne_bytes([header[4], header[5]]);

            if length < NLMSG_HEADER_LEN || offset + length > message.len() {
                // A short or oversized message is not a dump this understands;
                // stop rather than read past it.
                break;
            }

            let payload = &message[offset + NLMSG_HEADER_LEN..offset + length];

            match kind {
                NLMSG_DONE => {
                    parsed.done = true;
                    break;
                }
                NLMSG_ERROR => {
                    // The error is the first four bytes of the payload.
                    if payload.len() >= 4 {
                        parsed.error =
                            Some(i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]));
                    }
                    parsed.done = true;
                    break;
                }
                _ => {
                    if let Some(neighbour) = parse_neighbour(payload, interface_index) {
                        parsed.neighbours.push(neighbour);
                    }
                }
            }

            // Messages are padded to a four-byte boundary.
            offset += (length + 3) & !3;
        }

        parsed
    }

    /// Parse one `ndmsg` and its attributes.
    fn parse_neighbour(payload: &[u8], interface_index: u32) -> Option<Ipv6Neighbour> {
        if payload.len() < NDMSG_LEN || payload[0] != AF_INET6 {
            return None;
        }

        let message_interface = i32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if message_interface != interface_index as i32 {
            return None;
        }

        let mut address = None;
        let mut mac = None;

        let mut offset = NDMSG_LEN;
        while offset + ATTRIBUTE_HEADER_LEN <= payload.len() {
            let attribute = &payload[offset..offset + ATTRIBUTE_HEADER_LEN];
            let length = u16::from_ne_bytes([attribute[0], attribute[1]]) as usize;
            let kind = u16::from_ne_bytes([attribute[2], attribute[3]]);

            if length < ATTRIBUTE_HEADER_LEN || offset + length > payload.len() {
                break;
            }

            let value = &payload[offset + ATTRIBUTE_HEADER_LEN..offset + length];
            match kind {
                NDA_DST if value.len() == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(value);
                    address = Some(Ipv6Addr::from(octets));
                }
                NDA_LLADDR if value.len() == 6 => {
                    mac = Some(format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        value[0], value[1], value[2], value[3], value[4], value[5]
                    ));
                }
                _ => {}
            }

            // Attributes are padded too.
            offset += (length + 3) & !3;
        }

        Some(Ipv6Neighbour {
            address: address?,
            mac,
        })
    }

    #[cfg(test)]
    pub mod test_bytes {
        //! Building netlink bytes for the parser tests, so the tests describe
        //! the wire format rather than restating the parser.

        pub const NLMSG_HEADER_LEN: usize = 16;

        /// One `RTM_NEWNEIGH` message carrying an IPv6 address and a MAC.
        pub fn neighbour_message(interface_index: u32, address: [u8; 16], mac: [u8; 6]) -> Vec<u8> {
            let mut attributes = Vec::new();
            attributes.extend_from_slice(&attribute(1, &address));
            attributes.extend_from_slice(&attribute(2, &mac));

            let mut payload = ndmsg(interface_index);
            payload.extend_from_slice(&attributes);

            wrap(28, &payload)
        }

        /// The `NLMSG_DONE` message that ends every dump.
        pub fn done_message() -> Vec<u8> {
            wrap(3, &[])
        }

        /// An `NLMSG_ERROR` message carrying an errno.
        pub fn error_message(errno: i32) -> Vec<u8> {
            wrap(2, &errno.to_ne_bytes())
        }

        fn ndmsg(interface_index: u32) -> Vec<u8> {
            let mut message = vec![10u8, 0]; // AF_INET6, pad
            message.extend_from_slice(&0u16.to_ne_bytes());
            message.extend_from_slice(&(interface_index as i32).to_ne_bytes());
            message.extend_from_slice(&0u16.to_ne_bytes());
            message.push(0);
            message.push(0);
            message
        }

        fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
            let length = 4 + value.len();
            let mut attribute = Vec::with_capacity((length + 3) & !3);
            attribute.extend_from_slice(&(length as u16).to_ne_bytes());
            attribute.extend_from_slice(&kind.to_ne_bytes());
            attribute.extend_from_slice(value);
            while attribute.len() % 4 != 0 {
                attribute.push(0);
            }
            attribute
        }

        fn wrap(kind: u16, payload: &[u8]) -> Vec<u8> {
            let length = NLMSG_HEADER_LEN + payload.len();
            let mut message = Vec::with_capacity((length + 3) & !3);
            message.extend_from_slice(&(length as u32).to_ne_bytes());
            message.extend_from_slice(&kind.to_ne_bytes());
            message.extend_from_slice(&0u16.to_ne_bytes());
            message.extend_from_slice(&2u32.to_ne_bytes());
            message.extend_from_slice(&0u32.to_ne_bytes());
            message.extend_from_slice(payload);
            while message.len() % 4 != 0 {
                message.push(0);
            }
            message
        }
    }
}

#[cfg(test)]
mod tests {
    use super::netlink::test_bytes::{done_message, error_message, neighbour_message};
    use super::netlink::parse_dump;
    use super::*;

    fn neighbour(address: &str, mac: Option<&str>) -> Ipv6Neighbour {
        Ipv6Neighbour {
            address: address.parse().expect("a valid test address"),
            mac: mac.map(str::to_string),
        }
    }

    /// Build a nine-byte device list to merge into.
    fn devices() -> Vec<Device> {
        let mut device = Device::new("192.168.111.18".parse().expect("a valid test address"));
        device.mac = Some("C4:B2:5B:0A:03:26".to_string());
        vec![device]
    }

    #[test]
    fn test_interface_index_lookup() {
        assert!(interface_index("lo").is_some());
        assert_eq!(interface_index("netgap-no-such-interface"), None);
    }

    #[test]
    fn test_link_local_detection() {
        assert!(neighbour("fe80::1", None).is_link_local());
        assert!(!neighbour("2001:db8::1", None).is_link_local());
    }

    /// Observed live: the kernel's table carries an entry per multicast group
    /// this host joined, each with a synthetic `33:33:` MAC. Treating those as
    /// devices would add six imaginary hosts to every scan.
    #[test]
    fn test_multicast_memberships_are_not_devices() {
        for address in [
            "ff02::1",
            "ff02::2",
            "ff02::c",
            "ff02::16",
            "ff02::fb",
            "ff02::1:ffc1:eee2",
        ] {
            let membership = neighbour(address, Some("33:33:00:00:00:01"));
            assert!(membership.is_multicast(), "{} is multicast", address);
            assert!(!membership.is_a_device(), "{} is not a device", address);
        }

        assert!(neighbour("fe80::c6b2:5bff:fe0a:326", Some("C4:B2:5B:0A:03:26")).is_a_device());
        assert!(neighbour("2001:db8::1", Some("C4:B2:5B:0A:03:26")).is_a_device());
        assert!(!neighbour("::1", Some("C4:B2:5B:0A:03:26")).is_a_device());
    }

    #[test]
    fn test_stimulating_a_missing_interface_is_an_error() {
        assert!(stimulate("netgap-no-such-interface").is_err());
    }

    /// A parser that reads past its buffer is worse than one that finds
    /// nothing, so the shapes most likely to overflow are pinned here.
    #[test]
    fn test_truncated_messages_are_not_read_past() {
        let full = neighbour_message(3, [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [1, 2, 3, 4, 5, 6]);

        for length in 0..full.len() {
            let parsed = parse_dump(&full[..length], 3);
            assert!(
                parsed.neighbours.is_empty(),
                "a {} byte prefix should not parse as a neighbour",
                length
            );
        }
    }

    #[test]
    fn test_parsing_an_empty_dump_ends_cleanly() {
        let parsed = parse_dump(&done_message(), 3);
        assert!(parsed.done);
        assert!(parsed.error.is_none());
        assert!(parsed.neighbours.is_empty());
    }

    #[test]
    fn test_a_kernel_refusal_is_reported_rather_than_read_as_empty() {
        let parsed = parse_dump(&error_message(-1), 3);
        assert_eq!(parsed.error, Some(-1));
        assert!(parsed.done);
    }

    /// The addresses live in an attribute, so a message without one is not a
    /// neighbour and must not become a device at `::`.
    #[test]
    fn test_a_neighbour_without_an_address_attribute_is_skipped() {
        let mut message = neighbour_message(3, [0; 16], [1, 2, 3, 4, 5, 6]);
        // Overwrite the NDA_DST attribute's type with one the parser ignores.
        message[16 + 12 + 2] = 99;

        let parsed = parse_dump(&message, 3);
        assert!(parsed.neighbours.is_empty());
    }

    #[test]
    fn test_merging_matches_by_mac_case_insensitively() {
        let mut devices = devices();
        let summary = merge(
            &mut devices,
            &[neighbour("fe80::1", Some("c4:b2:5b:0a:03:26"))],
            true,
        );

        assert_eq!(summary, MergeSummary { matched: 1, added: 0 });
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ipv6_addresses, vec!["fe80::1".to_string()]);
    }

    /// Two IPv6 addresses on one device is ordinary — a link-local and a
    /// global — and must not add it twice.
    #[test]
    fn test_merging_twice_does_not_duplicate() {
        let mut devices = devices();
        let addresses = [
            neighbour("fe80::1", Some("C4:B2:5B:0A:03:26")),
            neighbour("fe80::1", Some("C4:B2:5B:0A:03:26")),
        ];

        let summary = merge(&mut devices, &addresses, true);

        assert_eq!(summary.matched, 1);
        assert_eq!(devices[0].ipv6_addresses.len(), 1);
    }

    #[test]
    fn test_a_device_only_ipv6_saw_is_added_once() {
        let mut devices = devices();
        let neighbours = [
            neighbour("fe80::c6b2:5bff:fe0a:326", Some("C4:B2:5B:0A:03:26")),
            neighbour("fe80::1234", Some("AA:BB:CC:DD:EE:FF")),
            neighbour("fe80::1234", Some("AA:BB:CC:DD:EE:FF")),
        ];

        let summary = merge(&mut devices, &neighbours, true);

        assert_eq!(summary, MergeSummary { matched: 1, added: 1 });
        assert_eq!(devices.len(), 2);

        let added = devices
            .iter()
            .find(|device| device.mac.as_deref() == Some("AA:BB:CC:DD:EE:FF"))
            .expect("the IPv6-only device");
        assert_eq!(added.ip, std::net::IpAddr::V6("fe80::1234".parse().expect("a valid address")));
        assert_eq!(added.ipv6_addresses, vec!["fe80::1234".to_string()]);
    }

    /// The neighbour table covers the whole link, so a scan narrowed to part
    /// of it must not report devices from the rest.
    #[test]
    fn test_a_narrowed_scan_annotates_but_does_not_add() {
        let mut devices = devices();
        let neighbours = [
            neighbour("fe80::c6b2:5bff:fe0a:326", Some("C4:B2:5B:0A:03:26")),
            neighbour("fe80::1234", Some("AA:BB:CC:DD:EE:FF")),
        ];

        let summary = merge(&mut devices, &neighbours, false);

        assert_eq!(summary, MergeSummary { matched: 1, added: 0 });
        assert_eq!(devices.len(), 1, "a device outside the target is not reported");
        assert_eq!(devices[0].ipv6_addresses, vec!["fe80::c6b2:5bff:fe0a:326".to_string()]);
    }

    /// An unanswered solicitation carries no hardware address, so there is
    /// nothing to attach it to.
    #[test]
    fn test_neighbours_without_a_mac_are_ignored() {
        let mut devices = devices();
        let summary = merge(&mut devices, &[neighbour("fe80::9", None)], true);

        assert_eq!(summary, MergeSummary::default());
        assert_eq!(devices.len(), 1);
    }

    /// Reading a table that is empty is an answer, not a failure — a machine
    /// with no IPv6 must not error out of a scan.
    #[test]
    fn test_reading_the_loopback_table_is_not_an_error() {
        let neighbours = read_neighbours("lo").expect("reading loopback neighbours");
        assert!(neighbours
            .iter()
            .all(|neighbour| !neighbour.address.is_unspecified()));
    }
}
