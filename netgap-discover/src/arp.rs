//! ARP-based host discovery.
//!
//! Sends broadcast ARP requests across the target subnet and records the
//! replies, which discovers every peer that answers ARP — including hosts that
//! drop TCP. Requires a raw socket (root or `CAP_NET_RAW`).

use crate::conflicts::MacChange;
use crate::{classify_channel_error, hosts_in_cidr, parse_cidr, DiscoveryConfig, DiscoveryError};
use anyhow::{anyhow, Result};
use netgap_core::Device;
use pnet::datalink::{self, Channel::Ethernet, Config, DataLinkReceiver};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// How long a single blocking read may last before control returns to the loop.
const READ_SLICE: Duration = Duration::from_millis(20);
/// Frames sent before draining the socket and yielding.
const SEND_BATCH: usize = 32;
/// Pause between send batches to let the kernel flush.
const SEND_PAUSE: Duration = Duration::from_millis(1);

/// Silent read slices tolerated before deciding no more replies are coming.
///
/// Deliberately generous: a broadcast burst goes out immediately, but replies
/// straggle in for hundreds of milliseconds — Wi-Fi stations in power save only
/// wake on their DTIM interval, and the access point serialises delivery. A
/// short cutoff returns an arbitrary subset of the network, which is exactly
/// the "sometimes 3 hosts, sometimes 16" symptom.
fn idle_slices(timeout_ms: u64) -> u32 {
    let silence_budget = timeout_ms / 2;
    let slices = silence_budget / READ_SLICE.as_millis() as u64;
    slices.max(5).min(u32::MAX as u64) as u32
}

/// Represents an ARP discovery session.
pub struct ArpDiscovery {
    config: DiscoveryConfig,
}

impl ArpDiscovery {
    /// Create a new ARP discovery session.
    pub fn new(config: DiscoveryConfig) -> Self {
        ArpDiscovery { config }
    }

    /// Run an ARP sweep, returning the devices and any address conflicts.
    async fn sweep(&self) -> Result<(Vec<Device>, Vec<MacChange>)> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == self.config.interface_name)
            .ok_or_else(|| DiscoveryError::InterfaceNotFound(self.config.interface_name.clone()))?;

        let (network, prefix) = parse_cidr(&self.config.target_cidr)?;
        let target_hosts = hosts_in_cidr(network, prefix, self.config.max_hosts)?;

        let source_ip = interface
            .ips
            .iter()
            .find_map(|ip| match ip {
                IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                _ => None,
            })
            .ok_or_else(|| {
                anyhow!(
                    "No IPv4 address on interface '{}'",
                    self.config.interface_name
                )
            })?;

        let source_mac = interface.mac.ok_or_else(|| {
            anyhow!(
                "No MAC address on interface '{}'",
                self.config.interface_name
            )
        })?;

        println!(
            "🔍 ARP discovery starting on {} (target: {})",
            self.config.interface_name, self.config.target_cidr
        );
        eprintln!("   Will scan {} hosts...", target_hosts.len());

        let config = Config {
            read_timeout: Some(READ_SLICE),
            ..Config::default()
        };

        let (mut tx, mut rx) = match datalink::channel(&interface, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow!("unsupported datalink channel")),
            Err(error) => return Err(classify_channel_error(error)),
        };

        let targets: HashSet<Ipv4Addr> = target_hosts.iter().copied().collect();
        let mut discovered: HashMap<Ipv4Addr, Device> = HashMap::new();
        let mut conflicts: Vec<MacChange> = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(self.config.timeout_ms.max(200));
        let retries = self.config.retries.max(1);

        // Sweep more than once, spreading the passes across the whole budget.
        // Sending them back to back would put every request in the first few
        // hundred milliseconds, so a station that wakes up later — Wi-Fi power
        // save only listens on its DTIM interval — would miss all of them.
        let timeout_ms = self.config.timeout_ms.max(200);
        let pass_budget = Duration::from_millis((timeout_ms / retries as u64).max(50));

        for _ in 1..=retries {
            if Instant::now() >= deadline {
                break;
            }
            let pass_deadline = (Instant::now() + pass_budget).min(deadline);

            for batch in target_hosts.chunks(SEND_BATCH) {
                if Instant::now() >= pass_deadline {
                    break;
                }

                for target_ip in batch {
                    let frame = build_arp_request(source_mac, source_ip, *target_ip);
                    tx.send_to(&frame, None)
                        .ok_or_else(|| anyhow!("failed to send ARP request"))??;
                }

                tokio::time::sleep(SEND_PAUSE).await;
                // Drain briefly so replies land while later batches go out.
                collect_replies(
                    &mut *rx,
                    Instant::now() + READ_SLICE,
                    &targets,
                    &mut discovered,
                    &mut conflicts,
                    1,
                )?;
            }

            // Read out the rest of this pass's slot before the next burst.
            let idle_limit = idle_slices(pass_budget.as_millis() as u64);
            collect_replies(
                &mut *rx,
                pass_deadline,
                &targets,
                &mut discovered,
                &mut conflicts,
                idle_limit,
            )?;
        }

        // Anything still in flight when the budget ran out.
        collect_replies(
            &mut *rx,
            deadline,
            &targets,
            &mut discovered,
            &mut conflicts,
            idle_slices(timeout_ms),
        )?;

        // The kernel's ARP layer saw every reply the network delivered,
        // including ones this socket missed. Fold those in so the result does
        // not depend on userspace read timing.
        let from_neighbors = merge_neighbor_hosts(
            &mut discovered,
            &crate::neighbor::read_neighbor_table(),
            &targets,
            &self.config.interface_name,
        );

        eprintln!("✓ Discovery complete: found {} host(s)", discovered.len());
        if from_neighbors > 0 {
            eprintln!(
                "   {} recovered from the kernel neighbour table",
                from_neighbors
            );
        }

        let mut results: Vec<Device> = discovered.into_values().collect();
        results.sort_by_key(|device| match device.ip {
            IpAddr::V4(ipv4) => u32::from(ipv4),
            IpAddr::V6(_) => u32::MAX,
        });

        conflicts.sort_by_key(|conflict| u32::from(conflict.ip));
        Ok((results, conflicts))
    }

    /// Run an ARP sweep, reporting addresses that answered from two different
    /// hardware addresses as well as the devices found.
    pub async fn scan_with_conflicts(&self) -> Result<(Vec<Device>, Vec<MacChange>)> {
        self.sweep().await
    }

    /// Run an ARP sweep on the configured network.
    /// Returns discovered devices with MAC addresses.
    pub async fn scan(&self) -> Result<Vec<Device>> {
        self.sweep().await.map(|(devices, _)| devices)
    }
}

/// Read ARP replies until `deadline`, or until `idle_limit` consecutive read
/// timeouts mean the replies have stopped.
///
/// A read timeout is expected here — it is how the loop checks the deadline —
/// so it must never abort collection. Only a non-timeout I/O error does.
pub(crate) fn collect_replies<R: DataLinkReceiver + ?Sized>(
    rx: &mut R,
    deadline: Instant,
    targets: &HashSet<Ipv4Addr>,
    discovered: &mut HashMap<Ipv4Addr, Device>,
    conflicts: &mut Vec<MacChange>,
    idle_limit: u32,
) -> Result<()> {
    let mut idle_slices = 0;

    while Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                idle_slices = 0;
                record_reply(packet, targets, discovered, conflicts);
            }
            Err(error) if error.kind() == ErrorKind::TimedOut => {
                idle_slices += 1;
                if idle_slices >= idle_limit {
                    break;
                }
            }
            Err(error) => return Err(error.into()),
        }
    }

    Ok(())
}

/// Record an ARP reply if it came from one of the addresses we asked about.
///
/// A second reply for the same address from a *different* hardware address is
/// recorded as a conflict: on a healthy network each address belongs to one
/// device, and two devices answering for one address is how an interception
/// starts. The reply is still recorded, so the sweep reports whoever answered
/// last rather than pretending the address went quiet.
fn record_reply(
    packet: &[u8],
    targets: &HashSet<Ipv4Addr>,
    discovered: &mut HashMap<Ipv4Addr, Device>,
    conflicts: &mut Vec<MacChange>,
) {
    let Some(ethernet) = EthernetPacket::new(packet) else {
        return;
    };
    if ethernet.get_ethertype() != EtherTypes::Arp {
        return;
    }

    let Some(arp) = ArpPacket::new(ethernet.payload()) else {
        return;
    };
    if arp.get_operation() != ArpOperations::Reply {
        return;
    }

    let ip = arp.get_sender_proto_addr();
    if !targets.contains(&ip) {
        return;
    }

    // The neighbour table reports addresses in upper case; matching that here
    // keeps one device from displaying differently depending on which path
    // found it.
    let mac = arp.get_sender_hw_addr().to_string().to_ascii_uppercase();

    if let Some(existing) = discovered.get(&ip) {
        if let Some(previous_mac) = &existing.mac {
            if !previous_mac.eq_ignore_ascii_case(&mac) {
                let change = MacChange {
                    ip,
                    previous_mac: previous_mac.clone(),
                    current_mac: mac.clone(),
                };
                if !conflicts.contains(&change) {
                    conflicts.push(change);
                }
            }
        }
    }

    let mut device = Device::new(IpAddr::V4(ip));
    device.mac = Some(mac);
    discovered.insert(ip, device);
}

/// Add hosts the kernel resolved during the sweep but this socket did not read.
///
/// Returns how many were added. Only entries on the scanned interface and
/// inside the target subnet count, so a sweep of one network is never padded
/// with devices from another (a docker bridge, a VPN).
fn merge_neighbor_hosts(
    discovered: &mut HashMap<Ipv4Addr, Device>,
    entries: &[crate::neighbor::NeighborEntry],
    targets: &HashSet<Ipv4Addr>,
    interface_name: &str,
) -> usize {
    let mut merged = 0;

    for entry in entries {
        if entry.iface != interface_name
            || !targets.contains(&entry.ip)
            || discovered.contains_key(&entry.ip)
        {
            continue;
        }

        let mut device = Device::new(IpAddr::V4(entry.ip));
        device.mac = Some(entry.mac.clone());
        discovered.insert(entry.ip, device);
        merged += 1;
    }

    merged
}

/// Build an Ethernet/IPv4 ARP request frame for `target_ip`.
fn build_arp_request(source_mac: MacAddr, source_ip: Ipv4Addr, target_ip: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0u8; 42];
    let mut ethernet = MutableEthernetPacket::new(&mut frame).expect("42 bytes is a valid frame");
    ethernet.set_destination(MacAddr::broadcast());
    ethernet.set_source(source_mac);
    ethernet.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(ethernet.payload_mut()).expect("ARP payload fits");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(source_mac);
    arp.set_sender_proto_addr(source_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target_ip);

    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io;

    const OUR_MAC: MacAddr = MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
    const OUR_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

    /// A receiver that replays a scripted sequence of reads.
    struct MockReceiver {
        script: VecDeque<io::Result<Vec<u8>>>,
        current: Vec<u8>,
    }

    impl MockReceiver {
        fn mock(script: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                script: script.into(),
                current: Vec::new(),
            }
        }

        fn timeout_error() -> io::Error {
            io::Error::new(ErrorKind::TimedOut, "Timed out")
        }

        fn timed_out() -> io::Result<Vec<u8>> {
            Err(Self::timeout_error())
        }
    }

    impl DataLinkReceiver for MockReceiver {
        fn next(&mut self) -> io::Result<&[u8]> {
            match self.script.pop_front() {
                Some(Ok(bytes)) => {
                    self.current = bytes;
                    Ok(&self.current)
                }
                Some(Err(error)) => Err(error),
                // Ran out of script: behave like an idle wire.
                None => Err(Self::timeout_error()),
            }
        }
    }

    /// Build an ARP reply frame as it would appear on the wire.
    fn arp_reply(sender_mac: MacAddr, sender_ip: Ipv4Addr) -> Vec<u8> {
        let mut frame = vec![0u8; 42];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).expect("valid frame");
        ethernet.set_destination(OUR_MAC);
        ethernet.set_source(sender_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(ethernet.payload_mut()).expect("valid payload");
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(sender_mac);
        arp.set_sender_proto_addr(sender_ip);
        arp.set_target_hw_addr(OUR_MAC);
        arp.set_target_proto_addr(OUR_IP);
        frame
    }

    fn targets(ips: &[Ipv4Addr]) -> HashSet<Ipv4Addr> {
        ips.iter().copied().collect()
    }

    #[test]
    fn test_build_arp_request_is_well_formed() {
        let frame = build_arp_request(OUR_MAC, OUR_IP, Ipv4Addr::new(192, 168, 1, 1));
        let ethernet = EthernetPacket::new(&frame).expect("valid ethernet");
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Arp);
        assert_eq!(ethernet.get_destination(), MacAddr::broadcast());
        assert_eq!(ethernet.get_source(), OUR_MAC);

        let arp = ArpPacket::new(ethernet.payload()).expect("valid arp");
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_proto_addr(), OUR_IP);
        assert_eq!(arp.get_target_proto_addr(), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_collect_replies_continues_after_timeouts() {
        let responder = Ipv4Addr::new(192, 168, 1, 1);
        let mac = MacAddr(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        // Timeout first: the old implementation broke out of the loop here and
        // lost every host on the network.
        let mut rx = MockReceiver::mock(vec![
            MockReceiver::timed_out(),
            Ok(arp_reply(mac, responder)),
            MockReceiver::timed_out(),
            MockReceiver::timed_out(),
        ]);

        let mut discovered = HashMap::new();
        let mut conflicts = Vec::new();
        collect_replies(
            &mut rx,
            Instant::now() + Duration::from_millis(500),
            &targets(&[responder]),
            &mut discovered,
            &mut conflicts,
            3,
        )
        .expect("collection should succeed");

        assert_eq!(discovered.len(), 1);
        let device = discovered.get(&responder).expect("host recorded");
        assert_eq!(device.mac.as_deref(), Some("00:11:22:33:44:55"));
    }

    #[test]
    fn test_collect_replies_stops_after_idle_slices() {
        let mut rx = MockReceiver::mock(
            (0..50).map(|_| MockReceiver::timed_out()).collect(),
        );

        let started = Instant::now();
        collect_replies(
            &mut rx,
            Instant::now() + Duration::from_secs(30),
            &targets(&[]),
            &mut HashMap::new(),
            &mut Vec::new(),
            2,
        )
        .expect("collection should succeed");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "idle slices should end collection early"
        );
    }

    #[test]
    fn test_collect_replies_ignores_hosts_outside_target() {
        let stranger = Ipv4Addr::new(10, 0, 0, 9);
        let mut rx = MockReceiver::mock(vec![
            Ok(arp_reply(MacAddr(0, 1, 2, 3, 4, 5), stranger)),
            MockReceiver::timed_out(),
            MockReceiver::timed_out(),
        ]);

        let mut discovered = HashMap::new();
        let mut conflicts = Vec::new();
        collect_replies(
            &mut rx,
            Instant::now() + Duration::from_millis(200),
            &targets(&[Ipv4Addr::new(192, 168, 1, 1)]),
            &mut discovered,
            &mut conflicts,
            2,
        )
        .expect("collection should succeed");

        assert!(discovered.is_empty());
    }

    /// A reply that arrives after several silent slices must still be
    /// collected: on Wi-Fi the whole reply set can lag the request burst.
    #[test]
    fn test_collect_replies_tolerates_a_long_silence_before_replying() {
        let responder = Ipv4Addr::new(192, 168, 1, 7);
        let mut script: Vec<io::Result<Vec<u8>>> =
            (0..8).map(|_| MockReceiver::timed_out()).collect();
        script.push(Ok(arp_reply(MacAddr(9, 9, 9, 9, 9, 9), responder)));

        let mut rx = MockReceiver::mock(script);
        let mut discovered = HashMap::new();
        let mut conflicts = Vec::new();

        collect_replies(
            &mut rx,
            Instant::now() + Duration::from_secs(5),
            &targets(&[responder]),
            &mut discovered,
            &mut conflicts,
            idle_slices(1000),
        )
        .expect("collection should succeed");

        assert_eq!(discovered.len(), 1, "late replies must not be cut off");
    }

    #[test]
    fn test_two_macs_answering_for_one_address_is_a_conflict() {
        let responder = Ipv4Addr::new(192, 168, 1, 1);
        let honest = arp_reply(MacAddr(0xAA, 0, 0, 0, 0, 1), responder);
        let impostor = arp_reply(MacAddr(0xDE, 0xAD, 0xBE, 0xEF, 0, 1), responder);

        let mut rx = MockReceiver::mock(vec![
            Ok(honest),
            MockReceiver::timed_out(),
            Ok(impostor),
            MockReceiver::timed_out(),
            MockReceiver::timed_out(),
        ]);

        let mut discovered = HashMap::new();
        let mut conflicts = Vec::new();

        collect_replies(
            &mut rx,
            Instant::now() + Duration::from_millis(300),
            &targets(&[responder]),
            &mut discovered,
            &mut conflicts,
            idle_slices(1000),
        )
        .expect("collection should succeed");

        assert_eq!(conflicts.len(), 1, "one address claimed twice");
        assert_eq!(conflicts[0].ip, responder);
        assert_eq!(conflicts[0].previous_mac, "AA:00:00:00:00:01");
        assert_eq!(conflicts[0].current_mac, "DE:AD:BE:EF:00:01");

        // The device is still reported, as whoever answered last.
        assert_eq!(discovered[&responder].mac.as_deref(), Some("DE:AD:BE:EF:00:01"));
    }

    #[test]
    fn test_repeated_replies_from_one_device_are_not_a_conflict() {
        let responder = Ipv4Addr::new(192, 168, 1, 1);
        let reply = arp_reply(MacAddr(0xAA, 0, 0, 0, 0, 1), responder);

        let mut rx = MockReceiver::mock(vec![
            Ok(reply.clone()),
            Ok(reply),
            MockReceiver::timed_out(),
            MockReceiver::timed_out(),
        ]);

        let mut conflicts = Vec::new();
        collect_replies(
            &mut rx,
            Instant::now() + Duration::from_millis(200),
            &targets(&[responder]),
            &mut HashMap::new(),
            &mut conflicts,
            idle_slices(1000),
        )
        .expect("collection should succeed");

        assert!(conflicts.is_empty(), "a device answering twice is normal");
    }

    #[test]
    fn test_idle_budget_scales_with_timeout() {
        // A 1s budget tolerates ~500ms of silence, well beyond the 200ms that
        // used to truncate sweeps.
        assert!(idle_slices(1000) >= 25);
        assert!(idle_slices(2000) > idle_slices(1000));
        assert!(idle_slices(1) >= 5, "always allow some silence");
    }

    #[test]
    fn test_merge_neighbor_hosts_filters_and_dedupes() {
        let known = Ipv4Addr::new(192, 168, 1, 1);
        let recovered = Ipv4Addr::new(192, 168, 1, 2);
        let off_target = Ipv4Addr::new(10, 0, 0, 5);
        let other_iface = Ipv4Addr::new(192, 168, 1, 3);

        let entries = vec![
            neighbor_entry(known, "AA:AA:AA:AA:AA:AA", "wlan0"),
            neighbor_entry(recovered, "BB:BB:BB:BB:BB:BB", "wlan0"),
            neighbor_entry(off_target, "CC:CC:CC:CC:CC:CC", "wlan0"),
            neighbor_entry(other_iface, "DD:DD:DD:DD:DD:DD", "docker0"),
        ];

        let mut discovered = HashMap::new();
        discovered.insert(known, Device::new(IpAddr::V4(known)));
        // The sweep targeted these three; `off_target` belongs to another subnet.
        let targets: HashSet<Ipv4Addr> = [known, recovered, other_iface].into_iter().collect();

        let merged = merge_neighbor_hosts(&mut discovered, &entries, &targets, "wlan0");

        assert_eq!(merged, 1, "only the on-target, on-interface host is added");
        assert_eq!(discovered.len(), 2);
        assert_eq!(
            discovered[&recovered].mac.as_deref(),
            Some("BB:BB:BB:BB:BB:BB")
        );
        assert!(!discovered.contains_key(&off_target), "off-subnet excluded");
        assert!(!discovered.contains_key(&other_iface), "other interface excluded");
    }

    fn neighbor_entry(ip: Ipv4Addr, mac: &str, iface: &str) -> crate::neighbor::NeighborEntry {
        crate::neighbor::NeighborEntry {
            ip,
            mac: mac.to_string(),
            iface: iface.to_string(),
        }
    }

    #[test]
    fn test_collect_replies_dedupes_by_ip() {
        let responder = Ipv4Addr::new(192, 168, 1, 1);
        let reply = arp_reply(MacAddr(0, 1, 2, 3, 4, 5), responder);
        let mut rx = MockReceiver::mock(vec![
            Ok(reply.clone()),
            Ok(reply),
            MockReceiver::timed_out(),
            MockReceiver::timed_out(),
        ]);

        let mut discovered = HashMap::new();
        let mut conflicts = Vec::new();
        collect_replies(
            &mut rx,
            Instant::now() + Duration::from_millis(200),
            &targets(&[responder]),
            &mut discovered,
            &mut conflicts,
            2,
        )
        .expect("collection should succeed");

        assert_eq!(discovered.len(), 1);
    }
}
