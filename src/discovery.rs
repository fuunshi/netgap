use anyhow::{anyhow, Context, Result};
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::icmp::{checksum as icmp_checksum, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol,
};
use pnet::util::MacAddr;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use crate::model::{DiscoveredHost, InterfaceInfo, ScanMode};

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let interfaces = datalink::interfaces();

    Ok(interfaces
        .into_iter()
        .map(|interface| InterfaceInfo {
            is_up: interface.is_up(),
            is_loopback: interface.is_loopback(),
            name: interface.name,
            ips: interface.ips.iter().map(|ip| ip.ip().to_string()).collect(),
            mac: interface.mac.map(|mac| mac.to_string()),
        })
        .collect())
}

pub fn select_interface(name: Option<&str>) -> Result<NetworkInterface> {
    let interfaces = datalink::interfaces();

    if let Some(name) = name {
        interfaces
            .into_iter()
            .find(|interface| interface.name == name)
            .ok_or_else(|| anyhow!("interface '{name}' was not found"))
    } else {
        interfaces
            .into_iter()
            .find(|interface| interface.is_up() && !interface.is_loopback())
            .context("no usable interface found; pass --interface to choose one")
    }
}

pub fn primary_ipv4(interface: &NetworkInterface) -> Result<Ipv4Addr> {
    interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(addr) => Some(addr),
            _ => None,
        })
        .context("selected interface does not have an IPv4 address")
}

pub fn discover_hosts(interface: &NetworkInterface, mode: ScanMode) -> Result<Vec<Ipv4Addr>> {
    let mut hosts = Vec::new();

    for ip_network in &interface.ips {
        if let IpAddr::V4(addr) = ip_network.ip() {
            let prefix = ip_network.prefix();
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = u32::from(addr) & mask;
            let broadcast = network | !mask;

            let start = network.saturating_add(1);
            let end = broadcast.saturating_sub(1);
            let host_limit = match mode {
                ScanMode::Quick => 64,
                ScanMode::Full => 256,
            };

            for value in start..=end {
                if hosts.len() >= host_limit {
                    break;
                }

                let candidate = Ipv4Addr::from(value);
                if candidate != addr {
                    hosts.push(candidate);
                }
            }
        }
    }

    if hosts.is_empty() {
        Err(anyhow!(
            "no IPv4 targets could be derived from interface {}",
            interface.name
        ))
    } else {
        Ok(hosts)
    }
}

pub fn discover_network(
    interface: &NetworkInterface,
    mode: ScanMode,
) -> Result<Vec<DiscoveredHost>> {
    let targets = discover_hosts(interface, mode)?;
    let mut discovered = arp_discover(interface, &targets)?;

    for (ip, host) in icmp_probe(interface, &targets)? {
        discovered.entry(ip).or_insert(host);
    }

    Ok(discovered.into_values().collect())
}

fn arp_discover(
    interface: &NetworkInterface,
    targets: &[Ipv4Addr],
) -> Result<HashMap<Ipv4Addr, DiscoveredHost>> {
    let source_ip = primary_ipv4(interface)?;
    let source_mac = interface
        .mac
        .context("selected interface does not expose a MAC address")?;

    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(200));
    let (mut tx, mut rx) = match datalink::channel(interface, config)? {
        Ethernet(tx, rx) => (tx, rx),
        _ => return Err(anyhow!("unsupported datalink channel")),
    };

    for target in targets {
        let mut frame = [0u8; 42];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(source_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp = MutableArpPacket::new(ethernet.payload_mut()).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        arp.set_sender_proto_addr(source_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(*target);

        tx.send_to(&frame, None)
            .ok_or_else(|| anyhow!("failed to send ARP request"))??;
    }

    let mut discovered = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(2);

    while Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }

                    if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                        if arp.get_operation() != ArpOperations::Reply {
                            continue;
                        }

                        let ip = arp.get_sender_proto_addr();
                        discovered.insert(
                            ip,
                            DiscoveredHost {
                                ip: ip.to_string(),
                                mac: Some(arp.get_sender_hw_addr().to_string()),
                                hostname: reverse_dns(ip),
                            },
                        );
                    }
                }
            }
            Err(_) => break,
        }
    }

    Ok(discovered)
}

fn icmp_probe(
    interface: &NetworkInterface,
    targets: &[Ipv4Addr],
) -> Result<HashMap<Ipv4Addr, DiscoveredHost>> {
    let _source_ip = primary_ipv4(interface)?;
    let (mut tx, mut rx) = transport_channel(
        1024,
        Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    let mut iter = icmp_packet_iter(&mut rx);
    let mut discovered = HashMap::new();
    let mut rng = thread_rng();

    for target in targets.iter().take(32) {
        let mut buffer = [0u8; 16];
        let mut request = MutableEchoRequestPacket::new(&mut buffer).unwrap();
        request.set_icmp_type(IcmpTypes::EchoRequest);
        request.set_icmp_code(IcmpCodes::NoCode);
        request.set_identifier(rng.gen());
        request.set_sequence_number(rng.gen());
        request.set_checksum(0);
        let checksum = icmp_checksum(&IcmpPacket::new(request.packet()).unwrap());
        request.set_checksum(checksum);
        tx.send_to(request, IpAddr::V4(*target))?;

        if let Ok(Some((packet, addr))) = iter.next_with_timeout(Duration::from_millis(200)) {
            if addr == IpAddr::V4(*target) && packet.get_icmp_type() == IcmpTypes::EchoReply {
                discovered.insert(
                    *target,
                    DiscoveredHost {
                        ip: target.to_string(),
                        mac: None,
                        hostname: reverse_dns(*target),
                    },
                );
            }
        }
    }

    Ok(discovered)
}

pub fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()
}
