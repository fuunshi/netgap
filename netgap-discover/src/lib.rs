//! Network device discovery engine.
//!
//! This module performs ARP-based host discovery on the selected LAN subnet.
//! It sends broadcast ARP requests and records any replies, so it discovers
//! peers on the network instead of only reporting the local host.

use anyhow::{anyhow, Result};
use netgap_core::Device;
use pnet::datalink::{self, Channel::Ethernet, Config};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// Configuration for ARP discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Network interface to use.
    pub interface_name: String,
    /// Target network in CIDR notation (e.g., "192.168.1.0/24").
    pub target_cidr: String,
    /// Timeout per ARP request in milliseconds.
    pub timeout_ms: u64,
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

    /// Run ARP sweep on the configured network.
    /// Returns list of discovered devices with MAC addresses.
    pub async fn scan(&self) -> Result<Vec<Device>> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == self.config.interface_name)
            .ok_or_else(|| anyhow!("Interface '{}' not found", self.config.interface_name))?;

        let (network, prefix) = parse_cidr(&self.config.target_cidr)?;
        let target_hosts = generate_ips(network, prefix);

        let source_ip = interface
            .ips
            .iter()
            .find_map(|ip| match ip {
                pnet::ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No IPv4 address on interface '{}'", self.config.interface_name))?;

        let source_mac = interface
            .mac
            .ok_or_else(|| anyhow!("No MAC address on interface '{}'", self.config.interface_name))?;

        println!(
            "🔍 ARP discovery starting on {} (target: {})",
            self.config.interface_name, self.config.target_cidr
        );
        println!("   Will scan {} hosts...", target_hosts.len());

        let mut config = Config::default();
        config.read_timeout = Some(Duration::from_millis(self.config.timeout_ms));

        let (mut tx, mut rx) = match datalink::channel(&interface, config)? {
            Ethernet(tx, rx) => (tx, rx),
            _ => return Err(anyhow!("unsupported datalink channel")),
        };

        for target_ip in &target_hosts {
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
            arp.set_target_proto_addr(*target_ip);

            tx.send_to(&frame, None)
                .ok_or_else(|| anyhow!("failed to send ARP request"))??;
        }

        let mut discovered: HashMap<Ipv4Addr, Device> = HashMap::new();
        let deadline = Instant::now() + Duration::from_millis(self.config.timeout_ms);

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
                            let mut device = Device::new(IpAddr::V4(ip));
                            device.mac = Some(arp.get_sender_hw_addr().to_string());
                            discovered.insert(ip, device);
                        }
                    }
                }
                Err(_) => break,
            }
        }

        let mut results: Vec<Device> = discovered.into_values().collect();
        results.sort_by_key(|device| device.ip.to_string());

        println!("✓ Discovery complete: found {} host(s)", results.len());
        Ok(results)
    }
}

/// Parse CIDR notation (e.g., "192.168.1.0/24") into network and prefix.
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid CIDR format: expected 'X.X.X.X/prefix'"));
    }

    let network: Ipv4Addr = parts[0].parse()?;
    let prefix: u32 = parts[1].parse()?;

    if prefix > 32 {
        return Err(anyhow!("Prefix must be between 0 and 32"));
    }

    Ok((network, prefix))
}

/// Generate all IP addresses in a network given CIDR.
fn generate_ips(network: Ipv4Addr, prefix: u32) -> Vec<Ipv4Addr> {
    let mask = if prefix == 0 {
        0u32
    } else {
        (!0u32) << (32 - prefix)
    };

    let start = u32::from(network) & mask;
    let end = start | (!mask);
    let mut ips = Vec::new();

    if end <= start + 1 {
        return ips;
    }

    // Skip network address and broadcast
    for i in (start + 1)..end {
        ips.push(Ipv4Addr::from(i));
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_valid() {
        let (network, prefix) = parse_cidr("192.168.1.0/24").expect("Parse failed");
        assert_eq!(network, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_cidr_invalid_format() {
        assert!(parse_cidr("192.168.1.0").is_err());
    }

    #[test]
    fn test_generate_ips_24_subnet() {
        let ips = generate_ips(Ipv4Addr::new(192, 168, 1, 0), 24);
        // Should have 254 hosts (skip .0 and .255)
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_generate_ips_30_subnet() {
        let ips = generate_ips(Ipv4Addr::new(10, 0, 0, 0), 30);
        // /30 has 4 addresses total, 2 usable (skip .0 and .3)
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips[1], Ipv4Addr::new(10, 0, 0, 2));
    }
}
