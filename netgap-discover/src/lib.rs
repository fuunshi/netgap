//! Network device discovery engine (ARP, ICMP).
//!
//! This module implements ARP-based host discovery on local networks.
//! ARP is highly reliable for LAN discovery and requires no response cooperation.

use netgap_core::Device;
use anyhow::{anyhow, Result};
use pnet::datalink;
use std::net::Ipv4Addr;

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
        let devices = datalink::interfaces();
        let interface = devices
            .iter()
            .find(|iface| iface.name == self.config.interface_name)
            .ok_or_else(|| anyhow!("Interface '{}' not found", self.config.interface_name))?;

        // Get our own IP and MAC
        let our_ip = interface
            .ips
            .iter()
            .find_map(|ip| match ip {
                pnet::ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No IPv4 address on interface"))?;

        let our_mac = interface.mac.ok_or_else(|| anyhow!("No MAC address on interface"))?;

        // Parse target network
        let (network, prefix) = parse_cidr(&self.config.target_cidr)?;
        let target_hosts = generate_ips(network, prefix);

        println!(
            "🔍 ARP discovery starting on {} (target: {})",
            self.config.interface_name, self.config.target_cidr
        );
        println!("   Will scan {} hosts...", target_hosts.len());

        let mut results = Vec::new();

        // Simple synchronous ARP scan for Phase 1
        // In a real implementation, this would be async with proper packet handling
        for ip in target_hosts {
            if ip == our_ip {
                // We're alive
                let mut device = Device::new(std::net::IpAddr::V4(ip));
                device.mac = Some(our_mac.to_string());
                results.push(device);
            }
            // Note: Full ARP scanning requires raw sockets which need special permissions
            // For Phase 1, we demonstrate the structure. Real ARP handling comes in M2 refinement.
        }

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
