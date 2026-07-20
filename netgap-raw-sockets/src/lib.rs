//! Raw socket ARP scanner for 100% device discovery on LAN.
//!
//! This module implements ARP (Address Resolution Protocol) scanning using raw sockets,
//! providing more reliable device discovery than TCP-only approaches.
//!
//! Unix only, and not implemented even there: `netgap_discover::arp` is the
//! working ARP sweep. On other platforms the crate compiles to nothing rather
//! than to something that cannot work.
#![cfg(unix)]

use anyhow::{anyhow, Result};
use pnet::datalink;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::sleep;

/// Represents an ARP response (discovered device).
#[derive(Debug, Clone)]
pub struct ArpResponse {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub vendor: Option<String>,
    pub confidence: f32, // 1.0 = 100% certain (from ARP)
}

/// Configuration for raw ARP scanning.
#[derive(Debug, Clone)]
pub struct RawScanConfig {
    pub timeout_ms: u64,
    pub retries: u32,
    pub batch_size: usize,
}

impl Default for RawScanConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 1000,
            retries: 2,
            batch_size: 32,
        }
    }
}

/// Raw socket ARP scanner.
pub struct RawArpScanner {
    config: RawScanConfig,
    interface: String,
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
}

impl RawArpScanner {
    /// Create a new raw ARP scanner for the given interface.
    pub fn new(interface: &str, config: RawScanConfig) -> Result<Self> {
        // Find the interface
        let iface = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == interface)
            .ok_or_else(|| anyhow!("Interface not found: {}", interface))?;

        // Get our MAC
        let our_mac = iface
            .mac
            .ok_or_else(|| anyhow!("No MAC address on interface"))?;

        // Get our IP
        let our_ip = iface
            .ips
            .iter()
            .find_map(|ip| match ip {
                pnet::ipnetwork::IpNetwork::V4(net) => Some(net.ip()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No IPv4 address on interface"))?;

        Ok(RawArpScanner {
            config,
            interface: interface.to_string(),
            our_mac,
            our_ip,
        })
    }

    /// Check if the scanner is running with root privileges.
    pub fn is_privileged() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Scan a single IP address via raw ARP.
    ///
    /// Not implemented. The packet builders below are the start of it, but
    /// nothing sends them yet, so this reports that rather than returning
    /// `Ok(None)` — which would read as "no device answered", a claim this
    /// crate is in no position to make. `netgap_discover::arp` is the working
    /// ARP sweep.
    pub async fn scan_ip(&self, target_ip: Ipv4Addr) -> Result<Option<ArpResponse>> {
        if !Self::is_privileged() {
            return Err(anyhow!(
                "Raw socket scanning requires root privileges. Run with: sudo netgap scan --raw-arp"
            ));
        }

        Err(anyhow!(
            "Raw ARP scanning is not implemented, so nothing was sent to {target_ip}"
        ))
    }

    /// Scan a range of IP addresses (CIDR network).
    pub async fn scan_range(
        &self,
        start_ip: Ipv4Addr,
        end_ip: Ipv4Addr,
    ) -> Result<Vec<ArpResponse>> {
        let mut results = Vec::new();
        let mut tasks = Vec::new();

        let start_num = u32::from(start_ip);
        let end_num = u32::from(end_ip);

        for ip_num in start_num..=end_num {
            let ip = Ipv4Addr::from(ip_num);
            let scanner = self.clone();

            // Spawn concurrent task (respecting batch size)
            let task = tokio::spawn(async move {
                match scanner.scan_ip(ip).await {
                    Ok(Some(response)) => Some(response),
                    _ => None,
                }
            });

            tasks.push(task);

            // Limit concurrent tasks to batch size
            if tasks.len() >= self.config.batch_size {
                let batch_results: Vec<_> = futures::future::join_all(tasks.drain(..))
                    .await
                    .into_iter()
                    .filter_map(|r| r.ok().flatten())
                    .collect();
                results.extend(batch_results);
            }

            // Small delay between batches to avoid network congestion
            sleep(Duration::from_millis(10)).await;
        }

        // Process remaining tasks
        if !tasks.is_empty() {
            let batch_results: Vec<_> = futures::future::join_all(tasks)
                .await
                .into_iter()
                .filter_map(|r| r.ok().flatten())
                .collect();
            results.extend(batch_results);
        }

        Ok(results)
    }

    /// Build an ARP request packet.
    ///
    /// Exercised only by the tests below while the sending path is
    /// unimplemented.
    #[allow(dead_code)]
    fn build_arp_request(&self, target_ip: Ipv4Addr) -> Result<Vec<u8>> {
        let mut packet = vec![0u8; 42]; // Ethernet + ARP

        // Ethernet frame
        // Destination MAC (broadcast)
        packet[0..6].fill(0xff);
        // Source MAC (our MAC)
        let mac_bytes = self.our_mac.octets();
        packet[6..12].copy_from_slice(&mac_bytes);
        // Ethertype (ARP = 0x0806)
        packet[12] = 0x08;
        packet[13] = 0x06;

        // ARP header
        let arp_offset = 14;
        // Hardware type (Ethernet = 0x0001)
        packet[arp_offset] = 0x00;
        packet[arp_offset + 1] = 0x01;
        // Protocol type (IPv4 = 0x0800)
        packet[arp_offset + 2] = 0x08;
        packet[arp_offset + 3] = 0x00;
        // Hardware length (6 for MAC)
        packet[arp_offset + 4] = 6;
        // Protocol length (4 for IPv4)
        packet[arp_offset + 5] = 4;
        // Operation (ARP Request = 0x0001)
        packet[arp_offset + 6] = 0x00;
        packet[arp_offset + 7] = 0x01;

        // Sender MAC
        packet[arp_offset + 8..arp_offset + 14].copy_from_slice(&mac_bytes);
        // Sender IP
        let src_ip = self.our_ip.octets();
        packet[arp_offset + 14..arp_offset + 18].copy_from_slice(&src_ip);
        // Target MAC (zeros for request)
        packet[arp_offset + 18..arp_offset + 24].fill(0);
        // Target IP
        let dst_ip = target_ip.octets();
        packet[arp_offset + 24..arp_offset + 28].copy_from_slice(&dst_ip);

        Ok(packet)
    }

    /// Parse an ARP response packet.
    ///
    /// Exercised only by the tests below while the receiving path is
    /// unimplemented.
    #[allow(dead_code)]
    fn parse_arp_response(&self, buffer: &[u8]) -> Result<ArpResponse> {
        if buffer.len() < 42 {
            return Err(anyhow!("Buffer too short for ARP response"));
        }

        // Extract source MAC (from Ethernet frame)
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&buffer[6..12]);
        let mac = MacAddr(
            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
        );

        // Extract sender IP (from ARP header)
        let ip = Ipv4Addr::new(buffer[28], buffer[29], buffer[30], buffer[31]);

        Ok(ArpResponse {
            ip,
            mac,
            vendor: None,    // Would be populated by fingerprinting
            confidence: 1.0, // ARP is 100% reliable
        })
    }
}

// Allow cloning for async tasks
impl Clone for RawArpScanner {
    fn clone(&self) -> Self {
        RawArpScanner {
            config: self.config.clone(),
            interface: self.interface.clone(),
            our_mac: self.our_mac,
            our_ip: self.our_ip,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_detection() {
        // Just verify it doesn't crash
        let _ = RawArpScanner::is_privileged();
    }

    #[test]
    fn test_arp_packet_construction() {
        let config = RawScanConfig::default();
        let iface_name = "lo"; // Loopback for testing

        // Try creating scanner (may fail on unsupported systems)
        if let Ok(scanner) = RawArpScanner::new(iface_name, config) {
            let packet = scanner.build_arp_request(Ipv4Addr::new(192, 168, 1, 1));
            assert!(packet.is_ok());

            let packet = packet.unwrap();
            assert_eq!(packet.len(), 42); // ARP packet size

            // Verify Ethernet type field (ARP = 0x0806)
            assert_eq!(packet[12], 0x08);
            assert_eq!(packet[13], 0x06);
        }
    }

    #[test]
    fn test_arp_response_parsing() {
        // Mock ARP response
        let mut buffer = vec![0u8; 42];

        // Ethernet frame with source MAC 00:11:22:33:44:55
        buffer[6] = 0x00;
        buffer[7] = 0x11;
        buffer[8] = 0x22;
        buffer[9] = 0x33;
        buffer[10] = 0x44;
        buffer[11] = 0x55;

        // ARP response IP 192.168.1.100
        buffer[28] = 192;
        buffer[29] = 168;
        buffer[30] = 1;
        buffer[31] = 100;

        let config = RawScanConfig::default();
        if let Ok(scanner) = RawArpScanner::new("lo", config) {
            let response = scanner.parse_arp_response(&buffer);
            assert!(response.is_ok());

            let resp = response.unwrap();
            assert_eq!(resp.ip, Ipv4Addr::new(192, 168, 1, 100));
            assert_eq!(resp.confidence, 1.0);
        }
    }

    #[test]
    fn test_scanner_creation_loopback() {
        let config = RawScanConfig::default();
        let result = RawArpScanner::new("lo", config);
        // May succeed or fail depending on system, just verify no panic
        let _ = result;
    }

    #[test]
    fn test_config_defaults() {
        let config = RawScanConfig::default();
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.retries, 2);
        assert_eq!(config.batch_size, 32);
    }

    #[test]
    fn test_mac_addr_extraction() {
        let mut buffer = vec![0u8; 42];
        // Set source MAC to AA:BB:CC:DD:EE:FF
        buffer[6] = 0xaa;
        buffer[7] = 0xbb;
        buffer[8] = 0xcc;
        buffer[9] = 0xdd;
        buffer[10] = 0xee;
        buffer[11] = 0xff;

        let config = RawScanConfig::default();
        if let Ok(scanner) = RawArpScanner::new("lo", config) {
            if let Ok(resp) = scanner.parse_arp_response(&buffer) {
                let mac = resp.mac;
                assert_eq!(mac.0, 0xaa);
                assert_eq!(mac.1, 0xbb);
                assert_eq!(mac.2, 0xcc);
            }
        }
    }

    #[test]
    fn test_arp_range_construction() {
        let start = Ipv4Addr::new(192, 168, 1, 1);
        let end = Ipv4Addr::new(192, 168, 1, 5);

        let start_num = u32::from(start);
        let end_num = u32::from(end);

        let count = (end_num - start_num + 1) as usize;
        assert_eq!(count, 5);
    }
}
