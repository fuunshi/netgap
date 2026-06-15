//! Network device discovery engine.
//!
//! Two discovery strategies are provided:
//!
//! * [`ArpDiscovery`] — an ARP sweep that finds peers directly on the LAN. It
//!   needs a raw socket (root or `CAP_NET_RAW`) but reaches hosts that never
//!   answer TCP.
//! * [`TcpSweeper`] — an unprivileged fallback that probes the subnet with TCP
//!   connects and enriches results from the kernel neighbour table.
//!
//! Use [`privilege::has_cap_net_raw`] to decide which to run.

use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

pub mod arp;
pub mod conflicts;
pub mod dhcp;
pub mod names;
pub mod neighbor;
pub mod privilege;
pub mod tcp_sweep;

pub use arp::ArpDiscovery;
pub use conflicts::{detect_mac_changes, detect_shared_macs, snapshot_mappings, MacChange, SharedMac};
pub use dhcp::{DhcpProbe, DhcpServer, ExpectedServers};
pub use names::resolve_hostnames;
pub use tcp_sweep::{TcpSweepConfig, TcpSweeper};

/// Default ceiling on how many hosts a single scan may target.
///
/// A `/16` holds 65k addresses; sweeping one by accident (a docker bridge, a
/// mistyped netmask) would flood the network for minutes.
pub const DEFAULT_MAX_HOSTS: usize = 4096;

/// Configuration for ARP discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Network interface to use.
    pub interface_name: String,
    /// Target network in CIDR notation (e.g., "192.168.1.0/24").
    pub target_cidr: String,
    /// Timeout per ARP request in milliseconds.
    pub timeout_ms: u64,
    /// Maximum number of hosts this scan may target.
    pub max_hosts: usize,
    /// How many times to sweep the network. More passes reach hosts that miss
    /// the first broadcast (sleeping Wi-Fi stations, congested links).
    pub retries: u32,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        DiscoveryConfig {
            interface_name: String::new(),
            target_cidr: String::new(),
            timeout_ms: 1000,
            max_hosts: DEFAULT_MAX_HOSTS,
            retries: 2,
        }
    }
}

/// Errors a caller may need to branch on.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Raw ARP discovery needs privileges this process does not have.
    #[error("raw ARP discovery requires root or CAP_NET_RAW")]
    PrivilegeRequired,
    /// The target subnet is larger than the configured host limit.
    #[error(
        "target {target} contains {hosts} hosts, which exceeds the limit of {limit}; \
         narrow --target or raise --max-hosts"
    )]
    TargetTooLarge {
        target: String,
        hosts: usize,
        limit: usize,
    },
    /// The named interface does not exist.
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),
}

/// Whether an error chain indicates a raw-socket permission failure.
///
/// Lets the CLI offer the unprivileged fallback instead of string-matching
/// "Operation not permitted".
pub fn is_privilege_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| matches!(cause.downcast_ref::<DiscoveryError>(), Some(DiscoveryError::PrivilegeRequired)))
}

/// Map a `datalink::channel` failure to a typed privilege error when the
/// kernel refused the raw socket.
pub(crate) fn classify_channel_error(error: std::io::Error) -> anyhow::Error {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        DiscoveryError::PrivilegeRequired.into()
    } else {
        error.into()
    }
}

/// Parse CIDR notation (e.g., "192.168.1.0/24") into network and prefix.
pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid CIDR format: expected 'X.X.X.X/prefix'"));
    }

    let network: Ipv4Addr = parts[0]
        .parse()
        .map_err(|_| anyhow!("Invalid IPv4 address syntax: '{}'", parts[0]))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| anyhow!("Invalid prefix length: '{}'", parts[1]))?;

    if prefix > 32 {
        return Err(anyhow!("Prefix must be between 0 and 32"));
    }

    Ok((network, prefix))
}

/// Generate the host addresses in a network, bounded by `limit`.
///
/// `/31` and `/32` networks have no network/broadcast addresses to skip, so
/// every address is a host (point-to-point links and single hosts).
pub fn hosts_in_cidr(network: Ipv4Addr, prefix: u8, limit: usize) -> Result<Vec<Ipv4Addr>> {
    let mask = if prefix == 0 {
        0u32
    } else {
        (!0u32) << (32 - prefix)
    };

    let start = u32::from(network) & mask;
    let end = start | (!mask);
    let total = (end - start) as usize + 1;

    // A /31 is a point-to-point link and a /32 is one host: all addresses count.
    let host_count = if prefix >= 31 { total } else { total.saturating_sub(2) };

    if host_count > limit {
        return Err(DiscoveryError::TargetTooLarge {
            target: format!("{}/{}", Ipv4Addr::from(start), prefix),
            hosts: host_count,
            limit,
        }
        .into());
    }

    let ips = if prefix >= 31 {
        (start..=end).map(Ipv4Addr::from).collect()
    } else {
        ((start + 1)..end).map(Ipv4Addr::from).collect()
    };

    Ok(ips)
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
    fn test_parse_cidr_rejects_truncated_octet() {
        // Regression: auto-detection used to emit "127.0.0/24".
        let error = parse_cidr("127.0.0/24").expect_err("should reject");
        assert!(error.to_string().contains("Invalid IPv4 address syntax"));
    }

    #[test]
    fn test_hosts_in_cidr_24_subnet() {
        let ips = hosts_in_cidr(Ipv4Addr::new(192, 168, 1, 0), 24, DEFAULT_MAX_HOSTS)
            .expect("should generate");
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn test_hosts_in_cidr_30_subnet() {
        let ips = hosts_in_cidr(Ipv4Addr::new(10, 0, 0, 0), 30, DEFAULT_MAX_HOSTS)
            .expect("should generate");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips[1], Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn test_hosts_in_cidr_31_and_32() {
        let point_to_point =
            hosts_in_cidr(Ipv4Addr::new(10, 0, 0, 0), 31, DEFAULT_MAX_HOSTS).expect("should generate");
        assert_eq!(point_to_point.len(), 2);

        let single = hosts_in_cidr(Ipv4Addr::new(10, 0, 0, 7), 32, DEFAULT_MAX_HOSTS)
            .expect("should generate");
        assert_eq!(single, vec![Ipv4Addr::new(10, 0, 0, 7)]);
    }

    #[test]
    fn test_hosts_in_cidr_enforces_limit() {
        let error = hosts_in_cidr(Ipv4Addr::new(172, 17, 0, 0), 16, DEFAULT_MAX_HOSTS)
            .expect_err("should refuse an oversized target");
        assert!(!is_privilege_error(&error));
        assert!(error.to_string().contains("exceeds the limit"));
    }
}
