//! Kernel neighbour (ARP) table access.
//!
//! The OS already knows the MAC address of every host it has recently talked
//! to. Reading that table lets the unprivileged TCP sweep attach MAC addresses
//! to the hosts it finds — no raw socket needed.

use netgap_core::Device;
use std::net::{IpAddr, Ipv4Addr};

/// One row of the neighbour table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborEntry {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub iface: String,
}

/// Read the neighbour table, if the platform exposes one.
///
/// Linux provides `/proc/net/arp`, which is world-readable. Other platforms
/// return an empty table: the sweep still works, hosts just keep no MAC.
pub fn read_neighbor_table() -> Vec<NeighborEntry> {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/net/arp") {
            Ok(contents) => parse_proc_net_arp(&contents),
            Err(_) => Vec::new(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Parse the contents of `/proc/net/arp`.
///
/// Rows look like:
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.111.1    0x1         0x2         c4:b2:5b:0a:03:26     *        wlan0
/// ```
/// Incomplete entries (flag `ATF_COM` unset) and zero MACs are skipped: the
/// kernel has not resolved them yet.
pub fn parse_proc_net_arp(contents: &str) -> Vec<NeighborEntry> {
    /// ATF_COM — the entry is complete and usable.
    const ATF_COM: u32 = 0x2;
    const ZERO_MAC: &str = "00:00:00:00:00:00";

    contents
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let ip: Ipv4Addr = fields.next()?.parse().ok()?;
            let _hw_type = fields.next()?;
            let flags = u32::from_str_radix(fields.next()?.trim_start_matches("0x"), 16).ok()?;
            let mac = fields.next()?;
            let _mask = fields.next()?;
            let iface = fields.next()?;

            if flags & ATF_COM == 0 || mac.eq_ignore_ascii_case(ZERO_MAC) {
                return None;
            }

            Some(NeighborEntry {
                ip,
                mac: mac.to_ascii_uppercase(),
                iface: iface.to_string(),
            })
        })
        .collect()
}

/// Attach MAC addresses from the neighbour table to already-discovered devices.
///
/// Returns how many devices gained a MAC. When `interface_name` is given, only
/// entries from that interface are considered.
pub fn enrich_macs(
    devices: &mut [Device],
    entries: &[NeighborEntry],
    interface_name: Option<&str>,
) -> usize {
    let mut resolved = 0;

    for device in devices.iter_mut() {
        if device.mac.is_some() {
            continue;
        }
        let IpAddr::V4(ip) = device.ip else { continue };

        let Some(entry) = entries.iter().find(|entry| {
            entry.ip == ip
                && interface_name
                    .map(|name| entry.iface == name)
                    .unwrap_or(true)
        }) else {
            continue;
        };

        device.mac = Some(entry.mac.clone());
        resolved += 1;
    }

    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.111.1    0x1         0x2         c4:b2:5b:0a:03:26     *        wlan0
192.168.111.37   0x1         0x2         50:eb:71:6b:4b:b2     *        wlan0
192.168.111.90   0x1         0x0         00:00:00:00:00:00     *        wlan0
172.22.0.6       0x1         0x2         76:35:aa:e8:31:27     *        br-be84c3272f4b
";

    #[test]
    fn test_parse_proc_net_arp_skips_incomplete_and_zero_macs() {
        let entries = parse_proc_net_arp(FIXTURE);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 111, 1));
        assert_eq!(entries[0].mac, "C4:B2:5B:0A:03:26");
        assert_eq!(entries[0].iface, "wlan0");

        assert!(!entries
            .iter()
            .any(|entry| entry.ip == Ipv4Addr::new(192, 168, 111, 90)));
    }

    #[test]
    fn test_enrich_macs_respects_interface_filter() {
        let entries = parse_proc_net_arp(FIXTURE);
        let mut devices = vec![
            Device::new(IpAddr::V4(Ipv4Addr::new(192, 168, 111, 1))),
            Device::new(IpAddr::V4(Ipv4Addr::new(172, 22, 0, 6))),
            Device::new(IpAddr::V4(Ipv4Addr::new(192, 168, 111, 200))),
        ];

        let resolved = enrich_macs(&mut devices, &entries, Some("wlan0"));
        assert_eq!(resolved, 1);
        assert_eq!(devices[0].mac.as_deref(), Some("C4:B2:5B:0A:03:26"));
        assert!(
            devices[1].mac.is_none(),
            "bridge entry should be filtered out"
        );
        assert!(devices[2].mac.is_none(), "unknown host stays unresolved");
    }

    #[test]
    fn test_enrich_macs_keeps_existing_mac() {
        let entries = parse_proc_net_arp(FIXTURE);
        let mut device = Device::new(IpAddr::V4(Ipv4Addr::new(192, 168, 111, 1)));
        device.mac = Some("AA:AA:AA:AA:AA:AA".to_string());

        let resolved = enrich_macs(&mut [device], &entries, None);
        assert_eq!(resolved, 0);
    }
}
