//! Detecting a device that starts claiming an address it did not hold before.
//!
//! On a normal network the mapping from IP address to hardware address is
//! stable: a device keeps its MAC and DHCP keeps handing it the same lease.
//! When an address moves to a different MAC between two observations,
//! something changed that is worth knowing about — most seriously, something
//! claiming to be the gateway.
//!
//! This is observation, not proof. A changed mapping has innocent explanations:
//! a device replaced, a laptop that bridges Wi-Fi and Ethernet, a phone that
//! randomized its address and reconnected. The finding says what was seen so
//! the owner can judge it, rather than declaring an attack.

use crate::neighbor::read_neighbor_table;
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// One address seen on a different hardware address than before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacChange {
    pub ip: Ipv4Addr,
    pub previous_mac: String,
    pub current_mac: String,
}

impl MacChange {
    /// Whether this change is on the address of the default gateway.
    ///
    /// The gateway is the address worth impersonating: everything leaving the
    /// network passes through it, so whoever holds it can read or alter that
    /// traffic. A change here deserves more attention than one on a printer.
    pub fn is_gateway(&self, gateway: Option<Ipv4Addr>) -> bool {
        gateway == Some(self.ip)
    }

    /// A sentence describing what was seen.
    pub fn describe(&self) -> String {
        format!(
            "{} was {}, now answers as {}",
            self.ip, self.previous_mac, self.current_mac
        )
    }
}

/// Snapshot which hardware address currently holds which address.
///
/// Read from the kernel's neighbour table, which is updated by ordinary
/// traffic and so is current without any privileged capture. Entries are
/// filtered to one interface: the same address can legitimately exist on
/// several, and comparing across them would invent conflicts.
pub fn snapshot_mappings(interface_name: &str) -> HashMap<Ipv4Addr, String> {
    read_neighbor_table()
        .into_iter()
        .filter(|entry| entry.iface == interface_name)
        .map(|entry| (entry.ip, entry.mac))
        .collect()
}

/// Addresses whose hardware address changed between two observations.
///
/// Only addresses present in both are compared: one that appears or disappears
/// is a device joining or leaving, which the change detection already reports.
pub fn detect_mac_changes(
    previous: &HashMap<Ipv4Addr, String>,
    current: &HashMap<Ipv4Addr, String>,
) -> Vec<MacChange> {
    let mut changes: Vec<MacChange> = current
        .iter()
        .filter_map(|(ip, mac)| {
            let previous_mac = previous.get(ip)?;
            (!mac.eq_ignore_ascii_case(previous_mac)).then(|| MacChange {
                ip: *ip,
                previous_mac: previous_mac.clone(),
                current_mac: mac.clone(),
            })
        })
        .collect();

    // A stable order, so repeated runs read the same way.
    changes.sort_by_key(|change| u32::from(change.ip));
    changes
}

/// A hardware address answering for two different addresses in one sweep.
///
/// The mirror image of [`MacChange`]: rather than one address changing hands,
/// one device answers for several. A machine with two addresses is normal; a
/// device answering for the gateway and something else at the same time is how
/// an interception is usually set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedMac {
    pub mac: String,
    pub addresses: Vec<Ipv4Addr>,
}

impl SharedMac {
    /// A sentence describing what was seen.
    pub fn describe(&self) -> String {
        let addresses: Vec<String> = self.addresses.iter().map(Ipv4Addr::to_string).collect();
        format!("{} answers for {}", self.mac, addresses.join(", "))
    }
}

/// Hardware addresses claiming more than one address.
///
/// Takes a list rather than a map so that duplicates are visible at all: a map
/// keyed by address would silently collapse an address that answered twice.
pub fn detect_shared_macs(observations: &[(Ipv4Addr, String)]) -> Vec<SharedMac> {
    let mut by_mac: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();

    for (ip, mac) in observations {
        let entry = by_mac.entry(mac.to_ascii_uppercase()).or_default();
        if !entry.contains(ip) {
            entry.push(*ip);
        }
    }

    let mut shared: Vec<SharedMac> = by_mac
        .into_iter()
        .filter(|(_, addresses)| addresses.len() > 1)
        .map(|(mac, mut addresses)| {
            addresses.sort_by_key(|ip| u32::from(*ip));
            SharedMac { mac, addresses }
        })
        .collect();

    shared.sort_by(|a, b| a.mac.cmp(&b.mac));
    shared
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mappings(entries: &[(&str, &str)]) -> HashMap<Ipv4Addr, String> {
        entries
            .iter()
            .map(|(ip, mac)| (ip.parse().expect("valid ip"), mac.to_string()))
            .collect()
    }

    #[test]
    fn test_a_stable_mapping_reports_nothing() {
        let before = mappings(&[("192.168.1.1", "C4:B2:5B:0A:03:26"), ("192.168.1.5", "AA:BB:CC:DD:EE:FF")]);
        let after = mappings(&[("192.168.1.1", "C4:B2:5B:0A:03:26"), ("192.168.1.5", "AA:BB:CC:DD:EE:FF")]);

        assert!(detect_mac_changes(&before, &after).is_empty());
    }

    #[test]
    fn test_a_changed_mapping_is_reported_with_both_addresses() {
        let before = mappings(&[("192.168.1.1", "C4:B2:5B:0A:03:26")]);
        let after = mappings(&[("192.168.1.1", "DE:AD:BE:EF:00:01")]);

        let changes = detect_mac_changes(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].previous_mac, "C4:B2:5B:0A:03:26");
        assert_eq!(changes[0].current_mac, "DE:AD:BE:EF:00:01");
        assert!(changes[0].describe().contains("was C4:B2:5B:0A:03:26"));
    }

    #[test]
    fn test_gateway_changes_are_identifiable() {
        let before = mappings(&[("192.168.1.1", "C4:B2:5B:0A:03:26"), ("192.168.1.9", "AA:BB:CC:DD:EE:FF")]);
        let after = mappings(&[("192.168.1.1", "DE:AD:BE:EF:00:01"), ("192.168.1.9", "11:22:33:44:55:66")]);

        let changes = detect_mac_changes(&before, &after);
        let gateway: Ipv4Addr = "192.168.1.1".parse().expect("valid ip");

        assert_eq!(changes.len(), 2);
        assert!(changes
            .iter()
            .find(|change| change.ip == gateway)
            .expect("gateway change")
            .is_gateway(Some(gateway)));
    }

    #[test]
    fn test_new_and_departed_addresses_are_not_changes() {
        let before = mappings(&[("192.168.1.1", "C4:B2:5B:0A:03:26"), ("192.168.1.9", "AA:BB:CC:DD:EE:FF")]);
        let after = mappings(&[("192.168.1.1", "C4:B2:5B:0A:03:26"), ("192.168.1.20", "11:22:33:44:55:66")]);

        // A device arriving or leaving is change detection's business, not a
        // conflict; treating it as one would make every scan an alarm.
        assert!(detect_mac_changes(&before, &after).is_empty());
    }

    #[test]
    fn test_mac_case_does_not_count_as_a_change() {
        let before = mappings(&[("192.168.1.1", "c4:b2:5b:0a:03:26")]);
        let after = mappings(&[("192.168.1.1", "C4:B2:5B:0A:03:26")]);

        assert!(detect_mac_changes(&before, &after).is_empty());
    }

    #[test]
    fn test_changes_are_ordered_by_address() {
        let before = mappings(&[
            ("192.168.1.9", "AA:AA:AA:AA:AA:AA"),
            ("192.168.1.2", "BB:BB:BB:BB:BB:BB"),
        ]);
        let after = mappings(&[
            ("192.168.1.9", "CC:CC:CC:CC:CC:CC"),
            ("192.168.1.2", "DD:DD:DD:DD:DD:DD"),
        ]);

        let changes = detect_mac_changes(&before, &after);
        assert_eq!(changes[0].ip.to_string(), "192.168.1.2");
        assert_eq!(changes[1].ip.to_string(), "192.168.1.9");
    }

    #[test]
    fn test_one_mac_answering_for_several_addresses() {
        let observations = vec![
            ("192.168.1.1".parse().expect("valid ip"), "DE:AD:BE:EF:00:01".to_string()),
            ("192.168.1.5".parse().expect("valid ip"), "DE:AD:BE:EF:00:01".to_string()),
            ("192.168.1.9".parse().expect("valid ip"), "AA:BB:CC:DD:EE:FF".to_string()),
        ];

        let shared = detect_shared_macs(&observations);
        assert_eq!(shared.len(), 1);
        assert_eq!(shared[0].mac, "DE:AD:BE:EF:00:01");
        assert_eq!(shared[0].addresses.len(), 2);
        assert!(shared[0].describe().contains("192.168.1.1"));
    }

    #[test]
    fn test_one_device_with_one_address_is_not_shared() {
        let observations = vec![
            ("192.168.1.1".parse().expect("valid ip"), "AA:BB:CC:DD:EE:FF".to_string()),
            ("192.168.1.2".parse().expect("valid ip"), "11:22:33:44:55:66".to_string()),
        ];

        assert!(detect_shared_macs(&observations).is_empty());
    }

    #[test]
    fn test_snapshot_reads_the_neighbour_table_without_panicking() {
        // The table may be empty on a machine with no traffic; either way this
        // must return rather than fail.
        let snapshot = snapshot_mappings("an-interface-that-does-not-exist");
        assert!(snapshot.is_empty());
    }
}
