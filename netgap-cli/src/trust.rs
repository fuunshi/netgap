//! The trusted-device list.
//!
//! A plain text file at `~/.config/netgap/trusted_devices`, one device per
//! line:
//!
//! ```text
//! # <mac>  <optional label>
//! C4:B2:5B:0A:03:26  living room router
//! 50:EB:71:6B:4B:B2
//! ```
//!
//! Devices are identified by MAC rather than IP, because DHCP reassigns
//! addresses but the hardware address stays put. Keeping this list explicit and
//! hand-editable is deliberate: only the owner knows what belongs on their
//! network, so the tool never guesses at it.

use anyhow::{anyhow, Context, Result};
use netgap_core::paths;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// A trusted device entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    pub mac: String,
    pub label: Option<String>,
}

/// The trusted-device list, keyed by normalized MAC.
#[derive(Debug, Clone, Default)]
pub struct TrustList {
    devices: Vec<TrustedDevice>,
}

impl TrustList {
    /// Load the list from the default location.
    ///
    /// A missing file is an empty list, not an error: nothing is trusted until
    /// the user says so.
    pub fn load() -> Result<Self> {
        let path = trust_file_path()?;
        Self::load_from(&path)
    }

    /// Load the list from a specific file.
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(TrustList::default());
        }

        let contents =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

        Ok(Self::parse(&contents))
    }

    /// Parse the file format.
    pub fn parse(contents: &str) -> Self {
        let devices = contents
            .lines()
            .map(|line| line.split('#').next().unwrap_or_default().trim())
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let mac = netgap_report::discovery::normalize_mac(parts.next()?);
                if mac.is_empty() {
                    return None;
                }
                let label = parts.collect::<Vec<_>>().join(" ");

                Some(TrustedDevice {
                    mac,
                    label: (!label.is_empty()).then_some(label),
                })
            })
            .collect();

        TrustList { devices }
    }

    /// Save the list to the default location.
    pub fn save(&self) -> Result<()> {
        let path = trust_file_path()?;
        self.save_to(&path)
    }

    /// Save the list to a specific file.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut contents = String::from(
            "# netgap trusted devices — one MAC per line, optional label after it.\n\
             # Devices here are reported as trusted; everything else is flagged for review.\n",
        );
        for device in &self.devices {
            match &device.label {
                Some(label) => contents.push_str(&format!("{} {}\n", device.mac, label)),
                None => contents.push_str(&format!("{}\n", device.mac)),
            }
        }

        std::fs::write(path, contents)?;
        Ok(())
    }

    /// MACs as a set, for lookups during reporting.
    pub fn macs(&self) -> HashSet<String> {
        self.devices
            .iter()
            .map(|device| device.mac.clone())
            .collect()
    }

    /// Label lookup by MAC.
    pub fn labels(&self) -> HashMap<String, String> {
        self.devices
            .iter()
            .filter_map(|device| Some((device.mac.clone(), device.label.clone()?)))
            .collect()
    }

    /// Add a device, returning false if it was already present.
    ///
    /// A label on an existing entry replaces the stored one, so
    /// `netgap trust <mac> "new name"` is not a silent no-op.
    pub fn trust(&mut self, mac: &str, label: Option<String>) -> bool {
        let mac = netgap_report::discovery::normalize_mac(mac);
        if let Some(existing) = self.devices.iter_mut().find(|device| device.mac == mac) {
            if label.is_some() {
                existing.label = label;
            }
            return false;
        }

        self.devices.push(TrustedDevice { mac, label });
        true
    }

    /// Remove a device, returning whether it was present.
    pub fn untrust(&mut self, mac: &str) -> bool {
        let mac = netgap_report::discovery::normalize_mac(mac);
        let before = self.devices.len();
        self.devices.retain(|device| device.mac != mac);
        self.devices.len() != before
    }

    /// Entries, sorted by MAC for stable output.
    pub fn entries(&self) -> Vec<TrustedDevice> {
        let mut entries = self.devices.clone();
        entries.sort_by(|a, b| a.mac.cmp(&b.mac));
        entries
    }

    /// Build a list from entries that are already trusted.
    ///
    /// Used by an import, which has a complete list in hand and should not have
    /// to replay `trust` calls — those deliberately refuse to clear a label,
    /// while an imported file says what each entry is.
    pub fn from_entries(entries: Vec<TrustedDevice>) -> Self {
        TrustList { devices: entries }
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

/// Where the trusted-device list lives.
pub fn trust_file_path() -> Result<PathBuf> {
    paths::config_dir()
        .map(|dir| dir.join("trusted_devices"))
        .ok_or_else(|| anyhow!("Could not determine the netgap config directory"))
}

/// Resolve a user-supplied MAC or IP to a MAC.
///
/// Accepting an address is a convenience: it saves the user from looking the
/// MAC up by hand, using the kernel's neighbour table for the translation.
pub fn resolve_identifier(identifier: &str) -> Result<String> {
    let identifier = identifier.trim();

    if !identifier.contains(':') {
        return Err(anyhow!(
            "'{}' is not a MAC address (expected aa:bb:cc:dd:ee:ff)",
            identifier
        ));
    }

    // An IPv4 address contains dots, never colons, so anything with colons is
    // treated as a MAC — but validate the shape before storing it.
    let octets: Vec<&str> = identifier.split(':').collect();
    if octets.len() != 6
        || octets
            .iter()
            .any(|octet| u8::from_str_radix(octet, 16).is_err())
    {
        return Err(anyhow!(
            "'{}' is not a valid MAC address (expected aa:bb:cc:dd:ee:ff)",
            identifier
        ));
    }

    Ok(netgap_report::discovery::normalize_mac(identifier))
}

/// Look up the MAC for an IPv4 address in the kernel neighbour table.
pub fn mac_for_ip(ip: &str) -> Result<String> {
    let ip: Ipv4Addr = ip
        .parse()
        .with_context(|| format!("'{}' is not an IPv4 address or MAC", ip))?;

    let entries = netgap_discover::neighbor::read_neighbor_table();
    entries
        .iter()
        .find(|entry| entry.ip == ip)
        .map(|entry| netgap_report::discovery::normalize_mac(&entry.mac))
        .ok_or_else(|| {
            anyhow!(
                "No MAC known for {} yet — scan or ping it first, or pass the MAC directly",
                ip
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ignores_comments_and_blank_lines() {
        let list = TrustList::parse(
            "# a comment\n\
             \n\
             C4:B2:5B:0A:03:26  living room router\n\
             50:eb:71:6b:4b:b2\n\
             # trailing comment\n",
        );

        let entries = list.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].mac, "50:EB:71:6B:4B:B2");
        assert_eq!(entries[1].mac, "C4:B2:5B:0A:03:26");
        assert_eq!(entries[1].label.as_deref(), Some("living room router"));
    }

    #[test]
    fn test_trust_and_untrust() {
        let mut list = TrustList::default();

        assert!(list.trust("c4:b2:5b:0a:03:26", Some("router".into())));
        assert_eq!(list.entries()[0].mac, "C4:B2:5B:0A:03:26");
        // Adding the same device twice is a no-op, not a duplicate.
        assert!(!list.trust("C4:B2:5B:0A:03:26", None));
        assert_eq!(list.entries().len(), 1);

        list.trust("C4:B2:5B:0A:03:26", Some("renamed".into()));
        assert_eq!(
            list.entries()[0].label.as_deref(),
            Some("renamed"),
            "a label on an existing entry should update it"
        );

        assert!(list.untrust("C4:B2:5B:0A:03:26"));
        assert!(!list.untrust("C4:B2:5B:0A:03:26"));
        assert!(list.is_empty());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("netgap-trust-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("trusted_devices");

        let mut list = TrustList::default();
        list.trust("C4:B2:5B:0A:03:26", Some("living room router".into()));
        list.trust("50:EB:71:6B:4B:B2", None);
        list.save_to(&path).expect("save");

        let loaded = TrustList::load_from(&path).expect("load");
        assert_eq!(loaded.entries(), list.entries());
        assert_eq!(
            loaded.labels().get("C4:B2:5B:0A:03:26").map(String::as_str),
            Some("living room router")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_missing_file_is_an_empty_list() {
        let path = std::env::temp_dir().join("netgap-trust-does-not-exist");
        let list = TrustList::load_from(&path).expect("load");
        assert!(list.is_empty());
    }

    #[test]
    fn test_resolve_identifier_validates_mac_shape() {
        assert_eq!(
            resolve_identifier("c4:b2:5b:0a:03:26").expect("valid"),
            "C4:B2:5B:0A:03:26"
        );
        assert!(resolve_identifier("192.168.1.1").is_err());
        assert!(resolve_identifier("zz:zz:zz:zz:zz:zz").is_err());
        assert!(resolve_identifier("c4:b2:5b").is_err());
    }
}
