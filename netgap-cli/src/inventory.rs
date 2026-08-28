//! `netgap inventory`: the trusted-device list as a file you can carry.
//!
//! The list of devices the owner has vouched for, with the label keeping the
//! note they wrote about each one, is the part of netgap's state that is
//! accumulated by hand rather than by scanning. It is also the part a person
//! would be annoyed to lose: a new laptop, a reinstall, a second machine on the
//! same network.
//!
//! The format is JSON and deliberately small — a MAC and an optional label — so
//! it can be read with `jq`, edited in an editor, and diffed in git. It is
//! versioned because a file that is meant to be kept for years will outlive the
//! code that wrote it.
//!
//! Import merges by default: the file adds devices and refreshes labels, and
//! never removes anything the machine already trusts. `--replace` is the
//! explicit way to say the file is now the whole truth, and it reports how many
//! devices it dropped so the result is not a surprise.

use anyhow::{anyhow, bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::trust::{resolve_identifier, TrustList, TrustedDevice};

/// The version of the file format written by this build.
///
/// A reader refuses a file it does not understand rather than importing half
/// of it: an older netgap meeting a newer inventory should say so.
pub const FORMAT_VERSION: u32 = 1;

/// What `netgap inventory export` writes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// Present so a future format can be told apart from this one.
    pub netgap_inventory: u32,
    pub exported_at: String,
    pub trusted_devices: Vec<Entry>,
}

/// One device in the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub mac: String,
    /// The note kept about this device, as written on the trusted list.
    #[serde(default)]
    pub label: Option<String>,
}

/// What an import changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    pub unchanged: usize,
    /// Only non-zero with `--replace`: devices that were trusted and are not
    /// in the file.
    pub removed: usize,
}

impl Inventory {
    /// The current list, ready to write.
    pub fn of(list: &TrustList) -> Self {
        Self {
            netgap_inventory: FORMAT_VERSION,
            exported_at: chrono::Utc::now().to_rfc3339(),
            trusted_devices: list
                .entries()
                .into_iter()
                .map(|device| Entry {
                    mac: device.mac,
                    label: device.label,
                })
                .collect(),
        }
    }

    /// Read a file, rejecting one this build does not understand.
    pub fn from_json(text: &str) -> Result<Self> {
        let inventory: Inventory = serde_json::from_str(text)
            .context("This is not a netgap inventory file (expected JSON with trusted_devices)")?;

        if inventory.netgap_inventory > FORMAT_VERSION {
            bail!(
                "This inventory was written by a newer netgap (format {}); this build understands up to {}. Upgrade netgap to import it.",
                inventory.netgap_inventory,
                FORMAT_VERSION
            );
        }
        if inventory.netgap_inventory == 0 {
            bail!("This inventory has no format version, so it cannot be read safely.");
        }

        Ok(inventory)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Read an inventory from a path, or from standard input for `-`.
    pub fn read(path: &str) -> Result<Self> {
        let text = if path == "-" {
            std::io::read_to_string(std::io::stdin()).context("reading standard input")?
        } else {
            std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
        };
        Self::from_json(&text)
    }

    /// Write the inventory to a path, or to standard output for `-`.
    ///
    /// The file is created `0600`: a list of the owner's devices and what they
    /// call them is not secret in the way a key is, but it describes their
    /// home, and there is no reason for it to be world-readable.
    pub fn write(&self, path: &str) -> Result<()> {
        let json = self.to_json()?;
        if path == "-" {
            println!("{json}");
            return Ok(());
        }

        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        write_private(path, &json).with_context(|| format!("writing {path}"))?;
        Ok(())
    }

    /// Apply the file to a trusted list, returning the new list and what changed.
    ///
    /// Merging is by MAC, the same identity the trusted list itself uses, so a
    /// device that changed address is still the same device and its label is
    /// refreshed rather than duplicated.
    pub fn merge(&self, current: &TrustList, replace: bool) -> Result<(TrustList, MergeReport)> {
        let before: HashMap<String, Option<String>> = current
            .entries()
            .into_iter()
            .map(|device| (device.mac.clone(), device.label))
            .collect();

        let mut entries: Vec<TrustedDevice> = if replace {
            Vec::new()
        } else {
            current.entries()
        };
        let mut report = MergeReport::default();

        for (index, entry) in self.trusted_devices.iter().enumerate() {
            let mac = resolve_identifier(&entry.mac).map_err(|error| {
                anyhow!(
                    "Device {} of this inventory ({}) is not usable: {error}",
                    index + 1,
                    entry.mac
                )
            })?;

            // The report describes the difference from the list that was there
            // before, which is what the person who runs the import cares about.
            // Comparing against the growing list instead would call everything
            // in a `--replace` "added".
            match before.get(&mac) {
                None => report.added += 1,
                Some(previous) if previous != &entry.label => report.updated += 1,
                Some(_) => report.unchanged += 1,
            }

            match entries.iter_mut().find(|device| device.mac == mac) {
                Some(existing) => existing.label = entry.label.clone(),
                None => entries.push(TrustedDevice {
                    mac,
                    label: entry.label.clone(),
                }),
            }
        }

        if replace {
            report.removed = before
                .keys()
                .filter(|mac| !entries.iter().any(|device| &device.mac == *mac))
                .count();
        }

        Ok((TrustList::from_entries(entries), report))
    }
}

/// Create the file with no access for other users.
#[cfg(unix)]
fn write_private(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_private(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

// ------------------------------------------------------------------- run ---

/// `netgap inventory export [path]`
pub fn export(path: Option<String>) -> Result<()> {
    let list = TrustList::load()?;
    let inventory = Inventory::of(&list);

    match path {
        // Piped output is the JSON and nothing else, so `| jq` works.
        None => inventory.write("-"),
        Some(path) => {
            inventory.write(&path)?;
            println!(
                "✔ Wrote {} to {}",
                plural(inventory.trusted_devices.len(), "device", "devices"),
                path
            );
            Ok(())
        }
    }
}

/// `netgap inventory import <path> [--replace]`
pub fn import(path: &str, replace: bool) -> Result<()> {
    let inventory = Inventory::read(path)?;
    let (merged, report) = inventory.merge(&TrustList::load()?, replace)?;

    merged.save()?;

    if merged.is_empty() {
        println!("The trusted list is now empty.");
        return Ok(());
    }

    if replace {
        // "0 added" would be technically true and read like a failure; with a
        // replace, what matters is the list that came out.
        let count = merged.entries().len();
        println!(
            "✔ Replaced the trusted list: {} now trusted.",
            if count == 1 {
                "1 device is".to_string()
            } else {
                format!("{count} devices are")
            }
        );
    } else {
        let mut parts = Vec::new();
        if report.added > 0 {
            parts.push(format!("{} added", report.added));
        }
        if report.updated > 0 {
            parts.push(format!("{} updated", report.updated));
        }
        if report.unchanged > 0 {
            parts.push(format!("{} unchanged", report.unchanged));
        }
        if parts.is_empty() {
            parts.push("nothing changed".to_string());
        }

        println!(
            "✔ {} ({})",
            plural(merged.entries().len(), "trusted device", "trusted devices"),
            parts.join(", ")
        );
    }
    if report.removed > 0 {
        println!(
            "  {}",
            format!(
                "{} no longer trusted, because the file replaced the list.",
                plural(report.removed, "device is", "devices are")
            )
            .dimmed()
        );
    }
    Ok(())
}

fn plural(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_with(entries: &[(&str, Option<&str>)]) -> TrustList {
        let entries = entries
            .iter()
            .map(|(mac, label)| TrustedDevice {
                mac: mac.to_string(),
                label: label.map(str::to_string),
            })
            .collect();
        TrustList::from_entries(entries)
    }

    #[test]
    fn an_export_holds_every_device_and_its_label() {
        let list = list_with(&[
            ("C4:B2:5B:0A:03:26", Some("living room router")),
            ("50:EB:71:6B:4B:B2", None),
        ]);

        let inventory = Inventory::of(&list);
        assert_eq!(inventory.netgap_inventory, FORMAT_VERSION);
        assert_eq!(inventory.trusted_devices.len(), 2);

        let json = inventory.to_json().expect("serialize");
        assert!(json.contains("\"living room router\""), "{json}");
        assert!(json.contains("\"mac\""), "{json}");

        let reloded = Inventory::from_json(&json).expect("parse");
        assert_eq!(reloded.trusted_devices, inventory.trusted_devices);
    }

    #[test]
    fn an_import_adds_refreshes_and_leaves_the_rest_alone() {
        let current = list_with(&[
            ("C4:B2:5B:0A:03:26", Some("router")),
            ("50:EB:71:6B:4B:B2", None),
        ]);
        let file = Inventory::of(&list_with(&[
            ("c4:b2:5b:0a:03:26", Some("living room router")),
            ("50:eb:71:6b:4b:b2", None),
            ("2C:F0:5D:11:22:33", Some("printer")),
        ]));

        let (merged, report) = file.merge(&current, false).expect("merge");
        assert_eq!(report.added, 1);
        assert_eq!(report.updated, 1);
        assert_eq!(report.unchanged, 1);
        assert_eq!(report.removed, 0);

        let entries = merged.entries();
        assert_eq!(entries.len(), 3);
        let router = entries
            .iter()
            .find(|device| device.mac == "C4:B2:5B:0A:03:26")
            .expect("router kept");
        assert_eq!(router.label.as_deref(), Some("living room router"));
    }

    #[test]
    fn a_label_can_be_cleared_by_an_import() {
        let current = list_with(&[("C4:B2:5B:0A:03:26", Some("router"))]);
        let file = Inventory::of(&list_with(&[("C4:B2:5B:0A:03:26", None)]));

        let (merged, report) = file.merge(&current, false).expect("merge");
        assert_eq!(report.updated, 1);
        assert_eq!(merged.entries()[0].label, None);
    }

    #[test]
    fn a_replace_drops_what_the_file_does_not_mention() {
        let current = list_with(&[
            ("C4:B2:5B:0A:03:26", Some("router")),
            ("50:EB:71:6B:4B:B2", Some("old laptop")),
        ]);
        let file = Inventory::of(&list_with(&[("C4:B2:5B:0A:03:26", Some("router"))]));

        let (merged, report) = file.merge(&current, true).expect("merge");
        assert_eq!(report.removed, 1);
        assert_eq!(report.unchanged, 1);
        assert_eq!(merged.entries().len(), 1);
        assert_eq!(merged.entries()[0].mac, "C4:B2:5B:0A:03:26");
    }

    #[test]
    fn a_newer_format_is_refused_with_a_reason() {
        let json = r#"{"netgap_inventory": 2, "exported_at": "", "trusted_devices": []}"#;
        let error = Inventory::from_json(json).unwrap_err().to_string();
        assert!(error.contains("newer netgap"), "{error}");
    }

    #[test]
    fn a_file_that_is_not_an_inventory_says_so() {
        let error = Inventory::from_json("[1, 2, 3]").unwrap_err().to_string();
        assert!(error.contains("not a netgap inventory"), "{error}");
    }

    #[test]
    fn a_bad_address_names_the_entry() {
        let file = Inventory {
            netgap_inventory: FORMAT_VERSION,
            exported_at: String::new(),
            trusted_devices: vec![
                Entry {
                    mac: "C4:B2:5B:0A:03:26".into(),
                    label: None,
                },
                Entry {
                    mac: "not-a-mac".into(),
                    label: None,
                },
            ],
        };

        let error = file
            .merge(&TrustList::default(), false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Device 2"), "{error}");
        assert!(error.contains("not-a-mac"), "{error}");
    }

    #[test]
    fn a_written_file_is_not_world_readable() {
        let dir =
            std::env::temp_dir().join(format!("netgap-inventory-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("inventory.json");

        Inventory::of(&list_with(&[("C4:B2:5B:0A:03:26", Some("router"))]))
            .write(path.to_str().expect("utf-8 path"))
            .expect("write");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        }

        let read_back = Inventory::read(path.to_str().expect("utf-8 path")).expect("read");
        assert_eq!(read_back.trusted_devices.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
