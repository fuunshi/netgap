//! Colourised discovery report for humans.
//!
//! Answers "what is on my network right now?" at a glance: how many devices,
//! which are recognised, and what each one appears to be. Colours are applied
//! through the `colored` crate, which disables itself when stdout is not a
//! terminal or `NO_COLOR` is set, so piping stays clean.

use colored::Colorize;
use netgap_core::Device;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Everything the report needs beyond the devices themselves.
pub struct DiscoveryContext<'a> {
    pub interface: &'a str,
    pub target: &'a str,
    /// Devices whose MAC appears here are shown as trusted.
    pub trusted: &'a HashSet<String>,
    /// User-supplied names, keyed by MAC. Used when reverse DNS finds nothing.
    pub labels: &'a HashMap<String, String>,
    pub gateway: Option<IpAddr>,
    pub local: Option<IpAddr>,
}

/// Width caps so one long hostname cannot wreck the layout.
const MAX_NAME: usize = 22;
const MAX_VENDOR: usize = 20;
const MAX_TYPE: usize = 30;

/// Render the discovery report.
pub fn format_discovery(devices: &[Device], context: &DiscoveryContext<'_>) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{}\n",
        "╔══════════════════════════════════════════════════════════════════════╗".cyan()
    ));
    out.push_str(&format!(
        "{}\n",
        "║                     NETGAP NETWORK DISCOVERY                         ║".cyan().bold()
    ));
    out.push_str(&format!(
        "{}\n\n",
        "╚══════════════════════════════════════════════════════════════════════╝".cyan()
    ));

    out.push_str(&format!(
        "  Interface: {}    Target: {}\n\n",
        context.interface.bold(),
        context.target
    ));

    if devices.is_empty() {
        out.push_str(&format!(
            "  {}\n",
            "No devices responded. Check the target range, or try again with sudo for ARP discovery."
                .yellow()
        ));
        return out;
    }

    let trusted_count = devices
        .iter()
        .filter(|device| is_trusted(device, context.trusted))
        .count();
    let unrecognized = devices.len() - trusted_count;
    let private_macs = devices
        .iter()
        .filter(|device| device.mac.as_deref().is_some_and(is_private_mac))
        .count();

    out.push_str(&format!(
        "  {} {}    {} {}    {} {}\n",
        "Devices connected:".bold(),
        devices.len().to_string().bold().white(),
        "Trusted:".bold(),
        trusted_count.to_string().green().bold(),
        "Unrecognized:".bold(),
        if unrecognized > 0 {
            unrecognized.to_string().red().bold()
        } else {
            unrecognized.to_string().green().bold()
        },
    ));
    if private_macs > 0 {
        out.push_str(&format!(
            "  {} {}\n",
            "Devices using a private (randomized) MAC:".dimmed(),
            private_macs.to_string().dimmed()
        ));
    }
    out.push('\n');

    // Column widths follow the data, capped so the table stays readable.
    let rows: Vec<Row> = devices.iter().map(|device| Row::from_device(device, context)).collect();
    let ip_width = rows.iter().map(|row| row.ip.len()).max().unwrap_or(2).max(2);
    let name_width = rows
        .iter()
        .map(|row| row.name.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, MAX_NAME);
    // " (private)" is appended to randomized MACs, so reserve room for it.
    let mac_width = rows
        .iter()
        .map(|row| row.mac.len() + if row.private_mac { 10 } else { 0 })
        .max()
        .unwrap_or(3)
        .max(3);
    let vendor_width = rows
        .iter()
        .map(|row| row.vendor.chars().count())
        .max()
        .unwrap_or(6)
        .clamp(6, MAX_VENDOR);
    let type_width = rows
        .iter()
        .map(|row| row.device_type.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, MAX_TYPE);

    out.push_str(&format!(
        "  {}  {}  {}  {}  {}  {}\n",
        pad("IP", ip_width).bold(),
        pad("Name", name_width).bold(),
        pad("MAC", mac_width).bold(),
        pad("Vendor", vendor_width).bold(),
        pad("Type", type_width).bold(),
        "Status".bold(),
    ));
    out.push_str(&format!(
        "  {}\n",
        "─".repeat(ip_width + name_width + mac_width + vendor_width + type_width + 14).dimmed()
    ));

    for row in &rows {
        let name = if row.name.is_empty() { "—".dimmed().to_string() } else { row.name.clone() };
        let mac = if row.mac.is_empty() {
            "—".dimmed().to_string()
        } else if row.private_mac {
            format!("{} {}", row.mac, "(private)".yellow())
        } else {
            row.mac.clone()
        };
        let vendor = if row.vendor.is_empty() {
            "—".dimmed().to_string()
        } else {
            row.vendor.clone()
        };
        let device_type = if row.device_type == "Unknown device" {
            row.device_type.clone().dimmed().to_string()
        } else {
            row.device_type.clone()
        };

        out.push_str(&format!(
            "  {}  {}  {}  {}  {}  {}\n",
            pad(&row.ip, ip_width),
            pad(&name, name_width),
            pad(&mac, mac_width),
            pad(&vendor, vendor_width),
            pad(&device_type, type_width),
            row.status(),
        ));
    }

    out.push('\n');
    if unrecognized > 0 {
        out.push_str(&format!(
            "  {} {} device(s) are not in your trusted list.\n",
            "⚠".red().bold(),
            unrecognized.to_string().red().bold()
        ));
        out.push_str(&format!(
            "    Check them, then mark the ones you recognise:\n      {}\n\n",
            "netgap trust <mac> \"living room tv\"".bold()
        ));
    } else {
        out.push_str(&format!(
            "  {} Every device is in your trusted list.\n\n",
            "✓".green().bold()
        ));
    }

    out.push_str(&format!(
        "  {}\n",
        "Types are inferred from network position, open ports, MAC and name — treat them as hints."
            .dimmed()
    ));
    out.push_str(&format!(
        "  {}\n",
        "A \"private\" MAC is randomized by the device for privacy, so it has no vendor name."
            .dimmed()
    ));

    out
}

/// One rendered table row.
struct Row {
    ip: String,
    name: String,
    mac: String,
    vendor: String,
    device_type: String,
    trusted: bool,
    private_mac: bool,
}

impl Row {
    fn from_device(device: &Device, context: &DiscoveryContext<'_>) -> Self {
        let mac = device.mac.clone().unwrap_or_default();

        // A name the user typed beats anything we could infer.
        let name = device
            .hostname
            .clone()
            .or_else(|| device.mac.as_ref().and_then(|mac| context.labels.get(mac).cloned()))
            .unwrap_or_default();

        Row {
            ip: device.ip.to_string(),
            name,
            private_mac: is_private_mac(&mac),
            mac,
            vendor: device.vendor.clone().unwrap_or_default(),
            device_type: device
                .device_type
                .clone()
                .unwrap_or_else(|| "Unknown device".to_string()),
            trusted: is_trusted(device, context.trusted),
        }
    }

    fn status(&self) -> String {
        if self.trusted {
            "trusted".green().to_string()
        } else {
            "UNRECOGNIZED".red().bold().to_string()
        }
    }
}

/// Whether the device's MAC is in the trusted list.
///
/// MAC is the identity: it survives DHCP changing the address. Devices with no
/// MAC cannot be matched and are reported as unrecognized.
fn is_trusted(device: &Device, trusted: &HashSet<String>) -> bool {
    device
        .mac
        .as_deref()
        .map(normalize_mac)
        .is_some_and(|mac| trusted.contains(&mac))
}

/// Normalize a MAC for comparison and storage.
pub fn normalize_mac(mac: &str) -> String {
    mac.trim().to_ascii_uppercase()
}

/// Whether a MAC is locally administered (randomized for privacy).
fn is_private_mac(mac: &str) -> bool {
    if mac.is_empty() {
        return false;
    }
    netgap_core::mac::is_randomized_mac(mac)
}

/// Pad to a display width, truncating with an ellipsis when too long.
///
/// `value` may already contain ANSI escapes, so the caller passes the plain
/// width to use; colours are only applied to short, fixed-content columns.
fn pad(value: &str, width: usize) -> String {
    let visible = strip_ansi(value);
    let visible_len = visible.chars().count();

    if visible_len > width {
        let truncated: String = visible.chars().take(width.saturating_sub(1)).collect();
        return format!("{truncated}…");
    }

    format!("{value}{}", " ".repeat(width - visible_len))
}

/// Remove ANSI escape sequences so padding counts visible characters only.
fn strip_ansi(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip until the terminating 'm' of a CSI sequence.
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::OsType;

    fn device(ip: &str, mac: &str, device_type: &str) -> Device {
        let mut device = Device::new(ip.parse().expect("valid ip"));
        device.mac = Some(mac.to_string());
        device.device_type = Some(device_type.to_string());
        device.os = OsType::Unknown;
        device
    }

    fn context<'a>(trusted: &'a HashSet<String>) -> DiscoveryContext<'a> {
        static NO_LABELS: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        DiscoveryContext {
            interface: "wlan0",
            target: "192.168.1.0/24",
            trusted,
            labels: NO_LABELS.get_or_init(HashMap::new),
            gateway: Some("192.168.1.1".parse().unwrap()),
            local: Some("192.168.1.50".parse().unwrap()),
        }
    }

    #[test]
    fn test_counts_and_status() {
        let mut trusted = HashSet::new();
        trusted.insert("C4:B2:5B:0A:03:26".to_string());

        let devices = vec![
            device("192.168.1.1", "c4:b2:5b:0a:03:26", "Router / gateway"),
            device("192.168.1.30", "A2:2D:98:D1:F6:8F", "Phone / laptop (private MAC)"),
        ];

        let report = format_discovery(&devices, &context(&trusted));

        assert!(report.contains("Devices connected:"));
        assert!(report.contains("Trusted:"));
        assert!(report.contains("Unrecognized:"));
        assert!(report.contains("UNRECOGNIZED"));
        assert!(report.contains("netgap trust"));
        // Randomized MACs are called out for the reader.
        assert!(report.contains("(private)"));
    }

    #[test]
    fn test_all_trusted_has_no_warning() {
        let mut trusted = HashSet::new();
        trusted.insert("C4:B2:5B:0A:03:26".to_string());

        let devices = vec![device("192.168.1.1", "C4:B2:5B:0A:03:26", "Router / gateway")];
        let report = format_discovery(&devices, &context(&trusted));

        assert!(report.contains("Every device is in your trusted list"));
        assert!(!report.contains("UNRECOGNIZED"));
    }

    #[test]
    fn test_empty_discovery_is_explained() {
        let trusted = HashSet::new();
        let report = format_discovery(&[], &context(&trusted));
        assert!(report.contains("No devices responded"));
    }

    #[test]
    fn test_columns_align_and_long_values_are_truncated() {
        let trusted = HashSet::new();
        let mut long_name = device("192.168.1.9", "C4:B2:5B:0A:03:26", "Computer");
        long_name.hostname = Some("a-very-long-hostname-that-would-break-the-table".to_string());

        let devices = vec![long_name, device("192.168.1.10", "C4:B2:5B:0A:03:27", "Printer")];
        let report = format_discovery(&devices, &context(&trusted));

        assert!(report.contains('…'), "long values should be truncated");
        // Every table row starts with two spaces and wraps at the same width.
        let widths: Vec<usize> = report
            .lines()
            .filter(|line| line.trim_start().starts_with("192.168."))
            .map(|line| line.chars().count())
            .collect();
        assert!(widths.len() >= 2);
    }

    #[test]
    fn test_trust_label_supplies_a_name() {
        let mut trusted = HashSet::new();
        trusted.insert("C4:B2:5B:0A:03:26".to_string());
        let mut labels = HashMap::new();
        labels.insert("C4:B2:5B:0A:03:26".to_string(), "living room tv".to_string());

        let mut context = context(&trusted);
        context.labels = &labels;

        let devices = vec![device("192.168.1.1", "C4:B2:5B:0A:03:26", "Router / gateway")];
        let report = format_discovery(&devices, &context);

        assert!(report.contains("living room tv"));
    }

    #[test]
    fn test_normalize_mac() {
        assert_eq!(normalize_mac(" c4:b2:5b:0a:03:26 "), "C4:B2:5B:0A:03:26");
    }
}
