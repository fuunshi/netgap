//! Netgap core types and data structures.
//!
//! This module defines the fundamental types shared across all netgap subsystems.
//! All types implement `serde` for portability across CLI, FFI, and mobile platforms.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

pub mod version {
    use std::cmp::Ordering;

    /// Version string handling.
    /// Compare two version strings the way a person would.
    ///
    /// Versions are split into digit and non-digit runs; digit runs compare as
    /// numbers, the rest case-insensitively. This is what makes "2.4.9" older than
    /// "2.4.10" — a plain string comparison puts it after, which turns a real
    /// vulnerability into a clean bill of health.
    ///
    /// Trailing zero components are ignored, so "1.18.0" and "1.18" compare equal.
    /// Pre-release suffixes ("1.0rc1") are treated as *newer* than the plain
    /// release, the opposite of their usual meaning; no range in the bundled
    /// database depends on that distinction.
    pub fn compare_versions(left: &str, right: &str) -> Ordering {
        let left_parts = version_parts(left);
        let right_parts = version_parts(right);

        for index in 0..left_parts.len().max(right_parts.len()) {
            match (left_parts.get(index), right_parts.get(index)) {
                (Some(left_part), Some(right_part)) => {
                    let ordering = compare_part(left_part, right_part);
                    if ordering != Ordering::Equal {
                        return ordering;
                    }
                }
                (Some(_), None) => {
                    // One version has components the other lacks. That only means
                    // anything if they carry information: the "0" in "1.18.0"
                    // does not make it newer than "1.18".
                    if !left_parts[index..].iter().all(is_insignificant) {
                        return Ordering::Greater;
                    }
                }
                (None, Some(_)) => {
                    if !right_parts[index..].iter().all(is_insignificant) {
                        return Ordering::Less;
                    }
                }
                (None, None) => break,
            }
        }

        Ordering::Equal
    }

    /// One run of digits or non-digits within a version string.
    #[derive(Debug, PartialEq, Eq)]
    enum VersionPart {
        Number(u64),
        Text(String),
    }

    /// Split a version into alternating digit and non-digit runs.
    fn version_parts(version: &str) -> Vec<VersionPart> {
        let mut parts = Vec::new();
        let mut current = String::new();
        let mut current_is_digit: Option<bool> = None;

        for character in version.trim().chars() {
            let is_digit = character.is_ascii_digit();
            if let Some(previous) = current_is_digit {
                if previous != is_digit {
                    push_part(&mut parts, &mut current, previous);
                }
            }
            current_is_digit = Some(is_digit);
            current.push(character);
        }

        if let Some(is_digit) = current_is_digit {
            push_part(&mut parts, &mut current, is_digit);
        }

        parts
    }

    fn push_part(parts: &mut Vec<VersionPart>, current: &mut String, is_digit: bool) {
        if current.is_empty() {
            return;
        }

        if is_digit {
            parts.push(VersionPart::Number(current.parse().unwrap_or(u64::MAX)));
        } else if current.chars().any(|c| c.is_alphanumeric()) {
            // Punctuation is a separator, not a component: dropping it here is what
            // lets "7.4p1" line up against "7.4.1" component by component.
            parts.push(VersionPart::Text(current.to_ascii_lowercase()));
        }

        current.clear();
    }

    /// Whether a component says nothing about which version is newer.
    fn is_insignificant(part: &VersionPart) -> bool {
        matches!(part, VersionPart::Number(0))
    }

    fn compare_part(left: &VersionPart, right: &VersionPart) -> Ordering {
        match (left, right) {
            (VersionPart::Number(a), VersionPart::Number(b)) => a.cmp(b),
            (VersionPart::Text(a), VersionPart::Text(b)) => a.cmp(b),
            // A numeric component outranks a textual one, so "7.4.1" > "7.4p1".
            (VersionPart::Number(_), VersionPart::Text(_)) => Ordering::Greater,
            (VersionPart::Text(_), VersionPart::Number(_)) => Ordering::Less,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_numeric_not_lexicographic() {
            // The reason this exists: as strings, "2.4.9" sorts after "2.4.10".
            assert_eq!(compare_versions("2.4.9", "2.4.10"), Ordering::Less);
            assert_eq!(compare_versions("2.4.10", "2.4.9"), Ordering::Greater);
            assert_eq!(compare_versions("10.6.12", "9.6"), Ordering::Greater);
            assert_eq!(compare_versions("8.0.32", "15.1"), Ordering::Less);
            assert_eq!(compare_versions("9.3", "9.3"), Ordering::Equal);
        }

        #[test]
        fn test_separators_and_trailing_zeros() {
            assert_eq!(compare_versions("1.18.0", "1.18"), Ordering::Equal);
            assert_eq!(compare_versions("7.4p1", "7.4.1"), Ordering::Less);
            assert_eq!(compare_versions("2.9", "2.9.0"), Ordering::Equal);
        }

        #[test]
        fn test_bounded_windows() {
            // The shape NVD ranges need: >= start and < end.
            assert_eq!(compare_versions("2.4.49", "2.4.49"), Ordering::Equal);
            assert_eq!(compare_versions("2.4.50", "2.4.51"), Ordering::Less);
            assert_eq!(compare_versions("2.4.48", "2.4.49"), Ordering::Less);
        }
    }
}

/// MAC address helpers.
pub mod mac {
    /// Whether a MAC is locally administered, which in practice means the
    /// device randomized it for privacy — phones and laptops mostly.
    ///
    /// Such an address deliberately carries no vendor information, so an
    /// unknown vendor for it says nothing about the device being foreign.
    pub fn is_randomized_mac(mac: &str) -> bool {
        let Some(first_octet) = mac.split(':').next() else {
            return false;
        };
        let Ok(octet) = u8::from_str_radix(first_octet.trim(), 16) else {
            return false;
        };
        // Bit 1 of the first octet is the locally-administered flag.
        octet & 0b0000_0010 != 0
    }
}

/// Filesystem locations used by netgap.
///
/// Centralised so every crate resolves the config directory the same way and so
/// tests can redirect it with `NETGAP_CONFIG_DIR` instead of writing to `$HOME`.
pub mod paths {
    use super::PathBuf;

    /// Resolve the netgap configuration directory.
    ///
    /// Order: `NETGAP_CONFIG_DIR`, then `XDG_CONFIG_HOME/netgap`, then
    /// `~/.config/netgap` (or `%USERPROFILE%\.config\netgap` on Windows).
    pub fn config_dir() -> Option<PathBuf> {
        if let Ok(dir) = std::env::var("NETGAP_CONFIG_DIR") {
            if !dir.trim().is_empty() {
                return Some(PathBuf::from(dir));
            }
        }

        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join("netgap"));
            }
        }

        home_dir().map(|home| home.join(".config").join("netgap"))
    }

    /// Path to the SQLite scan database.
    pub fn scans_db_path() -> Option<PathBuf> {
        config_dir().map(|dir| dir.join("scans.db"))
    }

    fn home_dir() -> Option<PathBuf> {
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()
            .filter(|home| !home.trim().is_empty())
            .map(PathBuf::from)
    }
}

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Informational message, no action required.
    Info,
    /// Medium priority, should be addressed.
    Medium,
    /// High priority, immediate attention recommended.
    High,
    /// Critical security issue, requires immediate remediation.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single security finding or observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding type.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Detailed description of what was found.
    pub description: String,
    /// Severity level.
    pub severity: Severity,
    /// IP address where this was found.
    pub ip: IpAddr,
    /// Port (if applicable).
    pub port: Option<u16>,
    /// Service name (if identified).
    pub service: Option<String>,
    /// Specific remediation action.
    pub remediation: String,
    /// Confidence level (0.0 to 1.0).
    pub confidence: f32,
}

/// Operating system type (used in device fingerprinting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    Windows,
    Linux,
    MacOS,
    #[allow(non_camel_case_types)]
    iOS,
    Android,
    Unknown,
}

impl fmt::Display for OsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsType::Windows => write!(f, "Windows"),
            OsType::Linux => write!(f, "Linux"),
            OsType::MacOS => write!(f, "macOS"),
            OsType::iOS => write!(f, "iOS"),
            OsType::Android => write!(f, "Android"),
            OsType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Represents a discovered network device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// IP address of the device.
    pub ip: IpAddr,
    /// MAC address (if available).
    pub mac: Option<String>,
    /// Vendor name (from OUI lookup).
    pub vendor: Option<String>,
    /// Guessed OS type.
    pub os: OsType,
    /// Confidence in OS guess (0.0 to 1.0).
    pub os_confidence: f32,
    /// Hostname (if available via reverse DNS).
    pub hostname: Option<String>,
    /// When this device was first seen across scan history, if it has been
    /// recorded before. `None` means this is the first sighting.
    ///
    /// Filled in from the scan store rather than by discovery, which knows
    /// only about now.
    #[serde(default)]
    pub first_seen: Option<String>,
    /// Best-effort device classification (router, printer, phone, ...).
    ///
    /// A heuristic guess, never a certainty: MAC randomization and the size of
    /// the OUI database both limit what can be inferred.
    #[serde(default)]
    pub device_type: Option<String>,
    /// Open ports discovered on this device.
    pub open_ports: Vec<u16>,
    /// Findings related to this device.
    pub findings: Vec<Finding>,
}

impl Device {
    /// Create a new device with minimal information.
    pub fn new(ip: IpAddr) -> Self {
        Device {
            ip,
            mac: None,
            vendor: None,
            os: OsType::Unknown,
            os_confidence: 0.0,
            hostname: None,
            first_seen: None,
            device_type: None,
            open_ports: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Add a finding to this device.
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add an open port to this device.
    pub fn add_open_port(&mut self, port: u16) {
        if !self.open_ports.contains(&port) {
            self.open_ports.push(port);
            self.open_ports.sort();
        }
    }

    /// Get the highest severity finding on this device.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// A stable identity for recognising this device across scans.
    ///
    /// The MAC address is used because DHCP reassigns addresses, falling back
    /// to the IP when no MAC is known.
    ///
    /// A device that randomizes its MAC changes identity between scans and
    /// will look new again; that is a property of the privacy feature, not
    /// something this can see through.
    pub fn identity(&self) -> String {
        match &self.mac {
            Some(mac) => mac.trim().to_ascii_uppercase(),
            None => format!("ip:{}", self.ip),
        }
    }
}

/// Configuration for a scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Network interface to use (e.g., "eth0").
    pub interface: String,
    /// CIDR or single IP to scan.
    pub target: String,
    /// Timeout per connection in milliseconds.
    pub timeout_ms: u64,
    /// Maximum concurrent tasks.
    pub concurrency: usize,
    /// Skip port scanning, only discovery.
    pub discovery_only: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            interface: String::new(),
            target: String::new(),
            timeout_ms: 3000,
            concurrency: 32,
            discovery_only: false,
        }
    }
}

/// Results from a complete scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Timestamp when scan started.
    pub started_at: String,
    /// Configuration used for this scan.
    pub config: ScanConfig,
    /// Discovered devices and their findings.
    pub devices: Vec<Device>,
    /// Total findings by severity.
    pub summary: FindingSummary,
}

/// Summary of findings by severity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub info: usize,
}

impl Default for FindingSummary {
    fn default() -> Self {
        FindingSummary::new()
    }
}

impl FindingSummary {
    /// Create an empty summary.
    pub fn new() -> Self {
        FindingSummary {
            critical: 0,
            high: 0,
            medium: 0,
            info: 0,
        }
    }

    /// Increment count for a severity level.
    pub fn add_finding(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Info => self.info += 1,
        }
    }

    /// Total finding count.
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Info);
    }

    #[test]
    fn test_device_creation() {
        let ip = "192.168.1.1".parse().unwrap();
        let device = Device::new(ip);
        assert_eq!(device.ip, ip);
        assert_eq!(device.os, OsType::Unknown);
        assert!(device.findings.is_empty());
    }

    #[test]
    fn test_device_add_port() {
        let ip = "192.168.1.1".parse().unwrap();
        let mut device = Device::new(ip);
        device.add_open_port(80);
        device.add_open_port(22);
        device.add_open_port(80); // Duplicate
        assert_eq!(device.open_ports, vec![22, 80]);
    }

    #[test]
    fn test_identity_prefers_the_mac() {
        let mut device = Device::new("192.168.1.5".parse().expect("valid ip"));
        assert_eq!(device.identity(), "ip:192.168.1.5");

        device.mac = Some("c4:b2:5b:0a:03:26".to_string());
        assert_eq!(device.identity(), "C4:B2:5B:0A:03:26");
    }

    #[test]
    fn test_finding_serde() {
        let finding = Finding {
            id: "telnet_open".to_string(),
            title: "Telnet Enabled".to_string(),
            description: "Unencrypted Telnet on port 23".to_string(),
            severity: Severity::Critical,
            ip: "192.168.1.100".parse().unwrap(),
            port: Some(23),
            service: Some("telnet".to_string()),
            remediation: "Disable Telnet, use SSH instead".to_string(),
            confidence: 0.95,
        };

        let json = serde_json::to_string(&finding).expect("serialize");
        let deserialized: Finding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.title, finding.title);
        assert_eq!(deserialized.severity, Severity::Critical);
    }

    #[test]
    fn test_finding_summary() {
        let mut summary = FindingSummary::new();
        summary.add_finding(Severity::Critical);
        summary.add_finding(Severity::High);
        summary.add_finding(Severity::High);
        summary.add_finding(Severity::Info);

        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 2);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.total(), 4);
    }
}
