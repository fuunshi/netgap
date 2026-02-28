//! Netgap core types and data structures.
//!
//! This module defines the fundamental types shared across all netgap subsystems.
//! All types implement `serde` for portability across CLI, FFI, and mobile platforms.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

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
    /// Hostname (if available via mDNS/DNS).
    pub hostname: Option<String>,
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
