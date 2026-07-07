//! Async port scanning and service fingerprinting.
//!
//! This module provides high-performance TCP port scanning using tokio.
//! It handles concurrent connections with tight timeouts and service detection.

use anyhow::Result;
use netgap_core::{Device, Finding, Severity};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Progress update for a host port scan.
#[derive(Debug, Clone)]
pub struct PortScanEvent {
    pub device_ip: IpAddr,
    pub completed_ports: usize,
    pub total_ports: usize,
    pub open_port: Option<u16>,
    pub finished: bool,
}

/// Top 20 most dangerous ports to scan by default.
pub const TOP_DANGEROUS_PORTS: &[u16] = &[
    20,   // FTP Data
    21,   // FTP
    22,   // SSH
    23,   // Telnet (CRITICAL)
    25,   // SMTP
    53,   // DNS
    69,   // TFTP
    80,   // HTTP
    110,  // POP3
    139,  // NetBIOS
    143,  // IMAP
    161,  // SNMP
    389,  // LDAP
    443,  // HTTPS
    445,  // SMB (CRITICAL)
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    8080, // Alt HTTP
    8443, // Alt HTTPS
];

/// Configuration for port scanning.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// List of ports to scan.
    pub ports: Vec<u16>,
    /// Timeout per connection in milliseconds.
    pub timeout_ms: u64,
    /// Maximum concurrent tasks.
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            ports: TOP_DANGEROUS_PORTS.to_vec(),
            timeout_ms: 2000,
            concurrency: 32,
        }
    }
}

/// High-performance async TCP port scanner.
pub struct PortScanner {
    config: ScanConfig,
}

impl Default for PortScanner {
    fn default() -> Self {
        PortScanner::with_default_config()
    }
}

impl PortScanner {
    /// Create a new port scanner with custom configuration.
    pub fn new(config: ScanConfig) -> Self {
        PortScanner { config }
    }

    /// Create with default configuration (top 20 ports, 2s timeout, 32 concurrent).
    pub fn with_default_config() -> Self {
        PortScanner::new(ScanConfig::default())
    }

    /// Scan a single IP address for open ports.
    pub async fn scan_ip(&self, ip: IpAddr) -> Result<Vec<u16>> {
        self.scan_ip_with_progress(ip, None).await
    }

    /// Scan a single IP address for open ports while emitting progress events.
    pub async fn scan_ip_with_progress(
        &self,
        ip: IpAddr,
        progress: Option<UnboundedSender<PortScanEvent>>,
    ) -> Result<Vec<u16>> {
        let mut open_ports = Vec::new();
        let total_ports = self.config.ports.len();

        // Create tasks for each port with semaphore for concurrency control
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));
        let mut tasks = JoinSet::new();

        for &port in &self.config.ports {
            let sem = semaphore.clone();
            let timeout_duration = Duration::from_millis(self.config.timeout_ms);

            tasks.spawn(async move {
                let _permit = sem.acquire().await;
                Self::check_port(ip, port, timeout_duration).await
            });
        }

        let mut completed_ports = 0;

        // Collect results as tasks finish so callers can render live progress.
        while let Some(handle) = tasks.join_next().await {
            let open_port = match handle {
                Ok(Some(port)) => {
                    open_ports.push(port);
                    Some(port)
                }
                _ => None,
            };

            completed_ports += 1;

            if let Some(progress) = &progress {
                let _ = progress.send(PortScanEvent {
                    device_ip: ip,
                    completed_ports,
                    total_ports,
                    open_port,
                    finished: completed_ports == total_ports,
                });
            }
        }

        open_ports.sort();
        Ok(open_ports)
    }

    /// Scan multiple devices.
    pub async fn scan_devices(&self, devices: &mut [Device]) -> Result<()> {
        self.scan_devices_with_progress(devices, None).await
    }

    /// Scan multiple devices while emitting progress events.
    pub async fn scan_devices_with_progress(
        &self,
        devices: &mut [Device],
        progress: Option<UnboundedSender<PortScanEvent>>,
    ) -> Result<()> {
        for device in devices.iter_mut() {
            // A link-local address (`fe80::/10`) is only reachable with a zone
            // — the interface — attached to it, and a device here does not
            // carry one. Connecting without it fails for every port, which
            // would read as "no open ports" rather than "not scanned".
            if let IpAddr::V6(address) = device.ip {
                if (address.segments()[0] & 0xffc0) == 0xfe80 {
                    eprintln!(
                        "  · Not port-scanning {}: link-local IPv6 needs an interface to be \
                         reached, which this device does not record",
                        device.ip
                    );
                    continue;
                }
            }

            eprintln!("🔍 Scanning {} for open ports...", device.ip);
            let open_ports = self
                .scan_ip_with_progress(device.ip, progress.clone())
                .await?;

            for port in open_ports {
                device.add_open_port(port);

                // Generate finding for dangerous ports
                if let Some(severity) = port_risk(port) {
                    let service = get_service_name(port);
                    let finding = Finding {
                        id: format!("open_port_{}", port),
                        title: format!("{} is reachable ({})", service, port),
                        description: format!(
                            "Port {} ({}) is open and accepting connections. {}",
                            port,
                            service,
                            risk_note(port)
                        ),
                        severity,
                        ip: device.ip,
                        port: Some(port),
                        service: Some(service.to_string()),
                        remediation: remediation_for(port, service),
                        confidence: 1.0,
                    };

                    device.add_finding(finding);
                }
            }

            if device.open_ports.is_empty() {
                eprintln!("  ✓ No dangerous open ports found");
            } else {
                eprintln!("  ⚠ Found {} open port(s)", device.open_ports.len());
            }
        }

        Ok(())
    }

    /// Check a single port for connectivity.
    async fn check_port(ip: IpAddr, port: u16, timeout_duration: Duration) -> Option<u16> {
        let socket_addr = SocketAddr::new(ip, port);

        match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
            Ok(Ok(_)) => Some(port), // Port is open
            _ => None,               // Timeout or connection refused
        }
    }
}

/// How much an open port on its own is worth reporting, or `None` when the
/// port is unremarkable and should not become a finding.
///
/// `None` is the answer for most of the scanned list — 443 open on a computer
/// is not a problem, and a report full of not-problems is one nobody reads.
/// What is here is the set where an open port *is* the finding: anything that
/// carries a password in the clear, or hands over control of the machine.
fn port_risk(port: u16) -> Option<Severity> {
    match port {
        // Everything typed into these crosses the network readable.
        23 | 512 | 513 | 514 => Some(Severity::Critical),
        // Access to files or to the desktop itself.
        139 | 445 | 3389 | 5900..=5902 => Some(Severity::High),
        // A database on a network is usually meant to be reachable only by the
        // application that uses it.
        3306 | 5432 | 6379 | 27017 => Some(Severity::High),
        // Unencrypted, but a person has to be using it at the time.
        21 | 161 => Some(Severity::Medium),
        _ => None,
    }
}

/// Why an open port matters, in one clause that completes "…connections. {this}".
fn risk_note(port: u16) -> &'static str {
    match port {
        23 => "Telnet sends everything typed into it, including the password, in readable form.",
        512..=514 => {
            "The r-services accept logins over the network without encryption, and often without \
             a password."
        }
        139 => "NetBIOS file sharing lets other machines read and write files on this one.",
        445 => "SMB file sharing lets other machines read and write files on this one.",
        3389 => "Remote Desktop lets someone at another machine take over this one.",
        5900..=5902 => "VNC lets someone at another machine see and control this screen.",
        3306 | 5432 => "A database is answering on the network.",
        6379 | 27017 => {
            "A database is answering on the network, and these often ship without a password."
        }
        21 => "FTP sends the password in readable form.",
        161 => "SNMP can describe the device's model, software and traffic to anyone who asks.",
        _ => "It may expose the device to attack.",
    }
}

/// What to do about an open port, phrased as the first thing to try.
fn remediation_for(port: u16, service: &str) -> String {
    match port {
        23 => "Disable Telnet and use SSH instead.".to_string(),
        512..=514 => "Disable the r-services; use SSH instead.".to_string(),
        139 | 445 => {
            "Turn file sharing off on this computer if it is not needed, and check that the \
             shared folders require a password."
                .to_string()
        }
        3389 => "Turn Remote Desktop off if it is not used.".to_string(),
        5900..=5902 => {
            "Turn the VNC server off if it is not used, and set a password if it is.".to_string()
        }
        3306 | 5432 | 6379 | 27017 => {
            "Restrict the database to the machines that need it, and set a password.".to_string()
        }
        21 => "Use SFTP or SCP instead of FTP.".to_string(),
        161 => "Turn SNMP off, or change the community string from its default.".to_string(),
        _ => format!("Restrict access to {service} with a firewall rule if it is not needed."),
    }
}

/// Get common service name for a port.
fn get_service_name(port: u16) -> &'static str {
    match port {
        20 => "FTP-DATA",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        69 => "TFTP",
        80 => "HTTP",
        110 => "POP3",
        139 => "NetBIOS",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        8080 => "HTTP-ALT",
        8443 => "HTTPS-ALT",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link-local address cannot be reached without a zone, so scanning one
    /// would report "no open ports" for a device that was never actually
    /// tried. It is skipped, and skipping must not look like a clean result.
    #[tokio::test]
    async fn test_link_local_devices_are_skipped_rather_than_reported_clean() {
        let mut devices = [Device::new(
            "fe80::c6b2:5bff:fe0a:326".parse().expect("a valid address"),
        )];

        let scanner = PortScanner::new(ScanConfig {
            ports: vec![22],
            timeout_ms: 50,
            concurrency: 1,
        });

        scanner.scan_devices(&mut devices).await.expect("scanning");

        assert!(devices[0].open_ports.is_empty());
        assert!(devices[0].findings.is_empty());
    }

    #[test]
    fn test_port_risk() {
        assert_eq!(port_risk(23), Some(Severity::Critical)); // Telnet
        assert_eq!(port_risk(514), Some(Severity::Critical)); // rsh
        assert_eq!(port_risk(445), Some(Severity::High)); // SMB
        assert_eq!(port_risk(3389), Some(Severity::High)); // RDP
        assert_eq!(port_risk(3306), Some(Severity::High)); // MySQL
        assert_eq!(port_risk(161), Some(Severity::Medium)); // SNMP

        // An open HTTPS port is not a problem worth a finding.
        assert_eq!(port_risk(443), None);
        assert_eq!(port_risk(80), None);
        assert_eq!(port_risk(22), None);
    }

    /// Every port that produces a finding needs a note and a fix, since both
    /// are rendered to the user.
    #[test]
    fn test_every_risky_port_has_an_explanation() {
        for port in [
            23, 512, 513, 514, 139, 445, 3389, 5900, 3306, 5432, 6379, 27017, 21, 161,
        ] {
            assert!(port_risk(port).is_some(), "{port} should be a finding");
            assert!(!risk_note(port).is_empty(), "{port} needs a note");
            assert!(
                !remediation_for(port, "service").is_empty(),
                "{port} needs a fix"
            );
        }
    }

    #[test]
    fn test_get_service_name() {
        assert_eq!(get_service_name(23), "Telnet");
        assert_eq!(get_service_name(445), "SMB");
        assert_eq!(get_service_name(22), "SSH");
        assert_eq!(get_service_name(9999), "Unknown");
    }

    #[test]
    fn test_default_config() {
        let config = ScanConfig::default();
        assert_eq!(config.timeout_ms, 2000);
        assert_eq!(config.concurrency, 32);
        assert_eq!(config.ports.len(), 20);
    }

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = PortScanner::default();
        assert_eq!(scanner.config.ports.len(), 20);
    }
}
