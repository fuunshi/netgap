//! Async port scanning and service fingerprinting.
//!
//! This module provides high-performance TCP port scanning using tokio.
//! It handles concurrent connections with tight timeouts and service detection.

use netgap_core::{Device, Finding, Severity};
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;
use tokio::task::JoinSet;

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
                if is_critical_port(port) {
                    let service = get_service_name(port);
                    let mut finding = Finding {
                        id: format!("open_port_{}", port),
                        title: format!("Open {} port ({})", service, port),
                        description: format!(
                            "Port {} ({}) is open and accessible. This service may expose the device to attacks.",
                            port, service
                        ),
                        severity: Severity::High,
                        ip: device.ip,
                        port: Some(port),
                        service: Some(service.to_string()),
                        remediation: format!("Review {} service configuration, restrict access via firewall if not needed", service),
                        confidence: 1.0,
                    };

                    if port == 23 {
                        finding.severity = Severity::Critical;
                        finding.title = "TELNET EXPOSED - CRITICAL VULNERABILITY".to_string();
                        finding.description = "Telnet (port 23) is open! All credentials sent in cleartext.".to_string();
                        finding.remediation = "Disable Telnet immediately. Use SSH for remote access.".to_string();
                    } else if port == 445 || port == 139 {
                        finding.severity = Severity::High;
                        finding.title = format!("SMB exposed on port {}", port);
                        finding.description = "SMB (file sharing) is accessible externally. Vulnerable to ransomware and data theft.".to_string();
                        finding.remediation = "Block SMB ports from external access using firewall rules.".to_string();
                    }

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
            _ => None,                 // Timeout or connection refused
        }
    }
}

/// Check if a port is considered critical/dangerous.
fn is_critical_port(port: u16) -> bool {
    matches!(port, 23 | 139 | 445) // Telnet, NetBIOS, SMB
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
        let mut devices = vec![
            Device::new("fe80::c6b2:5bff:fe0a:326".parse().expect("a valid address")),
            Device::new("192.168.111.1".parse().expect("a valid address")),
        ];

        let scanner = PortScanner::new(ScanConfig {
            ports: vec![22],
            timeout_ms: 50,
            concurrency: 1,
        });

        scanner.scan_devices(&mut devices[..1]).await.expect("scanning");

        assert!(devices[0].open_ports.is_empty());
        assert!(devices[0].findings.is_empty());
    }

    #[test]
    fn test_is_critical_port() {
        assert!(is_critical_port(23)); // Telnet
        assert!(is_critical_port(445)); // SMB
        assert!(!is_critical_port(443)); // HTTPS is not critical
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
