//! Vulnerability assessment engine.
//!
//! This module implements pluggable vulnerability checks that examine
//! discovered devices and services to identify security issues.

use netgap_core::{Device, Finding, Severity};

/// Trait for implementing vulnerability checks.
pub trait VulnerabilityCheck: Send + Sync {
    /// Check ID (e.g., "telnet_open", "smb_exposed")
    fn id(&self) -> &str;

    /// Human-readable check name
    fn name(&self) -> &str;

    /// Applies check to a device. Returns findings if vulnerabilities found.
    fn check(&self, device: &Device) -> Vec<Finding>;
}

/// Pluggable assessment runner
pub struct AssessmentRunner {
    checks: Vec<Box<dyn VulnerabilityCheck>>,
}

impl AssessmentRunner {
    /// Create a new assessment runner with default checks.
    pub fn new() -> Self {
        let checks: Vec<Box<dyn VulnerabilityCheck>> = vec![
            Box::new(TelnetExposedCheck),
            Box::new(FTPExposedCheck),
            Box::new(SMBExposedCheck),
            Box::new(SNMPExposedCheck),
            Box::new(UnencryptedHTTPCheck),
        ];

        AssessmentRunner { checks }
    }

    /// Run all checks on a device and collect findings
    pub fn assess(&self, device: &Device) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        for check in &self.checks {
            let findings = check.check(device);
            all_findings.extend(findings);
        }

        all_findings
    }

    /// Run all checks on multiple devices
    pub fn assess_all(&self, devices: &mut [Device]) {
        for device in devices.iter_mut() {
            let findings = self.assess(device);
            for finding in findings {
                device.add_finding(finding);
            }
        }
    }
}

impl Default for AssessmentRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Check for exposed Telnet (port 23) - CRITICAL
struct TelnetExposedCheck;

impl VulnerabilityCheck for TelnetExposedCheck {
    fn id(&self) -> &str {
        "telnet_exposed"
    }

    fn name(&self) -> &str {
        "Telnet Exposed"
    }

    fn check(&self, device: &Device) -> Vec<Finding> {
        if device.open_ports.contains(&23) {
            vec![Finding {
                id: "telnet_23_exposed".to_string(),
                title: "TELNET EXPOSED - CRITICAL VULNERABILITY".to_string(),
                description: "Telnet (port 23) is open and accessible. All credentials and traffic are transmitted in cleartext, making them trivial to intercept.".to_string(),
                severity: Severity::Critical,
                ip: device.ip,
                port: Some(23),
                service: Some("Telnet".to_string()),
                remediation: "Immediately disable Telnet. Use SSH (port 22) with key-based authentication instead. If legacy access required, tunnel through SSH.".to_string(),
                confidence: 1.0,
            }]
        } else {
            vec![]
        }
    }
}

/// Check for exposed FTP (port 21) - HIGH
struct FTPExposedCheck;

impl VulnerabilityCheck for FTPExposedCheck {
    fn id(&self) -> &str {
        "ftp_exposed"
    }

    fn name(&self) -> &str {
        "FTP Exposed"
    }

    fn check(&self, device: &Device) -> Vec<Finding> {
        if device.open_ports.contains(&21) {
            vec![Finding {
                id: "ftp_21_exposed".to_string(),
                title: "FTP Exposed - Unencrypted File Transfer".to_string(),
                description: "FTP (port 21) is open. Credentials and file contents are transmitted unencrypted and vulnerable to interception. This is a significant data security risk.".to_string(),
                severity: Severity::High,
                ip: device.ip,
                port: Some(21),
                service: Some("FTP".to_string()),
                remediation: "Disable FTP immediately. Use SFTP (SSH File Transfer Protocol) on port 22 or secure alternatives like HTTPS for file transfers.".to_string(),
                confidence: 1.0,
            }]
        } else {
            vec![]
        }
    }
}

/// Check for exposed SMB (ports 139, 445) - HIGH/CRITICAL
struct SMBExposedCheck;

impl VulnerabilityCheck for SMBExposedCheck {
    fn id(&self) -> &str {
        "smb_exposed"
    }

    fn name(&self) -> &str {
        "SMB Exposed"
    }

    fn check(&self, device: &Device) -> Vec<Finding> {
        let mut findings = Vec::new();

        if device.open_ports.contains(&445) {
            findings.push(Finding {
                id: "smb_445_exposed".to_string(),
                title: "SMB Exposed on Port 445 - Ransomware Risk".to_string(),
                description: "SMB (Server Message Block) is exposed on port 445. This is a primary vector for ransomware, lateral movement, and data exfiltration (EternalBlue, NotPetya, WannaCry, etc.).".to_string(),
                severity: Severity::Critical,
                ip: device.ip,
                port: Some(445),
                service: Some("SMB".to_string()),
                remediation: "Block SMB ports 139 and 445 from external access using firewall rules. If remote file sharing needed, use VPN + restricted IP whitelist. Ensure SMB signing and encryption enabled.".to_string(),
                confidence: 1.0,
            });
        }

        if device.open_ports.contains(&139) {
            findings.push(Finding {
                id: "smb_139_exposed".to_string(),
                title: "NetBIOS Exposed on Port 139 - Legacy SMB".to_string(),
                description: "NetBIOS over TCP (port 139) is exposed. This is legacy SMB and carries the same ransomware risks as port 445.".to_string(),
                severity: Severity::High,
                ip: device.ip,
                port: Some(139),
                service: Some("NetBIOS".to_string()),
                remediation: "Disable NetBIOS over TCP. Block port 139 from external access. Modern SMB should use port 445 with encryption and signing.".to_string(),
                confidence: 1.0,
            });
        }

        findings
    }
}

/// Check for exposed SNMP (port 161) - HIGH
struct SNMPExposedCheck;

impl VulnerabilityCheck for SNMPExposedCheck {
    fn id(&self) -> &str {
        "snmp_exposed"
    }

    fn name(&self) -> &str {
        "SNMP Exposed"
    }

    fn check(&self, device: &Device) -> Vec<Finding> {
        if device.open_ports.contains(&161) {
            vec![Finding {
                id: "snmp_161_exposed".to_string(),
                title: "SNMP Exposed on Port 161 - Information Disclosure".to_string(),
                description: "SNMP (Simple Network Management Protocol) is exposed. Default community strings (public, private, community, internal) can leak system info: uptime, processes, network configuration, installed software.".to_string(),
                severity: Severity::High,
                ip: device.ip,
                port: Some(161),
                service: Some("SNMP".to_string()),
                remediation: "Disable SNMP v1/v2c (uses cleartext community strings). Restrict SNMP to admin networks only. If needed, use SNMPv3 with authentication and encryption.".to_string(),
                confidence: 0.95,
            }]
        } else {
            vec![]
        }
    }
}

/// Check for unencrypted HTTP admin panel (port 80) - MEDIUM
struct UnencryptedHTTPCheck;

impl VulnerabilityCheck for UnencryptedHTTPCheck {
    fn id(&self) -> &str {
        "http_unencrypted"
    }

    fn name(&self) -> &str {
        "Unencrypted HTTP"
    }

    fn check(&self, device: &Device) -> Vec<Finding> {
        if device.open_ports.contains(&80) && !device.open_ports.contains(&443) {
            vec![Finding {
                id: "http_80_no_https".to_string(),
                title: "HTTP Without HTTPS - Admin Panel May Be Unencrypted".to_string(),
                description: "Port 80 (HTTP) is open but no HTTPS (port 443) detected. If this device has an admin panel, credentials and configuration may be transmitted unencrypted.".to_string(),
                severity: Severity::Medium,
                ip: device.ip,
                port: Some(80),
                service: Some("HTTP".to_string()),
                remediation: "Enable HTTPS on the device's admin interface. Redirect HTTP traffic to HTTPS. Use strong certificates and disable HTTP for sensitive operations.".to_string(),
                confidence: 0.80,
            }]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn create_test_device(ports: Vec<u16>) -> Device {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let mut device = Device::new(ip);
        for port in ports {
            device.add_open_port(port);
        }
        device
    }

    #[test]
    fn test_telnet_check() {
        let check = TelnetExposedCheck;
        let device = create_test_device(vec![23]);

        let findings = check.check(&device);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].description.contains("cleartext"));
    }

    #[test]
    fn test_telnet_not_exposed() {
        let check = TelnetExposedCheck;
        let device = create_test_device(vec![22, 80]);

        let findings = check.check(&device);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_smb_check() {
        let check = SMBExposedCheck;
        let device = create_test_device(vec![445]);

        let findings = check.check(&device);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].description.contains("ransomware"));
    }

    #[test]
    fn test_snmp_check() {
        let check = SNMPExposedCheck;
        let device = create_test_device(vec![161]);

        let findings = check.check(&device);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_assessment_runner() {
        let runner = AssessmentRunner::new();
        let device = create_test_device(vec![23, 445, 80]);

        let findings = runner.assess(&device);
        assert!(findings.len() >= 2); // At least Telnet and SMB

        let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
        assert!(has_critical);
    }

    #[test]
    fn test_assess_all_devices() {
        let runner = AssessmentRunner::new();
        let mut devices = vec![
            create_test_device(vec![23]),      // Telnet
            create_test_device(vec![80, 443]), // HTTP/HTTPS (safe)
        ];

        runner.assess_all(&mut devices);

        assert!(!devices[0].findings.is_empty());
        assert!(devices[1].findings.is_empty() || devices[1].findings.len() < devices[0].findings.len());
    }
}
