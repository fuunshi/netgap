//! Vulnerability assessment engine.
//!
//! This module implements pluggable vulnerability checks that examine
//! discovered devices and services to identify security issues.

use netgap_core::{Device, Finding, Severity};
use std::net::IpAddr;

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

/// Ports that serve router administration over plain HTTP.
const ADMIN_HTTP_PORTS: &[u16] = &[80, 8080];

/// Ports that expose the UPnP control interface.
const UPNP_CONTROL_PORTS: &[u16] = &[5000, 2869];

/// Ports that serve administration over TLS.
const ADMIN_TLS_PORTS: &[u16] = &[443, 8443];

/// Checks that only make sense for the network's gateway, where the stakes are
/// higher than on any other device: this is the one that routes everything.
///
/// Deliberately does not repeat the general checks. `UnencryptedHTTPCheck`
/// already reports a device serving HTTP with no HTTPS at all, so this adds
/// what that check cannot see: an admin interface reachable over HTTP *in
/// addition* to HTTPS, and an exposed UPnP control interface.
///
/// Nothing here tests credentials. Whether the admin page asks for a password,
/// and whether the default one still works, cannot be determined by looking at
/// a port, and claiming otherwise would be guesswork.
///
/// The UPnP check reads TCP ports only. UPnP discovery runs over UDP 1900,
/// which this does not probe, so a router that exposes SSDP without an HTTP
/// control interface will not be flagged — the check can miss UPnP, never
/// invent it.
pub fn check_gateway(device: &Device) -> Vec<Finding> {
    let mut findings = Vec::new();

    let http_admin: Vec<u16> = ADMIN_HTTP_PORTS
        .iter()
        .copied()
        .filter(|port| device.open_ports.contains(port))
        .collect();

    let has_tls_admin = ADMIN_TLS_PORTS
        .iter()
        .any(|port| device.open_ports.contains(port));

    if has_tls_admin && !http_admin.is_empty() {
        let port = http_admin[0];
        findings.push(Finding {
            id: "gateway_http_admin_available".to_string(),
            title: "Gateway administration is reachable over plain HTTP".to_string(),
            description: format!(
                "The gateway serves its administration interface on port {port} without encryption, alongside the encrypted interface. Anything typed into the HTTP page — including the router password — crosses the network in clear text, and anyone on the network can redirect that page elsewhere.",
            ),
            severity: Severity::Medium,
            ip: device.ip,
            port: Some(port),
            service: Some("HTTP".to_string()),
            remediation:
                "Disable the plain HTTP administration interface in the router settings, leaving only HTTPS. Prefer the HTTPS address when configuring it.".to_string(),
            confidence: 0.9,
        });
    }

    if let Some(port) = UPNP_CONTROL_PORTS
        .iter()
        .copied()
        .find(|port| device.open_ports.contains(port))
    {
        findings.push(Finding {
            id: "gateway_upnp_exposed".to_string(),
            title: "UPnP control interface is exposed on the gateway".to_string(),
            description: format!(
                "The gateway answers UPnP on port {port}. UPnP lets any device on the network ask the router to open an inbound port to the internet, with no authentication and no record of who asked. It is how some IoT devices and malware expose services without the owner ever choosing to.",
            ),
            severity: Severity::Medium,
            ip: device.ip,
            port: Some(port),
            service: Some("UPnP".to_string()),
            remediation:
                "Disable UPnP in the router settings unless something on the network depends on it, and forward ports explicitly instead.".to_string(),
            confidence: 0.85,
        });
    }

    findings
}

/// An inbound port a UPnP gateway has published, reduced to what a finding
/// needs. The network side lives in `netgap-probes`; these rules do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpnpMapping {
    pub external_port: u16,
    pub protocol: String,
    pub internal_client: String,
    pub internal_port: u16,
    pub description: String,
}

/// What the UPnP check found on the gateway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpnpExposure {
    /// What the router calls itself, when it said.
    pub name: Option<String>,
    /// The mappings it has published, enabled ones only.
    pub mappings: Vec<UpnpMapping>,
}

/// Findings for what the gateway's UPnP interface has published.
///
/// The port check in `check_gateway` can only say "UPnP answers here". This
/// says what it *did*: a mapping is a hole through the router's firewall that
/// any device on the network could have asked for, and which the router's own
/// page may not show.
///
/// A gateway that answers UPnP with nothing published is still worth a note —
/// the mechanism is armed, not used — but at a lower severity than an open
/// port, because nothing is reachable from outside until something asks.
pub fn upnp_findings(ip: IpAddr, exposure: &UpnpExposure) -> Vec<Finding> {
    if exposure.mappings.is_empty() {
        let name = exposure
            .name
            .as_deref()
            .map(|name| format!("{name} "))
            .unwrap_or_default();
        return vec![Finding {
            id: "gateway_upnp_answering".to_string(),
            title: "The gateway answers UPnP".to_string(),
            description: format!(
                "The {name}router accepts UPnP requests. Nothing is published to the internet right now, but any device on this network can ask it to open a port, with no password and no approval from you, and the result may not appear in the router's own settings page."
            ),
            severity: Severity::Medium,
            ip,
            port: Some(1900),
            service: Some("UPnP".to_string()),
            remediation:
                "Turn UPnP off in the router settings unless something on the network depends on it, and forward ports explicitly instead.".to_string(),
            confidence: 0.9,
        }];
    }

    let mut findings = Vec::new();
    for mapping in exposure.mappings.iter().take(10) {
        // Forwarding to the router itself is the worst case: it is the device
        // that holds the password to everything else.
        let to_router = mapping.internal_client == ip.to_string();
        let description = if mapping.description.is_empty() {
            String::new()
        } else {
            format!(" (\"{}\")", mapping.description)
        };
        findings.push(Finding {
            id: "gateway_upnp_port_mapping".to_string(),
            title: format!(
                "UPnP has published {} port {} to the internet",
                mapping.protocol.to_uppercase(),
                mapping.external_port
            ),
            description: format!(
                "The router forwards {} port {} from the internet to {}{}. Any device on this network could have asked for this: UPnP needs no password, and the router usually keeps no record of who made the request.",
                mapping.protocol.to_uppercase(),
                mapping.external_port,
                match to_router {
                    true => "the router itself".to_string(),
                    false => format!("{}:{}", mapping.internal_client, mapping.internal_port),
                },
                description,
            ),
            severity: if to_router {
                Severity::Critical
            } else {
                Severity::High
            },
            ip,
            port: Some(mapping.external_port),
            service: Some(mapping.protocol.to_uppercase()),
            remediation:
                "Remove this mapping in the router's settings, and turn UPnP off if nothing on the network needs it. If the service should be reachable, forward the port explicitly so it is visible and deliberate.".to_string(),
            confidence: 1.0,
        });
    }

    findings
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
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_device(ports: Vec<u16>) -> Device {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let mut device = Device::new(ip);
        for port in ports {
            device.add_open_port(port);
        }
        device
    }

    fn device_with_ports(ports: &[u16]) -> Device {
        let mut device = Device::new("192.168.1.1".parse().expect("valid ip"));
        for port in ports {
            device.add_open_port(*port);
        }
        device
    }

    #[test]
    fn test_gateway_http_admin_alongside_https() {
        // The general HTTP check stays quiet here because HTTPS is available;
        // on the gateway the plain-HTTP option is still worth flagging.
        let findings = check_gateway(&device_with_ports(&[80, 443]));

        let finding = findings
            .iter()
            .find(|finding| finding.id == "gateway_http_admin_available")
            .expect("plain HTTP admin should be reported");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.port, Some(80));
    }

    #[test]
    fn test_gateway_https_only_is_not_flagged() {
        let findings = check_gateway(&device_with_ports(&[443]));
        assert!(findings.is_empty());
    }

    #[test]
    fn test_gateway_upnp_is_reported() {
        let findings = check_gateway(&device_with_ports(&[80, 443, 5000]));

        let finding = findings
            .iter()
            .find(|finding| finding.id == "gateway_upnp_exposed")
            .expect("UPnP should be reported");
        assert_eq!(finding.port, Some(5000));

        // The UPnP control port on some routers.
        let findings = check_gateway(&device_with_ports(&[2869]));
        assert!(findings
            .iter()
            .any(|finding| finding.id == "gateway_upnp_exposed"));
    }

    #[test]
    fn test_gateway_checks_do_not_duplicate_the_general_http_check() {
        // HTTP with no HTTPS is the general check's business, not this one's.
        let device = device_with_ports(&[80]);
        assert!(check_gateway(&device).is_empty());
        assert!(!UnencryptedHTTPCheck.check(&device).is_empty());
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
        assert!(
            devices[1].findings.is_empty() || devices[1].findings.len() < devices[0].findings.len()
        );
    }

    fn mapping(port: u16, client: &str, description: &str) -> UpnpMapping {
        UpnpMapping {
            external_port: port,
            protocol: "TCP".into(),
            internal_client: client.into(),
            internal_port: 80,
            description: description.into(),
        }
    }

    #[test]
    fn test_a_published_upnp_mapping_is_high() {
        let exposure = UpnpExposure {
            name: Some("Archer AX10".into()),
            mappings: vec![mapping(8080, "192.168.1.50", "camera web")],
        };

        let findings = upnp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &exposure);
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.id, "gateway_upnp_port_mapping");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.port, Some(8080));
        assert!(finding.title.contains("8080"), "{}", finding.title);
        assert!(finding.description.contains("192.168.1.50:80"));
        assert!(finding.description.contains("camera web"));
    }

    #[test]
    fn test_a_mapping_to_the_router_itself_is_critical() {
        let exposure = UpnpExposure {
            name: None,
            mappings: vec![mapping(8443, "192.168.1.1", "")],
        };

        let findings = upnp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &exposure);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(
            findings[0].description.contains("the router itself"),
            "{}",
            findings[0].description
        );
    }

    #[test]
    fn test_a_gateway_with_nothing_published_is_only_a_note() {
        let exposure = UpnpExposure {
            name: Some("Archer AX10".into()),
            mappings: Vec::new(),
        };

        let findings = upnp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &exposure);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "gateway_upnp_answering");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(
            findings[0].description.contains("Archer AX10"),
            "{}",
            findings[0].description
        );
    }

    #[test]
    fn test_upnp_findings_stop_at_ten_mappings() {
        let mappings = (1..=15)
            .map(|port| mapping(port, "192.168.1.50", ""))
            .collect();
        let exposure = UpnpExposure {
            name: None,
            mappings,
        };

        let findings = upnp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &exposure);
        assert_eq!(findings.len(), 10);
    }
}
