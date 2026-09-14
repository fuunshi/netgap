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

/// Whether an SMB server insists on message signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbSigning {
    /// Unsigned sessions are refused.
    Required,
    /// Signing is supported but a client may decline it.
    Optional,
    /// The server said it does not sign.
    Disabled,
    /// An SMBv1-only server does not say until a session is set up.
    Unknown,
}

/// What a file server said about itself before anyone logged in. The wire side
/// lives in `netgap-probes`; these rules do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbServer {
    /// The server still accepts the SMBv1 dialect.
    pub smb1: bool,
    /// The server answered SMB2/3 negotiation.
    pub smb2: bool,
    /// The dialect it chose, when it said, e.g. "3.1.1".
    pub dialect: Option<String>,
    pub signing: SmbSigning,
}

/// Findings for what a file server negotiated without any credentials.
///
/// Both facts are stated by the server itself, so the confidence is exact.
///
/// The signing finding is graded by how far the server goes: a server that
/// signs but does not require it can be relayed against, and a server that has
/// signing off entirely cannot even be talked into it. Neither demands that a
/// victim is tricked into authenticating to the attacker first, which is why
/// this is not rated as high as an open cleartext service.
pub fn smb_findings(ip: IpAddr, port: u16, server: &SmbServer) -> Vec<Finding> {
    let mut findings = Vec::new();

    if server.smb1 {
        findings.push(Finding {
            id: "smb_v1_enabled".to_string(),
            title: "This file server still speaks SMBv1".to_string(),
            description: format!(
                "The server at {ip}:{port} accepted an SMBv1 negotiation. SMBv1 is the protocol the WannaCry and NotPetya worms spread through: they needed nothing but a reachable SMBv1 service on an unpatched machine. A network where no server negotiates SMBv1 cannot carry that class of worm."
            ),
            severity: Severity::High,
            ip,
            port: Some(port),
            service: Some("SMB".to_string()),
            remediation:
                "Turn SMBv1 off. Windows, Samba and macOS have shipped it disabled for years; it is usually still on only because an old copier or appliance needs it. Isolate that device behind its own rules instead."
                    .to_string(),
            confidence: 1.0,
        });
    }

    match server.signing {
        SmbSigning::Optional | SmbSigning::Disabled => {
            let (title, consequence) = match server.signing {
                SmbSigning::Disabled => (
                    "SMB signing is disabled on this file server",
                    "The server does not sign at all, so a client cannot ask for it even when it wants to.",
                ),
                _ => (
                    "This file server accepts unsigned SMB sessions",
                    "The server can sign but does not insist, so a client that declines is still let in.",
                ),
            };
            let dialect = server
                .dialect
                .as_deref()
                .map(|dialect| format!(" It negotiated SMB {dialect}."))
                .unwrap_or_default();

            findings.push(Finding {
                id: "smb_signing_not_required".to_string(),
                title: title.to_string(),
                description: format!(
                    "{consequence}{dialect} An attacker on this network can relay someone else's authentication to this server and act as them, without knowing or cracking their password — the technique behind most NTLM relay attacks. This matters most on a domain controller, where the relayed identity can be used to take over the domain."
                ),
                severity: match server.signing {
                    SmbSigning::Disabled => Severity::High,
                    _ => Severity::Medium,
                },
                ip,
                port: Some(port),
                service: Some("SMB".to_string()),
                remediation:
                    "Require signing on the server: on Windows, set RequireSecuritySignature for the SMB server; in Samba, `server signing = mandatory`. Clients that cannot sign will need fixing rather than being allowed to skip it."
                        .to_string(),
                confidence: 1.0,
            });
        }
        SmbSigning::Required | SmbSigning::Unknown => {}
    }

    findings
}

/// What an FTP server said when an anonymous login was attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpServer {
    /// The greeting the server sent, which often names the software.
    pub banner: Option<String>,
    /// The anonymous login was accepted.
    pub anonymous: bool,
}

/// Findings for an FTP server that lets anyone in.
///
/// Anonymous access is a deliberate setting, but the scan cannot know it was
/// deliberate on *this* network, and the difference between "FTP is open" and
/// "FTP will serve files to anyone" is the one that decides whether to act.
pub fn ftp_findings(ip: IpAddr, port: u16, server: &FtpServer) -> Vec<Finding> {
    if !server.anonymous {
        return Vec::new();
    }

    let software = server
        .banner
        .as_deref()
        .map(|banner| format!(" ({})", banner.trim()))
        .unwrap_or_default();

    vec![Finding {
        id: "ftp_anonymous_login".to_string(),
        title: "Anyone can log in to this FTP server".to_string(),
        description: format!(
            "The FTP server at {ip}:{port}{software} accepted the anonymous login, so everything it offers over FTP is available to anyone on this network without an account. FTP is also unencrypted, which means a real user's password crosses the network in the clear whenever they log in. Whether the anonymous share is writable was not tested."
        ),
        severity: Severity::High,
        ip,
        port: Some(port),
        service: Some("FTP".to_string()),
        remediation:
            "Turn anonymous access off (vsftpd: `anonymous_enable=NO`; ProFTPD: remove the `<Anonymous>` block), and replace FTP with SFTP where the software allows it, so passwords are not sent in the clear."
                .to_string(),
        confidence: 1.0,
    }]
}

/// What a Redis server allowed without a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisServer {
    /// The server answered `PING` without credentials.
    pub open: bool,
    /// The version, when `INFO` was answered too.
    pub version: Option<String>,
}

/// Findings for a Redis server with no access control.
///
/// This is rated critical because of what an open Redis can do rather than
/// what it stores: its own configuration commands write arbitrary files, which
/// is a short path from reachable to running code on the host.
pub fn redis_findings(ip: IpAddr, port: u16, server: &RedisServer) -> Vec<Finding> {
    if !server.open {
        return Vec::new();
    }

    let version = server
        .version
        .as_deref()
        .map(|version| format!(" (Redis {version})"))
        .unwrap_or_default();

    vec![Finding {
        id: "redis_unauthenticated".to_string(),
        title: "This Redis server has no password".to_string(),
        description: format!(
            "The Redis server at {ip}:{port}{version} answered a `PING` without credentials, so anyone on this network can read, change and delete every key it holds. Worse, Redis administration commands can write files to the host, so an open server is usually a way in to the machine itself, not just to the data."
        ),
        severity: Severity::Critical,
        ip,
        port: Some(port),
        service: Some("Redis".to_string()),
        remediation:
            "Bind Redis to a private interface (`bind 127.0.0.1`) and require a password (`requirepass`, or an ACL user on Redis 6+). If other machines genuinely need it, restrict the port to them with a firewall rather than leaving it open to the whole network."
                .to_string(),
        confidence: 1.0,
    }]
}

/// What a MongoDB server allowed without a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MongoServer {
    /// `listDatabases` was answered, which only an unauthenticated server does.
    pub open: bool,
}

/// Findings for a MongoDB server with authentication switched off.
///
/// The test is a listing, not a read of documents: the server either refuses
/// the administrative command until the client logs in, or it answers. When it
/// answers, everything else is open too.
pub fn mongo_findings(ip: IpAddr, port: u16, server: &MongoServer) -> Vec<Finding> {
    if !server.open {
        return Vec::new();
    }

    vec![Finding {
        id: "mongo_unauthenticated".to_string(),
        title: "This MongoDB server has no password".to_string(),
        description: format!(
            "The MongoDB server at {ip}:{port} listed its databases to a client that never logged in, which means authentication is switched off entirely. Anyone on this network can read, change and delete every database it holds, and the administration commands that drop them too."
        ),
        severity: Severity::Critical,
        ip,
        port: Some(port),
        service: Some("MongoDB".to_string()),
        remediation:
            "Turn authentication on (`security.authorization: enabled`), create an administrator user, then a user per application with only the roles it needs. Bind MongoDB to a private interface and restrict the port with a firewall so the whole network cannot reach it."
                .to_string(),
        confidence: 1.0,
    }]
}

/// What a device said to the `public` community.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpServer {
    /// The device answered a `GET` sent with the community `public`.
    pub public_community: bool,
    /// What it calls itself, when it said.
    pub description: Option<String>,
}

/// Findings for a device that answers SNMP with the factory community.
///
/// An SNMP agent that accepts `public` will usually also list its interfaces,
/// its ARP table and its routes — the reconnaissance an attacker does first.
/// The finding quotes the device's own description, because that is what makes
/// it recognisable to the person reading the report.
pub fn snmp_findings(ip: IpAddr, port: u16, server: &SnmpServer) -> Vec<Finding> {
    if !server.public_community {
        return Vec::new();
    }

    let description = server
        .description
        .as_deref()
        .map(|text| format!(" It describes itself as \"{}\".", truncate(text, 120)))
        .unwrap_or_default();

    vec![Finding {
        id: "snmp_public_community".to_string(),
        title: "This device answers SNMP with the default community".to_string(),
        description: format!(
            "The device at {ip} answered an SNMP request sent with the community string `public`, the factory default.{description} Anyone on this network can read its description, interface list and often its routing and ARP tables, and SNMP v1 and v2c send that community as plain text."
        ),
        severity: Severity::High,
        ip,
        port: Some(port),
        service: Some("SNMP".to_string()),
        remediation:
            "Change the community from `public` to a long random string, or move to SNMPv3 with authentication and encryption. If nothing manages the device over SNMP, turn SNMP off, and otherwise restrict UDP 161 to the management host."
                .to_string(),
        confidence: 1.0,
    }]
}

/// A string cut at a character boundary, for quoting in a finding.
fn truncate(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((index, _)) => format!("{}…", &text[..index]),
        None => text.to_string(),
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

    fn server(smb1: bool, signing: SmbSigning) -> SmbServer {
        SmbServer {
            smb1,
            smb2: true,
            dialect: Some("3.1.1".into()),
            signing,
        }
    }

    fn file_server() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 36))
    }

    #[test]
    fn test_smbv1_enabled_is_reported_whatever_the_signing() {
        let findings = smb_findings(file_server(), 445, &server(true, SmbSigning::Required));
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.id, "smb_v1_enabled");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.port, Some(445));
        assert!(finding.description.contains("192.168.1.36:445"));
    }

    #[test]
    fn test_optional_signing_is_a_medium_relay_risk() {
        let findings = smb_findings(file_server(), 445, &server(false, SmbSigning::Optional));
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.id, "smb_signing_not_required");
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.title.contains("unsigned"), "{}", finding.title);
        // The dialect the server chose is worth stating: it dates the server.
        assert!(finding.description.contains("SMB 3.1.1"));
    }

    #[test]
    fn test_disabled_signing_is_worse_than_optional() {
        let findings = smb_findings(file_server(), 445, &server(false, SmbSigning::Disabled));
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("disabled"));
    }

    #[test]
    fn test_a_fully_current_file_server_produces_nothing() {
        let findings = smb_findings(file_server(), 445, &server(false, SmbSigning::Required));
        assert!(findings.is_empty());

        // An SMBv1-only server never states its signing mode; that alone must
        // not be turned into a finding about signing.
        let v1_only = SmbServer {
            smb1: true,
            smb2: false,
            dialect: None,
            signing: SmbSigning::Unknown,
        };
        let findings = smb_findings(file_server(), 445, &v1_only);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "smb_v1_enabled");
    }

    #[test]
    fn test_anonymous_ftp_is_high_and_names_the_software() {
        let server = FtpServer {
            banner: Some("220 (vsFTPd 3.0.5)".into()),
            anonymous: true,
        };

        let findings = ftp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 21, &server);
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.id, "ftp_anonymous_login");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.port, Some(21));
        assert!(finding.description.contains("vsFTPd 3.0.5"));
    }

    #[test]
    fn test_a_passworded_ftp_server_produces_nothing() {
        let server = FtpServer {
            banner: Some("220 (vsFTPd 3.0.5)".into()),
            anonymous: false,
        };
        assert!(ftp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 21, &server).is_empty());
    }

    #[test]
    fn test_an_open_redis_server_is_critical() {
        let server = RedisServer {
            open: true,
            version: Some("7.2.4".into()),
        };

        let findings = redis_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)), 6379, &server);
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.id, "redis_unauthenticated");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.port, Some(6379));
        assert!(finding.description.contains("Redis 7.2.4"));
    }

    #[test]
    fn test_a_passworded_redis_server_produces_nothing() {
        let server = RedisServer {
            open: false,
            version: None,
        };
        assert!(
            redis_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)), 6379, &server).is_empty()
        );
    }

    #[test]
    fn test_an_unauthenticated_mongo_server_is_critical() {
        let findings = mongo_findings(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)),
            27017,
            &MongoServer { open: true },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "mongo_unauthenticated");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].port, Some(27017));
    }

    #[test]
    fn test_the_public_community_is_reported_with_the_device_description() {
        let server = SnmpServer {
            public_community: true,
            description: Some("Linux router 5.10.0".into()),
        };

        let findings = snmp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 161, &server);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "snmp_public_community");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].port, Some(161));
        assert!(findings[0].description.contains("Linux router 5.10.0"));
    }

    #[test]
    fn test_a_long_device_description_is_cut_for_the_finding() {
        let server = SnmpServer {
            public_community: true,
            description: Some("x".repeat(200)),
        };
        let findings = snmp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 161, &server);
        assert!(findings[0]
            .description
            .contains(&format!("{}…", "x".repeat(120))));
    }

    #[test]
    fn test_silence_to_the_public_community_is_not_a_finding() {
        let server = SnmpServer {
            public_community: false,
            description: None,
        };
        assert!(snmp_findings(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 161, &server).is_empty());
    }

    #[test]
    fn test_a_passworded_mongo_server_produces_nothing() {
        assert!(mongo_findings(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)),
            27017,
            &MongoServer { open: false }
        )
        .is_empty());
    }
}
