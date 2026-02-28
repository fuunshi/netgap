use crate::model::{GapFinding, HostReport, PortFinding, Severity};

pub fn analyze_host(host: &HostReport) -> Vec<GapFinding> {
    let mut findings = Vec::new();

    for port in &host.open_ports {
        findings.extend(analyze_port(port));
    }

    if host
        .hostname
        .as_deref()
        .is_some_and(|name| name.contains("router") || name.contains("gateway"))
    {
        findings.push(GapFinding {
            severity: Severity::Medium,
            title: "Potential network device admin surface".into(),
            description: "The hostname suggests this device may be a router or gateway.".into(),
            recommendation:
                "Verify LAN management access, firmware version, and credential hygiene.".into(),
            port: None,
        });
    }

    findings
}

pub fn analyze_port(port: &PortFinding) -> Vec<GapFinding> {
    let mut findings = Vec::new();

    match port.port {
        21 => findings.push(rule(
            Severity::High,
            21,
            "FTP exposed",
            "FTP is reachable on the LAN and may allow weak authentication or cleartext transfers.",
            "Disable FTP or restrict it to trusted management networks.",
        )),
        23 => findings.push(rule(
            Severity::Critical,
            23,
            "Telnet exposed",
            "Telnet is open and exposes unencrypted remote administration.",
            "Disable Telnet and use SSH with key-based authentication.",
        )),
        445 => findings.push(rule(
            Severity::High,
            445,
            "SMB exposed",
            "SMB is reachable on the LAN and may expose legacy protocols or shares.",
            "Verify SMB signing, disable SMBv1, and restrict access to trusted hosts.",
        )),
        3389 => findings.push(rule(
            Severity::High,
            3389,
            "RDP exposed",
            "Remote Desktop is reachable from the LAN and can be abused if authentication is weak.",
            "Restrict RDP to administrative hosts and enforce MFA or VPN access.",
        )),
        5900 | 5901 => findings.push(rule(
            Severity::Medium,
            port.port,
            "VNC exposed",
            "VNC is reachable and often lacks strong defaults.",
            "Require authentication, encryption, and LAN-only access.",
        )),
        80 | 443 => findings.push(rule(
            Severity::Medium,
            port.port,
            "Web admin surface exposed",
            "An HTTP(S) service is reachable from the LAN and could be an admin panel.",
            "Confirm access control, update firmware, and check for default credentials safely.",
        )),
        _ => {}
    }

    if matches!(port.port, 80 | 443 | 8080 | 8443)
        && port.banner.as_deref().is_some_and(|banner| {
            banner.contains("admin") || banner.contains("router") || banner.contains("login")
        })
    {
        findings.push(rule(
            Severity::High,
            port.port,
            "Possible admin panel",
            "Banner data suggests this service may expose an administrative web interface.",
            "Audit the interface, disable default credentials, and limit LAN access.",
        ));
    }

    findings
}

fn rule(
    severity: Severity,
    port: u16,
    title: &str,
    description: &str,
    recommendation: &str,
) -> GapFinding {
    GapFinding {
        severity,
        title: title.into(),
        description: description.into(),
        recommendation: recommendation.into(),
        port: Some(port),
    }
}
