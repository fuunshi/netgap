use crate::model::{GapFinding, PortFinding, Severity};

pub fn analyze_port(port: &PortFinding) -> Vec<GapFinding> {
    let mut findings = Vec::new();

    match port.port {
        23 => findings.push(GapFinding {
            severity: Severity::Critical,
            title: "Telnet exposed".into(),
            description: "Telnet is open and exposes unencrypted remote administration.".into(),
            recommendation: "Disable Telnet and use SSH with key-based authentication.".into(),
            port: Some(port.port),
        }),
        445 => findings.push(GapFinding {
            severity: Severity::High,
            title: "SMB exposed".into(),
            description: "SMB is reachable on the LAN and may expose legacy protocols or shares.".into(),
            recommendation: "Verify SMB signing, disable SMBv1, and restrict access to trusted hosts.".into(),
            port: Some(port.port),
        }),
        80 | 443 => findings.push(GapFinding {
            severity: Severity::Medium,
            title: "Web admin surface exposed".into(),
            description: "An HTTP(S) service is reachable from the LAN and could be an admin panel.".into(),
            recommendation: "Confirm access control, update firmware, and check for default credentials safely.".into(),
            port: Some(port.port),
        }),
        _ => {}
    }

    findings
}
