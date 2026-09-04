//! What file servers will do before anyone logs in.
//!
//! Most of the money in a LAN intrusion passes through a file server: it holds
//! the shares, and it is where credentials are relayed. Two configuration
//! facts decide how much of that is exposed, and both are read from the
//! NEGOTIATE exchange that comes before any login — SMBv1 support and whether
//! signing is required.
//!
//! Only devices already known to have a file-sharing port open are asked.
//! Nothing here authenticates, guesses a password, or sends a single request
//! past the negotiate.

use netgap_assess::{SmbServer, SmbSigning};
use netgap_core::Device;
use netgap_probes::smb::{self, SmbInfo};
use std::net::IpAddr;
use tokio::task::JoinSet;

/// Ports a file server listens on: SMB over TCP, then over NetBIOS.
const SMB_PORTS: &[u16] = &[445, 139];

/// How many servers to question at once. A negotiate is two small packets, so
/// the only reason to limit this is politeness to a slow network.
const CONCURRENCY: usize = 8;

/// The assessment rules' view of what the server negotiated.
pub fn configuration(info: &SmbInfo) -> SmbServer {
    SmbServer {
        smb1: info.smb1,
        smb2: info.smb2,
        dialect: info.dialect.clone(),
        signing: match info.signing {
            smb::Signing::Required => SmbSigning::Required,
            smb::Signing::Optional => SmbSigning::Optional,
            smb::Signing::Disabled => SmbSigning::Disabled,
            smb::Signing::Unknown => SmbSigning::Unknown,
        },
    }
}

/// Question every file server the scan found and attach what it said.
pub async fn check(devices: &mut [Device]) {
    let targets: Vec<(usize, IpAddr, u16)> = devices
        .iter()
        .enumerate()
        .filter_map(|(index, device)| {
            SMB_PORTS
                .iter()
                .copied()
                .find(|port| device.open_ports.contains(port))
                .map(|port| (index, device.ip, port))
        })
        .collect();

    if targets.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("SMB configuration");
    eprintln!("─────────────────");

    let mut results: Vec<(usize, u16, Option<SmbInfo>)> = Vec::new();
    for chunk in targets.chunks(CONCURRENCY) {
        let mut set = JoinSet::new();
        for (index, ip, port) in chunk {
            let (index, ip, port) = (*index, *ip, *port);
            set.spawn(async move {
                let info = smb::inspect(ip, port).await.ok();
                (index, port, info)
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok(result) = joined {
                results.push(result);
            }
        }
    }

    // Report in the order the devices were discovered, not the order the
    // probes happened to finish.
    results.sort_by_key(|(index, _, _)| *index);

    for (index, port, info) in results {
        // An open port that will not negotiate SMB is something else: skip it
        // rather than guess.
        let Some(info) = info else {
            continue;
        };

        let device = &mut devices[index];
        let findings = netgap_assess::smb_findings(device.ip, port, &configuration(&info));

        if findings.is_empty() {
            let dialect = info
                .dialect
                .as_deref()
                .map(|dialect| format!(" SMB {dialect},"))
                .unwrap_or_default();
            eprintln!("  ✓ {}:{} —{} signing required", device.ip, port, dialect);
        }

        for finding in findings {
            eprintln!(
                "  {}:{} [{}] {}",
                device.ip, port, finding.severity, finding.title
            );
            device.add_finding(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_probe_types_map_onto_the_rule_types() {
        let info = SmbInfo {
            smb1: true,
            smb2: true,
            dialect: Some("2.1".into()),
            signing: smb::Signing::Optional,
        };

        let server = configuration(&info);
        assert!(server.smb1);
        assert!(server.smb2);
        assert_eq!(server.dialect.as_deref(), Some("2.1"));
        assert_eq!(server.signing, SmbSigning::Optional);
    }

    #[test]
    fn test_every_signing_state_survives_the_mapping() {
        for (probe, rule) in [
            (smb::Signing::Required, SmbSigning::Required),
            (smb::Signing::Optional, SmbSigning::Optional),
            (smb::Signing::Disabled, SmbSigning::Disabled),
            (smb::Signing::Unknown, SmbSigning::Unknown),
        ] {
            let info = SmbInfo {
                smb1: false,
                smb2: true,
                dialect: None,
                signing: probe,
            };
            assert_eq!(configuration(&info).signing, rule);
        }
    }
}
