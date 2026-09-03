//! `netgap upnp`: what the gateway has published to the internet.
//!
//! The router is the one device that can silently widen the network from the
//! outside, and UPnP is the usual way it happens: something on the LAN asks
//! for a port, the router opens it, and the owner never sees the request or
//! the result. This command asks the router what it has published, which is a
//! question the router answers without authentication — the same reason the
//! exposure matters.
//!
//! Read-only. Nothing here adds or removes a mapping.

use anyhow::Result;
use colored::Colorize;
use netgap_assess::{UpnpExposure, UpnpMapping};
use netgap_core::{Device, Finding};
use netgap_probes::upnp::{self, Igd};
use std::net::IpAddr;
use std::process::exit;
use std::time::Duration;

/// How long to wait for the router to answer discovery.
///
/// Two seconds, sent to the multicast group and to the gateway at once: the
/// wait is the cost of this check, and it is paid on every assessment.
const SEARCH_WINDOW: Duration = Duration::from_secs(2);

/// The exposure a finding needs, from what the router said.
pub fn exposure(igd: &Igd) -> UpnpExposure {
    UpnpExposure {
        name: igd.name().map(str::to_string),
        mappings: igd
            .enabled_mappings()
            .into_iter()
            .map(|mapping| UpnpMapping {
                external_port: mapping.external_port,
                protocol: mapping.protocol.clone(),
                internal_client: mapping.internal_client.clone(),
                internal_port: mapping.internal_port,
                description: mapping.description.clone(),
            })
            .collect(),
    }
}

/// Findings about what the gateway has published, for a scan to attach.
///
/// A router that does not answer, or answers and then fails, produces nothing:
/// an assessment should not invent an exposure it could not read.
pub async fn gateway_findings(device: &Device) -> Vec<Finding> {
    match upnp::inspect(Some(device.ip), SEARCH_WINDOW).await {
        Ok(Some(igd)) => netgap_assess::upnp_findings(device.ip, &exposure(&igd)),
        _ => Vec::new(),
    }
}

/// `netgap upnp [--json] [--gateway <address>]`
pub async fn run(json: bool, gateway: Option<String>) -> Result<()> {
    let target = match gateway {
        Some(address) => Some(
            address
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("'{address}' is not an IP address"))?,
        ),
        None => netgap_interfaces::default_gateway_ipv4().map(IpAddr::V4),
    };

    let found = upnp::inspect(target, SEARCH_WINDOW).await?;

    let Some(igd) = found else {
        if json {
            println!("{}", serde_json::json!({ "igd": null }));
        } else {
            println!("{}", "🔌 UPnP".bold());
            println!(
                "  {}",
                "No gateway answered UPnP discovery. That usually means UPnP is turned off — or the network filters the multicast it uses, which is not proof either way."
                    .dimmed()
            );
        }
        return Ok(());
    };

    let open = igd.enabled_mappings();

    if json {
        print_json(&igd, &open);
    } else {
        print_text(&igd, &open);
    }

    // Like `diff`: the answer a script wants is "has anything been published",
    // so it is in the exit status too.
    if !open.is_empty() {
        exit(1);
    }
    Ok(())
}

fn print_json(igd: &Igd, open: &[&netgap_probes::upnp::PortMapping]) {
    let mappings: Vec<serde_json::Value> = open
        .iter()
        .map(|mapping| {
            serde_json::json!({
                "external_port": mapping.external_port,
                "protocol": mapping.protocol,
                "internal_client": mapping.internal_client,
                "internal_port": mapping.internal_port,
                "description": mapping.description,
                "lease_seconds": mapping.lease_seconds,
            })
        })
        .collect();

    let output = serde_json::json!({
        "igd": {
            "location": igd.location,
            "name": igd.friendly_name,
            "manufacturer": igd.manufacturer,
            "model": igd.model,
            "service": igd.service_type,
            "control_url": igd.control_url,
            "published": mappings,
        }
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

fn print_text(igd: &Igd, open: &[&netgap_probes::upnp::PortMapping]) {
    println!("{}", "🔌 UPnP on the gateway".bold());
    println!();

    if let Some(name) = igd.name() {
        let vendor = igd
            .manufacturer
            .as_deref()
            .filter(|vendor| Some(*vendor) != igd.friendly_name.as_deref())
            .map(|vendor| format!(" ({vendor})"))
            .unwrap_or_default();
        println!("  {} {}{}", "Router ".dimmed(), name, vendor.dimmed());
    }
    println!("  {} {}", "Control".dimmed(), igd.control_url.dimmed());
    println!();

    if open.is_empty() {
        println!("  {} Nothing is published to the internet.", "✓".green());
        println!(
            "  {}",
            "The router still answers UPnP, so any device on this network can ask it to open a port.".dimmed()
        );
        return;
    }

    println!("  {}", format!("Published ports ({})", open.len()).bold());
    for mapping in open {
        println!(
            "  {:<9} {} {:<23} {}",
            format!(
                "{}/{}",
                mapping.external_port,
                mapping.protocol.to_uppercase()
            )
            .green(),
            "→".dimmed(),
            match mapping.internal_client.is_empty() {
                true => format!("port {}", mapping.internal_port),
                false => format!("{}:{}", mapping.internal_client, mapping.internal_port),
            },
            mapping.description.dimmed()
        );
    }
    println!();
    println!(
        "  {}",
        "Any device on this network could have asked for these; UPnP needs no password and the router keeps no record of who asked."
            .yellow()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_probes::upnp::PortMapping;

    fn mapping(port: u16, enabled: bool, description: &str) -> PortMapping {
        PortMapping {
            external_port: port,
            protocol: "TCP".into(),
            internal_client: "192.168.1.50".into(),
            internal_port: 80,
            enabled,
            description: description.into(),
            lease_seconds: 0,
        }
    }

    fn igd(mappings: Vec<PortMapping>) -> Igd {
        Igd {
            location: "http://192.168.1.1/rootDesc.xml".into(),
            friendly_name: Some("Archer AX10".into()),
            manufacturer: Some("TP-Link".into()),
            model: Some("Archer AX10".into()),
            service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
            control_url: "http://192.168.1.1/ctl".into(),
            mappings,
        }
    }

    #[test]
    fn only_enabled_mappings_become_findings() {
        let exposure = exposure(&igd(vec![
            mapping(8080, true, "camera"),
            mapping(9000, false, "old"),
        ]));

        assert_eq!(exposure.name.as_deref(), Some("Archer AX10"));
        assert_eq!(exposure.mappings.len(), 1);
        assert_eq!(exposure.mappings[0].external_port, 8080);
        assert_eq!(exposure.mappings[0].description, "camera");
    }

    #[test]
    fn a_router_with_nothing_published_is_still_reported() {
        let exposure = exposure(&igd(Vec::new()));
        assert!(exposure.mappings.is_empty());
        assert_eq!(exposure.name.as_deref(), Some("Archer AX10"));
    }
}
