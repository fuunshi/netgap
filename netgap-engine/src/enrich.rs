//! Fill in the details that turn bare addresses into devices a person can
//! recognise: an IPv6 address, a hostname, a vendor and a type.

use netgap_core::Device;
use netgap_fingerprint::{classify_device, ClassifyContext, Fingerprinter};
use std::time::Duration;

use crate::discovery::DiscoveryPlan;

/// Ask the network's IPv6 side who is there, and fold the answers in.
///
/// IPv4 discovery cannot see a device that answers only on IPv6, and IPv6 has
/// no ARP to sweep — a `/64` is 2^64 addresses. The kernel's neighbour table
/// is the source instead, and unlike the ARP path it can be read and
/// stimulated without privileges, so this runs on every discovery rather than
/// only under sudo.
#[cfg(unix)]
pub fn run_ipv6(devices: &mut Vec<Device>, plan: &DiscoveryPlan) {
    let interface = plan.interface.name.as_str();

    // The neighbour table covers the whole link, whatever range was asked for.
    // A device it reveals is only worth adding when the scan was the whole
    // link to begin with; on a narrowed scan the addresses annotate the
    // devices found and nothing else is reported.
    let allow_new = is_whole_link(plan);

    match netgap_discover::ipv6::discover(interface) {
        Ok(neighbours) if neighbours.is_empty() => {
            if !plan.quiet {
                eprintln!("   IPv6: no neighbours answered (normal on an IPv4-only network)");
            }
        }
        Ok(neighbours) => {
            let summary = netgap_discover::ipv6::merge(devices, &neighbours, allow_new);
            let only_ipv6 = if summary.added > 0 {
                format!(", {} that IPv4 discovery could not see", summary.added)
            } else {
                String::new()
            };

            if !plan.quiet {
                eprintln!("   IPv6: {} neighbour(s){}", neighbours.len(), only_ipv6);
            }
        }
        Err(error) => {
            // An IPv4-only network is the common case, so this is a note, not
            // a warning: nothing is wrong.
            if !plan.quiet {
                eprintln!("   IPv6: skipped ({error})");
            }
        }
    }

    // The router holding the default route is a device on this link whether or
    // not the neighbour table has met it — the route table knows its address.
    if add_ipv6_gateway(devices, allow_new) && !plan.quiet {
        eprintln!("   IPv6: added the default gateway");
    }
}

/// Fold the IPv6 default gateway into the device list.
///
/// A router typically answers IPv6 at a link-local address, and the neighbour
/// table only learns that address once traffic has crossed it. Without this,
/// the one device known to route the network could be missing from a scan that
/// reports having found everything.
///
/// Returns whether a device was added.
#[cfg(unix)]
fn add_ipv6_gateway(devices: &mut Vec<Device>, allow_new: bool) -> bool {
    let Some(gateway) = netgap_interfaces::default_gateway_ipv6() else {
        return false;
    };
    let address = std::net::IpAddr::V6(gateway);
    let text = gateway.to_string();

    if let Some(device) = devices
        .iter_mut()
        .find(|device| device.ip == address || device.ipv6_addresses.contains(&text))
    {
        if !device.ipv6_addresses.contains(&text) {
            device.ipv6_addresses.push(text);
        }
        return false;
    }

    if !allow_new {
        return false;
    }

    let mut device = Device::new(address);
    device.ipv6_addresses.push(text);
    devices.push(device);
    true
}

/// IPv6 neighbour discovery is a Unix feature; elsewhere this is a no-op.
#[cfg(not(unix))]
pub fn run_ipv6(_devices: &mut Vec<Device>, plan: &DiscoveryPlan) {
    if !plan.quiet {
        eprintln!("   IPv6: not implemented on this platform (Unix only)");
    }
}

/// Whether the scan covers the interface's own network, rather than a slice of
/// it the user narrowed by hand.
#[cfg(unix)]
fn is_whole_link(plan: &DiscoveryPlan) -> bool {
    let Some(network) = plan.interface.ipv4_network() else {
        return false;
    };
    let Ok((target, prefix)) = netgap_discover::parse_cidr(&plan.target) else {
        return false;
    };

    target == network.network() && prefix == network.prefix()
}

/// Fill in the details that turn a bare IP and MAC into something a person can
/// recognise: a name, a vendor, and a device type.
pub async fn enrich_devices(plan: &DiscoveryPlan, devices: &mut [Device], identify: bool) {
    if devices.is_empty() {
        return;
    }

    // Names first: reverse DNS is unreliable on many networks, so it gets a
    // bounded budget and stays quiet when it finds nothing.
    let named = netgap_discover::resolve_hostnames(devices, Duration::from_secs(3)).await;
    if named > 0 && !plan.quiet {
        eprintln!("   Resolved {} hostname(s)", named);
    }

    // Optionally probe service ports, which is what makes type guesses useful.
    if identify {
        if !plan.quiet {
            eprintln!(
                "   Identifying device types (probing {} port(s) on {} host(s))...",
                IDENTIFY_PORTS.len(),
                devices.len()
            );
        }

        let ipv4_targets: Vec<std::net::Ipv4Addr> = devices
            .iter()
            .filter_map(|device| match device.ip {
                std::net::IpAddr::V4(ipv4) => Some(ipv4),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();

        let sweep = netgap_discover::TcpSweeper::new(netgap_discover::TcpSweepConfig {
            targets: ipv4_targets,
            ports: IDENTIFY_PORTS.to_vec(),
            timeout_ms: 400,
            concurrency: 128,
            include_neighbors: false,
            interface_name: Some(plan.interface.name.clone()),
            quiet: true,
        });

        match sweep.scan().await {
            Ok(probed) => {
                for probe in &probed {
                    if let Some(device) = devices.iter_mut().find(|device| device.ip == probe.ip) {
                        for port in &probe.open_ports {
                            device.add_open_port(*port);
                        }
                    }
                }
            }
            Err(error) => {
                if !plan.quiet {
                    eprintln!("   ⚠️  Identification probe failed: {}", error);
                }
            }
        }
    }

    // Vendor and type. `fingerprint_device` no longer clobbers a known OS, so
    // it is safe to call on already-enriched devices.
    let fingerprinter = Fingerprinter::new();
    let context = ClassifyContext {
        gateway: netgap_interfaces::default_gateway_ipv4().map(std::net::IpAddr::V4),
        local: plan
            .interface
            .ipv4_network()
            .map(|network| std::net::IpAddr::V4(network.ip())),
    };

    for device in devices.iter_mut() {
        fingerprinter.fingerprint_device(device);
        let classification = classify_device(device, &context);
        device.device_type = Some(classification.label);
    }
}

/// Ports probed by `--identify`, chosen to distinguish common device classes.
pub const IDENTIFY_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 139, 443, 445, 515, 554, 631, 1883, 2049, 3389, 5000, 8080, 9100,
];
