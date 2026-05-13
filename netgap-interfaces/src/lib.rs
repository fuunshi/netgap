//! Network interface enumeration and selection.
//!
//! This module provides functionality to enumerate available network interfaces
//! and pick the one that actually carries LAN traffic. Selection deliberately
//! skips loopback, link-local and virtual interfaces (docker bridges, veth
//! pairs, VPN tunnels) so an unqualified `netgap scan` targets the real network
//! instead of `lo`.
//!
//! The chosen interface is persisted as a preference and reused on later runs.

use anyhow::{anyhow, Result};
use netgap_core::paths;
use pnet::datalink;
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};

/// Interface name prefixes that never carry the LAN we want to scan.
///
/// Bridges, container pairs, VM switches and tunnels all look "up with an IPv4"
/// to the kernel but scanning them finds containers or a VPN peer, not the
/// local network.
const VIRTUAL_PREFIXES: &[&str] = &[
    "docker", "br", "veth", "virbr", "vmnet", "vboxnet", "tun", "tap", "wg", "zt", "tailscale",
    "utun", "awdl", "llw", "gif", "stf", "ip6tnl", "dummy", "ham",
];

/// Interface name prefixes that conventionally denote a physical NIC.
const PHYSICAL_PREFIXES: &[&str] = &["eth", "en", "wl", "ww", "em", "ib"];

/// Represents an enumerated network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub mac: Option<String>,
    pub is_up: bool,
    /// Carrier detected (IFF_LOWER_UP). `docker0` is "up" but has no carrier.
    pub is_lower_up: bool,
    pub is_loopback: bool,
    /// This interface owns the default route.
    pub is_default_route: bool,
    /// Prefix length of the interface's IPv4 address (e.g. 24).
    pub prefix: Option<u8>,
    /// Network address and prefix in CIDR notation (e.g. "192.168.1.0/24").
    pub cidr: Option<String>,
}

impl InterfaceInfo {
    /// Whether this interface is a candidate for scanning a real LAN.
    ///
    /// Requires carrier, a usable unicast IPv4, and rejects loopback and
    /// link-local (`169.254.0.0/16`) addresses.
    pub fn is_scannable(&self) -> bool {
        self.is_up
            && !self.is_loopback
            && self.ipv4.is_some()
            && self
                .ipv4_network()
                .map(|net| is_usable_ipv4(net.ip()))
                .unwrap_or(false)
    }

    /// Parse the stored IPv4 string back into a network, when present.
    pub fn ipv4_network(&self) -> Option<Ipv4Network> {
        let ipv4 = self.ipv4.as_ref()?;
        let prefix = self.prefix?;
        let addr: Ipv4Addr = ipv4.parse().ok()?;
        Ipv4Network::new(addr, prefix).ok()
    }

    /// Whether the interface name looks like a virtual/container/tunnel device.
    pub fn is_virtual(&self) -> bool {
        is_virtual_name(&self.name)
    }

    /// Whether the interface name looks like a physical NIC.
    pub fn is_physical(&self) -> bool {
        is_physical_name(&self.name)
    }
}

/// Get all available network interfaces on the system.
pub fn get_interfaces() -> Result<Vec<InterfaceInfo>> {
    let route_ip = default_route_ip();

    let mut result = Vec::new();

    for iface in datalink::interfaces() {
        // Prefer a routable IPv4 when an interface has several.
        let ipv4_net = iface
            .ips
            .iter()
            .filter_map(|ip| match ip {
                IpNetwork::V4(net) => Some(*net),
                _ => None,
            })
            .fold(None, |best: Option<Ipv4Network>, net| match best {
                Some(current) if is_usable_ipv4(current.ip()) => Some(current),
                _ if is_usable_ipv4(net.ip()) => Some(net),
                Some(current) => Some(current),
                None => Some(net),
            });

        let ipv6 = iface.ips.iter().find_map(|ip| match ip {
            IpNetwork::V6(ipv6) => Some(ipv6.ip().to_string()),
            _ => None,
        });

        let mac = iface.mac.map(|m| m.to_string());
        let ipv4 = ipv4_net.map(|net| net.ip().to_string());
        let prefix = ipv4_net.map(|net| net.prefix());
        let cidr = ipv4_net.map(|net| format!("{}/{}", net.network(), net.prefix()));
        let is_loopback =
            iface.is_loopback() || ipv4_net.map(|net| net.ip().is_loopback()).unwrap_or(false);
        let is_default_route = match (route_ip, ipv4_net) {
            (Some(route), Some(net)) => route == net.ip(),
            _ => false,
        };

        result.push(InterfaceInfo {
            name: iface.name.clone(),
            ipv4,
            ipv6,
            mac,
            is_up: iface.is_up(),
            is_lower_up: iface.is_lower_up(),
            is_loopback,
            is_default_route,
            prefix,
            cidr,
        });
    }

    Ok(result)
}

/// Get a specific interface by name.
pub fn get_interface(name: &str) -> Result<InterfaceInfo> {
    let interfaces = get_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| anyhow!("Interface '{}' not found", name))
}

/// List all interface names in human-readable format.
pub fn list_interfaces_formatted() -> Result<Vec<String>> {
    let interfaces = get_interfaces()?;
    let formatted: Vec<String> = interfaces
        .iter()
        .map(|iface| {
            let status = if iface.is_up { "UP" } else { "DOWN" };
            let ip = iface.ipv4.as_deref().unwrap_or("No IPv4");
            let mut notes = Vec::new();
            if iface.is_loopback {
                notes.push("loopback");
            } else if iface.is_virtual() {
                notes.push("virtual");
            }
            if iface.is_default_route {
                notes.push("default route");
            }
            let suffix = if notes.is_empty() {
                String::new()
            } else {
                format!(" [{}]", notes.join(", "))
            };
            format!("{:<15} {} ({}){}", iface.name, ip, status, suffix)
        })
        .collect();
    Ok(formatted)
}

/// Get the IPv4 CIDR notation for an interface's network, using its real netmask.
/// Example: "192.168.1.0/24".
pub fn get_interface_cidr(iface_name: &str) -> Result<String> {
    let iface = get_interface(iface_name)?;
    iface.cidr.ok_or_else(|| {
        anyhow!(
            "No IPv4 address found on interface '{}'",
            iface_name
        )
    })
}

/// Get an interface's IPv4 network address and prefix length.
pub fn get_interface_network(iface_name: &str) -> Result<(Ipv4Addr, u8)> {
    let iface = get_interface(iface_name)?;
    iface
        .ipv4_network()
        .map(|net| (net.network(), net.prefix()))
        .ok_or_else(|| {
            anyhow!(
                "No IPv4 address found on interface '{}'",
                iface_name
            )
        })
}

/// The IPv4 default gateway, read from the kernel routing table.
///
/// Knowing the gateway identifies one device on the network with certainty,
/// while everything else is inferred.
pub fn default_gateway_ipv4() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;

        routes.lines().skip(1).find_map(|line| {
            let mut fields = line.split_whitespace();
            let _iface = fields.next()?;
            let destination = fields.next()?;
            let gateway = fields.next()?;
            let flags = u32::from_str_radix(fields.next()?, 16).ok()?;

            // Destination 0.0.0.0 with RTF_GATEWAY set is the default route.
            const RTF_GATEWAY: u32 = 0x0002;
            if destination != "00000000" || flags & RTF_GATEWAY == 0 {
                return None;
            }

            let raw = u32::from_str_radix(gateway, 16).ok()?;
            // The kernel prints the address in host byte order.
            Some(Ipv4Addr::from(raw.swap_bytes()))
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Store selected interface in the config file.
pub fn save_interface_preference(interface_name: &str) -> Result<()> {
    let config_dir = config_dir()?;
    save_interface_preference_in(&config_dir, interface_name)
}

/// Load saved interface preference.
pub fn load_interface_preference() -> Result<Option<String>> {
    let config_dir = config_dir()?;
    load_interface_preference_from(&config_dir)
}

/// Store the interface preference inside `dir`.
///
/// Directory-explicit variant so tests never write to the user's home.
pub fn save_interface_preference_in(dir: &Path, interface_name: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("interface_preference"), interface_name)?;
    Ok(())
}

/// Load the interface preference from `dir`.
pub fn load_interface_preference_from(dir: &Path) -> Result<Option<String>> {
    let pref_file = dir.join("interface_preference");
    if pref_file.exists() {
        let content = std::fs::read_to_string(pref_file)?;
        Ok(Some(content.trim().to_string()))
    } else {
        Ok(None)
    }
}

/// Load the saved preference, but only if it still names a scannable interface.
///
/// A stale, down, loopback or link-local preference is reported and ignored so
/// auto-detection can fall through to a real LAN interface.
pub fn load_validated_preference() -> Result<Option<InterfaceInfo>> {
    let Some(saved) = load_interface_preference()? else {
        return Ok(None);
    };

    if saved.is_empty() {
        return Ok(None);
    }

    match get_interface(&saved) {
        Ok(iface) if iface.is_scannable() => Ok(Some(iface)),
        Ok(iface) => {
            let reason = if iface.is_loopback {
                "it is the loopback interface"
            } else if iface.ipv4.is_none() {
                "it has no IPv4 address"
            } else if !iface.is_up {
                "it is down"
            } else {
                "it is link-local"
            };
            eprintln!(
                "⚠ Ignoring saved interface preference '{}': {}",
                iface.name, reason
            );
            Ok(None)
        }
        Err(_) => {
            eprintln!(
                "⚠ Ignoring saved interface preference '{}': interface no longer exists",
                saved
            );
            Ok(None)
        }
    }
}

/// Get the config directory for netgap.
fn config_dir() -> Result<PathBuf> {
    paths::config_dir().ok_or_else(|| anyhow!("Could not determine home directory"))
}

/// Interactive terminal-based interface selector.
/// Shows a numbered list and prompts the user to select.
pub fn select_interface_interactive() -> Result<String> {
    let interfaces: Vec<InterfaceInfo> = get_interfaces()?
        .into_iter()
        .filter(|iface| iface.is_scannable())
        .collect();

    if interfaces.is_empty() {
        return Err(anyhow!("No scannable network interfaces found"));
    }

    println!("\n📡 Select Network Interface:\n");

    // Display interface options
    for (idx, iface) in interfaces.iter().enumerate() {
        let ip_str = iface.ipv4.as_deref().unwrap_or("No IPv4");
        let cidr = iface.cidr.as_deref().unwrap_or("-");
        let route = if iface.is_default_route { " [default]" } else { "" };
        println!(
            "  {}. {} ({}, {}){}",
            idx + 1,
            iface.name,
            ip_str,
            cidr,
            route
        );
    }

    // Get user input
    loop {
        print!("\nSelect interface (1-{}): ", interfaces.len());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if let Ok(choice) = input.trim().parse::<usize>() {
            if choice > 0 && choice <= interfaces.len() {
                let selected = interfaces[choice - 1].name.clone();
                save_interface_preference(&selected)?;
                println!("✓ Selected: {}\n", selected);
                return Ok(selected);
            }
        }

        println!("❌ Invalid selection. Please try again.");
    }
}

/// Get the best interface to scan, honoring a valid saved preference.
///
/// Selection order: a saved preference that is still scannable, then the
/// highest-scoring interface (default route, physical, private address).
pub fn get_interface_auto() -> Result<String> {
    if let Some(preferred) = load_validated_preference()? {
        return Ok(preferred.name);
    }

    let interfaces = get_interfaces()?;
    let route_name = interfaces
        .iter()
        .find(|iface| iface.is_default_route)
        .map(|iface| iface.name.clone());

    if let Some(best) = select_best(&interfaces, route_name.as_deref()) {
        return Ok(best.name.clone());
    }

    // Last resort: something is better than nothing, but say so loudly — this
    // usually means the only interface is loopback or a container bridge.
    if let Some(fallback) = interfaces
        .iter()
        .find(|iface| iface.is_up && iface.ipv4.is_some())
    {
        eprintln!(
            "⚠ No routable LAN interface found; falling back to '{}'. Pass --interface/--target to choose explicitly.",
            fallback.name
        );
        return Ok(fallback.name.clone());
    }

    Err(anyhow!("No network interfaces available"))
}

/// Pick the interface most likely to carry LAN traffic.
///
/// Pure function over enumerated interfaces so the ranking is unit-testable.
pub fn select_best<'a>(
    candidates: &'a [InterfaceInfo],
    default_route: Option<&str>,
) -> Option<&'a InterfaceInfo> {
    let mut viable: Vec<&InterfaceInfo> = candidates
        .iter()
        .filter(|iface| iface.is_scannable())
        .collect();

    viable.sort_by(|a, b| {
        score_interface(b, default_route)
            .cmp(&score_interface(a, default_route))
            .then_with(|| a.name.cmp(&b.name))
    });

    viable.first().copied()
}

/// Score a scannable interface; higher is a better scan target.
pub fn score_interface(iface: &InterfaceInfo, default_route: Option<&str>) -> i32 {
    if !iface.is_scannable() {
        return i32::MIN;
    }

    let mut score = 0;

    if default_route == Some(iface.name.as_str()) {
        // A tunnel that owns the default route is not the LAN.
        score += if iface.is_virtual() { 100 } else { 1000 };
    }

    if iface.is_physical() {
        score += 200;
    } else if iface.is_virtual() {
        score -= 500;
    }

    if iface.is_lower_up {
        score += 100;
    }

    match iface.prefix {
        // Container bridges are usually /16 and would sweep 65k hosts.
        Some(prefix) if prefix < 16 => score -= 200,
        Some(prefix) if (16..=24).contains(&prefix) => score += 50,
        _ => {}
    }

    if iface
        .ipv4_network()
        .map(|net| net.ip().is_private())
        .unwrap_or(false)
    {
        score += 30;
    }

    if iface.mac.as_deref().is_some_and(|mac| mac != "00:00:00:00:00:00") {
        score += 20;
    }

    score
}

/// Whether a name refers to a loopback/virtual/container/tunnel device.
pub fn is_virtual_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "lo" || VIRTUAL_PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
}

/// Whether a name conventionally denotes a physical NIC.
pub fn is_physical_name(name: &str) -> bool {
    if is_virtual_name(name) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    PHYSICAL_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Whether an address is usable as a LAN scan source.
fn is_usable_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

/// Find the local IPv4 the kernel would use for off-LAN traffic.
///
/// Connecting a UDP socket performs a route lookup only — no packet is ever
/// sent — so this works without network access and needs no privileges.
fn default_route_ip() -> Option<Ipv4Addr> {
    for probe in ["1.1.1.1:80", "8.8.8.8:53"] {
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        if socket.connect(probe).is_err() {
            continue;
        }
        if let Ok(local) = socket.local_addr() {
            if let IpAddr::V4(ip) = local.ip() {
                if is_usable_ipv4(ip) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: &str, prefix: u8, is_default: bool) -> InterfaceInfo {
        let addr: Ipv4Addr = ip.parse().expect("valid IPv4");
        let net = Ipv4Network::new(addr, prefix).expect("valid network");
        InterfaceInfo {
            name: name.to_string(),
            ipv4: Some(addr.to_string()),
            ipv6: None,
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            is_up: true,
            is_lower_up: true,
            is_loopback: addr.is_loopback(),
            is_default_route: is_default,
            prefix: Some(prefix),
            cidr: Some(format!("{}/{}", net.network(), net.prefix())),
        }
    }

    #[test]
    fn test_get_interfaces_not_empty() {
        let interfaces = get_interfaces().expect("Should get interfaces");
        assert!(
            !interfaces.is_empty(),
            "System should have at least one interface"
        );
    }

    #[test]
    fn test_list_interfaces_formatted() {
        let formatted = list_interfaces_formatted().expect("Should format interfaces");
        assert!(!formatted.is_empty());
        // Each line should have interface name and status
        for line in formatted {
            assert!(line.contains("UP") || line.contains("DOWN"));
        }
    }

    #[test]
    fn test_interface_names_not_empty() {
        let interfaces = get_interfaces().expect("Should get interfaces");
        for iface in interfaces {
            assert!(!iface.name.is_empty());
        }
    }

    #[test]
    fn test_get_interface_auto() {
        let iface = get_interface_auto().expect("Should get an interface");
        assert!(!iface.is_empty());
    }

    #[test]
    fn test_get_interface_auto_never_prefers_loopback_when_alternatives_exist() {
        let interfaces = get_interfaces().expect("Should get interfaces");
        let has_routable = interfaces
            .iter()
            .any(|iface| iface.is_scannable() && !iface.name.starts_with("docker"));

        if has_routable {
            let chosen = get_interface_auto().expect("Should get an interface");
            let iface = get_interface(&chosen).expect("chosen interface exists");
            assert!(!iface.is_loopback, "auto-selection returned loopback");
        }
    }

    /// Regression test: the CIDR must match the interface's real netmask and
    /// must never drop the last octet (the old code produced "127.0.0/24").
    #[test]
    fn test_cidr_uses_real_prefix() {
        let interfaces = get_interfaces().expect("Should get interfaces");
        for iface in &interfaces {
            let Some(cidr) = &iface.cidr else { continue };
            let (network, prefix) = cidr
                .split_once('/')
                .expect("cidr contains a slash");
            let network: Ipv4Addr = network.parse().expect("cidr network parses");
            let prefix: u8 = prefix.parse().expect("cidr prefix parses");
            let addr: Ipv4Addr = iface.ipv4.as_ref().unwrap().parse().unwrap();

            assert_eq!(prefix, iface.prefix.unwrap());
            assert_eq!(
                u32::from(network),
                u32::from(addr) & (!0u32 << (32 - prefix)),
                "network address not masked for {}",
                iface.name
            );
        }
    }

    #[test]
    fn test_virtual_and_physical_name_detection() {
        for name in [
            "lo",
            "docker0",
            "br-ae2cdaa3b008",
            "veth45a21a4",
            "virbr0",
            "tun0",
            "wg0",
            "tailscale0",
        ] {
            assert!(is_virtual_name(name), "{name} should be virtual");
        }

        for name in ["eth0", "enp1s0", "eno1", "wlp4s0", "wlx90610ca31294", "wlan0"] {
            assert!(!is_virtual_name(name), "{name} should not be virtual");
            assert!(is_physical_name(name), "{name} should be physical");
        }
    }

    #[test]
    fn test_select_best_prefers_default_route_physical_nic() {
        let candidates = vec![
            iface("lo", "127.0.0.1", 8, false),
            iface("docker0", "172.17.0.1", 16, false),
            iface("br-ae2cdaa3b008", "172.21.0.1", 16, false),
            iface("veth45a21a4", "169.254.10.1", 16, false),
            iface("wlx90610ca31294", "192.168.111.18", 24, true),
        ];

        let best = select_best(&candidates, Some("wlx90610ca31294")).expect("a best interface");
        assert_eq!(best.name, "wlx90610ca31294");
    }

    #[test]
    fn test_select_best_without_default_route_skips_virtual() {
        let candidates = vec![
            iface("lo", "127.0.0.1", 8, false),
            iface("docker0", "172.17.0.1", 16, false),
            iface("enp1s0", "10.0.0.5", 24, false),
        ];

        let best = select_best(&candidates, None).expect("a best interface");
        assert_eq!(best.name, "enp1s0");
    }

    #[test]
    fn test_select_best_returns_none_for_loopback_only() {
        let candidates = vec![iface("lo", "127.0.0.1", 8, false)];
        assert!(select_best(&candidates, None).is_none());
    }

    #[test]
    fn test_scannable_rejects_link_local_and_down() {
        let mut link_local = iface("eth0", "169.254.1.1", 16, false);
        assert!(!link_local.is_scannable());

        link_local.ipv4 = Some("192.168.1.5".to_string());
        assert!(link_local.is_scannable());

        link_local.is_up = false;
        assert!(!link_local.is_scannable());
    }

    #[test]
    fn test_default_route_scoring() {
        let routed = iface("wlp4s0", "192.168.1.20", 24, true);
        let bridge = iface("docker0", "172.17.0.1", 16, false);

        assert!(score_interface(&routed, Some("wlp4s0")) > score_interface(&bridge, Some("wlp4s0")));
        // Even without the route hint, a physical /24 beats a virtual /16.
        assert!(score_interface(&routed, None) > score_interface(&bridge, None));
    }

    #[test]
    fn test_default_gateway_is_usable_when_present() {
        // Not every machine has one; when it does it must be a usable address.
        if let Some(gateway) = default_gateway_ipv4() {
            assert!(is_usable_ipv4(gateway));
        }
    }

    #[test]
    fn test_save_load_interface_preference_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("netgap-iface-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        save_interface_preference_in(&dir, "eth0").expect("Should save preference");
        let loaded = load_interface_preference_from(&dir)
            .expect("Should load preference")
            .expect("Should have preference");
        assert_eq!(loaded, "eth0");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_validated_preference_ignores_loopback() {
        let dir = std::env::temp_dir().join(format!("netgap-iface-loopback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        save_interface_preference_in(&dir, "lo").expect("Should save preference");
        let loaded = load_interface_preference_from(&dir).expect("Should load preference");
        assert_eq!(loaded.as_deref(), Some("lo"));

        // The validation helper must not accept it as a scan target.
        let iface = get_interface("lo").expect("loopback exists");
        assert!(!iface.is_scannable());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
