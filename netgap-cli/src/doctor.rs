//! `netgap doctor`: why a scan would not find anything, before running one.
//!
//! Almost every "it found nothing" comes down to one of four things: the wrong
//! interface was picked, the process cannot open a raw socket, the target is
//! not the network this machine is on, or the link really is empty. Each is
//! cheap to check and tedious to guess, so this command checks them all and
//! prints what to do about the ones that are wrong.
//!
//! It is also the first thing to ask for in a bug report: the output says
//! which of the four it was.

use anyhow::Result;
use colored::Colorize;
use netgap_core::paths::scans_db_path;
use netgap_discover::{hosts_in_cidr, parse_cidr, TcpSweepConfig, TcpSweeper, DEFAULT_MAX_HOSTS};
// Linux exposes the table through /proc; elsewhere the check is skipped, and
// importing it only there keeps the Windows build warning-free.
#[cfg(target_os = "linux")]
use netgap_discover::neighbor::read_neighbor_table;
use netgap_engine::discovery::can_use_arp;
use netgap_interfaces::{
    default_gateway_ipv4, get_interface, get_interface_auto, get_interfaces, is_virtual_name,
    InterfaceInfo,
};
use netgap_storage::ScanStore;
use netgap_threat_intel::LocalCacheManager;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::alerts;

/// How many addresses the live probe may touch.
///
/// The probe answers one question — can this machine reach anything on the
/// link at all — and a block of 32 addresses answers it in a second or two.
/// A full sweep belongs in `netgap scan`.
const PROBE_HOSTS: usize = 32;

/// Ports tried against the default gateway, in order of how likely a router
/// is to answer them.
const GATEWAY_PORTS: [u16; 4] = [80, 443, 53, 22];

/// Run the checks and print the report.
///
/// Exits non-zero when something would stop a scan from working, so a script
/// can gate on it.
pub async fn run(interface: Option<String>, target: Option<String>, no_probe: bool) -> Result<()> {
    println!("{}", "netgap doctor".bold());
    println!(
        "{}",
        "Checks that a scan from this machine will find what is on the link.".dimmed()
    );

    let mut report = Report::new();

    let interfaces = get_interfaces()?;
    let chosen = check_interfaces(&mut report, &interfaces, interface);
    check_discovery(&mut report);
    check_target(&mut report, chosen.as_ref(), target);

    if let Some(iface) = &chosen {
        check_link(&mut report, iface, no_probe).await;
    } else {
        report.section("The link");
        report.note("skipped", "There is no interface to check the link from.");
    }

    check_setup(&mut report);
    report.verdict()
}

// ---------------------------------------------------------------- report ---

/// Collects the results so the counts are available for the verdict.
struct Report {
    warnings: usize,
    failures: usize,
}

impl Report {
    fn new() -> Self {
        Report {
            warnings: 0,
            failures: 0,
        }
    }

    fn section(&self, title: &str) {
        println!("\n{}", title.bold());
    }

    /// Something that is right. Printed, never counted.
    fn pass(&self, headline: &str, detail: &str) {
        self.line("✓".green(), headline, detail);
    }

    /// Something that works but will cost accuracy or convenience.
    fn warn(&mut self, headline: &str, detail: &str) {
        self.warnings += 1;
        self.line("⚠".yellow(), headline, detail);
    }

    /// Something that will stop a scan from working.
    fn fail(&mut self, headline: &str, detail: &str) {
        self.failures += 1;
        self.line("✗".red(), headline, detail);
    }

    /// Context that is neither right nor wrong.
    fn note(&self, headline: &str, detail: &str) {
        self.line("·".dimmed(), headline, detail);
    }

    fn line(&self, mark: colored::ColoredString, headline: &str, detail: &str) {
        println!("  {mark} {headline}");
        for line in detail.lines().filter(|line| !line.trim().is_empty()) {
            println!("      {}", line.dimmed());
        }
    }

    /// One sentence telling the reader whether to run the scan, then exit.
    ///
    /// Exiting here rather than returning an error keeps the output readable:
    /// the verdict above is the message, and `Error: 1 check failed` after it
    /// would only repeat it in a different tense.
    fn verdict(&self) -> Result<()> {
        self.section("Verdict");
        if self.failures > 0 {
            println!(
                "  {} {} {} failed — fix {} before scanning.",
                "✗".red(),
                self.failures,
                plural(self.failures, "check"),
                if self.failures == 1 { "it" } else { "them" }
            );
            std::process::exit(1);
        }
        if self.warnings > 0 {
            println!(
                "  {} Ready to scan, with {} {} above.",
                "✓".green(),
                self.warnings,
                plural(self.warnings, "warning")
            );
        } else {
            println!("  {} Ready to scan.", "✓".green());
        }
        Ok(())
    }
}

// --------------------------------------------------------------- checks ---

/// List the interfaces a scan can use and pick one, the same way a scan would.
fn check_interfaces(
    report: &mut Report,
    interfaces: &[InterfaceInfo],
    requested: Option<String>,
) -> Option<InterfaceInfo> {
    report.section("Interfaces");

    let mut scannable: Vec<&InterfaceInfo> = interfaces
        .iter()
        .filter(|iface| iface.is_scannable())
        .collect();
    scannable.sort_by_key(|iface| std::cmp::Reverse(iface.is_default_route));

    if scannable.is_empty() {
        report.fail(
            "no interface can be scanned",
            "Every interface is down, loopback, or has no usable IPv4 address.\n\
             Connect to a network and run this again.",
        );
        return None;
    }

    let chosen = match requested {
        Some(name) => match get_interface(&name) {
            Ok(iface) => Some(iface),
            Err(error) => {
                report.fail(
                    &format!("interface '{name}' is not available"),
                    &format!("{error}\nSee `netgap interfaces` for the names this machine has."),
                );
                None
            }
        },
        None => match get_interface_auto().and_then(|name| get_interface(&name)) {
            Ok(iface) => Some(iface),
            Err(error) => {
                report.fail(
                    "no interface could be chosen automatically",
                    &format!("{error}\nPick one with --interface."),
                );
                None
            }
        },
    };

    // A laptop with Docker installed has a dozen virtual bridges, and none of
    // them is the answer to "why did my scan find nothing". Show the physical
    // links and whichever one is being scanned; count the rest.
    let mut hidden = 0usize;
    for iface in &scannable {
        let selected = chosen
            .as_ref()
            .is_some_and(|current| current.name == iface.name);
        if is_virtual_name(&iface.name) && !selected && !iface.is_default_route {
            hidden += 1;
            continue;
        }

        let mut notes: Vec<&str> = Vec::new();
        if iface.is_default_route {
            notes.push("default route");
        }
        if is_virtual_name(&iface.name) {
            notes.push("virtual");
        }
        if selected {
            notes.push("in use");
        }

        let address = iface
            .cidr
            .clone()
            .or_else(|| iface.ipv4.clone())
            .unwrap_or_else(|| "no address".to_string());
        let suffix = if notes.is_empty() {
            String::new()
        } else {
            format!("  ({})", notes.join(", "))
        };
        report.pass(&format!("{}  {}{}", iface.name, address, suffix), "");
    }

    if hidden > 0 {
        report.note(
            &format!(
                "{hidden} other virtual {} not shown",
                plural(hidden, "interface")
            ),
            "Docker, VM and tunnel devices. `netgap interfaces` lists them all.",
        );
    }

    if let Some(iface) = &chosen {
        if !iface.is_scannable() && !scannable.iter().any(|c| c.name == iface.name) {
            report.warn(
                &format!("{} cannot carry a scan", iface.name),
                "It is down, loopback, or has no usable IPv4 address.",
            );
        }
    }

    chosen
}

/// Whether a complete sweep is possible, and how to get one if it is not.
fn check_discovery(report: &mut Report) {
    report.section("Discovery");

    if can_use_arp() {
        #[cfg(windows)]
        report.pass(
            "ARP sweep available",
            "Windows answers ARP for us; no administrator rights or packet driver needed.",
        );
        #[cfg(unix)]
        report.pass(
            "ARP sweep available",
            "This process may open a raw socket (root or CAP_NET_RAW).",
        );
        #[cfg(not(any(unix, windows)))]
        report.pass("ARP sweep available", "");
        return;
    }

    report.warn(
        "ARP sweep needs privileges",
        "Without it the scan falls back to TCP probing: quieter devices are missed, \
         and most hosts are reported without a MAC address.",
    );
    report.note("To get a complete sweep", &privilege_hint());
}

/// The copy-pasteable way to grant the capability to this binary.
#[cfg(target_os = "linux")]
fn privilege_hint() -> String {
    let program = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "netgap".to_string());
    format!("sudo setcap cap_net_raw+ep {program}\nor re-run this command with sudo")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn privilege_hint() -> String {
    let program = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "netgap".to_string());
    format!("sudo {program}")
}

#[cfg(not(unix))]
fn privilege_hint() -> String {
    "Re-run this command where raw sockets are permitted.".to_string()
}

/// Validate the range before it is used, and say whether it is this link's.
fn check_target(report: &mut Report, chosen: Option<&InterfaceInfo>, requested: Option<String>) {
    report.section("Target");

    let target = requested.or_else(|| chosen.and_then(|iface| iface.cidr.clone()));
    let Some(target) = target else {
        report.fail(
            "no target range",
            "No interface was selected and --target was not given.\nName a working interface with --interface, or pass --target.",
        );
        return;
    };

    let (network, prefix) = match parse_cidr(&target) {
        Ok(parsed) => parsed,
        Err(error) => {
            report.fail(
                &format!("'{target}' is not a usable range"),
                &error.to_string(),
            );
            return;
        }
    };

    match hosts_in_cidr(network, prefix, DEFAULT_MAX_HOSTS) {
        Ok(hosts) => report.pass(
            &format!("{target} — {} to sweep", plural(hosts.len(), "host")),
            "",
        ),
        Err(error) => report.fail(
            &format!("{target} is too large for one sweep"),
            &error.to_string(),
        ),
    }

    let Some(iface) = chosen else {
        return;
    };
    let Some(cidr) = &iface.cidr else {
        return;
    };
    let Ok(local) = parse_cidr(cidr) else {
        return;
    };

    if same_network(local, (network, prefix)) {
        report.pass(&format!("that is the network {} is on", iface.name), "");
    } else {
        report.warn(
            &format!(
                "that range is not the network {} is on ({})",
                iface.name, cidr
            ),
            "Hosts on a network this machine is not attached to will not answer ARP,\n\
             and a TCP probe to them goes through the router, which usually drops it.",
        );
    }
}

/// Gateway, kernel table, and a small live probe: is the link answering?
async fn check_link(report: &mut Report, iface: &InterfaceInfo, no_probe: bool) {
    report.section("The link");

    let network = iface.cidr.as_deref().and_then(|cidr| parse_cidr(cidr).ok());
    let local = iface
        .ipv4
        .as_ref()
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok());

    match default_gateway_ipv4() {
        Some(gateway) => {
            if let Some((net, prefix)) = network {
                if in_network(net, prefix, gateway) {
                    report.pass(&format!("default gateway {gateway} is on this link"), "");
                } else {
                    report.warn(
                        &format!("default gateway {gateway} is not on this link"),
                        "Traffic leaves through it over another interface, which usually\n\
                         means this is a VPN or a second network.",
                    );
                }
            } else {
                report.pass(&format!("default gateway {gateway}"), "");
            }

            if no_probe {
                report.note("gateway probe skipped (--no-probe)", "");
            } else {
                check_gateway_answers(report, gateway).await;
            }
        }
        None => report.warn(
            "no default gateway",
            "This machine has no default route: it is offline, or on an isolated link where\n\
             only direct neighbours can be reached.",
        ),
    }

    check_neighbor_table(report, &iface.name);

    if no_probe {
        report.note("live probe skipped (--no-probe)", "");
        return;
    }

    let (Some(local), Some((_, prefix))) = (local, network) else {
        report.note(
            "live probe skipped",
            "The interface has no IPv4 address to probe around.",
        );
        return;
    };

    let targets = probe_targets(local, prefix, PROBE_HOSTS);
    if targets.is_empty() {
        report.note(
            "live probe skipped",
            "There is no other address in this block to try.",
        );
        return;
    }

    let config = TcpSweepConfig {
        targets: targets.clone(),
        timeout_ms: 500,
        concurrency: PROBE_HOSTS,
        include_neighbors: false,
        interface_name: Some(iface.name.clone()),
        quiet: true,
        ..TcpSweepConfig::default()
    };

    match TcpSweeper::new(config).scan().await {
        Ok(found) if found.is_empty() => report.warn(
            &format!(
                "{} {} probed, none answered",
                targets.len(),
                plural(targets.len(), "host")
            ),
            "Either the devices here are quiet, or this network isolates clients from each\n\
             other. An ARP sweep may still find more than a TCP probe can.",
        ),
        Ok(found) => report.pass(
            &format!("{} of {} hosts answered", found.len(), targets.len()),
            "Discovery works from this machine.",
        ),
        Err(error) => report.fail("the live probe failed", &error.to_string()),
    }
}

/// Try the gateway on the ports a router is likely to answer on.
async fn check_gateway_answers(report: &mut Report, gateway: Ipv4Addr) {
    let (http, https, dns, ssh) = tokio::join!(
        tcp_answer(gateway, GATEWAY_PORTS[0]),
        tcp_answer(gateway, GATEWAY_PORTS[1]),
        tcp_answer(gateway, GATEWAY_PORTS[2]),
        tcp_answer(gateway, GATEWAY_PORTS[3]),
    );

    let answered = GATEWAY_PORTS
        .into_iter()
        .zip([http, https, dns, ssh])
        .find_map(|(port, answer)| answer.map(|answer| (port, answer)));

    match answered {
        Some((port, answer)) => report.pass(
            &format!("gateway {answer} on port {port}"),
            "The link is carrying traffic.",
        ),
        // Not a failure: plenty of routers drop all four, and a stateful
        // firewall in front of them is not a broken network.
        None => report.note(
            "gateway did not answer on 80, 443, 53 or 22",
            "Routers commonly drop these; on its own this does not mean the link is down.",
        ),
    }
}

/// `Some` when the host said anything at all — a refusal counts, because a
/// RST is a reply.
async fn tcp_answer(ip: Ipv4Addr, port: u16) -> Option<&'static str> {
    let attempt = tokio::time::timeout(
        Duration::from_millis(600),
        tokio::net::TcpStream::connect((ip, port)),
    )
    .await;

    match attempt {
        Ok(Ok(_)) => Some("accepted a connection"),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            Some("refused the connection, which still proves it is there")
        }
        _ => None,
    }
}

/// What the OS already knows about this link.
fn check_neighbor_table(report: &mut Report, interface: &str) {
    #[cfg(target_os = "linux")]
    {
        let known = read_neighbor_table()
            .into_iter()
            .filter(|entry| entry.iface == interface)
            .count();

        if known == 0 {
            report.note(
                "nothing in the kernel neighbour table yet",
                "It fills as this machine talks to the link; the probe below sends some traffic.",
            );
        } else {
            report.pass(
                &format!("{known} host(s) already known to the kernel on {interface}"),
                "",
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (report, interface);
        report.note(
            "kernel neighbour table not readable on this platform",
            "Discovery does not depend on it: the sweep collects the MAC addresses itself.",
        );
    }
}

/// History, threat-intel data and alerts: what the scan will be able to use.
fn check_setup(report: &mut Report) {
    report.section("Setup");

    match scans_db_path() {
        Some(path) if path.exists() => match ScanStore::open(&path) {
            Ok(store) => match store.list_scans() {
                Ok(scans) => report.pass(
                    &format!("scan history: {} scan(s)", scans.len()),
                    &path.display().to_string(),
                ),
                Err(error) => {
                    report.warn("the scan history could not be listed", &error.to_string())
                }
            },
            Err(error) => report.warn("the scan history could not be opened", &error.to_string()),
        },
        Some(path) => report.note(
            "no scan history yet",
            &format!("{} is created by the first scan.", path.display()),
        ),
        None => report.warn(
            "no location for the scan history",
            "Set HOME or NETGAP_CONFIG_DIR so scans can be saved.",
        ),
    }

    match LocalCacheManager::default_location() {
        Ok(cache) => match cache.load() {
            Ok(database) if !database.is_empty() => report.pass(
                &format!(
                    "threat-intel cache: {} product(s), {} critical CVE(s)",
                    database.products().len(),
                    database.critical_count()
                ),
                &cache.path().display().to_string(),
            ),
            Ok(_) => report.note(
                "no threat-intel data yet",
                "`netgap threat-intel update` fetches it; `netgap scan --threat-intel` uses it.",
            ),
            Err(error) => report.note(
                "the threat-intel cache could not be read",
                &error.to_string(),
            ),
        },
        Err(error) => report.note("no threat-intel cache location", &error.to_string()),
    }

    match alerts::AlertSettings::load() {
        Ok(Some(settings)) if settings.enabled => report.pass(
            "alerts: webhook configured",
            &alerts::mask_url(&settings.url),
        ),
        Ok(Some(_)) => report.note(
            "alerts are configured but switched off",
            "Run `netgap alert --critical` (or another rule) to switch them back on.",
        ),
        Ok(None) => report.note(
            "alerts off",
            "Optional: `netgap alert --url ...` sends changes to Slack, Discord or a webhook.",
        ),
        Err(error) => report.warn("the alert settings could not be read", &error.to_string()),
    }
}

// ---------------------------------------------------------------- helpers ---

/// `1 warning`, `2 warnings`.
fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

/// The network mask, as a number, so addresses can be compared.
fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    }
}

/// The network address `prefix` describes.
fn network_of(address: Ipv4Addr, prefix: u8) -> u32 {
    u32::from(address) & mask(prefix)
}

/// Whether two network/prefix pairs describe the same block.
fn same_network(a: (Ipv4Addr, u8), b: (Ipv4Addr, u8)) -> bool {
    a.1 == b.1 && network_of(a.0, a.1) == network_of(b.0, b.1)
}

/// Whether an address is inside a network.
fn in_network(network: Ipv4Addr, prefix: u8, address: Ipv4Addr) -> bool {
    network_of(network, prefix) == network_of(address, prefix)
}

/// A block of addresses around this host to prove the link with.
///
/// Deliberately not the whole target: a scan that finds nothing usually means
/// the immediate neighbours do not answer, and checking them is enough to tell
/// "isolated" from "wrong settings" without sending 254 probes to do it.
fn probe_targets(local: Ipv4Addr, prefix: u8, limit: usize) -> Vec<Ipv4Addr> {
    let block = prefix.clamp(27, 32);
    let base = network_of(local, block);
    let size = 1u32 << (32 - block);
    let broadcast = base + size - 1;

    // A /31 is a point-to-point link and a /32 is a single host: neither has
    // network or broadcast addresses to leave out.
    let (first, last) = if block >= 31 {
        (base, broadcast)
    } else {
        (base + 1, broadcast - 1)
    };

    let mut targets = Vec::new();
    for address in first..=last {
        let ip = Ipv4Addr::from(address);
        if ip == local {
            continue;
        }
        targets.push(ip);
        if targets.len() >= limit {
            break;
        }
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mask_of_zero_covers_everything() {
        assert_eq!(mask(0), 0);
        assert!(in_network(
            Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ipv4Addr::new(203, 0, 113, 9)
        ));
    }

    #[test]
    fn a_host_mask_covers_only_itself() {
        let host = Ipv4Addr::new(10, 0, 0, 7);
        assert!(in_network(host, 32, host));
        assert!(!in_network(host, 32, Ipv4Addr::new(10, 0, 0, 8)));
    }

    #[test]
    fn a_gateway_on_the_link_is_recognised() {
        assert!(in_network(
            Ipv4Addr::new(192, 168, 1, 0),
            24,
            Ipv4Addr::new(192, 168, 1, 1)
        ));
        assert!(!in_network(
            Ipv4Addr::new(192, 168, 1, 0),
            24,
            Ipv4Addr::new(10, 7, 0, 2)
        ));
    }

    #[test]
    fn networks_are_the_same_only_at_the_same_prefix() {
        let a = (Ipv4Addr::new(192, 168, 1, 24), 24);
        let b = (Ipv4Addr::new(192, 168, 1, 0), 24);
        let wider = (Ipv4Addr::new(192, 168, 0, 0), 16);
        assert!(same_network(a, b));
        assert!(!same_network(a, wider));
    }

    #[test]
    fn the_probe_samples_the_block_around_this_host() {
        // 192.168.1.24 is in 192.168.1.0/27.
        let targets = probe_targets(Ipv4Addr::new(192, 168, 1, 24), 24, 32);
        assert!(targets.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(targets.contains(&Ipv4Addr::new(192, 168, 1, 30)));
        // Network and broadcast addresses are not hosts.
        assert!(!targets.contains(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!targets.contains(&Ipv4Addr::new(192, 168, 1, 31)));
        assert!(!targets.contains(&Ipv4Addr::new(192, 168, 1, 32)));
    }

    #[test]
    fn the_scanning_host_is_never_probed() {
        let local = Ipv4Addr::new(192, 168, 1, 24);
        let targets = probe_targets(local, 24, 32);
        assert!(!targets.contains(&local));
        assert_eq!(targets.len(), 29);
    }

    #[test]
    fn the_probe_stays_inside_a_narrow_link() {
        // A /30 has two usable addresses; there is nothing to widen to.
        let targets = probe_targets(Ipv4Addr::new(10, 9, 9, 1), 30, 32);
        assert_eq!(targets, vec![Ipv4Addr::new(10, 9, 9, 2)]);
    }

    #[test]
    fn the_probe_is_capped() {
        let targets = probe_targets(Ipv4Addr::new(10, 0, 0, 5), 16, 8);
        assert_eq!(targets.len(), 8);
    }

    #[test]
    fn a_single_host_link_has_nothing_to_probe() {
        assert!(probe_targets(Ipv4Addr::new(10, 0, 0, 7), 32, 32).is_empty());
    }
}
