//! Discovery method selection and execution.
//!
//! ARP finds every peer on the LAN but needs `CAP_NET_RAW`; without it the
//! scan falls back to a TCP sweep. Because the fallback sees strictly fewer
//! hosts, an unprivileged run tells the user what they are giving up and lets
//! them re-run under sudo instead.

use anyhow::{anyhow, Result};
use netgap_core::Device;
use netgap_discover::{hosts_in_cidr, parse_cidr, TcpSweepConfig, TcpSweeper};
#[cfg(unix)]
use netgap_discover::{is_privilege_error, privilege, ArpDiscovery, DiscoveryConfig};
use netgap_interfaces::{get_interface, get_interface_auto, get_interface_cidr, InterfaceInfo};
#[cfg(unix)]
use std::io::{self, IsTerminal, Write};
use std::net::Ipv4Addr;

/// How the scan will find hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    /// Raw-socket ARP sweep; requires root or `CAP_NET_RAW`.
    Arp,
    /// Unprivileged TCP connect sweep.
    Tcp,
}

impl DiscoveryMethod {
    /// Human-readable label shown in the scan banner.
    pub fn label(self) -> &'static str {
        match self {
            DiscoveryMethod::Arp => "ARP (raw socket)",
            DiscoveryMethod::Tcp => "TCP connect (unprivileged)",
        }
    }
}

/// Everything needed to run discovery: which method, which interface, what to
/// scan, and how large a subnet may be.
#[derive(Debug, Clone)]
pub struct DiscoveryPlan {
    pub method: DiscoveryMethod,
    pub interface: InterfaceInfo,
    pub target: String,
    pub max_hosts: usize,
    /// Whether a failed ARP attempt may silently fall back to TCP. False when
    /// the user explicitly asked for ARP.
    ///
    /// Unix only: elsewhere the TCP sweep is the method rather than the
    /// fallback, so there is nothing to fall back from.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub allow_fallback: bool,
    /// Whether to ask devices to identify themselves over mDNS.
    pub mdns: bool,
    /// Suppress progress notes on stderr.
    ///
    /// The full-screen UI owns the terminal, so a stray line from a scan would
    /// land in the middle of a drawn frame. The CLI leaves this false.
    pub quiet: bool,
}

impl DiscoveryPlan {
    /// The hosts this plan will probe, excluding the scanning host itself.
    pub fn target_hosts(&self) -> Result<Vec<Ipv4Addr>> {
        let (network, prefix) = parse_cidr(&self.target)?;
        let mut hosts = hosts_in_cidr(network, prefix, self.max_hosts)?;

        if let Some(local) = self.interface.ipv4_network().map(|net| net.ip()) {
            hosts.retain(|host| *host != local);
        }

        Ok(hosts)
    }
}

/// Decide how to scan, prompting when the privileged path is unavailable.
///
/// `non_interactive` suppresses the prompt entirely (used for `--format json`
/// and when stdin is not a terminal) so scripts never block.
pub fn resolve_plan(
    interface: Option<String>,
    target: Option<String>,
    requested: Option<DiscoveryMethod>,
    assume_yes: bool,
    non_interactive: bool,
    max_hosts: usize,
    mdns: bool,
) -> Result<DiscoveryPlan> {
    let interface_name = match interface {
        Some(name) => name,
        None => get_interface_auto()?,
    };
    let interface = get_interface(&interface_name)?;

    let target = match target {
        Some(target) => target,
        None => get_interface_cidr(&interface_name)?,
    };

    // Validate the subnet before doing anything else, so an oversized or
    // malformed target fails fast instead of after a prompt.
    let (network, prefix) = parse_cidr(&target)?;
    hosts_in_cidr(network, prefix, max_hosts)?;

    // Raw sockets are a Unix business here. On Windows the TCP sweep is not a
    // fallback, it is the method, so the privilege prompt has nothing to offer.
    #[cfg(unix)]
    let privileged = privilege::has_cap_net_raw();
    #[cfg(not(unix))]
    let privileged = false;

    let (method, allow_fallback) = match requested {
        // An explicit choice is honored, and falling back would contradict it.
        Some(method) => (method, false),
        None if privileged => (DiscoveryMethod::Arp, true),
        None => {
            #[cfg(unix)]
            choose_fallback(&target, assume_yes, non_interactive)?;

            #[cfg(not(unix))]
            let _ = (assume_yes, non_interactive);

            (DiscoveryMethod::Tcp, true)
        }
    };

    Ok(DiscoveryPlan {
        method,
        interface,
        target,
        max_hosts,
        allow_fallback,
        mdns,
        quiet: false,
    })
}

/// Explain the trade-off and let the user decide between continuing
/// unprivileged or exiting to re-run under sudo.
#[cfg(unix)]
fn choose_fallback(target: &str, assume_yes: bool, non_interactive: bool) -> Result<()> {
    if assume_yes || non_interactive || std::env::var_os("CI").is_some() {
        eprintln!(
            "⚠  ARP discovery needs root; using the TCP fallback (fewer hosts, limited MAC addresses)."
        );
        eprintln!(
            "   Re-run with sudo for a complete scan: {}",
            sudo_command_line()
        );
        return Ok(());
    }

    let interactive = io::stdin().is_terminal() && io::stderr().is_terminal();
    if !interactive {
        eprintln!(
            "⚠  ARP discovery needs root; using the TCP fallback. Re-run with sudo: {}",
            sudo_command_line()
        );
        return Ok(());
    }

    eprintln!();
    eprintln!("⚠  Full ARP discovery needs root (CAP_NET_RAW), which this process lacks.");
    eprintln!("   The unprivileged fallback finds fewer hosts and can only read MAC");
    eprintln!("   addresses the kernel already knows.");
    eprintln!();
    eprintln!("   Best results:  {}", sudo_command_line());
    eprintln!("   Target:        {}", target);
    eprintln!();
    eprintln!("   [c] continue with the unprivileged TCP scan (default)");
    eprintln!("   [x] exit so it can be re-run with sudo");
    eprint!("   choice [c/x]: ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "x" | "exit" | "q"
    ) {
        eprintln!();
        eprintln!("Exiting. Re-run with:");
        eprintln!();
        eprintln!("    {}", sudo_command_line());
        eprintln!();
        std::process::exit(2);
    }

    Ok(())
}

/// This invocation, prefixed with sudo, so the user can copy-paste it.
#[cfg(unix)]
fn sudo_command_line() -> String {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "netgap".to_string());
    let rest: Vec<String> = args.collect();
    format!("sudo {} {}", program, rest.join(" "))
}

/// Run discovery according to the plan.
pub async fn run(plan: &DiscoveryPlan) -> Result<Vec<Device>> {
    match plan.method {
        #[cfg(unix)]
        DiscoveryMethod::Arp => match run_arp(plan).await {
            Ok(devices) => Ok(devices),
            Err(error) if plan.allow_fallback && is_privilege_error(&error) => {
                if !plan.quiet {
                    eprintln!(
                        "⚠  Raw sockets unavailable ({}); falling back to the TCP sweep.",
                        error
                    );
                }
                run_tcp(plan).await
            }
            Err(error) => Err(error),
        },
        // Unreachable on Windows, where nothing selects the ARP method, and
        // the compiler is told as much rather than pretending it can happen.
        #[cfg(not(unix))]
        DiscoveryMethod::Arp => run_tcp(plan).await,
        DiscoveryMethod::Tcp => run_tcp(plan).await,
    }
}

/// Raw-socket ARP sweep.
#[cfg(unix)]
async fn run_arp(plan: &DiscoveryPlan) -> Result<Vec<Device>> {
    let config = DiscoveryConfig {
        interface_name: plan.interface.name.clone(),
        target_cidr: plan.target.clone(),
        timeout_ms: 2000,
        max_hosts: plan.max_hosts,
        retries: 3,
    };

    let (devices, conflicts) = ArpDiscovery::new(config).scan_with_conflicts().await?;
    if !plan.quiet {
        report_arp_conflicts(&conflicts);
    }

    Ok(devices)
}

/// Print any address that answered from two hardware addresses during a sweep.
///
/// Only a raw-socket sweep can see this: the unprivileged path reads the
/// kernel's table, which holds one entry per address and so cannot show two
/// devices claiming it. Watch mode covers that case by comparing across scans.
#[cfg(unix)]
fn report_arp_conflicts(conflicts: &[netgap_discover::MacChange]) {
    if conflicts.is_empty() {
        return;
    }

    eprintln!();
    eprintln!(
        "⚠️  {} address(es) answered from more than one device:",
        conflicts.len()
    );
    for conflict in conflicts {
        eprintln!("    {}", conflict.describe());
    }
    eprintln!(
        "    On a healthy network each address belongs to one device. On the gateway\n    \
         this is how traffic gets intercepted; elsewhere it is usually a replaced\n    \
         device or a duplicate address."
    );
    eprintln!();
}

/// Unprivileged TCP sweep with neighbour-table MAC enrichment.
async fn run_tcp(plan: &DiscoveryPlan) -> Result<Vec<Device>> {
    let config = TcpSweepConfig {
        targets: plan.target_hosts()?,
        timeout_ms: 400,
        concurrency: 128,
        include_neighbors: true,
        interface_name: Some(plan.interface.name.clone()),
        ..TcpSweepConfig::default()
    };

    let devices = TcpSweeper::new(config).scan().await?;
    if !plan.quiet {
        eprintln!("✓ Discovery complete: found {} host(s)", devices.len());
    }
    Ok(devices)
}

/// Parse a `--discovery` value.
pub fn parse_method(value: &str) -> Result<DiscoveryMethod> {
    match value.to_ascii_lowercase().as_str() {
        "arp" => Ok(DiscoveryMethod::Arp),
        "tcp" => Ok(DiscoveryMethod::Tcp),
        other => Err(anyhow!(
            "unknown discovery method '{}'; expected 'auto', 'arp' or 'tcp'",
            other
        )),
    }
}
