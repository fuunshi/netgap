//! Discovery method selection and execution.
//!
//! ARP finds every peer on the LAN. On Unix it needs `CAP_NET_RAW`; on
//! Windows it goes through `SendARP`, which needs no privileges at all.
//! Without ARP the scan falls back to a TCP sweep. Because the fallback sees
//! strictly fewer hosts, an unprivileged run tells the user what they are
//! giving up and lets them re-run under sudo. That explanation lives in the
//! CLI; this crate only decides and runs.

use anyhow::{anyhow, Result};
use netgap_core::Device;
use netgap_discover::{hosts_in_cidr, parse_cidr, TcpSweepConfig, TcpSweeper};
#[cfg(unix)]
use netgap_discover::{is_privilege_error, privilege, ArpDiscovery, DiscoveryConfig};
use netgap_interfaces::InterfaceInfo;
use std::net::Ipv4Addr;

/// The largest subnet a single sweep may cover unless told otherwise.
pub use netgap_discover::DEFAULT_MAX_HOSTS;

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
    pub allow_fallback: bool,
    /// Whether to ask devices to identify themselves over mDNS.
    pub mdns: bool,
    /// Suppress progress notes on stderr.
    ///
    /// A full-screen front end owns the terminal or the window, so a stray
    /// line from a scan would land somewhere it does not belong. The CLI
    /// leaves this false.
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

/// Whether this build can run an ARP sweep without extra setup.
///
/// Unix opens a raw socket, which needs root or `CAP_NET_RAW`. Windows asks
/// the system through `SendARP`, which needs neither an administrator nor a
/// packet-capture driver — so there is always a complete sweep available
/// there, and the TCP fallback is only a fallback.
pub fn can_use_arp() -> bool {
    #[cfg(unix)]
    {
        privilege::has_cap_net_raw()
    }
    #[cfg(windows)]
    {
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Build a plan for a known interface and target.
///
/// `requested` is an explicit method choice. `None` means automatic: ARP when
/// this process can use raw sockets, TCP otherwise. Validation happens here,
/// before anything is sent, so an oversized or malformed target fails fast.
pub fn build_plan(
    interface: InterfaceInfo,
    target: String,
    requested: Option<DiscoveryMethod>,
    max_hosts: usize,
    mdns: bool,
    quiet: bool,
) -> Result<DiscoveryPlan> {
    let (network, prefix) = parse_cidr(&target)?;
    hosts_in_cidr(network, prefix, max_hosts)?;

    let (method, allow_fallback) = match requested {
        // An explicit choice is honored, and falling back would contradict it.
        Some(method) => (method, false),
        None if can_use_arp() => (DiscoveryMethod::Arp, true),
        None => (DiscoveryMethod::Tcp, true),
    };

    Ok(DiscoveryPlan {
        method,
        interface,
        target,
        max_hosts,
        allow_fallback,
        mdns,
        quiet,
    })
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
        // Unprivileged ARP through the Windows API. A sweep that the system
        // refuses outright (the target not being on this link, say) falls
        // back to TCP, which at least has a chance across a router.
        #[cfg(windows)]
        DiscoveryMethod::Arp => match run_windows_arp(plan).await {
            Ok(devices) => Ok(devices),
            Err(error) if plan.allow_fallback => {
                if !plan.quiet {
                    eprintln!(
                        "⚠  ARP discovery failed ({}); falling back to the TCP sweep.",
                        error
                    );
                }
                run_tcp(plan).await
            }
            Err(error) => Err(error),
        },
        // Neither raw sockets nor `SendARP`: the TCP sweep is all there is.
        #[cfg(not(any(unix, windows)))]
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

/// ARP sweep through the Windows IP Helper API.
#[cfg(windows)]
async fn run_windows_arp(plan: &DiscoveryPlan) -> Result<Vec<Device>> {
    let config = netgap_discover::arp_windows::ArpSweepConfig {
        targets: plan.target_hosts()?,
        source: plan
            .interface
            .ipv4
            .as_deref()
            .and_then(|ipv4| ipv4.parse().ok()),
        concurrency: 32,
    };

    let devices = netgap_discover::arp_windows::sweep(&config).await?;
    if !plan.quiet {
        eprintln!("✓ ARP discovery complete: found {} host(s)", devices.len());
    }
    Ok(devices)
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
