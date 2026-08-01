//! Discovery method selection and the CLI's privilege prompt.
//!
//! The sweep itself lives in `netgap-engine`. What is left here is the part
//! only a terminal can do: picking an interface when none was given, and
//! explaining the unprivileged fallback before a scan starts.

use anyhow::Result;
use netgap_engine::discovery::{build_plan, can_use_arp};
use netgap_interfaces::{get_interface, get_interface_auto, get_interface_cidr};
#[cfg(unix)]
use std::io::{self, IsTerminal, Write};

pub use netgap_engine::discovery::{parse_method, run, DiscoveryMethod, DiscoveryPlan};

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
    let requested = match requested {
        Some(method) => Some(method),
        // Automatic with raw sockets: the engine picks ARP.
        None if can_use_arp() => None,
        None => {
            #[cfg(unix)]
            choose_fallback(&target, assume_yes, non_interactive)?;

            #[cfg(not(unix))]
            let _ = (assume_yes, non_interactive);

            // Already told the user; the engine should not ask again.
            Some(DiscoveryMethod::Tcp)
        }
    };

    build_plan(interface, target, requested, max_hosts, mdns, false)
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
