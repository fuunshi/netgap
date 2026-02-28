use anyhow::{anyhow, Context, Result};
use colored::Colorize;

use crate::discovery;
use crate::model::{OutputFormat, ScanMode};
use crate::output;

pub fn print_interfaces() -> Result<()> {
    let interfaces = discovery::list_interfaces()?;

    println!("{}", "Available interfaces".bold().bright_cyan());
    for interface in interfaces {
        let status = if interface.is_up { "up".green() } else { "down".red() };
        let loopback = if interface.is_loopback { " loopback".bright_black() } else { "".to_string().normal() };
        let ips = if interface.ips.is_empty() { "no IPs".bright_black().to_string() } else { interface.ips.join(", ").bright_white().to_string() };

        println!("  {} {}{} - {}", interface.name.bold(), status, loopback, ips);
    }

    Ok(())
}

pub fn run_scan(
    interface_name: Option<&str>,
    mode: ScanMode,
    output_format: OutputFormat,
    output_file: Option<&std::path::Path>,
) -> Result<()> {
    let selected = discovery::select_interface(interface_name)?;
    let targets = discovery::discover_hosts(&selected, mode)?;

    let summary = output::build_summary(selected.name.clone(), mode, targets, discovery::list_interfaces()?)
        .context("failed to assemble scan summary")?;

    output::emit(&summary, output_format, output_file)
        .map_err(|error| anyhow!(error))
}