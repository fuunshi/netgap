use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

use crate::model::{OutputFormat, ScanMode, ScanSummary};

pub fn build_summary(
    interface: String,
    mode: ScanMode,
    hosts: Vec<std::net::Ipv4Addr>,
    interfaces: Vec<crate::model::InterfaceInfo>,
) -> Result<ScanSummary> {
    Ok(ScanSummary {
        interface,
        mode,
        hosts: hosts
            .into_iter()
            .map(|ip| crate::model::HostReport {
                ip: ip.to_string(),
                hostname: None,
                mac: None,
                open_ports: Vec::new(),
                gaps: Vec::new(),
            })
            .collect(),
        interfaces,
    })
}

pub fn emit(summary: &ScanSummary, format: OutputFormat, output_file: Option<&Path>) -> Result<()> {
    match format {
        OutputFormat::Terminal => emit_terminal(summary),
        OutputFormat::Json => emit_json(summary),
        OutputFormat::Html => emit_html(summary, output_file),
    }
}

fn emit_terminal(summary: &ScanSummary) -> Result<()> {
    println!("{}", "Scan summary".bold().bright_cyan());
    println!("  interface: {}", summary.interface.bright_white());
    println!("  mode: {:?}", summary.mode);
    println!("  discovered hosts: {}", summary.hosts.len().to_string().bright_green());
    Ok(())
}

fn emit_json(summary: &ScanSummary) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(summary)?);
    Ok(())
}

fn emit_html(summary: &ScanSummary, output_file: Option<&Path>) -> Result<()> {
    let html = format!(
        "<html><body><h1>netgap report</h1><p>Interface: {}</p><p>Mode: {:?}</p><p>Hosts: {}</p></body></html>",
        summary.interface,
        summary.mode,
        summary.hosts.len()
    );

    let path = output_file.unwrap_or(Path::new("netgap-report.html"));
    fs::write(path, html).with_context(|| format!("failed to write report to {}", path.display()))?;
    println!("wrote HTML report to {}", path.display());
    Ok(())
}
