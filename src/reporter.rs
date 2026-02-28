use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

use crate::model::{HostReport, OutputFormat, ScanSummary, Severity};

pub fn emit(summary: &ScanSummary, format: OutputFormat, output_file: Option<&Path>) -> Result<()> {
    match format {
        OutputFormat::Terminal => emit_terminal(summary),
        OutputFormat::Json => emit_json(summary),
        OutputFormat::Html => emit_html(summary, output_file),
    }
}

fn emit_terminal(summary: &ScanSummary) -> Result<()> {
    println!("{}", "netgap scan report".bold().bright_cyan());
    println!("  interface: {}", summary.interface.bright_white());
    println!("  mode: {:?}", summary.mode);
    println!(
        "  hosts discovered: {}",
        summary.hosts.len().to_string().bright_green()
    );

    for host in &summary.hosts {
        print_host(host);
    }

    Ok(())
}

fn print_host(host: &HostReport) {
    println!("\n{}", host.ip.bold().bright_white());

    if let Some(hostname) = &host.hostname {
        println!("  hostname: {}", hostname.bright_black());
    }

    if let Some(mac) = &host.mac {
        println!("  mac: {}", mac.bright_black());
    }

    if host.open_ports.is_empty() {
        println!("  open ports: {}", "none detected".bright_black());
    } else {
        println!("  open ports:");
        for port in &host.open_ports {
            let service = port.service.as_deref().unwrap_or("unknown");
            let banner = port.banner.as_deref().unwrap_or("");
            println!(
                "    {:>5}/tcp  {:<18} {}",
                port.port,
                service.bright_green(),
                banner.bright_black()
            );
        }
    }

    if !host.gaps.is_empty() {
        println!("  gaps:");
        for gap in &host.gaps {
            let label = match gap.severity {
                Severity::Low => "low".bright_green(),
                Severity::Medium => "medium".bright_yellow(),
                Severity::High => "high".bright_red(),
                Severity::Critical => "critical".red().bold(),
            };
            println!("    [{}] {}", label, gap.title.bold());
            println!("      {}", gap.description);
            println!("      {}", gap.recommendation.bright_black());
        }
    }
}

fn emit_json(summary: &ScanSummary) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(summary)?);
    Ok(())
}

fn emit_html(summary: &ScanSummary, output_file: Option<&Path>) -> Result<()> {
    let mut rows = String::new();

    for host in &summary.hosts {
        for gap in &host.gaps {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td></tr>",
                host.ip,
                gap.port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "-".into()),
                gap.severity,
                gap.title,
                gap.recommendation
            ));
        }
    }

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>netgap report</title>
  <style>
	body {{ font-family: system-ui, sans-serif; margin: 32px; background: #0f172a; color: #e2e8f0; }}
	h1 {{ color: #7dd3fc; }}
	table {{ width: 100%; border-collapse: collapse; margin-top: 24px; }}
	th, td {{ border-bottom: 1px solid #334155; padding: 12px; text-align: left; vertical-align: top; }}
	th {{ color: #94a3b8; }}
  </style>
</head>
<body>
  <h1>netgap report</h1>
  <p><strong>Interface:</strong> {}</p>
  <p><strong>Mode:</strong> {:?}</p>
  <p><strong>Hosts discovered:</strong> {}</p>
  <table>
	<thead><tr><th>Host</th><th>Port</th><th>Severity</th><th>Finding</th><th>Recommendation</th></tr></thead>
	<tbody>{}</tbody>
  </table>
</body>
</html>"#,
        summary.interface,
        summary.mode,
        summary.hosts.len(),
        rows
    );

    let path = output_file.unwrap_or(Path::new("netgap-report.html"));
    fs::write(path, html)
        .with_context(|| format!("failed to write report to {}", path.display()))?;
    println!("wrote HTML report to {}", path.display());
    Ok(())
}
