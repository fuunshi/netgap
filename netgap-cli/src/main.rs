use clap::{Parser, Subcommand};
use netgap_core::{Device, Finding, Severity, ScanConfig, ScanResult, FindingSummary};
use netgap_interfaces::InterfaceInfo;
use netgap_discover::DiscoveryConfig;
use netgap_scan::{PortScanner, ScanConfig as PortScanConfig};
use netgap_report::ReportFormatter;
use std::net::IpAddr;
use chrono::Local;

#[derive(Parser)]
#[command(name = "netgap")]
#[command(about = "Network security scanner for discovering and assessing vulnerabilities on your LAN", long_about = None)]
#[command(version = "0.1.0")]
#[command(author = "GitHub Copilot")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List available network interfaces
    Interfaces,

    /// Run a security scan on the selected network
    Scan {
        /// Network interface to scan (e.g., eth0)
        #[arg(short, long)]
        interface: Option<String>,

        /// Target network in CIDR notation (default: auto-detect)
        #[arg(short, long)]
        target: Option<String>,

        /// Quick scan mode (ARP + top 20 ports only)
        #[arg(long)]
        quick: bool,

        /// Deep scan mode (all checks enabled)
        #[arg(long)]
        deep: bool,

        /// Output format: table, json, summary
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Display results from the last scan
    Report {
        /// Output format: table, json, summary
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Continuous monitoring mode
    Watch,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Interfaces => {
            cmd_interfaces()?;
        }
        Commands::Scan {
            interface,
            target,
            quick,
            deep,
            format,
        } => {
            cmd_scan(interface, target, quick, deep, &format).await?;
        }
        Commands::Report { format } => {
            println!("📊 Report generation (format: {})", format);
            println!("(Loading from persistent storage - coming in future milestone)");
        }
        Commands::Watch => {
            println!("👁️  Continuous monitoring mode");
            println!("(Scheduled alerting coming in future milestone)");
        }
    }

    Ok(())
}

fn cmd_interfaces() -> Result<(), Box<dyn std::error::Error>> {
    println!("📡 Available Network Interfaces\n");
    let interfaces = netgap_interfaces::get_interfaces()?;

    for (idx, iface) in interfaces.iter().enumerate() {
        println!("  {}. {} {}", idx + 1, iface.name, if iface.is_up { "✓" } else { "✗" });
        if let Some(ipv4) = &iface.ipv4 {
            println!("     IPv4: {}", ipv4);
        }
        if let Some(mac) = &iface.mac {
            println!("     MAC:  {}", mac);
        }
    }

    Ok(())
}

async fn cmd_scan(
    interface: Option<String>,
    target: Option<String>,
    quick: bool,
    deep: bool,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = if quick {
        "quick"
    } else if deep {
        "deep"
    } else {
        "standard"
    };

    println!("🔍 Starting {} scan...\n", mode);

    // Get interface
    let iface_name = interface.unwrap_or_else(|| {
        println!("ℹ️  Using first available interface (specify with -i to change)");
        "eth0".to_string()
    });

    println!("📍 Interface: {}", iface_name);

    // Determine target CIDR
    let target_cidr = target.unwrap_or_else(|| {
        println!("ℹ️  Using default target 192.168.1.0/24 (specify with -t to change)");
        "192.168.1.0/24".to_string()
    });

    println!("🎯 Target: {}\n", target_cidr);

    // Create scan result
    let mut result = ScanResult {
        started_at: Local::now().to_rfc3339(),
        config: ScanConfig {
            interface: iface_name.clone(),
            target: target_cidr.clone(),
            timeout_ms: if quick { 1000 } else { 2000 },
            concurrency: if quick { 16 } else { 32 },
            discovery_only: quick,
        },
        devices: Vec::new(),
        summary: FindingSummary::new(),
    };

    // Discovery phase
    println!("Phase 1: Device Discovery");
    println!("─────────────────────────");

    let discovery_config = DiscoveryConfig {
        interface_name: iface_name,
        target_cidr,
        timeout_ms: 1000,
    };

    let discovery = netgap_discover::ArpDiscovery::new(discovery_config);
    let mut devices = discovery.scan().await?;

    if devices.is_empty() {
        println!("\n✗ No devices discovered on target network");
    } else {
        println!("✓ Discovered {} device(s)\n", devices.len());

        // Port scanning phase (unless quick mode)
        if !quick {
            println!("Phase 2: Port Scanning");
            println!("─────────────────────");

            let port_config = PortScanConfig {
                ports: netgap_scan::TOP_DANGEROUS_PORTS.to_vec(),
                timeout_ms: 2000,
                concurrency: 32,
            };

            let scanner = PortScanner::new(port_config);
            scanner.scan_devices(&mut devices).await?;

            println!();
        }
    }

    // Update results
    result.devices = devices.clone();
    for device in &result.devices {
        for finding in &device.findings {
            result.summary.add_finding(finding.severity);
        }
    }

    // Output results
    println!("\n{}", "─".repeat(70));
    println!("SCAN RESULTS");
    println!("{}\n", "─".repeat(70));

    let output = match format {
        "json" => ReportFormatter::format_json(&result)?,
        "summary" => ReportFormatter::format_summary(&result)?,
        _ => ReportFormatter::format_terminal(&result)?,
    };

    println!("{}", output);

    Ok(())
}
