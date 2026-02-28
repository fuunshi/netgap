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
#[command(author = "Pranil Shrestha")]
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

    /// Display results from the last scan or export reports
    Report {
        /// Scan ID to report on (latest if not specified)
        #[arg(short, long)]
        scan_id: Option<String>,

        /// Compare with another scan (shows changes between scans)
        #[arg(long)]
        compare: Option<String>,

        /// Export format: table, json, summary, markdown, html, csv
        #[arg(short, long, default_value = "table")]
        format: String,

        /// List all historical scans
        #[arg(long)]
        history: bool,
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
        Commands::Report { scan_id, compare, format, history } => {
            cmd_report(scan_id, compare, &format, history)?;
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

fn cmd_report(scan_id: Option<String>, compare: Option<String>, format: &str, history: bool) -> Result<(), Box<dyn std::error::Error>> {
    use netgap_storage::ScanStore;

    let store = ScanStore::default()?;

    if history {
        println!("📋 Scan History\n");
        let scans = store.list_scans()?;
        if scans.is_empty() {
            println!("  No scans found. Run 'netgap scan' to start scanning.");
        } else {
            for scan in scans {
                println!("  {} - {} ({} devices, {} findings)", 
                    scan.id, scan.started_at, scan.device_count, scan.finding_count);
                if scan.critical_count > 0 {
                    println!("    🔴 {} critical issues", scan.critical_count);
                }
            }
        }
        return Ok(());
    }

    if let (Some(id1), Some(id2)) = (scan_id.as_ref(), compare.as_ref()) {
        println!("🔄 Comparing scans {} → {}\n", id1, id2);
        let comparison = store.compare_scans(id1, id2)?;
        
        println!("Scan 1: {} ({})", comparison.scan1_id, comparison.scan1_date);
        println!("Scan 2: {} ({})\n", comparison.scan2_id, comparison.scan2_date);

        if !comparison.new_devices.is_empty() {
            println!("✨ New Devices ({}):", comparison.new_devices.len());
            for ip in &comparison.new_devices {
                println!("  + {}", ip);
            }
            println!();
        }

        if !comparison.removed_devices.is_empty() {
            println!("👋 Removed Devices ({}):", comparison.removed_devices.len());
            for ip in &comparison.removed_devices {
                println!("  - {}", ip);
            }
            println!();
        }

        if !comparison.new_critical.is_empty() {
            println!("🔴 New Critical Findings ({}):", comparison.new_critical.len());
            for (title, ip) in &comparison.new_critical {
                println!("  + {} on {}", title, ip);
            }
            println!();
        }

        if !comparison.resolved_findings.is_empty() {
            println!("✅ Resolved Findings ({}):", comparison.resolved_findings.len());
            for (title, ip) in &comparison.resolved_findings {
                println!("  ✓ {} on {}", title, ip);
            }
        }

        return Ok(());
    }

    let scan_to_report = if let Some(id) = scan_id {
        id
    } else {
        let scans = store.list_scans()?;
        if scans.is_empty() {
            println!("❌ No scans found. Run 'netgap scan' first.");
            return Ok(());
        }
        scans[0].id.clone()
    };

    match format {
        "markdown" => {
            let md = store.export_markdown(&scan_to_report)?;
            println!("{}", md);
        }
        "html" => {
            let html = store.export_html(&scan_to_report)?;
            println!("{}", html);
        }
        "csv" => {
            let csv = store.export_csv(&scan_to_report)?;
            println!("{}", csv);
        }
        _ => {
            println!("❌ Format '{}' not yet supported for reports. Use: markdown, html, csv", format);
        }
    }

    Ok(())
}
