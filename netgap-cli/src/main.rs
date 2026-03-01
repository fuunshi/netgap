use clap::{Parser, Subcommand};
use netgap_core::{ScanConfig, ScanResult, FindingSummary};
use netgap_discover::DiscoveryConfig;
use netgap_scan::{PortScanner, ScanConfig as PortScanConfig};
use netgap_fingerprint::Fingerprinter;
use netgap_mdns::MdnsDiscovery;
use netgap_services::{VulnerabilityCheck, ServiceInfo};
use netgap_report::ReportFormatter;
use chrono::Local;
use std::net::Ipv4Addr;

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

        /// Include mDNS service discovery
        #[arg(long)]
        mdns: bool,

        /// Perform banner grabbing for service identification
        #[arg(long)]
        fingerprint: bool,

        /// Include vulnerability assessment (requires --deep or --fingerprint)
        #[arg(long)]
        assess: bool,

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
            mdns,
            fingerprint,
            assess,
            format,
        } => {
            cmd_scan(interface, target, quick, deep, mdns, fingerprint, assess, &format).await?;
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
    mdns: bool,
    fingerprint: bool,
    assess: bool,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mode = if quick {
        "quick"
    } else if deep {
        "deep"
    } else if mdns || fingerprint || assess {
        "enhanced"
    } else {
        "standard"
    };

    println!("🔍 Starting {} scan...", mode);
    if mdns {
        println!("   📡 mDNS discovery enabled");
    }
    if fingerprint {
        println!("   🔎 Service fingerprinting enabled");
    }
    if assess {
        println!("   ⚠️  Vulnerability assessment enabled");
    }
    println!();

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

        // mDNS discovery phase (if mdns flag enabled)
        if mdns {
            println!("Phase 2b: mDNS Service Discovery");
            println!("────────────────────────────────");

            match MdnsDiscovery::discover_services(3).await {
                Ok(services) => {
                    if services.is_empty() {
                        println!("  No mDNS services discovered");
                    } else {
                        println!("  Discovered {} mDNS service(s):", services.len());
                        for service in &services {
                            println!("    • {} ({})", service.name, service.service_type.display_name());
                            if let Some(ip) = &service.ip {
                                println!("      IP: {}", ip);
                            }
                            println!("      Port: {}", service.port);
                        }
                    }
                }
                Err(e) => {
                    println!("  ⚠️  mDNS discovery error: {}", e);
                }
            }

            println!();
        }

        // Banner grabbing phase (if fingerprint flag enabled)
        if fingerprint {
            println!("Phase 3: Service Fingerprinting");
            println!("──────────────────────────────");

            for device in &mut devices {
                for port in &device.open_ports {
                    // Try to grab banners for common services
                    let banner_result = if *port == 80 || *port == 8080 {
                        Fingerprinter::grab_http_banner(
                            &device.ip.to_string(),
                            *port,
                        )
                        .await
                    } else if *port == 22 {
                        Fingerprinter::grab_ssh_banner(
                            &device.ip.to_string(),
                            *port,
                        )
                        .await
                    } else if *port == 21 {
                        Fingerprinter::grab_ftp_banner(
                            &device.ip.to_string(),
                            *port,
                        )
                        .await
                    } else {
                        None
                    };

                    // If banner was grabbed, display it
                    if let Some(banner) = banner_result {
                        println!(
                            "  {}:{} ({}) - {}",
                            device.ip, banner.port, banner.protocol, banner.service_name
                                .as_ref()
                                .unwrap_or(&"Unknown".to_string())
                        );
                        if let Some(v) = &banner.version {
                            println!("    Version: {}", v);
                        }
                    }
                }
            }

            println!();
        }

        // Vulnerability assessment (if assess flag enabled)
        if assess {
            println!("Phase 4: Vulnerability Assessment");
            println!("─────────────────────────────────");

            let mut has_findings = false;

            for device in &devices {
                // For each open port, try to assess vulnerabilities
                for port in &device.open_ports {
                    // Map port to service name for vulnerability lookup
                    let service_name = match *port {
                        21 => Some("FTP"),
                        22 => Some("OpenSSH"),
                        23 => Some("Telnet"),
                        80 | 8080 => Some("Apache"),
                        443 | 8443 => Some("Apache"),
                        3306 => Some("MySQL"),
                        5432 => Some("PostgreSQL"),
                        _ => None,
                    };

                    if let Some(svc_name) = service_name {
                        // Create a basic service info for vulnerability check
                        let service_info = ServiceInfo {
                            ip: if let std::net::IpAddr::V4(v4) = device.ip {
                                v4
                            } else {
                                Ipv4Addr::UNSPECIFIED
                            },
                            port: *port,
                            name: svc_name.to_string(),
                            version: None, // Would need banner grabbing for actual version
                            service_type: match *port {
                                21 => "ftp".to_string(),
                                22 => "ssh".to_string(),
                                23 => "telnet".to_string(),
                                _ => "http".to_string(),
                            },
                            banner: None,
                            confidence: 0.75,
                            vulnerabilities: Vec::new(),
                        };

                        // Check for vulnerabilities
                        let vulns = VulnerabilityCheck::check_version(&service_info);
                        if !vulns.is_empty() {
                            has_findings = true;
                            println!("  {}:{} ({}) - {} finding(s):", device.ip, port, svc_name, vulns.len());
                            for vuln in vulns {
                                let severity_emoji = match vuln.severity.as_str() {
                                    "Critical" => "🔴",
                                    "High" => "🟠",
                                    "Medium" => "🟡",
                                    _ => "🔵",
                                };
                                println!(
                                    "    {} [{}] {}: {}",
                                    severity_emoji, vuln.cve_id, vuln.severity.as_str(), vuln.description
                                );
                                println!("       Affected: {}", vuln.affected_versions);
                                println!("       Fix: {}", vuln.remediation);
                            }
                        }
                    }
                }
            }

            if !has_findings {
                println!("  ✓ No known vulnerabilities detected for open ports");
            }

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
