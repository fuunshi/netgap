use clap::{Parser, Subcommand};
use netgap_core::{ScanConfig, ScanResult, FindingSummary};
use netgap_discover::DiscoveryConfig;
use netgap_scan::{PortScanner, ScanConfig as PortScanConfig};
use netgap_fingerprint::Fingerprinter;
use netgap_mdns::MdnsDiscovery;
use netgap_services::{VulnerabilityCheck, ServiceInfo};
use netgap_trends::{ChangeDetection, HealthScore, ScanHistory, AlertRule};
use netgap_report::ReportFormatter;
use chrono::Local;
use std::net::Ipv4Addr;
use std::time::Duration;
use netgap_interfaces::{get_interface_auto, get_interface_cidr};

mod interactive;

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

    /// Discover devices on the selected network without scanning ports
    Discover {
        /// Network interface to use (auto-detected if not specified)
        #[arg(short, long)]
        interface: Option<String>,

        /// Target network in CIDR notation (default: derived from interface)
        #[arg(short, long)]
        target: Option<String>,

        /// Output format: table, json
        #[arg(short, long, default_value = "table")]
        format: String,
    },

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

        /// Show an interactive dashboard with per-host scan progress
        #[arg(long)]
        interactive: bool,

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

    /// Continuous monitoring mode (watch for network changes)
    Watch {
        /// Network interface to scan (e.g., eth0)
        #[arg(short, long)]
        interface: Option<String>,

        /// Target network in CIDR notation (default: auto-detect)
        #[arg(short, long)]
        target: Option<String>,

        /// Interval in seconds between scans (default: 60)
        #[arg(long, default_value = "60")]
        interval: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Interfaces => {
            cmd_interfaces()?;
        }
        Commands::Discover { interface, target, format } => {
            cmd_discover(interface, target, &format).await?;
        }
        Commands::Scan {
            interface,
            target,
            quick,
            deep,
            mdns,
            fingerprint,
            assess,
            interactive,
            format,
        } => {
            cmd_scan(interface, target, quick, deep, mdns, fingerprint, assess, interactive, &format).await?;
        }
        Commands::Report { scan_id, compare, format, history } => {
            cmd_report(scan_id, compare, &format, history)?;
        }
        Commands::Watch { interface, target, interval } => {
            cmd_watch(interface, target, interval).await?;
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
    interactive: bool,
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

    let iface_name = resolve_interface(interface)?;

    println!("📍 Interface: {}", iface_name);

    let target_cidr = resolve_target(target, &iface_name)?;

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

    let mut devices = run_discovery_and_port_scan(&iface_name, &target_cidr, quick, interactive).await?;

    if devices.is_empty() {
        println!("\n✗ No devices discovered on target network");
    } else {
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

async fn cmd_discover(
    interface: Option<String>,
    target: Option<String>,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let iface_name = resolve_interface(interface)?;
    let target_cidr = resolve_target(target, &iface_name)?;

    println!("🔍 Discovering devices on {} ({})\n", iface_name, target_cidr);

    let discovery_config = DiscoveryConfig {
        interface_name: iface_name,
        target_cidr,
        timeout_ms: 1000,
    };

    let discovery = netgap_discover::ArpDiscovery::new(discovery_config);
    let devices = discovery.scan().await?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&devices)?);
        }
        _ => {
            if devices.is_empty() {
                println!("No devices discovered");
            } else {
                println!("Discovered {} device(s):", devices.len());
                for device in &devices {
                    println!("  {}{}", device.ip, device.mac.as_ref().map(|mac| format!("  [{}]", mac)).unwrap_or_default());
                }
            }
        }
    }

    Ok(())
}

async fn run_discovery_and_port_scan(
    iface_name: &str,
    target_cidr: &str,
    quick: bool,
    interactive: bool,
) -> Result<Vec<netgap_core::Device>, Box<dyn std::error::Error>> {
    println!("Phase 1: Device Discovery");
    println!("─────────────────────────");

    if interactive {
        return interactive::run(Some(iface_name.to_string()), Some(target_cidr.to_string()), quick).await.map_err(Into::into);
    }

    let discovery_config = DiscoveryConfig {
        interface_name: iface_name.to_string(),
        target_cidr: target_cidr.to_string(),
        timeout_ms: 1000,
    };

    let discovery = netgap_discover::ArpDiscovery::new(discovery_config);
    let mut devices = discovery.scan().await?;

    if devices.is_empty() {
        return Ok(devices);
    }

    println!("✓ Discovered {} device(s)\n", devices.len());

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

    Ok(devices)
}

fn resolve_interface(interface: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match interface {
        Some(iface) => iface,
        None => get_interface_auto()?,
    })
}

fn resolve_target(target: Option<String>, iface_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match target {
        Some(target) => target,
        None => get_interface_cidr(iface_name)?,
    })
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

async fn cmd_watch(
    interface: Option<String>,
    target: Option<String>,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("👁️  Continuous Monitoring Mode");
    println!("Interval: {}s | Press Ctrl+C to stop\n", interval_secs);

    let mut last_history: Option<ScanHistory> = None;
    let mut scan_count = 0;

    loop {
        scan_count += 1;
        println!("📊 Scan #{} — {}", scan_count, Local::now().format("%H:%M:%S"));

        // Run a standard scan without extra features for speed
        let iface_name = interface.clone().unwrap_or_else(|| "eth0".to_string());
        let target_cidr = target.clone().unwrap_or_else(|| "192.168.1.0/24".to_string());

        let discovery_config = DiscoveryConfig {
            interface_name: iface_name,
            target_cidr,
            timeout_ms: 1000,
        };

        match netgap_discover::ArpDiscovery::new(discovery_config).scan().await {
            Ok(mut devices) => {
                // Port scanning
                let port_config = PortScanConfig {
                    ports: netgap_scan::TOP_DANGEROUS_PORTS.to_vec(),
                    timeout_ms: 1500,
                    concurrency: 32,
                };
                let scanner = PortScanner::new(port_config);
                if let Err(e) = scanner.scan_devices(&mut devices).await {
                    println!("⚠️  Port scanning error: {}", e);
                }

                // Create scan result
                let result = ScanResult {
                    started_at: Local::now().to_rfc3339(),
                    config: ScanConfig {
                        interface: interface.clone().unwrap_or_default(),
                        target: target.clone().unwrap_or_default(),
                        timeout_ms: 1500,
                        concurrency: 32,
                        discovery_only: false,
                    },
                    devices,
                    summary: FindingSummary::new(),
                };

                // Create history snapshot
                let current_history = ScanHistory::from_scan_result(
                    format!("scan-{}", scan_count),
                    &result,
                );

                // Detect changes if we have previous history
                if let Some(prev) = &last_history {
                    let changes = ChangeDetection::detect_changes(&prev, &current_history);
                    let prev_health = HealthScore::calculate(&prev);
                    let curr_health = HealthScore::calculate(&current_history);

                    let health_drop = if curr_health.score < prev_health.score {
                        Some((prev_health.score as i16 - curr_health.score as i16) as i16)
                    } else {
                        None
                    };

                    if !changes.is_empty() {
                        println!("\n⚠️  Changes Detected:\n");
                        for change in &changes {
                            println!("  • {}", change);
                        }

                        // Check alert rules
                        let critical_rule = AlertRule::critical_vulnerability();
                        let health_drop_rule = AlertRule::health_drop(5);

                        if critical_rule.should_trigger(&changes, None) {
                            println!("\n🔴 ALERT: Critical vulnerability detected!");
                        }
                        if let Some(drop) = health_drop {
                            if health_drop_rule.should_trigger(&changes, Some(drop)) {
                                println!("\n🟠 ALERT: Network health score dropped {} points", drop);
                            }
                        }
                    } else {
                        println!("  ✓ No changes detected");
                    }

                    println!(
                        "\nHealth Score: {}/100 {} ({}) → {}/100 {} ({})",
                        prev_health.score,
                        if curr_health.score >= prev_health.score { "↑" } else { "↓" },
                        prev_health.risk_level(),
                        curr_health.score,
                        if curr_health.score >= prev_health.score { "↑" } else { "↓" },
                        curr_health.risk_level(),
                    );
                } else {
                    println!("✓ Discovered {} device(s)", current_history.device_count);
                    let health = HealthScore::calculate(&current_history);
                    println!("  Health Score: {}/100 ({})", health.score, health.risk_level());
                }

                last_history = Some(current_history);
            }
            Err(e) => {
                println!("❌ Scan failed: {}", e);
            }
        }

        println!("\n---");
        println!("Next scan in {}s (Ctrl+C to stop)", interval_secs);
        println!("---\n");

        // Sleep before next iteration
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}
