use clap::{Parser, Subcommand};
use netgap_assess::AssessmentRunner;
use netgap_core::{Device, Finding, FindingSummary, ScanConfig, ScanResult, Severity};
use netgap_fingerprint::{classify_device, BannerGrabResult, ClassifyContext, Fingerprinter};
use netgap_mdns::MdnsDiscovery;
use netgap_report::discovery::DiscoveryContext;
use netgap_report::{format_discovery, ReportFormatter};
use netgap_scan::{PortScanner, ScanConfig as PortScanConfig};
use netgap_services::{ServiceInfo, VulnerabilityCheck, VulnerabilityFinding};
use netgap_trends::{AlertRule, ChangeDetection, HealthScore, ScanHistory};
use chrono::Local;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

mod discovery;
mod interactive;
mod trust;

use discovery::DiscoveryPlan;

#[derive(Parser)]
#[command(name = "netgap")]
#[command(about = "Network security scanner for discovering and assessing vulnerabilities on your LAN", long_about = None)]
#[command(version = "0.1.0")]
#[command(author = "Pranil Shrestha")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Arguments shared by every command that performs discovery.
#[derive(clap::Args, Clone)]
struct DiscoveryArgs {
    /// Network interface to use (auto-detected if not specified)
    #[arg(short, long)]
    interface: Option<String>,

    /// Target network in CIDR notation (default: derived from the interface)
    #[arg(short, long)]
    target: Option<String>,

    /// Discovery method: auto, arp, or tcp
    #[arg(long, default_value = "auto")]
    discovery: String,

    /// Continue without prompting when root is unavailable (use the TCP fallback)
    #[arg(short = 'y', long)]
    yes: bool,

    /// Refuse to scan more hosts than this in one sweep
    #[arg(long, default_value_t = netgap_discover::DEFAULT_MAX_HOSTS)]
    max_hosts: usize,
}

impl DiscoveryArgs {
    /// Resolve the interface, target and discovery method for this run.
    ///
    /// `non_interactive` keeps machine-readable output clean by suppressing the
    /// privilege prompt.
    fn resolve(&self, non_interactive: bool) -> Result<DiscoveryPlan, Box<dyn std::error::Error>> {
        let requested = if self.discovery.eq_ignore_ascii_case("auto") {
            None
        } else {
            Some(discovery::parse_method(&self.discovery)?)
        };

        Ok(discovery::resolve_plan(
            self.interface.clone(),
            self.target.clone(),
            requested,
            self.yes,
            non_interactive,
            self.max_hosts,
        )?)
    }
}

#[derive(Subcommand)]
enum Commands {
    /// List available network interfaces
    Interfaces,

    /// Discover devices on the local network and report what they are
    Discover {
        #[command(flatten)]
        discovery: DiscoveryArgs,

        /// Output format: report, json
        #[arg(short, long, default_value = "report")]
        format: String,

        /// Mark every device found as trusted (useful for a first run)
        #[arg(long)]
        trust_all: bool,

        /// Probe common service ports to identify device types (extra traffic)
        #[arg(long)]
        identify: bool,
    },

    /// Add a device to the trusted list (by MAC, or by IP if it is known)
    Trust {
        /// MAC address (aa:bb:cc:dd:ee:ff) or an IP that is already known
        device: String,

        /// Optional human-readable label
        label: Option<String>,
    },

    /// Remove a device from the trusted list
    Untrust {
        /// MAC address or an IP that is already known
        device: String,
    },

    /// List trusted devices
    Trusted,

    /// Run a security scan on the selected network
    Scan {
        #[command(flatten)]
        discovery: DiscoveryArgs,

        /// Quick scan mode: discovery only, no port scanning (fastest)
        #[arg(long)]
        quick: bool,

        /// Deep scan mode: implies --fingerprint and --assess
        #[arg(long)]
        deep: bool,

        /// Include mDNS service discovery (not yet implemented)
        #[arg(long)]
        mdns: bool,

        /// Perform banner grabbing for service identification
        #[arg(long)]
        fingerprint: bool,

        /// Include vulnerability assessment
        #[arg(long)]
        assess: bool,

        /// Show an interactive dashboard with per-host scan progress
        #[arg(long)]
        interactive: bool,

        /// Do not write the result to the scan history database
        #[arg(long)]
        no_save: bool,

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
        #[command(flatten)]
        discovery: DiscoveryArgs,

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
        Commands::Discover {
            discovery,
            format,
            trust_all,
            identify,
        } => {
            cmd_discover(discovery, &format, trust_all, identify).await?;
        }
        Commands::Trust { device, label } => {
            cmd_trust(device, label)?;
        }
        Commands::Untrust { device } => {
            cmd_untrust(device)?;
        }
        Commands::Trusted => {
            cmd_trusted()?;
        }
        Commands::Scan {
            discovery,
            quick,
            deep,
            mdns,
            fingerprint,
            assess,
            interactive,
            no_save,
            format,
        } => {
            cmd_scan(
                discovery,
                quick,
                deep,
                mdns,
                fingerprint,
                assess,
                interactive,
                no_save,
                &format,
            )
            .await?;
        }
        Commands::Report {
            scan_id,
            compare,
            format,
            history,
        } => {
            cmd_report(scan_id, compare, &format, history)?;
        }
        Commands::Watch {
            discovery,
            interval,
        } => {
            cmd_watch(discovery, interval).await?;
        }
    }

    Ok(())
}

fn cmd_interfaces() -> Result<(), Box<dyn std::error::Error>> {
    println!("📡 Available Network Interfaces\n");
    let interfaces = netgap_interfaces::get_interfaces()?;

    for (idx, iface) in interfaces.iter().enumerate() {
        let mut notes = Vec::new();
        if iface.is_loopback {
            notes.push("loopback".to_string());
        } else if iface.is_virtual() {
            notes.push("virtual".to_string());
        }
        if iface.is_default_route {
            notes.push("default route".to_string());
        }
        if iface.is_scannable() && !iface.is_virtual() && !iface.is_loopback {
            notes.push("scannable".to_string());
        }

        println!(
            "  {}. {} {}",
            idx + 1,
            iface.name,
            if iface.is_up { "✓" } else { "✗" }
        );
        if let Some(ipv4) = &iface.ipv4 {
            println!("     IPv4: {}", ipv4);
        }
        if let Some(cidr) = &iface.cidr {
            println!("     CIDR: {}", cidr);
        }
        if let Some(mac) = &iface.mac {
            println!("     MAC:  {}", mac);
        }
        if !notes.is_empty() {
            println!("     Notes: {}", notes.join(", "));
        }
    }

    println!("\nInterfaces marked 'scannable' are candidates for auto-selection.\n");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_scan(
    discovery_args: DiscoveryArgs,
    quick: bool,
    deep: bool,
    mdns: bool,
    mut fingerprint: bool,
    mut assess: bool,
    interactive: bool,
    no_save: bool,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // --deep is a shorthand for turning on everything.
    if deep {
        fingerprint = true;
        assess = true;
    }

    let mode = if quick {
        "quick"
    } else if deep {
        "deep"
    } else if mdns || fingerprint || assess {
        "enhanced"
    } else {
        "standard"
    };

    eprintln!("🔍 Starting {} scan...", mode);
    if mdns {
        eprintln!("   📡 mDNS discovery requested");
    }
    if fingerprint {
        eprintln!("   🔎 Service fingerprinting enabled");
    }
    if assess {
        eprintln!("   ⚠️  Vulnerability assessment enabled");
    }
    eprintln!();

    let plan = discovery_args.resolve(format == "json")?;

    eprintln!("📍 Interface: {}", plan.interface.name);
    if let Some(cidr) = &plan.interface.cidr {
        eprintln!("   Network:   {}", cidr);
    }
    eprintln!("🎯 Target:  {}", plan.target);
    eprintln!("🛰️  Discovery: {}\n", plan.method.label());

    // Create scan result
    let mut result = ScanResult {
        started_at: Local::now().to_rfc3339(),
        config: ScanConfig {
            interface: plan.interface.name.clone(),
            target: plan.target.clone(),
            timeout_ms: if quick { 1000 } else { 2000 },
            concurrency: if quick { 16 } else { 32 },
            discovery_only: quick,
        },
        devices: Vec::new(),
        summary: FindingSummary::new(),
    };

    let mut devices = run_discovery_and_port_scan(&plan, quick, interactive).await?;

    // Name and classify the devices we found; port data is available by now,
    // which is what makes the type guess worthwhile.
    if !devices.is_empty() {
        enrich_devices(&plan, &mut devices, false).await;
    }

    if devices.is_empty() {
        eprintln!("\n✗ No devices discovered on target network");
    } else {
        if mdns {
            eprintln!("Phase 2b: mDNS Service Discovery");
            eprintln!("────────────────────────────────");

            if !MdnsDiscovery::IMPLEMENTED {
                // Saying "no services found" here would be a lie: the search
                // never happens.
                eprintln!("  ⚠️  mDNS discovery is not implemented in this build; skipping");
            } else {
                match MdnsDiscovery::discover_services(3).await {
                    Ok(services) if services.is_empty() => {
                        eprintln!("  No mDNS services discovered");
                    }
                    Ok(services) => {
                        eprintln!("  Discovered {} mDNS service(s):", services.len());
                        for service in &services {
                            println!(
                                "    • {} ({})",
                                service.name,
                                service.service_type.display_name()
                            );
                            if let Some(ip) = &service.ip {
                                eprintln!("      IP: {}", ip);
                            }
                            eprintln!("      Port: {}", service.port);
                        }
                    }
                    Err(e) => eprintln!("  ⚠️  mDNS discovery error: {}", e),
                }
            }

            println!();
        }

        // Banner grabbing phase (if fingerprint flag enabled)
        let banners = if fingerprint {
            eprintln!("Phase 3: Service Fingerprinting");
            eprintln!("──────────────────────────────");
            let banners = fingerprint_devices(&mut devices).await;
            println!();
            banners
        } else {
            Vec::new()
        };

        // Vulnerability assessment (if assess flag enabled)
        if assess {
            eprintln!("Phase 4: Vulnerability Assessment");
            eprintln!("─────────────────────────────────");

            let found = apply_assessment(&mut devices, &banners);

            if found == 0 {
                eprintln!("  ✓ No known vulnerabilities detected for open ports");
            }

            println!();
        }
    }

    // Update results and count every finding now attached to a device.
    result.devices = devices;
    for device in &result.devices {
        for finding in &device.findings {
            result.summary.add_finding(finding.severity);
        }
    }

    // Output results
    eprintln!("\n{}", "─".repeat(70));
    eprintln!("SCAN RESULTS");
    eprintln!("{}\n", "─".repeat(70));

    let output = match format {
        "json" => ReportFormatter::format_json(&result)?,
        "summary" => ReportFormatter::format_summary(&result)?,
        _ => ReportFormatter::format_terminal(&result)?,
    };

    println!("{}", output);

    if !no_save && !result.devices.is_empty() {
        match netgap_storage::ScanStore::open_default()
            .and_then(|mut store| store.save_scan(&result))
        {
            Ok(scan_id) => {
                eprintln!("💾 Saved as '{}' — view it with: netgap report", scan_id);
            }
            Err(error) => eprintln!("⚠️  Could not save scan to history: {}", error),
        }
    }

    Ok(())
}

async fn cmd_discover(
    discovery_args: DiscoveryArgs,
    format: &str,
    trust_all: bool,
    identify: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = discovery_args.resolve(format == "json")?;

    eprintln!(
        "🔍 Discovering devices on {} ({})\n",
        plan.interface.name, plan.target
    );

    let mut devices = discovery::run(&plan).await?;
    enrich_devices(&plan, &mut devices, identify).await;

    let mut trust_list = trust::TrustList::load()?;

    if trust_all && !devices.is_empty() {
        let mut added = 0;
        for device in &devices {
            if let Some(mac) = device.mac.as_deref() {
                if trust_list.trust(mac, None) {
                    added += 1;
                }
            }
        }
        trust_list.save()?;
        eprintln!(
            "✓ Trusted {} new device(s) ({} total)",
            added,
            trust_list.entries().len()
        );
    }

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&devices)?);
        }
        _ => {
            // The report is the result, so it goes to stdout.
            let context = DiscoveryContext {
                interface: &plan.interface.name,
                target: &plan.target,
                trusted: &trust_list.macs(),
                labels: &trust_list.labels(),
                gateway: netgap_interfaces::default_gateway_ipv4().map(std::net::IpAddr::V4),
                local: plan
                    .interface
                    .ipv4_network()
                    .map(|network| std::net::IpAddr::V4(network.ip())),
            };
            println!("{}", format_discovery(&devices, &context));
        }
    }

    Ok(())
}

/// Fill in the details that turn a bare IP and MAC into something a person can
/// recognise: a name, a vendor, and a device type.
async fn enrich_devices(plan: &DiscoveryPlan, devices: &mut [Device], identify: bool) {
    if devices.is_empty() {
        return;
    }

    // Names first: reverse DNS is unreliable on many networks, so it gets a
    // bounded budget and stays quiet when it finds nothing.
    let named = netgap_discover::resolve_hostnames(devices, Duration::from_secs(3)).await;
    if named > 0 {
        eprintln!("   Resolved {} hostname(s)", named);
    }

    // Optionally probe service ports, which is what makes type guesses useful.
    if identify {
        eprintln!(
            "   Identifying device types (probing {} port(s) on {} host(s))...",
            IDENTIFY_PORTS.len(),
            devices.len()
        );

        let ipv4_targets: Vec<std::net::Ipv4Addr> = devices
            .iter()
            .filter_map(|device| match device.ip {
                std::net::IpAddr::V4(ipv4) => Some(ipv4),
                std::net::IpAddr::V6(_) => None,
            })
            .collect();

        let sweep = netgap_discover::TcpSweeper::new(netgap_discover::TcpSweepConfig {
            targets: ipv4_targets,
            ports: IDENTIFY_PORTS.to_vec(),
            timeout_ms: 400,
            concurrency: 128,
            include_neighbors: false,
            interface_name: Some(plan.interface.name.clone()),
            quiet: true,
        });

        match sweep.scan().await {
            Ok(probed) => {
                for probe in &probed {
                    if let Some(device) = devices.iter_mut().find(|device| device.ip == probe.ip) {
                        for port in &probe.open_ports {
                            device.add_open_port(*port);
                        }
                    }
                }
            }
            Err(error) => eprintln!("   ⚠️  Identification probe failed: {}", error),
        }
    }

    // Vendor and type. `fingerprint_device` no longer clobbers a known OS, so
    // it is safe to call on already-enriched devices.
    let fingerprinter = Fingerprinter::new();
    let context = ClassifyContext {
        gateway: netgap_interfaces::default_gateway_ipv4().map(std::net::IpAddr::V4),
        local: plan
            .interface
            .ipv4_network()
            .map(|network| std::net::IpAddr::V4(network.ip())),
    };

    for device in devices.iter_mut() {
        fingerprinter.fingerprint_device(device);
        let classification = classify_device(device, &context);
        device.device_type = Some(classification.label);
    }
}

/// Ports probed by `--identify`, chosen to distinguish common device classes.
const IDENTIFY_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 139, 443, 445, 515, 554, 631, 1883, 2049, 3389, 5000, 8080, 9100,
];

fn cmd_trust(device: String, label: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mac = resolve_mac(&device)?;
    let mut list = trust::TrustList::load()?;

    let added = list.trust(&mac, label.clone());
    list.save()?;

    match (added, label) {
        (true, Some(label)) => println!("✓ Trusted {} ({})", mac, label),
        (true, None) => println!("✓ Trusted {}", mac),
        (false, Some(label)) => println!("✓ Updated {} label to '{}'", mac, label),
        (false, None) => println!("Already trusted: {}", mac),
    }

    Ok(())
}

fn cmd_untrust(device: String) -> Result<(), Box<dyn std::error::Error>> {
    let mac = resolve_mac(&device)?;
    let mut list = trust::TrustList::load()?;

    if list.untrust(&mac) {
        list.save()?;
        println!("✓ Removed {} from the trusted list", mac);
    } else {
        println!("{} was not in the trusted list", mac);
    }

    Ok(())
}

fn cmd_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let list = trust::TrustList::load()?;

    if list.is_empty() {
        println!("No trusted devices yet. Run 'netgap discover' and then:");
        println!("  netgap trust <mac> \"label\"");
        return Ok(());
    }

    println!("📋 Trusted devices ({})\n", list.entries().len());
    for entry in list.entries() {
        match entry.label {
            Some(label) => println!("  {}  {}", entry.mac, label),
            None => println!("  {}", entry.mac),
        }
    }
    println!(
        "\nStored in {}",
        trust::trust_file_path()?.display()
    );

    Ok(())
}

/// Accept either a MAC or an IP address, resolving the latter via the kernel
/// neighbour table so the user does not have to look it up manually.
fn resolve_mac(identifier: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = identifier.trim();
    if trimmed.contains(':') {
        Ok(trust::resolve_identifier(trimmed)?)
    } else {
        Ok(trust::mac_for_ip(trimmed)?)
    }
}

async fn run_discovery_and_port_scan(
    plan: &DiscoveryPlan,
    quick: bool,
    interactive: bool,
) -> Result<Vec<Device>, Box<dyn std::error::Error>> {
    eprintln!("Phase 1: Device Discovery");
    eprintln!("─────────────────────────");

    if interactive {
        return interactive::run(plan, quick).await.map_err(Into::into);
    }

    let mut devices = discovery::run(plan).await?;

    if devices.is_empty() {
        return Ok(devices);
    }

    eprintln!("✓ Discovered {} device(s)\n", devices.len());

    if !quick {
        eprintln!("Phase 2: Port Scanning");
        eprintln!("─────────────────────");

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

/// Grab service banners for the open ports of each device and fold the result
/// into the device (vendor/OUI and OS heuristics).
async fn fingerprint_devices(devices: &mut [Device]) -> Vec<(IpAddr, BannerGrabResult)> {
    let fingerprinter = Fingerprinter::new();
    let mut banners = Vec::new();

    for device in devices.iter_mut() {
        for port in device.open_ports.clone() {
            let banner = match port {
                80 | 8080 => {
                    Fingerprinter::grab_http_banner(&device.ip.to_string(), port).await
                }
                22 => Fingerprinter::grab_ssh_banner(&device.ip.to_string(), port).await,
                21 => Fingerprinter::grab_ftp_banner(&device.ip.to_string(), port).await,
                _ => None,
            };

            if let Some(banner) = banner {
                let service = banner
                    .service_name
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string());
                eprintln!("  {}:{} ({}) - {}", device.ip, banner.port, banner.protocol, service);
                if let Some(version) = &banner.version {
                    eprintln!("    Version: {}", version);
                }
                banners.push((device.ip, banner));
            }
        }

        let previous_vendor = device.vendor.clone();
        fingerprinter.fingerprint_device(device);
        if device.vendor != previous_vendor {
            if let Some(vendor) = &device.vendor {
                eprintln!("  {} - Vendor: {}", device.ip, vendor);
            }
        }
    }

    banners
}

/// Run vulnerability checks and attach every finding to its device.
///
/// Findings must live on `Device` to reach reports, the summary, trends and
/// the scan database — printing them alone loses them.
fn apply_assessment(devices: &mut [Device], banners: &[(IpAddr, BannerGrabResult)]) -> usize {
    let runner = AssessmentRunner::new();
    let mut total = 0;

    for device in devices.iter_mut() {
        let known: HashSet<String> = device.findings.iter().map(|finding| finding.id.clone()).collect();
        // The port scanner already reports exposure for the dangerous ports it
        // scans; repeating them here would double every SMB/Telnet finding.
        let already_reported: HashSet<u16> = device
            .findings
            .iter()
            .filter_map(|finding| finding.port)
            .collect();

        for finding in runner.assess(device) {
            if known.contains(&finding.id) {
                continue;
            }
            if finding.port.is_some_and(|port| already_reported.contains(&port)) {
                continue;
            }
            eprintln!(
                "  {}:{} [{}] {}",
                device.ip,
                finding.port.map(|port| port.to_string()).unwrap_or_else(|| "-".to_string()),
                finding.severity,
                finding.title
            );
            device.add_finding(finding);
            total += 1;
        }
    }

    // Version-specific CVEs, using versions recovered by banner grabbing.
    for device in devices.iter_mut() {
        let IpAddr::V4(ipv4) = device.ip else { continue };

        for port in device.open_ports.clone() {
            let Some(service_name) = service_name_for_port(port) else {
                continue;
            };

            let version = banners
                .iter()
                .find(|(ip, banner)| *ip == device.ip && banner.port == port)
                .and_then(|(_, banner)| banner.version.clone());

            let service_info = ServiceInfo {
                ip: ipv4,
                port,
                name: service_name.to_string(),
                version,
                service_type: service_type_for_port(port).to_string(),
                banner: None,
                confidence: 0.75,
                vulnerabilities: Vec::new(),
            };

            for vulnerability in VulnerabilityCheck::check_version(&service_info) {
                let finding = cve_finding(device.ip, port, service_name, &vulnerability);
                if device.findings.iter().any(|existing| existing.id == finding.id) {
                    continue;
                }

                eprintln!(
                    "  {}:{} {} [{}] {}",
                    device.ip, port, vulnerability.cve_id, finding.severity, finding.title
                );
                eprintln!("     Affected: {}", vulnerability.affected_versions);
                eprintln!("     Fix: {}", vulnerability.remediation);

                device.add_finding(finding);
                total += 1;
            }
        }
    }

    total
}

/// Convert a service-crate vulnerability into a core finding.
fn cve_finding(
    ip: IpAddr,
    port: u16,
    service: &str,
    vulnerability: &VulnerabilityFinding,
) -> Finding {
    Finding {
        id: format!("cve-{}", vulnerability.cve_id),
        title: format!("{} in {}", vulnerability.cve_id, service),
        description: format!(
            "{} Affected versions: {}.",
            vulnerability.description, vulnerability.affected_versions
        ),
        // The services crate has five levels; core has four.
        severity: match vulnerability.severity {
            netgap_services::Severity::Critical => Severity::Critical,
            netgap_services::Severity::High => Severity::High,
            netgap_services::Severity::Medium => Severity::Medium,
            netgap_services::Severity::Low | netgap_services::Severity::Info => Severity::Info,
        },
        ip,
        port: Some(port),
        service: Some(service.to_string()),
        remediation: vulnerability.remediation.clone(),
        confidence: vulnerability.confidence,
    }
}

/// Service name used for vulnerability lookups.
fn service_name_for_port(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("FTP"),
        22 => Some("OpenSSH"),
        23 => Some("Telnet"),
        80 | 8080 => Some("Apache"),
        443 | 8443 => Some("Apache"),
        3306 => Some("MySQL"),
        5432 => Some("PostgreSQL"),
        _ => None,
    }
}

/// Service type used for vulnerability lookups.
fn service_type_for_port(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        _ => "http",
    }
}

fn cmd_report(
    scan_id: Option<String>,
    compare: Option<String>,
    format: &str,
    history: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use netgap_storage::ScanStore;

    let store = ScanStore::open_default()?;

    if history {
        println!("📋 Scan History\n");
        let scans = store.list_scans()?;
        if scans.is_empty() {
            println!("  No scans found. Run 'netgap scan' to start scanning.");
        } else {
            for scan in scans {
                println!(
                    "  {} - {} ({} devices, {} findings)",
                    scan.id, scan.started_at, scan.device_count, scan.finding_count
                );
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
        "table" => println!("{}", ReportFormatter::format_terminal(&store.load_scan(&scan_to_report)?)?),
        "json" => println!("{}", ReportFormatter::format_json(&store.load_scan(&scan_to_report)?)?),
        "summary" => println!("{}", ReportFormatter::format_summary(&store.load_scan(&scan_to_report)?)?),
        "markdown" => println!("{}", store.export_markdown(&scan_to_report)?),
        "html" => println!("{}", store.export_html(&scan_to_report)?),
        "csv" => println!("{}", store.export_csv(&scan_to_report)?),
        other => {
            return Err(format!(
                "unknown report format '{}'; expected table, json, summary, markdown, html or csv",
                other
            )
            .into())
        }
    }

    Ok(())
}

async fn cmd_watch(
    discovery_args: DiscoveryArgs,
    interval_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Resolve once: re-detecting the interface every cycle would also make the
    // scan target wander between cycles.
    let plan = discovery_args.resolve(true)?;

    println!("👁️  Continuous Monitoring Mode");
    println!(
        "Interface: {} | Target: {} | Discovery: {}",
        plan.interface.name,
        plan.target,
        plan.method.label()
    );
    println!("Interval: {}s | Press Ctrl+C to stop\n", interval_secs);

    let mut last_history: Option<ScanHistory> = None;
    let mut scan_count = 0;

    loop {
        scan_count += 1;
        println!("📊 Scan #{} — {}", scan_count, Local::now().format("%H:%M:%S"));

        match discovery::run(&plan).await {
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
                let mut result = ScanResult {
                    started_at: Local::now().to_rfc3339(),
                    config: ScanConfig {
                        interface: plan.interface.name.clone(),
                        target: plan.target.clone(),
                        timeout_ms: 1500,
                        concurrency: 32,
                        discovery_only: false,
                    },
                    devices,
                    summary: FindingSummary::new(),
                };

                for device in &result.devices {
                    for finding in &device.findings {
                        result.summary.add_finding(finding.severity);
                    }
                }

                // Create history snapshot
                let current_history =
                    ScanHistory::from_scan_result(format!("scan-{}", scan_count), &result);

                // Detect changes if we have previous history
                if let Some(prev) = &last_history {
                    let changes = ChangeDetection::detect_changes(prev, &current_history);
                    let prev_health = HealthScore::calculate(prev);
                    let curr_health = HealthScore::calculate(&current_history);

                    let health_drop = if curr_health.score < prev_health.score {
                        Some(prev_health.score as i16 - curr_health.score as i16)
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

                    let trend = match curr_health.score.cmp(&prev_health.score) {
                        std::cmp::Ordering::Greater => "↑",
                        std::cmp::Ordering::Less => "↓",
                        std::cmp::Ordering::Equal => "→",
                    };

                    println!(
                        "\nHealth Score: {}/100 ({}) {} {}/100 ({})",
                        prev_health.score,
                        prev_health.risk_level(),
                        trend,
                        curr_health.score,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn device_with_ports(ports: &[u16]) -> Device {
        let mut device = Device::new("192.168.1.10".parse().expect("valid ip"));
        for port in ports {
            device.add_open_port(*port);
        }
        device
    }

    #[test]
    fn test_service_lookup_helpers() {
        assert_eq!(service_name_for_port(22), Some("OpenSSH"));
        assert_eq!(service_name_for_port(23), Some("Telnet"));
        assert_eq!(service_name_for_port(9999), None);
        assert_eq!(service_type_for_port(21), "ftp");
        assert_eq!(service_type_for_port(80), "http");
    }

    #[test]
    fn test_cve_finding_maps_severity_into_core_levels() {
        let ip: IpAddr = "192.168.1.10".parse().expect("valid ip");

        for (service_severity, expected) in [
            (netgap_services::Severity::Critical, Severity::Critical),
            (netgap_services::Severity::High, Severity::High),
            (netgap_services::Severity::Medium, Severity::Medium),
            // Core has no `Low`; it must not be dropped or upgraded.
            (netgap_services::Severity::Low, Severity::Info),
            (netgap_services::Severity::Info, Severity::Info),
        ] {
            let vulnerability = VulnerabilityFinding {
                cve_id: "CVE-2021-1234".to_string(),
                severity: service_severity,
                description: "A flaw.".to_string(),
                affected_versions: "< 1.2.3".to_string(),
                remediation: "Upgrade.".to_string(),
                confidence: 0.8,
            };

            let finding = cve_finding(ip, 80, "Apache", &vulnerability);

            assert_eq!(finding.severity, expected);
            assert_eq!(finding.id, "cve-CVE-2021-1234");
            assert_eq!(finding.port, Some(80));
            assert_eq!(finding.service.as_deref(), Some("Apache"));
            assert_eq!(finding.ip, ip);
            assert!(finding.description.contains("< 1.2.3"));
        }
    }

    /// Assessment findings must land on the device: anything kept only in a
    /// `println!` never reaches the report, summary, trends or database.
    #[test]
    fn test_apply_assessment_attaches_findings_to_devices() {
        let mut devices = vec![device_with_ports(&[23])];
        let attached = apply_assessment(&mut devices, &[]);

        assert!(attached > 0, "telnet exposure should be reported");
        assert_eq!(devices[0].findings.len(), attached);
        assert!(devices[0]
            .findings
            .iter()
            .any(|finding| finding.severity == Severity::Critical));
    }

    #[test]
    fn test_apply_assessment_does_not_duplicate_ports_already_reported() {
        let mut devices = vec![device_with_ports(&[445])];

        // Simulate the port scanner having already reported SMB exposure.
        let ip = devices[0].ip;
        devices[0].add_finding(Finding {
            id: "open_port_445".to_string(),
            title: "SMB exposed on port 445".to_string(),
            description: "SMB is accessible.".to_string(),
            severity: Severity::High,
            ip,
            port: Some(445),
            service: Some("SMB".to_string()),
            remediation: "Block SMB.".to_string(),
            confidence: 1.0,
        });

        apply_assessment(&mut devices, &[]);

        let smb_findings = devices[0]
            .findings
            .iter()
            .filter(|finding| finding.port == Some(445))
            .count();
        assert_eq!(smb_findings, 1, "port 445 should be reported once");
    }

    #[test]
    fn test_apply_assessment_adds_version_specific_cves() {
        // An old Apache version with a banner-supplied version string.
        let mut devices = vec![device_with_ports(&[80])];
        let banners = vec![(
            devices[0].ip,
            BannerGrabResult {
                ip: devices[0].ip.to_string(),
                port: 80,
                protocol: "HTTP".to_string(),
                banner: "Apache/2.4.49".to_string(),
                service_name: Some("Apache".to_string()),
                version: Some("2.4.49".to_string()),
                confidence: 0.9,
            },
        )];

        apply_assessment(&mut devices, &banners);

        let cve_ids: Vec<&str> = devices[0]
            .findings
            .iter()
            .map(|finding| finding.id.as_str())
            .filter(|id| id.starts_with("cve-"))
            .collect();
        assert!(
            !cve_ids.is_empty(),
            "a vulnerable Apache version should produce CVE findings"
        );
    }
}
