use chrono::Local;
use clap::{Parser, Subcommand};
use netgap_assess::AssessmentRunner;
use netgap_core::{Device, Finding, FindingSummary, ScanConfig, ScanResult, Severity};
use netgap_engine::enrich::{enrich_devices, run_ipv6};
use netgap_fingerprint::Fingerprinter;
use netgap_mdns::MdnsDiscovery;
use netgap_probes::{probe_ports, ProbeResult};
use netgap_report::discovery::DiscoveryContext;
use netgap_report::{format_discovery, ReportFormatter};
use netgap_scan::{PortScanner, ScanConfig as PortScanConfig};
use netgap_services::{ServiceInfo, VulnerabilityCheck, VulnerabilityFinding};
use netgap_threat_intel::{CvssSeverity, LocalCacheManager, NvdClient, NvdDatabase};
use netgap_trends::{AlertRule, ChangeDetection, HealthScore, ScanHistory};
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

mod alerts;
mod discovery;
mod doctor;
mod interactive;
mod trust;
mod ui;

use discovery::DiscoveryPlan;

#[derive(Parser)]
#[command(name = "netgap")]
#[command(about = "Network security scanner for discovering and assessing vulnerabilities on your LAN", long_about = None)]
#[command(version)]
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

    /// Also ask devices to name themselves over mDNS (printers, TVs, speakers)
    #[arg(long)]
    mdns: bool,
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
            self.mdns,
        )?)
    }
}

#[derive(Subcommand)]
enum Commands {
    /// List available network interfaces
    Interfaces,

    /// Check that a scan will work here, and say what to fix if it will not
    Doctor {
        /// Network interface to check (auto-detected if not specified)
        #[arg(short, long)]
        interface: Option<String>,

        /// Target network in CIDR notation to check (default: the interface's)
        #[arg(short, long)]
        target: Option<String>,

        /// Only inspect the settings: send no packets, and skip the live probe
        #[arg(long)]
        no_probe: bool,
    },

    /// Open the full-screen interactive view (interfaces, scans and findings)
    Ui,

    /// Discover devices on the local network and report what they are
    Discover {
        #[command(flatten)]
        discovery: DiscoveryArgs,

        /// Output format: report, json
        #[arg(short, long, default_value = "report")]
        format: String,

        /// Write the report to a file instead of stdout (useful with --format html)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,

        /// Mark every device found as trusted (useful for a first run)
        #[arg(long)]
        trust_all: bool,

        /// Probe common service ports to identify device types (extra traffic)
        #[arg(long)]
        identify: bool,

        /// Do not record this discovery in the scan history
        #[arg(long)]
        no_save: bool,
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

    /// Manage the local NVD vulnerability database
    ThreatIntel {
        #[command(subcommand)]
        action: ThreatIntelAction,
    },

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

        /// Perform banner grabbing for service identification
        #[arg(long)]
        fingerprint: bool,

        /// Include vulnerability assessment
        #[arg(long)]
        assess: bool,

        /// Show an interactive dashboard with per-host scan progress
        #[arg(long)]
        interactive: bool,

        /// Match findings against the local NVD database (see 'netgap threat-intel update')
        #[arg(long)]
        threat_intel: bool,

        /// With --threat-intel: fetch data for the services found, then cache it
        #[arg(long)]
        threat_intel_update: bool,

        /// Do not write the result to the scan history database
        #[arg(long)]
        no_save: bool,

        /// Output format: table, json, summary
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Do not send alerts, even if a webhook is configured
        #[arg(long)]
        no_alert: bool,
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

        /// Ask the network who provides DHCP, and report servers other than the gateway
        #[arg(long)]
        check_dhcp: bool,

        /// Do not send alerts, even if a webhook is configured
        #[arg(long)]
        no_alert: bool,
    },

    /// Send alerts to a webhook when something changes
    Alert {
        /// Set the webhook URL to send to
        #[arg(long)]
        url: Option<String>,

        /// Message format for the endpoint: generic, slack, discord, mattermost
        #[arg(long)]
        provider: Option<String>,

        /// Allow a plain http:// endpoint (the alert describes your network)
        #[arg(long)]
        allow_http: bool,

        /// Alert when a serious finding appears that was not there last time
        #[arg(long, conflicts_with = "no_critical")]
        critical: bool,

        /// Stop alerting about new findings
        #[arg(long)]
        no_critical: bool,

        /// Alert when a device that has not been seen before joins
        #[arg(long, conflicts_with = "no_new_device")]
        new_device: bool,

        /// Stop alerting about new devices
        #[arg(long)]
        no_new_device: bool,

        /// Alert when a device that was there stops answering
        #[arg(long, conflicts_with = "no_device_offline")]
        device_offline: bool,

        /// Stop alerting when a device stops answering
        #[arg(long)]
        no_device_offline: bool,

        /// Alert when a known device opens or closes a port (on by default)
        #[arg(long, conflicts_with = "no_port_change")]
        port_change: bool,

        /// Stop alerting when a device's open ports change
        #[arg(long, conflicts_with = "port_change")]
        no_port_change: bool,

        /// Alert when the health score falls by this much in one scan
        #[arg(long)]
        health_drop: Option<u8>,

        /// Send a test alert to the configured webhook and report what happened
        #[arg(long)]
        test: bool,

        /// Stop sending alerts (keeps the URL, turns it off)
        #[arg(long)]
        off: bool,
    },
}

/// What to do with the local NVD database.
#[derive(Subcommand)]
enum ThreatIntelAction {
    /// Download CVE data from NVD into the local cache
    Update {
        /// Maximum CVEs to keep per product
        #[arg(long, default_value_t = 500)]
        per_product: usize,
    },

    /// Show what the local cache holds
    Status,

    /// Delete the local cache
    Clear,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Interfaces => {
            cmd_interfaces()?;
        }
        Commands::Doctor {
            interface,
            target,
            no_probe,
        } => {
            doctor::run(interface, target, no_probe).await?;
        }
        Commands::Ui => {
            ui::run().await?;
        }
        Commands::Discover {
            discovery,
            format,
            trust_all,
            identify,
            no_save,
            output,
        } => {
            cmd_discover(
                discovery,
                &format,
                trust_all,
                identify,
                no_save,
                output.as_deref(),
            )
            .await?;
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
        Commands::ThreatIntel { action } => {
            cmd_threat_intel(action).await?;
        }
        Commands::Scan {
            discovery,
            quick,
            deep,
            fingerprint,
            assess,
            interactive,
            threat_intel,
            threat_intel_update,
            no_save,
            format,
            no_alert,
        } => {
            cmd_scan(
                discovery,
                quick,
                deep,
                fingerprint,
                assess,
                interactive,
                threat_intel,
                threat_intel_update,
                no_save,
                &format,
                no_alert,
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
            check_dhcp,
            no_alert,
        } => {
            cmd_watch(discovery, interval, check_dhcp, no_alert).await?;
        }
        Commands::Alert {
            url,
            provider,
            allow_http,
            critical,
            no_critical,
            new_device,
            no_new_device,
            device_offline,
            no_device_offline,
            port_change,
            no_port_change,
            health_drop,
            test,
            off,
        } => {
            let changes = alerts::AlertChanges {
                url,
                provider,
                allow_http,
                critical: if critical {
                    Some(true)
                } else if no_critical {
                    Some(false)
                } else {
                    None
                },
                new_device: if new_device {
                    Some(true)
                } else if no_new_device {
                    Some(false)
                } else {
                    None
                },
                device_offline: if device_offline {
                    Some(true)
                } else if no_device_offline {
                    Some(false)
                } else {
                    None
                },
                port_change: if port_change {
                    Some(true)
                } else if no_port_change {
                    Some(false)
                } else {
                    None
                },
                health_drop,
                off,
            };

            cmd_alert(changes, test).await?;
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
    mut fingerprint: bool,
    mut assess: bool,
    interactive: bool,
    threat_intel: bool,
    threat_intel_update: bool,
    no_save: bool,
    format: &str,
    no_alert: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mdns = discovery_args.mdns;

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
            run_mdns(&mut devices).await;
            eprintln!();
        }

        // Service identification (if fingerprint flag enabled)
        let mut probes = if fingerprint {
            eprintln!("Phase 3: Service Fingerprinting");
            eprintln!("──────────────────────────────");
            let probes = fingerprint_devices(&mut devices).await;
            eprintln!();
            probes
        } else {
            Vec::new()
        };

        // The gateway routes everything else, so it gets the checks that only
        // make sense for the device holding the network together.
        if assess {
            check_gateway_exposure(&mut devices, &mut probes).await;
        }

        // Vulnerability assessment (if assess flag enabled)
        if assess {
            eprintln!("Phase 4: Vulnerability Assessment");
            eprintln!("─────────────────────────────────");

            // Fetching for the services actually found keeps this to one
            // request per identified product, instead of mirroring NVD.
            if threat_intel && threat_intel_update && !probes.is_empty() {
                if let Err(error) = update_cache_for_probes(&probes).await {
                    eprintln!("  ⚠️  NVD update failed: {error}");
                }
            }

            // Loading the cache is offline; fetching is a separate command.
            let nvd = if threat_intel {
                match LocalCacheManager::default_location().and_then(|cache| cache.load()) {
                    Ok(database) if database.is_empty() => {
                        eprintln!(
                            "  ⚠️  NVD cache is empty — run 'netgap threat-intel update' for live CVE data"
                        );
                        None
                    }
                    Ok(database) => {
                        eprintln!(
                            "  NVD: {} entries (updated {})",
                            database.entry_count,
                            database.last_updated.as_deref().unwrap_or("unknown")
                        );
                        Some(database)
                    }
                    Err(error) => {
                        eprintln!("  ⚠️  Could not read the NVD cache: {error}");
                        None
                    }
                }
            } else {
                None
            };

            let found = apply_assessment(&mut devices, &probes, nvd.as_ref());

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
        // The scan before this one is what an alert compares against, so it
        // has to be read before this one is written.
        let previous = previous_scan(&plan.target);

        match netgap_storage::ScanStore::open_default()
            .and_then(|mut store| store.save_scan(&result))
        {
            Ok(scan_id) => {
                eprintln!("💾 Saved as '{}' — view it with: netgap report", scan_id);
            }
            Err(error) => eprintln!("⚠️  Could not save scan to history: {}", error),
        }

        if !no_alert {
            send_alerts(previous.as_ref(), &result).await;
        }
    } else if !no_alert && no_save {
        eprintln!("   (--no-save: no history to compare against, so no alerts were considered)");
    }

    Ok(())
}

/// The last recorded result for a target, if there is one.
///
/// Matched on the network rather than on recency alone: a scan of one subnet
/// must not be compared against a scan of a different one, or every device
/// would look new and every finding would look like a regression.
fn previous_scan(target: &str) -> Option<ScanResult> {
    let store = netgap_storage::ScanStore::open_default().ok()?;
    let scans = store.list_scans().ok()?;

    let previous = scans
        .into_iter()
        .filter(|scan| scan.target == target)
        .max_by_key(|scan| scan.created_at.clone())?;

    store.load_scan(&previous.id).ok()
}

/// Send an alert if a webhook is configured and something changed.
async fn send_alerts(previous: Option<&ScanResult>, current: &ScanResult) {
    let settings = match alerts::AlertSettings::load() {
        Ok(Some(settings)) => settings,
        // Not configured is the normal case, and not worth a message.
        Ok(None) => return,
        Err(error) => {
            eprintln!("   ⚠️  Alerts are configured but could not be read: {error}");
            return;
        }
    };

    if !settings.enabled {
        return;
    }

    if previous.is_none() {
        eprintln!("   (first scan of this network: nothing to compare against, so no alert)");
        return;
    }

    let outcome = alerts::alert_on_changes(&settings, previous, current).await;

    match (outcome.sent, &outcome.error) {
        (true, _) => eprintln!(
            "🔔 Alert sent for {} change(s) to {}",
            outcome.changes.len(),
            alerts::mask_url(&settings.url)
        ),
        (false, Some(error)) => eprintln!("   ⚠️  Alert could not be sent: {error}"),
        (false, None) => {}
    }
}

async fn cmd_discover(
    discovery_args: DiscoveryArgs,
    format: &str,
    trust_all: bool,
    identify: bool,
    no_save: bool,
    output: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Anything machine-readable or written to a file runs without the
    // privilege prompt, which would otherwise land in the middle of a
    // document.
    let plan = discovery_args.resolve(format != "report" || output.is_some())?;

    eprintln!(
        "🔍 Discovering devices on {} ({})\n",
        plan.interface.name, plan.target
    );

    let mut devices = discovery::run(&plan).await?;

    // Before enrichment, so a device only IPv6 could see gets named and
    // classified like any other.
    run_ipv6(&mut devices, &plan);

    enrich_devices(&plan, &mut devices, identify).await;

    if discovery_args.mdns {
        eprintln!("   Asking devices to identify themselves over mDNS...");
        run_mdns(&mut devices).await;
    }

    let mut trust_list = trust::TrustList::load()?;

    // When each device was first seen, from previous scans. Devices absent
    // from this map are the ones this scan is seeing for the first time.
    let store = netgap_storage::ScanStore::open_default().ok();
    if let Some(store) = &store {
        match store.device_history() {
            Ok(history) => {
                for device in devices.iter_mut() {
                    device.first_seen = history
                        .get(&device.identity())
                        .map(|record| record.first_seen.clone());
                }
            }
            Err(error) => eprintln!("   ⚠️  Could not read device history: {error}"),
        }
    }

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

    let new_devices = devices
        .iter()
        .filter(|device| device.first_seen.is_none())
        .count();

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

    // A report written to a file is read later, on paper or in an editor;
    // colour codes that were meant for a terminal would land in it as
    // escape sequences. `colored` decides by looking at stdout, which is
    // still a terminal when the destination is a file.
    if output.is_some() {
        colored::control::set_override(false);
    }

    let rendered = match format {
        "json" => serde_json::to_string_pretty(&devices)?,
        "html" => netgap_report::format_discovery_html(&devices, &context),
        _ => format_discovery(&devices, &context),
    };

    match output {
        Some(path) => {
            std::fs::write(path, &rendered)
                .map_err(|error| format!("could not write {}: {error}", path.display()))?;
            eprintln!(
                "✓ Report written to {} {}",
                path.display(),
                how_to_open(format)
            );
        }
        None => println!("{rendered}"),
    }

    if new_devices > 0 {
        eprintln!(
            "   Recorded {} device(s) for the first time; the next scan will report what changed.",
            new_devices
        );
    }

    if !no_save && !devices.is_empty() {
        if let Some(store) = store {
            record_discovery(store, &plan, &devices)?;
        }
    }

    Ok(())
}

/// Store a discovery run so later scans have something to compare against.
///
/// A discovery has no findings and no port data, which is exactly what the
/// history needs: the question it answers is who was on the network, not what
/// was wrong with them.
fn record_discovery(
    mut store: netgap_storage::ScanStore,
    plan: &DiscoveryPlan,
    devices: &[Device],
) -> Result<(), Box<dyn std::error::Error>> {
    let result = ScanResult {
        started_at: Local::now().to_rfc3339(),
        config: ScanConfig {
            interface: plan.interface.name.clone(),
            target: plan.target.clone(),
            timeout_ms: 0,
            concurrency: 0,
            discovery_only: true,
        },
        devices: devices.to_vec(),
        summary: FindingSummary::new(),
    };

    match store.save_scan(&result) {
        Ok(_) => Ok(()),
        Err(error) => {
            eprintln!("   ⚠️  Could not record this discovery: {error}");
            Ok(())
        }
    }
}

/// Configure, inspect, and test where alerts go.
async fn cmd_alert(
    changes: alerts::AlertChanges,
    test: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if test {
        // Test against what is configured, not against what this run changed.
        let Some(settings) = alerts::AlertSettings::load()? else {
            eprintln!("No webhook is configured. Set one first:");
            eprintln!("  netgap alert --url https://hooks.example.com/... --provider slack");
            return Ok(());
        };

        println!(
            "Sending a test alert to {}\n",
            alerts::mask_url(&settings.url)
        );
        let alert = netgap_webhooks::WebhookAlert::new(
            "Info",
            "Test alert from netgap",
            "If you can read this, alerts are wired up. This one is not about \
             anything that happened on your network.",
        )
        .affecting(&["—".to_string()]);

        match settings.manager().send(&alert).await {
            Ok(()) => {
                println!("✓ Delivered. Nothing further to check.");
                return Ok(());
            }
            Err(error) => {
                // Not an Err return: the command did its job, and the answer
                // is that the endpoint refused it.
                eprintln!("✗ Delivery failed: {error}");
                eprintln!("  The endpoint, the URL, and the network path are the things to check.");
                std::process::exit(1);
            }
        }
    }

    let display_only = changes.is_display_only();
    let notes = changes.describe();
    let settings = changes.apply()?;

    for note in notes {
        println!("✓ {note}");
    }

    let Some(settings) = settings else {
        if display_only {
            println!("No alerts are configured. To set them up:");
            println!("  netgap alert --url <webhook-url> [--provider slack|discord|mattermost]");
            println!("\nThen check it works:");
            println!("  netgap alert --test");
        } else {
            println!("Alerts are off and no webhook is configured.");
        }
        return Ok(());
    };

    if let Some(path) = alerts::AlertSettings::path() {
        if let Some(parent) = path.parent() {
            println!("\nSettings: {}", path.display());
            let _ = parent;
        }
    }

    println!(
        "\nWebhook:  {} ({})",
        alerts::mask_url(&settings.url),
        settings.provider.as_str()
    );
    println!("Alerts:   {}", if settings.enabled { "on" } else { "off" });
    let yes_no = |enabled: bool| if enabled { "yes" } else { "no" };
    println!("Sending:");
    for (what, value) in [
        ("new findings", yes_no(settings.rules.critical).to_string()),
        ("new devices", yes_no(settings.rules.new_device).to_string()),
        (
            "devices going offline",
            yes_no(settings.rules.device_offline).to_string(),
        ),
        (
            "port changes",
            yes_no(settings.rules.port_change).to_string(),
        ),
        (
            "health score drops",
            match settings.rules.health_drop {
                Some(drop) => format!("{drop}+ points"),
                None => "no".to_string(),
            },
        ),
    ] {
        println!("  {what:<22} {value}");
    }

    if settings.enabled {
        println!("\nCheck it works with: netgap alert --test");
        println!("On a schedule, alerts fire from 'netgap scan' — see the README section on");
        println!("running it from cron or a systemd timer.");
    }

    Ok(())
}

/// How to read the file that was just written, which depends on what is in it.
fn how_to_open(format: &str) -> &'static str {
    match format {
        "html" => "— open it in a browser to read or share",
        "json" => "— machine-readable, for scripts and other tools",
        _ => "— plain text",
    }
}

/// Ask the network to name itself over mDNS, and fold the answers into the
/// device list.
///
/// This is where "Unknown device" becomes "HP LaserJet MFP". It runs after the
/// other enrichment so it fills gaps rather than overwriting observed facts.
async fn run_mdns(devices: &mut Vec<Device>) {
    // Long enough for devices to answer, short enough not to feel stuck.
    const MDNS_TIMEOUT_SECS: u64 = 3;

    match MdnsDiscovery::discover_services(MDNS_TIMEOUT_SECS).await {
        Ok(services) if services.is_empty() => {
            eprintln!(
                "  No mDNS services answered (normal on networks that block multicast, \
                 or when nothing advertises)"
            );
        }
        Ok(services) => {
            eprintln!("  Discovered {} mDNS service(s):", services.len());
            for service in &services {
                eprintln!(
                    "    • {} ({}){}{}",
                    service.name,
                    service.service_type.display_name(),
                    service
                        .ip
                        .map(|ip| format!(" @ {}", ip))
                        .unwrap_or_default(),
                    if service.port > 0 {
                        format!(" :{}", service.port)
                    } else {
                        String::new()
                    }
                );
            }

            let outcome = netgap_mdns::merge_into_devices(devices, &services);
            if outcome.named > 0 {
                eprintln!("  Named {} device(s) from mDNS", outcome.named);
            }
            if outcome.classified > 0 {
                eprintln!(
                    "  Identified {} device type(s) from mDNS",
                    outcome.classified
                );
            }
            if outcome.added > 0 {
                eprintln!("  Added {} device(s) only mDNS knew about", outcome.added);
            }
        }
        Err(error) => eprintln!("  ⚠️  mDNS discovery failed: {}", error),
    }
}

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
    println!("\nStored in {}", trust::trust_file_path()?.display());

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

    // A device that answers only on IPv6 is a device on the network, and a
    // count that omits it is quietly wrong.
    run_ipv6(&mut devices, plan);

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

/// A probe result tied to the device and port it came from.
struct ServiceProbe {
    ip: IpAddr,
    port: u16,
    result: ProbeResult,
}

/// Identify the service behind each open port, and fold vendor data into the
/// device.
///
/// This is what turns a port number into a product and version, which is what
/// vulnerability matching needs to be anything more than a guess.
async fn fingerprint_devices(devices: &mut [Device]) -> Vec<ServiceProbe> {
    let fingerprinter = Fingerprinter::new();
    let mut probes = Vec::new();

    for device in devices.iter_mut() {
        if !device.open_ports.is_empty() {
            let results = probe_ports(device.ip, &device.open_ports, 16).await;

            for (port, result) in results {
                match result.product_version() {
                    Some(identity) => {
                        eprintln!("  {}:{} {} — {}", device.ip, port, result.service, identity)
                    }
                    None => eprintln!("  {}:{} {}", device.ip, port, result.service),
                }
                if let Some(details) = &result.details {
                    eprintln!("    {}", details);
                }

                probes.push(ServiceProbe {
                    ip: device.ip,
                    port,
                    result,
                });
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

    probes
}

/// Run vulnerability checks and attach every finding to its device.
///
/// Findings must live on `Device` to reach reports, the summary, trends and
/// the scan database — printing them alone loses them.
fn apply_assessment(
    devices: &mut [Device],
    probes: &[ServiceProbe],
    nvd: Option<&NvdDatabase>,
) -> usize {
    let runner = AssessmentRunner::new();
    let mut total = 0;

    for device in devices.iter_mut() {
        let known: HashSet<String> = device
            .findings
            .iter()
            .map(|finding| finding.id.clone())
            .collect();
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
            if finding
                .port
                .is_some_and(|port| already_reported.contains(&port))
            {
                continue;
            }
            eprintln!(
                "  {}:{} [{}] {}",
                device.ip,
                finding
                    .port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                finding.severity,
                finding.title
            );
            device.add_finding(finding);
            total += 1;
        }
    }

    // Version-specific CVEs, using what the probes identified.
    for device in devices.iter_mut() {
        let IpAddr::V4(ipv4) = device.ip else {
            continue;
        };

        for port in device.open_ports.clone() {
            // A version is the whole point: without one there is nothing to
            // compare against a range, so an unidentified port is skipped
            // rather than guessed at. Run --fingerprint to identify services.
            let Some(probe) = probes
                .iter()
                .find(|probe| probe.ip == device.ip && probe.port == port)
            else {
                continue;
            };
            // TLS findings describe the connection, not a software version, so
            // they are collected before the version check that everything below
            // depends on.
            for finding in tls_findings(device.ip, port, &probe.result) {
                if device
                    .findings
                    .iter()
                    .any(|existing| existing.id == finding.id)
                {
                    continue;
                }

                eprintln!(
                    "  {}:{} [{}] {}",
                    device.ip, port, finding.severity, finding.title
                );
                device.add_finding(finding);
                total += 1;
            }

            let Some(version) = probe.result.version.clone() else {
                continue;
            };

            // Prefer the product the service reported over a guess from the
            // port number: "port 80, probably Apache" produces confident
            // findings about software that may not be installed at all. The
            // port only names the service when a version proved what it is but
            // the product string was unparseable.
            let service_name = probe
                .result
                .product
                .as_deref()
                .and_then(netgap_services::canonical_service_name)
                .or_else(|| service_name_for_port(port));

            let Some(service_name) = service_name else {
                continue;
            };

            let service_info = ServiceInfo {
                ip: ipv4,
                port,
                name: service_name.to_string(),
                version: Some(version),
                service_type: probe.result.service.to_lowercase(),
                banner: probe.result.banner.clone(),
                confidence: 0.95,
                vulnerabilities: Vec::new(),
            };

            for vulnerability in VulnerabilityCheck::check_version(&service_info) {
                let finding = cve_finding(device.ip, port, service_name, &vulnerability);
                if device
                    .findings
                    .iter()
                    .any(|existing| existing.id == finding.id)
                {
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

            // Live NVD data, when a cache is present. This runs alongside the
            // bundled database rather than replacing it: the bundled entries
            // are curated and the NVD cache may be partial.
            if let Some(database) = nvd {
                for finding in nvd_findings(device.ip, port, &probe.result, database) {
                    if device
                        .findings
                        .iter()
                        .any(|existing| existing.id == finding.id)
                    {
                        continue;
                    }

                    eprintln!(
                        "  {}:{} [{}] {}",
                        device.ip, port, finding.severity, finding.title
                    );
                    device.add_finding(finding);
                    total += 1;
                }
            }
        }
    }

    total
}

/// Fetch NVD data for the products and versions a scan identified.
///
/// Only versions the cache has not already been populated for are requested, so
/// repeat scans of the same network make no requests at all.
async fn update_cache_for_probes(
    probes: &[ServiceProbe],
) -> Result<usize, Box<dyn std::error::Error>> {
    let cache = LocalCacheManager::default_location()?;
    let mut database = cache.load()?;
    let client = NvdClient::new();

    // Distinct product/version pairs, so ten web servers cost one request.
    let mut wanted: Vec<(&str, &str, &str)> = Vec::new();
    for probe in probes {
        let (Some(product), Some(version)) = (
            probe.result.product.as_deref(),
            probe.result.version.as_deref(),
        ) else {
            continue;
        };
        let Some((vendor, _)) = netgap_threat_intel::cpe_for_product(product) else {
            continue;
        };
        if database.has_queried(vendor, cpe_product_for(product), version) {
            continue;
        }
        let entry = (vendor, cpe_product_for(product), version);
        if !wanted.contains(&entry) {
            wanted.push(entry);
        }
    }

    if wanted.is_empty() {
        eprintln!("  NVD: cache already covers every identified service");
        return Ok(0);
    }

    if !client.has_api_key() {
        eprintln!(
            "  ℹ️  No NVD_API_KEY set: {} request(s), rate limited to 5 per 30s",
            wanted.len()
        );
    }

    let total = wanted.len();
    let mut fetched = 0;

    for (index, (vendor, product, version)) in wanted.iter().enumerate() {
        eprintln!("  [{}/{}] {product} {version}", index + 1, total);

        match client
            .fetch_for_version(vendor, product, version, 2000)
            .await
        {
            Ok(entries) => {
                let count = entries.len();
                for entry in entries {
                    database.add_entry(entry);
                }
                database.mark_queried(vendor, product, version);
                fetched += count;
            }
            Err(error) => eprintln!("    ⚠️  {error}"),
        }

        if !client.has_api_key() && index + 1 < total {
            tokio::time::sleep(std::time::Duration::from_secs(7)).await;
        }
    }

    database.last_updated = Some(chrono::Utc::now().to_rfc3339());
    cache.save(&database)?;

    if fetched > 0 {
        eprintln!(
            "  NVD: cached {} entr(ies); {} total",
            fetched, database.entry_count
        );
    }

    Ok(fetched)
}

/// The CPE product name for a probe product, defaulting to the probe's own.
fn cpe_product_for(product: &str) -> &str {
    netgap_threat_intel::cpe_for_product(product)
        .map(|(_, cpe)| cpe)
        .unwrap_or(product)
}

/// Ports worth checking on the gateway itself.
///
/// The standard port list covers the common ones; these are the router-specific
/// interfaces it does not include — the alternate admin ports and the UPnP
/// control interface.
const GATEWAY_PORTS: &[u16] = &[80, 443, 8080, 8443, 5000, 2869, 23];

/// Probe the gateway's administration and UPnP ports, and report what it exposes.
///
/// A focused pass against a single host: the gateway is identified exactly (it
/// owns the default route), so this costs one short probe rather than widening
/// the scan for everyone.
async fn check_gateway_exposure(devices: &mut [Device], probes: &mut Vec<ServiceProbe>) {
    let Some(gateway) = netgap_interfaces::default_gateway_ipv4() else {
        return;
    };
    let gateway_ip = IpAddr::V4(gateway);

    let Some(device) = devices.iter_mut().find(|device| device.ip == gateway_ip) else {
        return;
    };

    eprintln!();
    eprintln!("Gateway checks ({})", gateway);
    eprintln!("──────────────────────────────");

    // Skip anything the fingerprinting phase already probed; probe the rest,
    // including ports already known to be open, because the probe is also what
    // reports what the admin page calls itself.
    let already_probed: Vec<u16> = probes
        .iter()
        .filter(|probe| probe.ip == gateway_ip)
        .map(|probe| probe.port)
        .collect();

    let to_probe: Vec<u16> = GATEWAY_PORTS
        .iter()
        .copied()
        .filter(|port| !already_probed.contains(port))
        .collect();

    if !to_probe.is_empty() {
        let results = probe_ports(gateway_ip, &to_probe, 8).await;
        for (port, result) in results {
            device.add_open_port(port);
            probes.push(ServiceProbe {
                ip: gateway_ip,
                port,
                result,
            });
        }
    }

    // What the administration page calls itself, which is often the clearest
    // thing a person can recognise.
    if let Some(probe) = probes
        .iter()
        .find(|probe| probe.ip == gateway_ip && probe.port == 80)
    {
        if let Some(details) = &probe.result.details {
            eprintln!("  Administration page: {}", details);
        }
    }

    let findings = netgap_assess::check_gateway(device);
    for finding in findings {
        eprintln!("  [{}] {}", finding.severity, finding.title);
        device.add_finding(finding);
    }

    if device.findings.is_empty() {
        eprintln!("  ✓ No gateway-specific exposure found");
    }
}

/// Findings from what a TLS handshake revealed.
///
/// These are observations about the connection itself rather than about
/// software versions, so they do not depend on any CVE data.
fn tls_findings(ip: IpAddr, port: u16, probe: &ProbeResult) -> Vec<Finding> {
    let Some(tls) = &probe.tls else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let mut finding =
        |id: &str, title: String, description: String, severity: Severity, remediation: String| {
            findings.push(Finding {
                id: id.to_string(),
                title,
                description,
                severity,
                ip,
                port: Some(port),
                service: Some("HTTPS".to_string()),
                remediation,
                confidence: 1.0,
            });
        };

    // A protocol deprecated in 2021 and broken since POODLE. Servers that
    // still accept it will use it with a client that offers only that.
    if tls.supports_legacy_tls {
        finding(
            "tls_legacy_protocol",
            "Legacy TLS accepted (TLS 1.0/1.1)".to_string(),
            format!(
                "The service negotiated {} but also answered a TLS 1.0 hello, so it still accepts a protocol with known attacks. Modern clients will use a newer version, but an attacker can force the downgrade.",
                tls.protocol_version
            ),
            Severity::High,
            "Disable TLS 1.0 and 1.1 in the service configuration, leaving TLS 1.2 or newer.".to_string(),
        );
    }

    if !tls.has_forward_secrecy() {
        finding(
            "tls_no_forward_secrecy",
            format!("Weak TLS cipher suite ({})", tls.cipher_suite),
            "The negotiated suite uses static RSA key exchange, which has no forward secrecy: traffic recorded today can be decrypted later by anyone who obtains the server's private key.".to_string(),
            Severity::Medium,
            "Enable ECDHE cipher suites, which provide forward secrecy.".to_string(),
        );
    }

    if let Some(certificate) = &tls.certificate {
        if certificate.is_expired() {
            finding(
                "tls_certificate_expired",
                format!("Expired TLS certificate ({})", certificate.subject),
                format!(
                    "The certificate for {} expired on {} ({} days ago). Browsers and clients will refuse or warn, and an expired certificate usually means the device is no longer maintained.",
                    certificate.subject, certificate.not_after, -certificate.days_until_expiry
                ),
                Severity::High,
                "Renew the certificate, or replace the device if it can no longer be updated.".to_string(),
            );
        } else if certificate.expires_soon() {
            finding(
                "tls_certificate_expiring",
                format!("TLS certificate expires soon ({})", certificate.subject),
                format!(
                    "The certificate for {} expires on {}, in {} day(s).",
                    certificate.subject, certificate.not_after, certificate.days_until_expiry
                ),
                Severity::Medium,
                "Renew the certificate before it expires.".to_string(),
            );
        }

        // Normal on a LAN, and worth stating plainly rather than alarming
        // about: it is information, not a vulnerability.
        if certificate.self_signed {
            finding(
                "tls_self_signed",
                format!("Self-signed TLS certificate ({})", certificate.subject),
                format!(
                    "{} presents a certificate signed by itself, so nothing vouches for its identity. That is normal for a router or printer on a home network, but it also means a device impersonating it would look no different.",
                    ip
                ),
                Severity::Info,
                "Nothing to fix on a home network. Install a trusted certificate if the device is reached by name from outside.".to_string(),
            );
        }
    }

    findings
}

/// Findings for one identified service, from the local NVD database.
///
/// A CVE already reported by the bundled database is skipped, so the same flaw
/// is not listed twice under two identifiers.
fn nvd_findings(
    ip: IpAddr,
    port: u16,
    probe: &ProbeResult,
    database: &NvdDatabase,
) -> Vec<Finding> {
    let (Some(product), Some(version)) = (probe.product.as_deref(), probe.version.as_deref())
    else {
        return Vec::new();
    };

    // NVD indexes by CPE product ("http_server"), not by the name a service
    // reports ("Apache"). Without a mapping there is nothing to look up.
    let Some((_vendor, cpe_product)) = netgap_threat_intel::cpe_for_product(product) else {
        return Vec::new();
    };

    database
        .matching(cpe_product, version)
        .into_iter()
        .map(|entry| {
            let ranges = entry.ranges_for(cpe_product);
            let reference = entry
                .references
                .first()
                .map(|url| format!(" See {url}."))
                .unwrap_or_default();

            Finding {
                id: format!("nvd-{}", entry.cve_id),
                title: format!("{} in {} {}", entry.cve_id, product, version),
                description: format!(
                    "{} (NVD, CVSS {:.1} {}). Affected: {}.{}",
                    entry.description,
                    entry.cvss_score,
                    entry.severity,
                    if ranges.is_empty() {
                        "see reference".to_string()
                    } else {
                        ranges.join("; ")
                    },
                    reference
                ),
                severity: match entry.severity {
                    CvssSeverity::Critical => Severity::Critical,
                    CvssSeverity::High => Severity::High,
                    CvssSeverity::Medium => Severity::Medium,
                    // Core has no separate Low; both fold into Info.
                    CvssSeverity::Low | CvssSeverity::None => Severity::Info,
                },
                ip,
                port: Some(port),
                service: Some(product.to_string()),
                remediation: format!(
                    "Upgrade {} past the affected range, or restrict access to port {}.",
                    product, port
                ),
                confidence: 0.95,
            }
        })
        .collect()
}

async fn cmd_threat_intel(action: ThreatIntelAction) -> Result<(), Box<dyn std::error::Error>> {
    let cache = LocalCacheManager::default_location()?;

    match action {
        ThreatIntelAction::Status => {
            let database = cache.load()?;

            println!("📚 NVD vulnerability database\n");
            println!("  Cache:    {}", cache.path().display());
            println!("  Entries:  {}", database.entry_count);
            println!(
                "  Updated:  {}",
                database.last_updated.as_deref().unwrap_or("never")
            );
            println!(
                "  Severity: {} critical, {} high or critical",
                database.critical_count(),
                database.high_or_critical_count()
            );
            println!(
                "  Versions: {} product version(s) queried",
                database.queried_versions.len()
            );

            if database.is_empty() {
                println!("\n  Empty. Run 'netgap threat-intel update' to download CVE data.");
            } else {
                let mut products: Vec<(String, usize)> = database.products().into_iter().collect();
                products.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

                println!("\n  Products covered:");
                for (product, count) in products.iter().take(20) {
                    println!("    {:<28} {}", product, count);
                }
                if products.len() > 20 {
                    println!("    ... and {} more", products.len() - 20);
                }
            }
        }

        ThreatIntelAction::Clear => {
            cache.clear()?;
            println!("✓ Cleared the NVD cache");
        }

        ThreatIntelAction::Update { per_product } => {
            let client = NvdClient::new();
            if !client.has_api_key() {
                println!(
                    "ℹ️  No NVD_API_KEY set: limited to 5 requests per 30s, so this will take a \
                     few minutes. Set NVD_API_KEY for a higher quota."
                );
            }
            println!("⬇️  Fetching CVE data from NVD...\n");

            let database = client
                .fetch_known_products(per_product, |product, index, total| {
                    println!("  [{index}/{total}] {product}");
                })
                .await?;

            cache.save(&database)?;

            println!(
                "\n✓ Cached {} entries for {} product(s) at {}",
                database.entry_count,
                database.products().len(),
                cache.path().display()
            );
            println!("  Scans can now use them with --threat-intel");
        }
    }

    Ok(())
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

/// Service name used for vulnerability lookups when a probe identified nothing.
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

/// Compare this cycle's address mappings against the previous one.
///
/// Reads the kernel's neighbour table, which ordinary traffic keeps current, so
/// this needs no privileges and no capture — and it is the only option when the
/// scan itself is unprivileged. It sees what has settled: a device that took an
/// address over and is still using it. A spoof that starts and stops between
/// two cycles is missed, which is the cost of looking rather than listening.
/// Ask the network who provides DHCP, and report anyone unexpected.
///
/// A DHCP server decides what gateway and DNS server a device will use, so a
/// second one on a network can quietly redirect everything that device sends.
/// Finding it needs privileges: a DHCP client binds port 68.
#[cfg(unix)]
async fn check_dhcp_servers(plan: &DiscoveryPlan, gateway: Option<std::net::Ipv4Addr>) {
    use netgap_discover::dhcp::{DhcpProbe, ExpectedServers};

    let Ok(interface) = netgap_interfaces::get_interface(&plan.interface.name) else {
        return;
    };
    let Some(mac) = interface
        .mac
        .as_deref()
        .and_then(netgap_discover::dhcp::parse_mac)
    else {
        eprintln!(
            "  DHCP check skipped: no hardware address for {}",
            plan.interface.name
        );
        return;
    };

    let probe = DhcpProbe::new(plan.interface.name.clone(), Duration::from_secs(4));

    let servers = match probe.discover_servers(mac).await {
        Ok(servers) => servers,
        Err(error) if netgap_discover::is_privilege_error(&error) => {
            eprintln!(
                "  ⚠️  DHCP check needs root: a DHCP client binds port 68. Run with sudo to enable it."
            );
            return;
        }
        Err(error) => {
            eprintln!("  ⚠️  DHCP check failed: {error}");
            return;
        }
    };

    if servers.is_empty() {
        // Silence is not evidence of a problem, and the reasons are worth
        // naming: a network may use static addressing, and a host firewall
        // that drops broadcast will hide a server that is answering everyone
        // else. Saying only "no server answered" would send someone looking in
        // the wrong place.
        println!(
            "\n  DHCP: no server answered.\n   \
             Either the network uses static addressing, or something here is dropping\n   \
             broadcast traffic — a host firewall on this machine would hide a server\n   \
             that is answering every other device."
        );
        return;
    }

    let expected = ExpectedServers::new(gateway);
    for server in &servers {
        let name = server
            .hostname
            .as_deref()
            .map(|hostname| format!(" ({hostname})"))
            .unwrap_or_default();

        if expected.contains(server.server_id) {
            println!("\n  DHCP server: {}{}", server.server_id, name);
        } else if expected.is_empty() {
            println!(
                "\n  DHCP server: {}{} — not the gateway, and no expected server is known to compare against",
                server.server_id, name
            );
        } else {
            println!(
                "\n🚨 ALERT: an unexpected DHCP server answered — {}{}\n   \
                 A DHCP server tells every device which gateway and DNS server to use.\n   \
                 If you did not add one, it can redirect what this network sends.",
                server.server_id, name
            );
        }
    }
}

/// Alert lines for what changed between two observations of the network.
///
/// Split out from the loop so the wording is testable: what an alert says is
/// the part a person has to act on, and it should not depend on getting a live
/// spoof to occur.
fn conflict_alerts(
    changes: &[netgap_discover::MacChange],
    shared: &[netgap_discover::SharedMac],
    gateway: Option<std::net::Ipv4Addr>,
) -> Vec<String> {
    let mut alerts = Vec::new();

    for change in changes {
        if change.is_gateway(gateway) {
            alerts.push(format!(
                "🚨 ALERT: the gateway address changed hands — {}\n   \
                 That is how traffic on a network gets intercepted. Unless the router\n   \
                 was replaced, treat what you send from here with suspicion.",
                change.describe()
            ));
        } else {
            alerts.push(format!("⚠️  Address changed hands: {}", change.describe()));
        }
    }

    // One device answering for several addresses only matters when one of them
    // is the gateway: nothing legitimate needs to hold the router's address as
    // well as its own.
    for entry in shared {
        if gateway.is_some_and(|gateway| entry.addresses.contains(&gateway)) {
            alerts.push(format!(
                "🚨 ALERT: one device answers for several addresses — {}",
                entry.describe()
            ));
        }
    }

    alerts
}

/// Compare this cycle's address mappings against the previous one.
///
/// Reads the kernel's neighbour table, which ordinary traffic keeps current, so
/// this needs no privileges and no capture — and it is the only option when the
/// scan itself is unprivileged. It sees what has settled: a device that took an
/// address over and is still using it. A spoof that starts and stops between
/// two cycles is missed, which is the cost of looking rather than listening.
fn check_for_address_conflicts(
    last_mappings: &mut Option<std::collections::HashMap<std::net::Ipv4Addr, String>>,
    plan: &DiscoveryPlan,
    gateway: Option<std::net::Ipv4Addr>,
) {
    let current = netgap_discover::snapshot_mappings(&plan.interface.name);

    if let Some(previous) = last_mappings.as_ref() {
        let changes = netgap_discover::detect_mac_changes(previous, &current);

        let observations: Vec<(std::net::Ipv4Addr, String)> =
            current.iter().map(|(ip, mac)| (*ip, mac.clone())).collect();
        let shared = netgap_discover::detect_shared_macs(&observations);

        for alert in conflict_alerts(&changes, &shared, gateway) {
            println!("\n{alert}");
        }
    }

    *last_mappings = Some(current);
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

        println!(
            "Scan 1: {} ({})",
            comparison.scan1_id, comparison.scan1_date
        );
        println!(
            "Scan 2: {} ({})\n",
            comparison.scan2_id, comparison.scan2_date
        );

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
            println!(
                "🔴 New Critical Findings ({}):",
                comparison.new_critical.len()
            );
            for (title, ip) in &comparison.new_critical {
                println!("  + {} on {}", title, ip);
            }
            println!();
        }

        if !comparison.resolved_findings.is_empty() {
            println!(
                "✅ Resolved Findings ({}):",
                comparison.resolved_findings.len()
            );
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
        "table" => println!(
            "{}",
            ReportFormatter::format_terminal(&store.load_scan(&scan_to_report)?)?
        ),
        "json" => println!(
            "{}",
            ReportFormatter::format_json(&store.load_scan(&scan_to_report)?)?
        ),
        "summary" => println!(
            "{}",
            ReportFormatter::format_summary(&store.load_scan(&scan_to_report)?)?
        ),
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
    check_dhcp: bool,
    no_alert: bool,
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
    // Kept alongside the history so the trend compares like with like: the
    // score cannot be recomputed from a snapshot.
    let mut last_health: Option<HealthScore> = None;
    // Kept for the same reason: an alert describes what changed, and the
    // snapshot holds counts rather than findings.
    let mut last_result: Option<ScanResult> = None;
    let mut last_mappings: Option<std::collections::HashMap<std::net::Ipv4Addr, String>> = None;

    // The gateway is the address worth impersonating, so a change there reads
    // differently from one on a printer. It is also the DHCP server a home
    // network is expected to have.
    let gateway = netgap_interfaces::default_gateway_ipv4();

    if check_dhcp {
        #[cfg(unix)]
        check_dhcp_servers(&plan, gateway).await;

        #[cfg(not(unix))]
        eprintln!("   DHCP check: not implemented on this platform (Unix only)");
    }
    let mut scan_count = 0;

    loop {
        scan_count += 1;
        println!(
            "📊 Scan #{} — {}",
            scan_count,
            Local::now().format("%H:%M:%S")
        );

        match discovery::run(&plan).await {
            Ok(mut devices) => {
                if plan.mdns {
                    run_mdns(&mut devices).await;
                }

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

                // Scored from the result rather than the history snapshot: the
                // score is charged per kind of problem, and the snapshot keeps
                // only counts.
                let curr_health = HealthScore::from_result(&result);

                // Detect changes if we have previous history
                if let Some(prev) = &last_history {
                    let changes = ChangeDetection::detect_changes(prev, &current_history);
                    let prev_health = last_health.unwrap_or(curr_health);

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
                        // A port that was not open before is how a new
                        // service — or a compromised machine — first appears,
                        // and it is worth a line of its own rather than being
                        // one bullet in a list.
                        if AlertRule::service_changed().should_trigger(&changes, None) {
                            println!("\n🟡 ALERT: A device opened or closed a port");
                        }
                        if let Some(drop) = health_drop {
                            if health_drop_rule.should_trigger(&changes, Some(drop)) {
                                println!(
                                    "\n🟠 ALERT: Network health score dropped {} points",
                                    drop
                                );
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
                    println!(
                        "  Health Score: {}/100 ({})",
                        curr_health.score,
                        curr_health.risk_level()
                    );
                }

                // Alerts go out from the same place they do in `scan`, so a
                // watching machine and a scheduled one say the same things.
                if !no_alert {
                    send_alerts(last_result.as_ref(), &result).await;
                }

                last_history = Some(current_history);
                last_health = Some(curr_health);
                last_result = Some(result);
                check_for_address_conflicts(&mut last_mappings, &plan, gateway);

                if check_dhcp {
                    #[cfg(unix)]
                    check_dhcp_servers(&plan, gateway).await;

                    #[cfg(not(unix))]
                    eprintln!("   DHCP check: not implemented on this platform (Unix only)");
                }
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
        let attached = apply_assessment(&mut devices, &[], None);

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

        apply_assessment(&mut devices, &[], None);

        let smb_findings = devices[0]
            .findings
            .iter()
            .filter(|finding| finding.port == Some(445))
            .count();
        assert_eq!(smb_findings, 1, "port 445 should be reported once");
    }

    fn probe(ip: IpAddr, port: u16, product: &str, version: &str) -> ServiceProbe {
        ServiceProbe {
            ip,
            port,
            result: ProbeResult {
                service: "HTTP".to_string(),
                product: Some(product.to_string()),
                version: Some(version.to_string()),
                banner: Some(format!("{product}/{version}")),
                details: None,
                tls: None,
            },
        }
    }

    #[test]
    fn test_apply_assessment_adds_version_specific_cves() {
        let mut devices = vec![device_with_ports(&[80])];
        let probes = vec![probe(devices[0].ip, 80, "Apache", "2.4.49")];

        apply_assessment(&mut devices, &probes, None);

        assert!(
            devices[0]
                .findings
                .iter()
                .any(|finding| finding.id.starts_with("cve-")),
            "a vulnerable Apache version should produce CVE findings"
        );
    }

    #[test]
    fn test_probed_product_overrides_the_port_guess() {
        // Port 80 is usually assumed to be Apache. When the probe says nginx,
        // the finding must be about nginx — guessing here is how a scanner ends
        // up reporting CVEs for software that is not installed.
        let mut devices = vec![device_with_ports(&[80])];
        let probes = vec![probe(devices[0].ip, 80, "nginx", "1.14.0")];

        apply_assessment(&mut devices, &probes, None);

        let titles: Vec<String> = devices[0]
            .findings
            .iter()
            .map(|finding| finding.title.clone())
            .collect();
        assert!(
            titles.iter().any(|title| title.contains("nginx")),
            "expected an nginx finding, got {titles:?}"
        );
        assert!(
            !titles.iter().any(|title| title.contains("Apache")),
            "must not report Apache for a port the probe identified as nginx"
        );
    }

    fn change(ip: &str, previous: &str, current: &str) -> netgap_discover::MacChange {
        netgap_discover::MacChange {
            ip: ip.parse().expect("valid ip"),
            previous_mac: previous.to_string(),
            current_mac: current.to_string(),
        }
    }

    #[test]
    fn test_gateway_change_reads_as_an_alert() {
        let gateway = Some("192.168.1.1".parse().expect("valid ip"));
        let alerts = conflict_alerts(
            &[change(
                "192.168.1.1",
                "C4:B2:5B:0A:03:26",
                "DE:AD:BE:EF:00:01",
            )],
            &[],
            gateway,
        );

        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("ALERT"));
        assert!(alerts[0].contains("gateway"));
        // Both addresses are named, so the reader can check them.
        assert!(alerts[0].contains("C4:B2:5B:0A:03:26"));
        assert!(alerts[0].contains("DE:AD:BE:EF:00:01"));
    }

    #[test]
    fn test_ordinary_change_is_reported_without_alarm() {
        let gateway = Some("192.168.1.1".parse().expect("valid ip"));
        let alerts = conflict_alerts(
            &[change(
                "192.168.1.50",
                "AA:BB:CC:DD:EE:FF",
                "11:22:33:44:55:66",
            )],
            &[],
            gateway,
        );

        assert_eq!(alerts.len(), 1);
        assert!(!alerts[0].contains("ALERT"));
        assert!(alerts[0].contains("changed hands"));
    }

    #[test]
    fn test_shared_mac_only_alerts_when_it_touches_the_gateway() {
        let gateway = Some("192.168.1.1".parse().expect("valid ip"));

        let innocent = netgap_discover::SharedMac {
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            addresses: vec![
                "192.168.1.20".parse().expect("valid ip"),
                "192.168.1.21".parse().expect("valid ip"),
            ],
        };
        assert!(
            conflict_alerts(&[], std::slice::from_ref(&innocent), gateway).is_empty(),
            "a device holding two of its own addresses is not an alert"
        );

        let suspicious = netgap_discover::SharedMac {
            mac: "DE:AD:BE:EF:00:01".to_string(),
            addresses: vec![
                "192.168.1.1".parse().expect("valid ip"),
                "192.168.1.77".parse().expect("valid ip"),
            ],
        };
        let alerts = conflict_alerts(&[], std::slice::from_ref(&suspicious), gateway);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].contains("ALERT"));
    }

    #[test]
    fn test_nothing_changed_means_no_alerts() {
        assert!(
            conflict_alerts(&[], &[], Some("192.168.1.1".parse().expect("valid ip"))).is_empty()
        );
        assert!(conflict_alerts(&[], &[], None).is_empty());
    }

    fn tls_probe(
        protocol: &str,
        cipher: &str,
        legacy: bool,
        certificate: Option<netgap_probes::tls::CertificateInfo>,
    ) -> ProbeResult {
        ProbeResult {
            service: "HTTPS".to_string(),
            product: None,
            version: None,
            banner: None,
            details: None,
            tls: Some(netgap_probes::tls::TlsInspection {
                protocol_version: protocol.to_string(),
                cipher_suite: cipher.to_string(),
                supports_legacy_tls: legacy,
                certificate,
            }),
        }
    }

    fn certificate(
        days_until_expiry: i64,
        self_signed: bool,
    ) -> netgap_probes::tls::CertificateInfo {
        netgap_probes::tls::CertificateInfo {
            subject: "router.local".to_string(),
            issuer: if self_signed {
                "router.local"
            } else {
                "Test CA"
            }
            .to_string(),
            not_before: "2020-01-01".to_string(),
            not_after: "2030-01-01".to_string(),
            self_signed,
            days_until_expiry,
        }
    }

    #[test]
    fn test_legacy_tls_is_reported_as_high() {
        let probe = tls_probe(
            "TLSv1.0",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            true,
            Some(certificate(1000, false)),
        );

        let findings = tls_findings("192.168.1.1".parse().unwrap(), 443, &probe);

        let legacy = findings
            .iter()
            .find(|finding| finding.id == "tls_legacy_protocol")
            .expect("legacy TLS should be reported");
        assert_eq!(legacy.severity, Severity::High);
        assert!(legacy.description.contains("TLS 1.0"));
    }

    #[test]
    fn test_static_rsa_suite_is_reported_without_forward_secrecy() {
        let probe = tls_probe("TLSv1.2", "TLS_RSA_WITH_AES_256_GCM_SHA384", false, None);

        let findings = tls_findings("192.168.1.1".parse().unwrap(), 443, &probe);

        let weak = findings
            .iter()
            .find(|finding| finding.id == "tls_no_forward_secrecy")
            .expect("static RSA should be reported");
        assert_eq!(weak.severity, Severity::Medium);

        // An ECDHE suite must not be flagged.
        let good = tls_probe("TLSv1.3", "TLS13_AES_128_GCM_SHA256", false, None);
        assert!(tls_findings("192.168.1.1".parse().unwrap(), 443, &good).is_empty());
    }

    #[test]
    fn test_certificate_problems_are_reported_by_severity() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let expired = tls_probe(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            false,
            Some(certificate(-3, false)),
        );
        let findings = tls_findings(ip, 443, &expired);
        let finding = findings
            .iter()
            .find(|finding| finding.id == "tls_certificate_expired")
            .expect("expired certificate should be reported");
        assert_eq!(finding.severity, Severity::High);

        let expiring = tls_probe(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            false,
            Some(certificate(7, false)),
        );
        let findings = tls_findings(ip, 443, &expiring);
        assert!(findings
            .iter()
            .any(|finding| finding.id == "tls_certificate_expiring"));

        // Self-signed is normal on a LAN: reported, but not as a problem.
        let self_signed = tls_probe(
            "TLSv1.2",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            false,
            Some(certificate(1000, true)),
        );
        let findings = tls_findings(ip, 443, &self_signed);
        let finding = findings
            .iter()
            .find(|finding| finding.id == "tls_self_signed")
            .expect("self-signed should be reported");
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn test_non_tls_probes_produce_no_tls_findings() {
        let probes = vec![
            probe("192.168.1.1".parse().unwrap(), 80, "nginx", "1.18.0"),
            ServiceProbe {
                ip: "192.168.1.1".parse().unwrap(),
                port: 80,
                result: ProbeResult {
                    service: "TCP".to_string(),
                    product: None,
                    version: None,
                    banner: None,
                    details: None,
                    tls: None,
                },
            },
        ];

        for probe in &probes {
            assert!(tls_findings(probe.ip, probe.port, &probe.result).is_empty());
        }
    }

    fn nvd_entry(
        cve_id: &str,
        product: &str,
        start: &str,
        end: &str,
    ) -> netgap_threat_intel::CveEntry {
        netgap_threat_intel::CveEntry {
            cve_id: cve_id.to_string(),
            cvss_score: 9.8,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            severity: netgap_threat_intel::CvssSeverity::Critical,
            description: "A live NVD entry.".to_string(),
            affected: vec![netgap_threat_intel::AffectedProduct {
                vendor: "apache".to_string(),
                product: product.to_string(),
                range: netgap_threat_intel::VersionRange {
                    start_including: Some(start.to_string()),
                    end_excluding: Some(end.to_string()),
                    ..Default::default()
                },
            }],
            references: vec!["https://nvd.nist.gov/vuln/detail/X".to_string()],
            published_date: "2021-10-05T00:00:00.000".to_string(),
            last_modified: "2025-01-01T00:00:00.000".to_string(),
        }
    }

    #[test]
    fn test_nvd_findings_match_an_identified_version() {
        let mut database = NvdDatabase::new();
        database.add_entry(nvd_entry(
            "CVE-2021-42013",
            "http_server",
            "2.4.49",
            "2.4.51",
        ));

        let mut devices = vec![device_with_ports(&[80])];
        let probes = vec![probe(devices[0].ip, 80, "Apache", "2.4.50")];

        apply_assessment(&mut devices, &probes, Some(&database));

        let nvd: Vec<&Finding> = devices[0]
            .findings
            .iter()
            .filter(|finding| finding.id.starts_with("nvd-"))
            .collect();

        assert_eq!(nvd.len(), 1, "expected one NVD finding, got {nvd:?}");
        assert_eq!(nvd[0].severity, Severity::Critical);
        assert!(nvd[0].title.contains("CVE-2021-42013"));
        assert!(nvd[0].description.contains("2.4.49"));
    }

    #[test]
    fn test_nvd_findings_respect_the_version_window() {
        let mut database = NvdDatabase::new();
        database.add_entry(nvd_entry(
            "CVE-2021-42013",
            "http_server",
            "2.4.49",
            "2.4.51",
        ));

        // 2.4.51 is outside the window and must not be reported.
        let mut devices = vec![device_with_ports(&[80])];
        let probes = vec![probe(devices[0].ip, 80, "Apache", "2.4.51")];

        apply_assessment(&mut devices, &probes, Some(&database));

        assert!(!devices[0]
            .findings
            .iter()
            .any(|finding| finding.id.starts_with("nvd-")));
    }

    #[test]
    fn test_nvd_lookup_needs_a_known_cpe_product() {
        let mut database = NvdDatabase::new();
        database.add_entry(nvd_entry(
            "CVE-2021-42013",
            "http_server",
            "2.4.49",
            "2.4.51",
        ));

        // A product with no CPE mapping cannot be looked up, and must not
        // silently match something else.
        let mut devices = vec![device_with_ports(&[80])];
        let probes = vec![probe(devices[0].ip, 80, "Cloudflare", "2.4.50")];

        apply_assessment(&mut devices, &probes, Some(&database));

        assert!(!devices[0]
            .findings
            .iter()
            .any(|finding| finding.id.starts_with("nvd-")));
    }

    #[test]
    fn test_ports_without_a_version_produce_no_cve_findings() {
        // No probe ran, so there is no version to compare against any range.
        // Reporting a CVE here would mean inventing one.
        let mut devices = vec![device_with_ports(&[3306])];
        apply_assessment(&mut devices, &[], None);

        assert!(!devices[0]
            .findings
            .iter()
            .any(|finding| finding.id.starts_with("cve-")));
    }

    #[test]
    fn test_port_name_fills_in_when_the_product_is_unparseable() {
        // A version without a product name: the port still identifies which
        // table to consult, and a real version makes the range check meaningful.
        let mut devices = vec![device_with_ports(&[3306])];
        let probes = vec![ServiceProbe {
            ip: devices[0].ip,
            port: 3306,
            result: ProbeResult {
                service: "MySQL".to_string(),
                product: None,
                version: Some("5.7.30".to_string()),
                banner: None,
                details: None,
                tls: None,
            },
        }];

        apply_assessment(&mut devices, &probes, None);

        assert!(devices[0]
            .findings
            .iter()
            .any(|finding| finding.service.as_deref() == Some("MySQL")));
    }
}
