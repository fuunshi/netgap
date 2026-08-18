//! `netgap diff`: what changed between two scans, as its own command.
//!
//! `netgap report --compare a b` already answers this for one pair of ids, but
//! it is a reporting flag: it needs both ids, it cannot say "since last time",
//! and its exit status is always zero. Diffing two scans is the operation
//! people put in a cron job or a CI step — *did anything change since the
//! deploy?* — so it takes scan references that are convenient to type, prints
//! the same information grouped the way a person reads it, and exits non-zero
//! when the answer is "yes".
//!
//! The comparison itself is not reimplemented: `ChangeDetection` in
//! `netgap-trends` already decides what counts as a change, and it is what the
//! alerting path uses. Two definitions of "changed" would be one too many.

use anyhow::{bail, Result};
use colored::Colorize;
use netgap_core::{HealthScore, ScanResult};
use netgap_storage::{ScanMetadata, ScanStore};
use netgap_trends::{ChangeDetection, NetworkChange, ScanHistory};
use std::net::IpAddr;
use std::process::exit;
use std::str::FromStr;

/// Run the comparison and print it.
///
/// `from` and `to` are scan references — an id, a unique prefix of one,
/// `latest` or `previous`. With neither, the last two scans are compared.
pub fn run(from: Option<String>, to: Option<String>, json: bool) -> Result<()> {
    let store = ScanStore::open_default()?;
    let scans = store.list_scans()?; // newest first

    if scans.len() < 2 {
        println!("{}", "netgap diff".bold());
        println!(
            "  {}",
            match scans.len() {
                0 => "There are no scans in the history yet. Run `netgap scan` first.".to_string(),
                _ => "Only one scan is stored, and a diff needs two. Run another scan.".to_string(),
            }
            .dimmed()
        );
        return Ok(());
    }

    let (from_index, to_index) = match (from, to) {
        (None, None) => (1, 0),
        (Some(reference), None) => {
            let index = resolve(&scans, &reference)?;
            if index == 0 {
                println!(
                    "{} is the latest scan, and nothing has run since it.",
                    scans[0].id
                );
                return Ok(());
            }
            (index, 0)
        }
        (Some(a), Some(b)) => (resolve(&scans, &a)?, resolve(&scans, &b)?),
        // Clap cannot produce this — a second positional needs the first — but
        // the type allows it, and "since last time, up to this scan" is the
        // reading that matches the other arms.
        (None, Some(b)) => (1, resolve(&scans, &b)?),
    };

    if from_index == to_index {
        println!(
            "Both references resolve to {}, so there is nothing to compare.",
            scans[from_index].id
        );
        return Ok(());
    }

    let older = &scans[from_index];
    let newer = &scans[to_index];
    let older_result = store.load_scan(&older.id)?;
    let newer_result = store.load_scan(&newer.id)?;

    let before = ScanHistory::from_scan_result(older.id.clone(), &older_result);
    let after = ScanHistory::from_scan_result(newer.id.clone(), &newer_result);
    let changes = ChangeDetection::detect_changes(&before, &after);

    if json {
        print_json(older, &older_result, newer, &newer_result, &changes)?;
    } else {
        print_text(older, &older_result, newer, &newer_result, &changes);
    }

    // Like `diff(1)`: a script wants to know whether anything changed without
    // parsing the output, so the answer is in the exit status too.
    if !changes.is_empty() {
        exit(1);
    }
    Ok(())
}

// ------------------------------------------------------------- resolving ---

/// Turn a reference on the command line into an index into `scans`, which is
/// newest first.
///
/// Ids carry the time they were made (`scan-<millis>`), so a prefix is enough
/// to name one, and typing the first ten characters is usually less work than
/// copying the id out of `report --history`.
fn resolve(scans: &[ScanMetadata], reference: &str) -> Result<usize> {
    match reference {
        "latest" | "last" => return Ok(0),
        "previous" | "prev" => {
            if scans.len() < 2 {
                bail!("There is no scan before the latest one.");
            }
            return Ok(1);
        }
        _ => {}
    }

    if let Some(index) = scans.iter().position(|scan| scan.id == reference) {
        return Ok(index);
    }

    let matches: Vec<usize> = scans
        .iter()
        .enumerate()
        .filter(|(_, scan)| scan.id.starts_with(reference))
        .map(|(index, _)| index)
        .collect();

    match matches.len() {
        0 => {
            bail!("No scan matches \"{reference}\". Run `netgap report --history` to see the ids.")
        }
        1 => Ok(matches[0]),
        // Letting a prefix pick an arbitrary match is how you diff the wrong
        // two scans and believe the result.
        _ => bail!(
            "\"{reference}\" matches {} scans ({}). Use more of the id.",
            matches.len(),
            matches
                .iter()
                .map(|index| scans[*index].id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

// ----------------------------------------------------------------- print ---

fn print_text(
    older: &ScanMetadata,
    older_result: &ScanResult,
    newer: &ScanMetadata,
    newer_result: &ScanResult,
    changes: &[NetworkChange],
) {
    println!("{}", "🔄 netgap diff".bold());
    println!();

    let label = |name: &str, scan: &ScanMetadata, result: &ScanResult| {
        println!(
            "  {} {}  {}  {}  {}",
            name.dimmed(),
            scan.id.as_str().bold(),
            short_time(&scan.started_at),
            result.config.target.dimmed(),
            format!(
                "{} devices, {} findings",
                result.devices.len(),
                total_findings(result)
            )
            .dimmed()
        );
    };
    label("from", older, older_result);
    label("to  ", newer, newer_result);
    println!();

    if changes.is_empty() {
        println!(
            "  {} Nothing changed since {} — the network looks the same.",
            "✓".green(),
            short_time(&older.started_at)
        );
        print_scores(older_result, newer_result);
        return;
    }

    let groups = Groups::of(changes);

    if !groups.new_devices.is_empty() {
        section("✨", "New devices", groups.new_devices.len());
        for (ip, hostname) in &groups.new_devices {
            match hostname {
                Some(name) => println!("  {} {:<17} {}", "+".green(), ip, name.dimmed()),
                None => println!("  {} {}", "+".green(), ip),
            }
        }
        println!();
    }

    if !groups.gone_devices.is_empty() {
        section("👋", "Devices gone", groups.gone_devices.len());
        for ip in &groups.gone_devices {
            println!("  {} {}", "-".yellow(), ip);
        }
        println!();
    }

    if !groups.opened.is_empty() {
        section("🔌", "Ports opened", groups.opened.len());
        for (ip, ports) in per_device(&groups.opened) {
            println!(
                "  {} {:<17} {}",
                "+".green(),
                ip,
                formatted_ports(&ports, "+").green()
            );
        }
        println!();
    }

    if !groups.closed.is_empty() {
        section("🔌", "Ports closed", groups.closed.len());
        for (ip, ports) in per_device(&groups.closed) {
            println!(
                "  {} {:<17} {}",
                "-".yellow(),
                ip,
                formatted_ports(&ports, "-").yellow()
            );
        }
        println!();
    }

    if !groups.critical.is_empty() {
        section("🔴", "New critical findings", groups.critical.len());
        for (ip, count) in &groups.critical {
            println!("  {} {:<17} +{} critical", "▲".red(), ip, count);
        }
        println!();
    }

    if !groups.regressed.is_empty() {
        section("🟠", "Worse", groups.regressed.len());
        for ip in &groups.regressed {
            println!("  {} {:<17} more high findings", "▲".red(), ip);
        }
        println!();
    }

    if !groups.improved.is_empty() {
        section("✅", "Better", groups.improved.len());
        for ip in &groups.improved {
            println!("  {} {:<17} fewer high findings", "▼".green(), ip);
        }
        println!();
    }

    print_scores(older_result, newer_result);
}

fn section(icon: &str, title: &str, count: usize) {
    println!("{} {}", icon, format!("{title} ({count})").bold());
}

/// A stored timestamp in the reader's own time, at a glance.
///
/// Scans record RFC 3339 in UTC; the person comparing them cares what time it
/// was where they are.
fn short_time(timestamp: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(timestamp) {
        Ok(time) => time
            .with_timezone(&chrono::Local)
            .format("%b %d, %H:%M")
            .to_string(),
        Err(_) => timestamp.chars().take(16).collect(),
    }
}

fn print_scores(older: &ScanResult, newer: &ScanResult) {
    let before = HealthScore::from_result(older).score;
    let after = HealthScore::from_result(newer).score;
    let delta = after as i16 - before as i16;

    let change = match delta {
        0 => "no change".dimmed().to_string(),
        d if d > 0 => format!("+{d}").green().to_string(),
        d => format!("{d}").red().to_string(),
    };
    println!(
        "  {} {} → {}  ({})",
        "Health".dimmed(),
        before,
        after,
        change
    );
}

fn total_findings(result: &ScanResult) -> usize {
    result
        .devices
        .iter()
        .map(|device| device.findings.len())
        .sum()
}

/// The changes, split into the groups the reader sees.
#[derive(Default)]
struct Groups {
    opened: Vec<(String, u16)>,
    closed: Vec<(String, u16)>,
    new_devices: Vec<(String, Option<String>)>,
    gone_devices: Vec<String>,
    critical: Vec<(String, usize)>,
    improved: Vec<String>,
    regressed: Vec<String>,
}

impl Groups {
    fn of(changes: &[NetworkChange]) -> Self {
        let mut groups = Self::default();
        for change in changes {
            match change {
                NetworkChange::NewService { ip, port } => groups.opened.push((ip.clone(), *port)),
                NetworkChange::ServiceClosed { ip, port } => {
                    groups.closed.push((ip.clone(), *port))
                }
                NetworkChange::NewDevice { ip, hostname } => {
                    groups.new_devices.push((ip.clone(), hostname.clone()))
                }
                NetworkChange::DeviceGone { ip } => groups.gone_devices.push(ip.clone()),
                NetworkChange::CriticalVulnDetected { ip, count } => {
                    groups.critical.push((ip.clone(), *count))
                }
                NetworkChange::VulnerabilityRegressed { ip } => groups.regressed.push(ip.clone()),
                NetworkChange::VulnerabilityImproved { ip } => groups.improved.push(ip.clone()),
            }
        }

        groups.new_devices.sort_by(|a, b| ip_order(&a.0, &b.0));
        groups.gone_devices.sort_by(|a, b| ip_order(a, b));
        groups.critical.sort_by(|a, b| ip_order(&a.0, &b.0));
        groups.regressed.sort_by(|a, b| ip_order(a, b));
        groups.improved.sort_by(|a, b| ip_order(a, b));
        groups
            .opened
            .sort_by(|a, b| ip_order(&a.0, &b.0).then(a.1.cmp(&b.1)));
        groups
            .closed
            .sort_by(|a, b| ip_order(&a.0, &b.0).then(a.1.cmp(&b.1)));
        groups
    }
}

/// Collect per-device ports, one address per line.
fn per_device(entries: &[(String, u16)]) -> Vec<(String, Vec<u16>)> {
    let mut grouped: Vec<(String, Vec<u16>)> = Vec::new();
    for (ip, port) in entries {
        match grouped.last_mut() {
            Some((last_ip, ports)) if last_ip == ip => ports.push(*port),
            _ => grouped.push((ip.clone(), vec![*port])),
        }
    }
    grouped
}

fn formatted_ports(ports: &[u16], sign: &str) -> String {
    ports
        .iter()
        .map(|port| format!("{sign}{port}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Addresses in the order a person reads them, not the order strings sort in.
///
/// A plain string sort puts `.100` before `.11`, which makes a device list look
/// shuffled for no reason.
fn ip_order(a: &str, b: &str) -> std::cmp::Ordering {
    match (IpAddr::from_str(a), IpAddr::from_str(b)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => a.cmp(b),
    }
}

// ------------------------------------------------------------------ json ---

fn print_json(
    older: &ScanMetadata,
    older_result: &ScanResult,
    newer: &ScanMetadata,
    newer_result: &ScanResult,
    changes: &[NetworkChange],
) -> Result<()> {
    let side = |scan: &ScanMetadata, result: &ScanResult| {
        serde_json::json!({
            "id": scan.id,
            "started_at": scan.started_at,
            "interface": result.config.interface,
            "target": result.config.target,
            "devices": result.devices.len(),
            "findings": total_findings(result),
            "score": HealthScore::from_result(result).score,
        })
    };

    let output = serde_json::json!({
        "from": side(older, older_result),
        "to": side(newer, newer_result),
        "changes": changes,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(id: &str, started_at: &str) -> ScanMetadata {
        ScanMetadata {
            id: id.to_string(),
            started_at: started_at.to_string(),
            interface: "eth0".to_string(),
            target: "192.168.1.0/24".to_string(),
            device_count: 0,
            finding_count: 0,
            critical_count: 0,
            high_count: 0,
            created_at: started_at.to_string(),
        }
    }

    fn sample() -> Vec<ScanMetadata> {
        // newest first, as `list_scans` returns them
        vec![
            scan("scan-300", "2026-12-28T10:00:00+00:00"),
            scan("scan-200", "2026-12-27T10:00:00+00:00"),
            scan("scan-100", "2026-12-26T10:00:00+00:00"),
        ]
    }

    #[test]
    fn latest_and_previous_are_relative() {
        assert_eq!(resolve(&sample(), "latest").unwrap(), 0);
        assert_eq!(resolve(&sample(), "previous").unwrap(), 1);
    }

    #[test]
    fn an_id_can_be_shortened_to_a_unique_prefix() {
        assert_eq!(resolve(&sample(), "scan-200").unwrap(), 1);
        assert_eq!(resolve(&sample(), "scan-2").unwrap(), 1);
    }

    #[test]
    fn a_prefix_that_fits_several_scans_is_refused() {
        let error = resolve(&sample(), "scan-").unwrap_err().to_string();
        assert!(error.contains("matches 3 scans"), "{error}");
    }

    #[test]
    fn an_unknown_reference_says_where_to_find_one() {
        let error = resolve(&sample(), "scan-999").unwrap_err().to_string();
        assert!(error.contains("report --history"), "{error}");
    }

    #[test]
    fn ports_are_grouped_per_address_and_sorted() {
        let groups = Groups::of(&[
            NetworkChange::NewService {
                ip: "192.168.1.100".into(),
                port: 445,
            },
            NetworkChange::NewService {
                ip: "192.168.1.9".into(),
                port: 80,
            },
            NetworkChange::NewService {
                ip: "192.168.1.100".into(),
                port: 22,
            },
        ]);

        let grouped = per_device(&groups.opened);
        assert_eq!(
            grouped,
            vec![
                ("192.168.1.9".to_string(), vec![80]),
                ("192.168.1.100".to_string(), vec![22, 445]),
            ]
        );
        assert_eq!(formatted_ports(&grouped[1].1, "+"), "+22 +445");
    }

    #[test]
    fn addresses_sort_numerically_not_lexically() {
        let mut ips = vec!["192.168.1.100", "192.168.1.9", "192.168.1.11"];
        ips.sort_by(|a, b| ip_order(a, b));
        assert_eq!(ips, vec!["192.168.1.9", "192.168.1.11", "192.168.1.100"]);
    }

    #[test]
    fn opening_and_closing_are_kept_apart() {
        let groups = Groups::of(&[
            NetworkChange::NewService {
                ip: "192.168.1.5".into(),
                port: 445,
            },
            NetworkChange::ServiceClosed {
                ip: "192.168.1.5".into(),
                port: 80,
            },
            NetworkChange::NewDevice {
                ip: "192.168.1.7".into(),
                hostname: Some("printer.lan".into()),
            },
        ]);

        assert_eq!(groups.opened, vec![("192.168.1.5".to_string(), 445)]);
        assert_eq!(groups.closed, vec![("192.168.1.5".to_string(), 80)]);
        assert_eq!(
            groups.new_devices,
            vec![("192.168.1.7".to_string(), Some("printer.lan".to_string()))]
        );
    }
}
