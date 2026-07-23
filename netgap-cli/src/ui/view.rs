//! Drawing for the interactive view.
//!
//! The whole frame is built as a list of lines and written once per redraw, so
//! the cursor never lands where a scan's output could appear. Lines are cut to
//! the terminal width before they reach the screen; a row that does not fit is
//! shortened rather than wrapped, because a wrapped row makes the columns
//! below it lie.

use super::{App, ScanMode, Screen};
use anyhow::Result;
use colored::Colorize;
use crossterm::cursor;
use crossterm::execute;
use crossterm::terminal::{self, ClearType};
use netgap_core::{Device, Severity};
use netgap_interfaces::InterfaceInfo;
use std::io::{stdout, Write};

/// Braille would be prettier and is not worth the font problem.
const SPINNER: [&str; 4] = ["|", "/", "-", "\\"];

/// Draw one frame.
pub(super) fn render(app: &App) -> Result<()> {
    let (columns, rows) = terminal::size()?;
    let width = (columns as usize).max(40);
    let height = (rows as usize).max(8);

    // Header, two rules, status and keys are always on screen; the body gets
    // what is left.
    let body_height = height.saturating_sub(5).max(1);

    let mut body = if app.help {
        help_body()
    } else {
        match app.screen {
            Screen::Interfaces => interfaces_body(app, body_height),
            Screen::Options => options_body(app),
            Screen::Scanning => scanning_body(app),
            Screen::Devices => devices_body(app, body_height),
            Screen::Scans => scans_body(app, body_height),
        }
    };

    body.truncate(body_height);
    while body.len() < body_height {
        body.push(String::new());
    }

    let mut lines = Vec::with_capacity(height);
    lines.push(fit(&header(app, width), width));
    lines.push(rule(width));
    lines.extend(body.into_iter().map(|line| fit(&line, width)));
    lines.push(rule(width));
    lines.push(fit(&status(app), width));
    lines.push(fit(&footer(app), width));

    lines.truncate(height);
    while lines.len() < height {
        lines.push(String::new());
    }

    let mut out = stdout();
    execute!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All))?;
    write!(out, "{}", lines.join("\r\n"))?;
    out.flush()?;
    Ok(())
}

fn header(app: &App, width: usize) -> String {
    let left = " netgap  network overview";
    let right = match app.screen {
        Screen::Interfaces | Screen::Options | Screen::Scanning => "1 Interfaces   2 Saved scans",
        Screen::Scans => "1 Interfaces  [2 Saved scans]",
        Screen::Devices => {
            if app.saved_scan.is_some() {
                "1 Interfaces  [2 Saved scans]  [3 Devices]"
            } else {
                "1 Interfaces  [3 Devices]"
            }
        }
    };
    let padding = width.saturating_sub(left.chars().count() + right.chars().count());
    let line = format!("{left}{}{right}", " ".repeat(padding));
    // Fitted here rather than in `render` so a narrow terminal cannot push the
    // tabs off the line.
    fit(&line, width).bold().to_string()
}

fn rule(width: usize) -> String {
    "─".repeat(width).dimmed().to_string()
}

fn status(app: &App) -> String {
    if app.status.is_empty() {
        " Ready.".dimmed().to_string()
    } else {
        format!(" {}", app.status).yellow().to_string()
    }
}

fn footer(app: &App) -> String {
    if app.help {
        return " ? or Esc close help    q quit".dimmed().to_string();
    }

    let keys = match app.screen {
        Screen::Interfaces => {
            " ↑↓ select   Enter scan options   a filter   d saved scans   r refresh   ? help   q quit"
        }
        Screen::Options => {
            " ↑↓ scan type   ←→ discovery method   Enter start   Esc back   ? help   q quit"
        }
        Screen::Scanning => " Esc stop   q quit",
        Screen::Devices => {
            " ↑↓ device   i interfaces   s saved scans   Esc back   ? help   q quit"
        }
        Screen::Scans => " ↑↓ select   Enter open   r refresh   i interfaces   ? help   q quit",
    };
    keys.dimmed().to_string()
}

// ── Interfaces ─────────────────────────────────────────────────────────────

fn interfaces_body(app: &App, body_height: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let visible = app.visible_interfaces();
    let filter = if app.show_all {
        "all interfaces"
    } else {
        "network interfaces"
    };
    lines.push(
        format!(
            " Interfaces — {filter} ({} of {})",
            visible.len(),
            app.interfaces.len()
        )
        .bold()
        .to_string(),
    );
    lines.push(String::new());

    // The details pane is the reason a selected row is useful; on a short
    // terminal the list is the reason the screen exists, so it wins.
    let show_details = body_height >= 14;
    let detail_height = if show_details { 8 } else { 0 };
    let list_height = body_height
        .saturating_sub(lines.len() + detail_height)
        .max(2);

    lines.push(
        format!(
            "   {} {} {} {}",
            cell("NAME", 20),
            cell("ADDRESS", 20),
            cell("TYPE", 10),
            "NOTES"
        )
        .dimmed()
        .to_string(),
    );

    if visible.is_empty() {
        lines.push("   No interfaces match this filter. Press 'a' to show all.".to_string());
    } else {
        let position = visible
            .iter()
            .position(|&index| index == app.selected)
            .unwrap_or(0);
        let start = position.saturating_sub(list_height.saturating_sub(1));

        for &index in visible.iter().skip(start).take(list_height) {
            let interface = &app.interfaces[index];
            let marker = if index == app.selected { ">" } else { " " };
            let address = interface
                .cidr
                .as_deref()
                .or(interface.ipv4.as_deref())
                .unwrap_or("—");
            lines.push(format!(
                " {marker} {} {} {} {}",
                cell(&interface.name, 20),
                cell(address, 20),
                cell(interface_kind(interface), 10),
                interface_notes(interface)
            ));
        }
    }

    if show_details {
        lines.push(String::new());
        lines.push(
            " ── Selected ───────────────────────────────────────"
                .dimmed()
                .to_string(),
        );

        if let Some(interface) = app.selected_interface() {
            lines.push(format!(
                "   {:<11} {}",
                "Address",
                interface.ipv4.as_deref().unwrap_or("—")
            ));
            lines.push(format!(
                "   {:<11} {}",
                "Network",
                interface.cidr.as_deref().unwrap_or("—")
            ));
            lines.push(format!(
                "   {:<11} {}",
                "MAC",
                interface.mac.as_deref().unwrap_or("—")
            ));
            lines.push(format!(
                "   {:<11} {}",
                "Status",
                interface_notes(interface)
            ));
            lines.push(format!("   {:<11} {}", "Discovery", app.discovery_label()));
        } else {
            lines.push("   Nothing selected.".to_string());
        }
    }

    lines
}

fn interface_kind(interface: &InterfaceInfo) -> &'static str {
    if interface.is_loopback {
        "loopback"
    } else if interface.is_virtual() {
        "virtual"
    } else if interface.is_physical() {
        "physical"
    } else {
        "other"
    }
}

fn interface_notes(interface: &InterfaceInfo) -> String {
    let mut notes = Vec::new();
    notes.push(if interface.is_up { "up" } else { "down" });
    if interface.is_lower_up {
        notes.push("carrier");
    }
    if interface.is_default_route {
        notes.push("default route");
    }
    notes.join(", ")
}

// ── Options ────────────────────────────────────────────────────────────────

fn options_body(app: &App) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(" Scan options".bold().to_string());
    lines.push(String::new());

    match app.selected_interface() {
        Some(interface) => {
            lines.push(format!(
                "   {:<12}{}  ·  {}",
                "Interface",
                interface.name,
                interface.cidr.as_deref().unwrap_or("no IPv4 network")
            ));
            lines.push(format!("   {:<12}{}", "Type", interface_notes(interface)));
        }
        None => lines.push("   No interface selected.".to_string()),
    }

    lines.push(format!(
        "   {:<12}< {} >",
        "Discovery",
        app.discovery_label()
    ));
    lines.push(format!("   {:<12}< {} >", "Scan type", app.mode.label()));
    lines.push(String::new());
    lines.push(format!("   {}", app.mode.detail()));
    lines.push(String::new());

    if app.mode == ScanMode::Ports {
        lines.push(
            "   A port scan sends a connection attempt to each common service port."
                .dimmed()
                .to_string(),
        );
    } else {
        lines.push(
            "   Switch to 'Ports & findings' with ↑/↓ to also scan for open services."
                .dimmed()
                .to_string(),
        );
    }

    lines
}

// ── Scanning ───────────────────────────────────────────────────────────────

fn scanning_body(app: &App) -> Vec<String> {
    let spinner = SPINNER[app.spinner % SPINNER.len()];
    let mut lines = Vec::new();
    lines.push(" Scanning".bold().to_string());
    lines.push(String::new());

    if let Some(interface) = app.selected_interface() {
        lines.push(format!("   {:<12}{}", "Interface", interface.name));
        lines.push(format!(
            "   {:<12}{}",
            "Target",
            interface.cidr.as_deref().unwrap_or("—")
        ));
    }
    lines.push(format!("   {:<12}{}", "Discovery", app.discovery_label()));
    lines.push(format!("   {:<12}{}", "Mode", app.mode.label()));
    lines.push(String::new());
    lines.push(format!("   {spinner}  {}", app.stage).bold().to_string());
    lines.push(String::new());
    lines.push(
        "   Esc stops the scan; anything already found is discarded."
            .dimmed()
            .to_string(),
    );

    lines
}

// ── Devices ────────────────────────────────────────────────────────────────

fn devices_body(app: &App, body_height: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let title = match &app.saved_scan {
        Some(metadata) => format!(
            " Saved scan {} — {} on {} ({})",
            metadata.id,
            short_date(&metadata.started_at),
            metadata.interface,
            metadata.target
        ),
        None => match app.selected_interface() {
            Some(interface) => format!(
                " Devices — {} ({})",
                interface.name,
                interface.cidr.as_deref().unwrap_or("unknown network")
            ),
            None => " Devices".to_string(),
        },
    };
    lines.push(title.bold().to_string());
    lines.push(String::new());

    if app.devices.is_empty() {
        lines.push("   No devices were found.".to_string());
        lines
            .push("   Esc goes back; 'a' on the interface list shows every interface.".to_string());
        return lines;
    }

    let show_details = body_height >= 15;
    let detail_height = if show_details { 10 } else { 0 };
    let list_height = body_height
        .saturating_sub(lines.len() + 1 + detail_height)
        .max(2);

    lines.push(
        format!(
            "   {} {} {} {} {}",
            cell("ADDRESS", 16),
            cell("NAME / TYPE", 20),
            cell("VENDOR", 16),
            cell("PORTS", 14),
            "FINDINGS"
        )
        .dimmed()
        .to_string(),
    );

    let position = app.device_selected.min(app.devices.len() - 1);
    let start = position.saturating_sub(list_height.saturating_sub(1));
    for (index, device) in app.devices.iter().enumerate().skip(start).take(list_height) {
        let marker = if index == position { ">" } else { " " };
        let findings = if device.findings.is_empty() {
            "—".to_string()
        } else {
            device.findings.len().to_string()
        };
        lines.push(format!(
            " {marker} {} {} {} {} {}",
            cell(&device.ip.to_string(), 16),
            cell(device_name(device), 20),
            cell(device.vendor.as_deref().unwrap_or("—"), 16),
            cell(&ports_summary(&device.open_ports), 14),
            findings
        ));
    }

    if show_details {
        if let Some(device) = app.devices.get(position) {
            lines.push(String::new());
            lines.push(
                format!(
                    " ── {} ──────────────────────────────────────────────",
                    device.ip
                )
                .dimmed()
                .to_string(),
            );
            lines.push(format!(
                "   {:<12}{}  ·  {}",
                "Name",
                device_name(device),
                device.mac.as_deref().unwrap_or("MAC unknown")
            ));
            lines.push(format!(
                "   {:<12}{}{}",
                "Hardware",
                device.vendor.as_deref().unwrap_or("vendor unknown"),
                device
                    .device_type
                    .as_deref()
                    .map(|kind| format!("  ·  {kind}"))
                    .unwrap_or_default()
            ));
            lines.push(format!(
                "   {:<12}{}{}",
                "System",
                device.os,
                if device.os_confidence > 0.0 {
                    format!(" ({:.0}%)", device.os_confidence * 100.0)
                } else {
                    String::new()
                }
            ));
            lines.push(format!(
                "   {:<12}{}",
                "Ports",
                if device.open_ports.is_empty() {
                    "none open".to_string()
                } else {
                    device
                        .open_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
            if let Some(ipv6) = device.ipv6_addresses.first() {
                lines.push(format!("   {:<12}{}", "IPv6", ipv6));
            }
            lines.push(findings_heading(device));
            for finding in device.findings.iter().take(2) {
                lines.push(format!(
                    "     {}  {}",
                    severity_mark(finding.severity),
                    finding.title
                ));
            }
        }
    }

    lines
}

fn findings_heading(device: &Device) -> String {
    if device.findings.is_empty() {
        return "   Findings    none".to_string();
    }
    let extra = device.findings.len().saturating_sub(2);
    if extra == 0 {
        format!("   Findings    {}", device.findings.len())
    } else {
        format!(
            "   Findings    {} ({extra} not shown)",
            device.findings.len()
        )
    }
}

fn device_name(device: &Device) -> &str {
    device
        .hostname
        .as_deref()
        .or(device.device_type.as_deref())
        .unwrap_or("Unknown")
}

fn ports_summary(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "—".to_string();
    }
    let shown: Vec<String> = ports.iter().take(4).map(u16::to_string).collect();
    let mut summary = shown.join(", ");
    if ports.len() > 4 {
        summary.push_str(&format!(" +{}", ports.len() - 4));
    }
    summary
}

fn severity_mark(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRIT",
        Severity::High => "HIGH",
        Severity::Medium => "MED ",
        Severity::Info => "INFO",
    }
}

// ── Saved scans ────────────────────────────────────────────────────────────

fn scans_body(app: &App, body_height: usize) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(
        format!(" Saved scans ({})", app.scans.len())
            .bold()
            .to_string(),
    );
    lines.push(String::new());

    if app.scans.is_empty() {
        lines.push("   No scans recorded yet.".to_string());
        lines.push("   Go back with Esc and run one from the interface list.".to_string());
        return lines;
    }

    lines.push(
        format!(
            "   {} {} {} {} {}",
            cell("DATE", 16),
            cell("ID", 18),
            cell("TARGET", 18),
            cell("DEVICES", 7),
            "FINDINGS"
        )
        .dimmed()
        .to_string(),
    );

    let show_detail = body_height >= 10;
    let list_height = body_height
        .saturating_sub(lines.len() + if show_detail { 2 } else { 0 })
        .max(2);
    let start = app
        .scan_selected
        .saturating_sub(list_height.saturating_sub(1));
    for (index, scan) in app.scans.iter().enumerate().skip(start).take(list_height) {
        let marker = if index == app.scan_selected { ">" } else { " " };
        lines.push(format!(
            " {marker} {} {} {} {} {}",
            cell(&short_date(&scan.started_at), 16),
            cell(&scan.id, 18),
            cell(&scan.target, 18),
            cell(&format!("{}", scan.device_count), 7),
            scan.finding_count
        ));
    }

    if show_detail {
        if let Some(scan) = app.scans.get(app.scan_selected) {
            lines.push(String::new());
            lines.push(format!(
                " Selected  {}  ·  {}  ·  {} device(s), {} finding(s)",
                scan.id, scan.interface, scan.device_count, scan.finding_count
            ));
        }
    }

    lines
}

fn short_date(timestamp: &str) -> String {
    // RFC 3339 to the minute: enough to tell two scans apart, and no
    // seconds to push a wider column off the screen.
    timestamp
        .replace('T', " ")
        .chars()
        .take(16)
        .collect::<String>()
}

// ── Help ───────────────────────────────────────────────────────────────────

fn help_body() -> Vec<String> {
    vec![
        " Keyboard".bold().to_string(),
        String::new(),
        "   ↑ / ↓  or  k / j   move the selection".to_string(),
        "   Enter             open the selection, or start a scan".to_string(),
        "   Esc               go back, or stop a running scan".to_string(),
        "   a                 show every interface / only scannable ones".to_string(),
        "   ← / →  or  m       change how devices are found".to_string(),
        "   d or s             open the saved scans".to_string(),
        "   i                  return to the interfaces".to_string(),
        "   r                  reload the current list".to_string(),
        "   ?                  open or close this help".to_string(),
        "   q or Ctrl-C        quit".to_string(),
        String::new(),
        " Scanning records every run in the same history `netgap report` reads."
            .dimmed()
            .to_string(),
    ]
}

// ── Text helpers ───────────────────────────────────────────────────────────

/// Shorten a line to the terminal width, keeping colour when it fits.
///
/// Cutting in the middle of an escape sequence would leave the terminal in
/// whatever colour the sequence set, so a line that needs shortening is
/// stripped of colour first.
fn fit(text: &str, width: usize) -> String {
    let visible = strip_ansi(text);
    if visible.chars().count() <= width {
        return text.to_string();
    }

    let mut shortened: String = visible.chars().take(width.saturating_sub(1)).collect();
    shortened.push('…');
    shortened
}

/// Pad or shorten a fixed-width table cell.
///
/// A shortened cell ends in an ellipsis, so "Phone / laptop (privacy)" reads
/// as a cut name rather than as a device genuinely called "Phone / laptop
/// (priv".
fn cell(text: &str, width: usize) -> String {
    let shown: String = if text.chars().count() > width {
        let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
        cut.push('…');
        cut
    } else {
        text.to_string()
    };
    format!("{shown:<width$}")
}

fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character == '\x1b' {
            // Skip a CSI sequence: ESC [ ... final byte.
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(character);
        }
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::{Finding, OsType};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_fit_leaves_a_short_line_alone() {
        let line = "hello".green().to_string();
        assert_eq!(fit(&line, 20), line);
    }

    #[test]
    fn test_fit_shortens_a_long_line() {
        let fitted = fit("abcdefghij", 5);
        assert_eq!(fitted, "abcd…");
        assert_eq!(strip_ansi(&fitted).chars().count(), 5);
    }

    #[test]
    fn test_fit_drops_colour_only_when_it_must() {
        let long = "abcdefghij".red().to_string();
        let fitted = fit(&long, 5);
        assert!(!fitted.contains('\x1b'), "colour must not survive a cut");
        assert_eq!(fitted, "abcd…");
    }

    #[test]
    fn test_strip_ansi_removes_colour_codes() {
        assert_eq!(strip_ansi(&"hello".red().to_string()), "hello");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn test_cell_pads_and_cuts() {
        assert_eq!(cell("abc", 5), "abc  ");
        assert_eq!(cell("abcdef", 4), "abc…");
        assert_eq!(cell("abcdef", 6), "abcdef");
    }

    #[test]
    fn test_ports_summary_reports_the_overflow() {
        assert_eq!(ports_summary(&[]), "—");
        assert_eq!(ports_summary(&[22]), "22");
        assert_eq!(
            ports_summary(&[22, 80, 443, 445, 3389]),
            "22, 80, 443, 445 +1"
        );
    }

    #[test]
    fn test_severity_marks_are_fixed_width() {
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Info,
        ] {
            assert_eq!(severity_mark(severity).chars().count(), 4);
        }
    }

    #[test]
    fn test_short_date_drops_the_timezone_and_the_seconds() {
        assert_eq!(short_date("2026-11-03T12:34:56+05:45"), "2026-11-03 12:34");
    }

    #[test]
    fn test_device_name_falls_back_through_what_is_known() {
        let mut device = Device::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(device_name(&device), "Unknown");
        device.device_type = Some("printer".to_string());
        assert_eq!(device_name(&device), "printer");
        device.hostname = Some("office-printer".to_string());
        assert_eq!(device_name(&device), "office-printer");
    }

    #[test]
    fn test_findings_heading_counts_what_is_not_shown() {
        let mut device = Device::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(findings_heading(&device), "   Findings    none");

        device.add_finding(finding("one"));
        device.add_finding(finding("two"));
        assert_eq!(findings_heading(&device), "   Findings    2");

        device.add_finding(finding("three"));
        assert_eq!(findings_heading(&device), "   Findings    3 (1 not shown)");
    }

    fn finding(title: &str) -> Finding {
        Finding {
            id: format!("finding-{title}"),
            title: title.to_string(),
            description: String::new(),
            severity: Severity::High,
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            port: Some(445),
            service: None,
            remediation: String::new(),
            confidence: 1.0,
        }
    }

    #[test]
    fn test_os_display_is_not_the_debug_name() {
        assert_eq!(OsType::Linux.to_string(), "Linux");
    }
}
