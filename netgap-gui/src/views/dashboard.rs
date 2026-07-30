//! The overview: is the network healthy, what is wrong, and what happened
//! recently.

use std::collections::HashMap;

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, RichText, Sense, Stroke, Ui, Vec2};
use netgap_core::{HealthScore, Severity};
use netgap_report::RiskSummary;

use crate::app::{NetgapApp, ScanChanges, Tab};
use crate::format::{self, SeverityCounts};
use crate::theme::{self, Palette};
use crate::widgets;

pub fn show(app: &mut NetgapApp, ui: &mut Ui) {
    let p = app.palette;

    widgets::page_header(
        ui,
        &p,
        "// 01 · OVERVIEW",
        "Dashboard",
        "Your network, and what needs attention.",
        |ui| {
            if widgets::primary_button(ui, &p, "Scan network") {
                app.tab = Tab::Scan;
            }
            if widgets::secondary_button(ui, &p, "Refresh") {
                app.refresh();
            }
        },
    );

    ui.add_space(18.0);

    if let Some(error) = app.store_error.clone() {
        warning_card(ui, &p, "History is unavailable", &error);
        ui.add_space(12.0);
    }

    let Some(snapshot) = snapshot(app) else {
        empty_state(app, ui, &p);
        return;
    };

    ui.columns(4, |columns| {
        widgets::kpi_card(
            &mut columns[0],
            &p,
            "Health score",
            format!("{}", snapshot.health.score),
            snapshot.health.risk_level().to_string(),
            widgets::score_color(&p, snapshot.health.score),
        );
        widgets::kpi_card(
            &mut columns[1],
            &p,
            "Devices",
            format!("{}", snapshot.devices),
            if snapshot.affected == 0 {
                "none with findings".to_string()
            } else {
                format!("{} with findings", snapshot.affected)
            },
            p.accent,
        );
        widgets::kpi_card(
            &mut columns[2],
            &p,
            "Critical",
            format!("{}", snapshot.counts.critical),
            if snapshot.counts.critical == 0 {
                "nothing critical".to_string()
            } else {
                "fix these first".to_string()
            },
            if snapshot.counts.critical == 0 {
                p.muted
            } else {
                p.critical
            },
        );
        widgets::kpi_card(
            &mut columns[3],
            &p,
            "High",
            format!("{}", snapshot.counts.high),
            format!("{} medium", snapshot.counts.medium),
            if snapshot.counts.high == 0 {
                p.muted
            } else {
                p.high
            },
        );
    });

    ui.add_space(14.0);

    ui.columns(2, |columns| {
        health_card(&mut columns[0], &p, &snapshot);
        severity_card(&mut columns[1], &p, &snapshot);
    });

    ui.add_space(14.0);

    ui.columns(2, |columns| {
        attention_card(app, &mut columns[0], &p, &snapshot);
        ports_card(&mut columns[1], &p, &snapshot);
    });

    ui.add_space(14.0);

    ui.columns(2, |columns| {
        changes_card(&mut columns[0], &p, &snapshot);
        composition_card(&mut columns[1], &p, &snapshot);
    });

    ui.add_space(14.0);

    ui.columns(2, |columns| {
        recent_card(app, &mut columns[0], &p);
        issues_card(&mut columns[1], &p, &snapshot);
    });
}

/// A device with findings, in the order the attention card lists them.
struct Attention {
    index: usize,
    ip: String,
    name: String,
    findings: usize,
    severity: Severity,
}

/// Everything the cards need, copied out of the scan once so the UI closures
/// do not hold a borrow of the whole result.
struct Snapshot {
    counts: SeverityCounts,
    health: HealthScore,
    devices: usize,
    affected: usize,
    last_scan: String,
    target: String,
    interface: String,
    issues: Vec<(Severity, String, &'static str)>,
    other_findings: usize,
    attention: Vec<Attention>,
    /// Port number, service name and how many devices answer on it.
    ports: Vec<(u16, &'static str, usize)>,
    open_ports: usize,
    devices_with_ports: usize,
    composition: Vec<(String, usize)>,
    discovery_only: bool,
    changes: Option<ScanChanges>,
}

fn snapshot(app: &NetgapApp) -> Option<Snapshot> {
    let scan = app.latest.as_ref()?;
    let counts = SeverityCounts::of(&scan.result);
    let health = HealthScore::from_result(&scan.result);
    let summary = RiskSummary::from_result(&scan.result);
    let affected = scan
        .result
        .devices
        .iter()
        .filter(|device| !device.findings.is_empty())
        .count();

    let mut attention: Vec<Attention> = scan
        .result
        .devices
        .iter()
        .enumerate()
        .filter(|(_, device)| !device.findings.is_empty())
        .map(|(index, device)| Attention {
            index,
            ip: device.ip.to_string(),
            name: format::device_name(device),
            findings: device.findings.len(),
            severity: format::worst_severity(device).unwrap_or(Severity::Info),
        })
        .collect();
    attention.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| b.findings.cmp(&a.findings))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    attention.truncate(5);

    let mut port_counts: HashMap<u16, usize> = HashMap::new();
    let mut open_ports = 0;
    let mut devices_with_ports = 0;
    for device in &scan.result.devices {
        if !device.open_ports.is_empty() {
            devices_with_ports += 1;
        }
        for port in &device.open_ports {
            *port_counts.entry(*port).or_default() += 1;
            open_ports += 1;
        }
    }
    let mut ports: Vec<(u16, &'static str, usize)> = port_counts
        .into_iter()
        .map(|(port, count)| (port, format::port_service(port).unwrap_or("service"), count))
        .collect();
    ports.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    ports.truncate(6);

    let mut type_counts: HashMap<String, usize> = HashMap::new();
    for device in &scan.result.devices {
        let kind = device
            .device_type
            .as_deref()
            .filter(|kind| !kind.is_empty())
            .map(profile_kind)
            .unwrap_or_else(|| "Unclassified".to_string());
        *type_counts.entry(kind).or_default() += 1;
    }
    let mut composition: Vec<(String, usize)> = type_counts.into_iter().collect();
    composition.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    composition.truncate(5);

    Some(Snapshot {
        counts,
        health,
        devices: scan.result.devices.len(),
        affected,
        last_scan: format::relative_time(&scan.result.started_at),
        target: scan.result.config.target.clone(),
        interface: scan.result.config.interface.clone(),
        issues: summary
            .issues
            .iter()
            .take(3)
            .map(|issue| (issue.severity, issue.what.clone(), issue.action))
            .collect(),
        other_findings: summary.other_findings,
        attention,
        ports,
        open_ports,
        devices_with_ports,
        composition,
        discovery_only: scan.result.config.discovery_only,
        changes: app.changes.clone(),
    })
}

fn health_card(ui: &mut Ui, p: &Palette, snapshot: &Snapshot) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(ui, p, "Network health", None);
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            widgets::health_ring(ui, p, snapshot.health.score, 156.0);
            ui.add_space(8.0);
            ui.vertical(|ui| {
                ui.add_space(14.0);
                ui.label(
                    RichText::new(snapshot.health.risk_level())
                        .size(20.0)
                        .strong()
                        .color(widgets::score_color(p, snapshot.health.score)),
                );
                ui.add_space(2.0);
                ui.label(
                    RichText::new(snapshot.health.verdict())
                        .size(13.0)
                        .color(p.text),
                );
                ui.add_space(10.0);
                ui.label(
                    RichText::new(format!("scanned {}", snapshot.last_scan))
                        .size(11.5)
                        .color(p.muted),
                );
                ui.label(
                    RichText::new(format!("{} · {}", snapshot.interface, snapshot.target))
                        .size(11.5)
                        .color(p.muted),
                );
            });
        });
    });
}

fn severity_card(ui: &mut Ui, p: &Palette, snapshot: &Snapshot) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(
            ui,
            p,
            "Findings by severity",
            Some("Groups of the same problem count once towards the score."),
        );
        ui.add_space(12.0);
        widgets::severity_bars(ui, p, snapshot.counts);
        ui.add_space(2.0);
        ui.separator();
        ui.add_space(6.0);

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format::findings(snapshot.counts.total()))
                    .size(13.0)
                    .strong()
                    .color(p.text),
            );
            ui.label(
                RichText::new(format!("across {}", format::devices(snapshot.devices)))
                    .size(12.0)
                    .color(p.muted),
            );
        });

        if snapshot.other_findings > 0 {
            ui.add_space(2.0);
            ui.label(
                RichText::new(format!(
                    "{} not described by the plain-language summary",
                    format::findings(snapshot.other_findings)
                ))
                .size(11.5)
                .color(p.muted),
            );
        }
    });
}

/// The worst devices, as a shortcut into the Devices screen.
fn attention_card(app: &mut NetgapApp, ui: &mut Ui, p: &Palette, snapshot: &Snapshot) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(
            ui,
            p,
            "Devices needing attention",
            Some("Worst findings first. Click one to inspect it."),
        );
        ui.add_space(8.0);

        if snapshot.attention.is_empty() {
            ui.label(
                RichText::new("No device has an open finding.")
                    .size(13.0)
                    .color(p.success),
            );
            ui.add_space(2.0);
            widgets::muted(
                ui,
                p,
                "That is the state to keep. Scan with port checks to look again.",
            );
            return;
        }

        let mut open = None;
        for entry in &snapshot.attention {
            if attention_row(ui, p, entry) {
                open = Some(entry.index);
            }
            ui.add_space(2.0);
        }

        if let Some(index) = open {
            app.open_device(index);
        }
    });
}

fn attention_row(ui: &mut Ui, p: &Palette, entry: &Attention) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 38.0), Sense::click());
    let painter = ui.painter().with_clip_rect(rect);
    let severity = p.severity(entry.severity);

    if response.hovered() {
        painter.rect_filled(rect, egui::CornerRadius::same(6), p.hover);
    }

    painter.circle_filled(Pos2::new(rect.left() + 9.0, rect.center().y), 4.0, severity);
    painter.text(
        Pos2::new(rect.left() + 21.0, rect.top() + 12.0),
        Align2::LEFT_CENTER,
        &entry.ip,
        FontId::monospace(11.5),
        p.text,
    );
    painter.text(
        Pos2::new(rect.left() + 21.0, rect.top() + 27.0),
        Align2::LEFT_CENTER,
        format::truncate(&entry.name, 30),
        FontId::proportional(10.5),
        p.muted,
    );
    painter.text(
        Pos2::new(rect.right() - 4.0, rect.center().y),
        Align2::RIGHT_CENTER,
        format::findings(entry.findings),
        FontId::proportional(10.5),
        severity,
    );

    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// The attack surface in one card: which ports answer, and on how many
/// devices.
fn ports_card(ui: &mut Ui, p: &Palette, snapshot: &Snapshot) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(
            ui,
            p,
            "Open ports",
            Some("What is listening, most common first."),
        );
        ui.add_space(8.0);

        if snapshot.discovery_only {
            widgets::muted(
                ui,
                p,
                "This scan only looked for devices, so no ports were checked.",
            );
            return;
        }

        if snapshot.ports.is_empty() {
            widgets::muted(ui, p, "No open ports were found in this scan.");
            ui.add_space(2.0);
            widgets::muted(
                ui,
                p,
                "Closed ports are good news: nothing is answering on the checked list.",
            );
            return;
        }

        ui.label(
            RichText::new(format!(
                "{} on {}",
                format::plural(snapshot.open_ports, "open port", "open ports"),
                format::devices(snapshot.devices_with_ports)
            ))
            .size(12.0)
            .color(p.muted),
        );
        ui.add_space(6.0);

        let max = snapshot
            .ports
            .iter()
            .map(|(_, _, count)| *count)
            .max()
            .unwrap_or(1);
        for (port, service, count) in &snapshot.ports {
            port_row(ui, p, *port, service, *count, max);
            ui.add_space(2.0);
        }
    });
}

fn port_row(ui: &mut Ui, p: &Palette, port: u16, service: &str, count: usize, max: usize) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 19.0), Sense::hover());
    let painter = ui.painter();

    painter.text(
        Pos2::new(rect.left(), rect.center().y),
        Align2::LEFT_CENTER,
        format!("{port}"),
        theme::mono(10.5),
        p.text,
    );
    painter.text(
        Pos2::new(rect.left() + 42.0, rect.center().y),
        Align2::LEFT_CENTER,
        service,
        theme::mono(9.0),
        p.muted,
    );

    let bar_left = rect.left() + 118.0;
    let bar_right = (rect.right() - 26.0).max(bar_left + 16.0);
    let track = Rect::from_min_max(
        Pos2::new(bar_left, rect.center().y - 2.5),
        Pos2::new(bar_right, rect.center().y + 2.5),
    );
    painter.rect_filled(track, egui::CornerRadius::same(2), p.track);

    let filled = track.width() * (count as f32 / max.max(1) as f32);
    painter.rect_filled(
        Rect::from_min_size(track.min, Vec2::new(filled.max(2.0), track.height())),
        egui::CornerRadius::same(2),
        p.accent,
    );

    painter.text(
        Pos2::new(rect.right(), rect.center().y),
        Align2::RIGHT_CENTER,
        format!("{count}"),
        theme::mono(10.0),
        p.muted,
    );
}

/// What changed between the newest scan and the one before it. The comparison
/// is by address: a device that DHCP moved looks new and its old address looks
/// gone, which is what the note under the rows is for.
fn changes_card(ui: &mut Ui, p: &Palette, snapshot: &Snapshot) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(
            ui,
            p,
            "Since the last scan",
            Some("New and missing devices, and how critical findings changed."),
        );
        ui.add_space(8.0);

        let Some(changes) = &snapshot.changes else {
            widgets::muted(
                ui,
                p,
                "This is the first recorded scan. The next one will show what changed.",
            );
            return;
        };

        ui.label(
            RichText::new(format!(
                "Compared with the scan from {}.",
                changes.previous_when
            ))
            .size(11.5)
            .color(p.muted),
        );
        ui.add_space(8.0);

        let mut rows = 0;
        for ip in changes.new_devices.iter().take(3) {
            change_row(ui, p, "+", p.success, format!("{ip}  first seen"));
            rows += 1;
        }
        if changes.new_devices.len() > 3 {
            widgets::muted(
                ui,
                p,
                format!(
                    "and {} more new {}",
                    changes.new_devices.len() - 3,
                    if changes.new_devices.len() - 3 == 1 {
                        "device"
                    } else {
                        "devices"
                    },
                ),
            );
        }
        for ip in changes.missing_devices.iter().take(3) {
            change_row(ui, p, "−", p.high, format!("{ip}  not seen this time"));
            rows += 1;
        }
        if changes.missing_devices.len() > 3 {
            widgets::muted(
                ui,
                p,
                format!(
                    "and {} more missing {}",
                    changes.missing_devices.len() - 3,
                    if changes.missing_devices.len() - 3 == 1 {
                        "device"
                    } else {
                        "devices"
                    },
                ),
            );
        }

        if rows == 0 {
            ui.label(
                RichText::new("The same devices answered as before.")
                    .size(12.0)
                    .color(p.success),
            );
        }

        if changes.critical_in_scan > 0 || changes.critical_gone > 0 {
            ui.add_space(6.0);
            if changes.critical_in_scan > 0 {
                ui.label(
                    RichText::new(format!(
                        "{} in this scan",
                        format::plural(
                            changes.critical_in_scan,
                            "critical finding",
                            "critical findings",
                        )
                    ))
                    .size(12.0)
                    .color(p.critical),
                );
            }
            if changes.critical_gone > 0 {
                ui.label(
                    RichText::new(format!(
                        "{} no longer seen",
                        format::plural(
                            changes.critical_gone,
                            "critical finding",
                            "critical findings",
                        )
                    ))
                    .size(12.0)
                    .color(p.success),
                );
            }
        }

        ui.add_space(4.0);
        widgets::muted(
            ui,
            p,
            "Compared by address, so a device DHCP moved can look new and gone at once.",
        );
    });
}

fn change_row(ui: &mut Ui, p: &Palette, sign: &str, color: Color32, text: String) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [14.0, 16.0],
            egui::Label::new(RichText::new(sign).font(theme::mono(12.0)).color(color)),
        );
        ui.label(RichText::new(text).font(theme::mono(10.5)).color(p.text));
    });
}

/// The classifier adds its reason in brackets ("private MAC"). The profile is
/// about the kind of device, so the reason is dropped and the kinds are
/// counted together.
fn profile_kind(label: &str) -> String {
    let base = label.split(" (").next().unwrap_or(label).trim();
    if base.is_empty() {
        "Unclassified".to_string()
    } else {
        base.to_string()
    }
}

/// What kinds of device the scan found. A rough census, not a security
/// finding, but it is how a person notices the thing that does not belong.
fn composition_card(ui: &mut Ui, p: &Palette, snapshot: &Snapshot) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(
            ui,
            p,
            "Network profile",
            Some("What kinds of device this scan found."),
        );
        ui.add_space(8.0);

        if snapshot.composition.is_empty() {
            widgets::muted(ui, p, "This scan found no devices to classify.");
            return;
        }

        let max = snapshot
            .composition
            .iter()
            .map(|(_, count)| *count)
            .max()
            .unwrap_or(1);
        for (kind, count) in &snapshot.composition {
            composition_row(ui, p, kind, *count, max);
            ui.add_space(2.0);
        }
    });
}

fn composition_row(ui: &mut Ui, p: &Palette, label: &str, count: usize, max: usize) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 19.0), Sense::hover());
    let painter = ui.painter();

    painter.text(
        Pos2::new(rect.left(), rect.center().y),
        Align2::LEFT_CENTER,
        format::truncate(label, 26),
        FontId::proportional(11.5),
        p.text,
    );

    let bar_left = rect.left() + 156.0;
    let bar_right = (rect.right() - 26.0).max(bar_left + 16.0);
    let track = Rect::from_min_max(
        Pos2::new(bar_left, rect.center().y - 2.5),
        Pos2::new(bar_right, rect.center().y + 2.5),
    );
    painter.rect_filled(track, egui::CornerRadius::same(2), p.track);

    let filled = track.width() * (count as f32 / max.max(1) as f32);
    painter.rect_filled(
        Rect::from_min_size(track.min, Vec2::new(filled.max(2.0), track.height())),
        egui::CornerRadius::same(2),
        p.accent,
    );

    painter.text(
        Pos2::new(rect.right(), rect.center().y),
        Align2::RIGHT_CENTER,
        format!("{count}"),
        theme::mono(10.0),
        p.muted,
    );
}

fn recent_card(app: &mut NetgapApp, ui: &mut Ui, p: &Palette) {
    let recent: Vec<_> = app.scans.iter().take(5).cloned().collect();

    widgets::card(ui, p, |ui| {
        ui.horizontal(|ui| {
            widgets::section_heading(ui, p, "Recent scans", None);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::secondary_button(ui, p, "View all") {
                    app.tab = Tab::History;
                }
            });
        });
        ui.add_space(8.0);

        if recent.is_empty() {
            widgets::muted(ui, p, "No scans have been recorded yet.");
            return;
        }

        let mut open: Option<String> = None;
        for scan in &recent {
            if scan_row(ui, p, scan) {
                open = Some(scan.id.clone());
            }
            ui.add_space(2.0);
        }

        if let Some(id) = open {
            app.open_scan(&id);
            app.tab = Tab::History;
        }
    });
}

fn scan_row(ui: &mut Ui, p: &Palette, scan: &netgap_storage::ScanMetadata) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 32.0), Sense::click());
    let painter = ui.painter();

    if response.hovered() {
        painter.rect_filled(rect, egui::CornerRadius::same(7), p.hover);
    }

    painter.text(
        Pos2::new(rect.left() + 8.0, rect.center().y),
        Align2::LEFT_CENTER,
        format::short_time(&scan.created_at),
        FontId::proportional(12.0),
        p.muted,
    );
    painter.text(
        Pos2::new(rect.left() + 108.0, rect.center().y),
        Align2::LEFT_CENTER,
        format::truncate(&scan.target, 22),
        FontId::proportional(12.5),
        p.text,
    );
    painter.text(
        Pos2::new(rect.right() - 8.0, rect.center().y),
        Align2::RIGHT_CENTER,
        format!(
            "{} · {}",
            format::devices(scan.device_count.max(0) as usize),
            format::findings(scan.finding_count.max(0) as usize)
        ),
        FontId::proportional(11.0),
        if scan.critical_count > 0 {
            p.critical
        } else {
            p.muted
        },
    );

    response.clicked()
}

fn issues_card(ui: &mut Ui, p: &Palette, snapshot: &Snapshot) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(
            ui,
            p,
            "What to fix first",
            Some("The worst problems, in plain language."),
        );
        ui.add_space(10.0);

        if snapshot.issues.is_empty() {
            if snapshot.counts.critical + snapshot.counts.high + snapshot.counts.medium == 0 {
                ui.label(
                    RichText::new("Nothing to act on in this scan.")
                        .size(13.0)
                        .color(p.success),
                );
                widgets::muted(
                    ui,
                    p,
                    "An open port nobody needs is still worth closing, even when it is not a finding here.",
                );
            } else {
                widgets::muted(ui, p, "The findings are below; no summary advice applies.");
            }
            return;
        }

        for (severity, what, action) in &snapshot.issues {
            ui.horizontal_top(|ui| {
                widgets::severity_chip(ui, p, *severity);
                ui.vertical(|ui| {
                    ui.label(RichText::new(what).size(12.5).color(p.text));
                    ui.label(RichText::new(*action).size(11.0).color(p.muted));
                });
            });
            ui.add_space(7.0);
        }
    });
}

fn warning_card(ui: &mut Ui, p: &Palette, title: &str, body: &str) {
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.medium))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("!").strong().color(p.medium));
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(13.0).strong().color(p.text));
                    ui.label(RichText::new(body).size(11.5).color(p.muted));
                });
            });
        });
}

fn empty_state(app: &mut NetgapApp, ui: &mut Ui, p: &Palette) {
    ui.add_space(40.0);

    ui.vertical_centered(|ui| {
        widgets::logo_mark(ui, p, 88.0);

        ui.add_space(12.0);
        ui.label(
            RichText::new("No scans yet")
                .size(22.0)
                .strong()
                .color(p.text),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Scan your network once and this page fills in: every device, \
                 what is exposed, and how the score moves over time.",
            )
            .size(13.0)
            .color(p.muted),
        );
        ui.add_space(16.0);

        if widgets::primary_button(ui, p, "Scan your network") {
            app.tab = Tab::Scan;
        }
        ui.add_space(10.0);
        ui.label(
            RichText::new(
                "Nothing leaves this computer. Results are kept in the same \
                 history the command line uses.",
            )
            .size(11.0)
            .color(p.muted),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::profile_kind;

    #[test]
    fn profile_kind_drops_the_reason() {
        assert_eq!(
            profile_kind("Phone / laptop (private MAC)"),
            "Phone / laptop"
        );
        assert_eq!(profile_kind("Router / gateway"), "Router / gateway");
        assert_eq!(profile_kind(""), "Unclassified");
    }
}
