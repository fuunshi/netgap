//! The overview: is the network healthy, what is wrong, and what happened
//! recently.

use eframe::egui::{self, Align2, FontId, Pos2, RichText, Sense, Stroke, Ui, Vec2};
use netgap_core::{HealthScore, Severity};
use netgap_report::RiskSummary;

use crate::app::{NetgapApp, Tab};
use crate::format::{self, SeverityCounts};
use crate::theme::Palette;
use crate::widgets;

pub fn show(app: &mut NetgapApp, ui: &mut Ui) {
    let p = app.palette;

    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new("Overview").size(26.0).strong().color(p.text));
            ui.label(
                RichText::new("Your network, and what needs attention.")
                    .size(13.5)
                    .color(p.muted),
            );
        });

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if widgets::primary_button(ui, &p, "Scan network") {
                app.tab = Tab::Scan;
            }
        });
    });

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
        recent_card(app, &mut columns[0], &p);
        issues_card(&mut columns[1], &p, &snapshot);
    });
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
                    RichText::new(format!("Last scan {}", snapshot.last_scan))
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
        .stroke(Stroke::new(1.0, p.medium))
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
        let (rect, _) = ui.allocate_exact_size(Vec2::new(72.0, 72.0), Sense::hover());
        let painter = ui.painter();
        painter.circle_filled(rect.center(), 34.0, p.accent_soft);
        painter.circle_stroke(rect.center(), 34.0, Stroke::new(1.5, p.accent));
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "◎",
            FontId::proportional(30.0),
            p.accent,
        );

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
