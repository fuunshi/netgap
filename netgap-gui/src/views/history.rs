//! Every scan that has been recorded, and how the numbers moved.

use eframe::egui::{self, Align2, FontId, Pos2, RichText, Sense, Ui, Vec2};
use netgap_core::HealthScore;

use crate::app::{NetgapApp, Tab};
use crate::format::{self, SeverityCounts};
use crate::theme::Palette;
use crate::widgets;

pub fn show(app: &mut NetgapApp, ui: &mut Ui) {
    let p = app.palette;

    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new("History").size(26.0).strong().color(p.text));
            ui.label(
                RichText::new("Every scan is kept in the same database the command line writes.")
                    .size(13.5)
                    .color(p.muted),
            );
        });
    });

    ui.add_space(16.0);

    if let Some(error) = app.store_error.clone() {
        widgets::card(ui, &p, |ui| {
            ui.label(RichText::new(error).size(12.0).color(p.high));
        });
        ui.add_space(12.0);
    }

    if app.scans.is_empty() {
        empty_state(app, ui, &p);
        return;
    }

    let scans = app.scans.clone();
    let total_findings: i64 = scans.iter().map(|scan| scan.finding_count as i64).sum();
    let total_critical: i64 = scans.iter().map(|scan| scan.critical_count as i64).sum();
    let oldest = scans
        .last()
        .map(|scan| format::date_only(&scan.created_at))
        .unwrap_or_else(|| "—".to_string());

    ui.columns(4, |columns| {
        widgets::kpi_card(
            &mut columns[0],
            &p,
            "Scans recorded",
            format!("{}", scans.len()),
            format!("oldest {oldest}"),
            p.accent,
        );
        widgets::kpi_card(
            &mut columns[1],
            &p,
            "Devices ever seen",
            format!("{}", app.seen_devices),
            "recognised across scans".to_string(),
            p.info,
        );
        widgets::kpi_card(
            &mut columns[2],
            &p,
            "Findings recorded",
            format!("{total_findings}"),
            "across all scans".to_string(),
            p.text,
        );
        widgets::kpi_card(
            &mut columns[3],
            &p,
            "Critical records",
            format!("{total_critical}"),
            if total_critical == 0 {
                "none recorded".to_string()
            } else {
                "worst kind, repeated across scans".to_string()
            },
            if total_critical == 0 {
                p.muted
            } else {
                p.critical
            },
        );
    });

    ui.add_space(14.0);

    widgets::card(ui, &p, |ui| {
        ui.horizontal(|ui| {
            widgets::section_heading(
                ui,
                &p,
                "Findings over time",
                Some("The last twelve scans, oldest on the left."),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                legend(ui, &p, p.critical, "critical");
                legend(ui, &p, p.accent_soft, "all findings");
            });
        });
        ui.add_space(8.0);
        widgets::trend_chart(ui, &p, &scans, 150.0);
    });

    ui.add_space(14.0);

    let detail = selected_detail(app);
    ui.columns(2, |columns| {
        scans_card(app, &mut columns[0], &p, &scans);
        if let Some(detail) = detail {
            detail_card(app, &mut columns[1], &p, &detail);
        }
    });
}

fn legend(ui: &mut Ui, p: &Palette, color: egui::Color32, label: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(9.0, 9.0), Sense::hover());
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(2), color);
        ui.label(RichText::new(label).size(10.5).color(p.muted));
    });
}

struct Detail {
    health: HealthScore,
    counts: SeverityCounts,
    devices: usize,
    target: String,
    interface: String,
    when: String,
    id: Option<String>,
}

fn selected_detail(app: &NetgapApp) -> Option<Detail> {
    let scan = app.current()?;
    let counts = SeverityCounts::of(&scan.result);
    let health = HealthScore::from_result(&scan.result);

    Some(Detail {
        health,
        counts,
        devices: scan.result.devices.len(),
        target: scan.result.config.target.clone(),
        interface: scan.result.config.interface.clone(),
        when: format::short_time(&scan.result.started_at),
        id: scan.id.clone(),
    })
}

fn scans_card(
    app: &mut NetgapApp,
    ui: &mut Ui,
    p: &Palette,
    scans: &[netgap_storage::ScanMetadata],
) {
    let selected_id = app.current().and_then(|scan| scan.id.clone());

    let mut clicked = None;

    widgets::card(ui, p, |ui| {
        widgets::section_heading(ui, p, "Recorded scans", Some("Click one to inspect it."));
        ui.add_space(8.0);

        // Column headings.
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), 20.0), Sense::hover());
        let painter = ui.painter();
        let heading = FontId::proportional(10.0);
        painter.text(
            Pos2::new(rect.left() + 8.0, rect.center().y),
            Align2::LEFT_CENTER,
            "WHEN",
            heading.clone(),
            p.muted,
        );
        painter.text(
            Pos2::new(rect.left() + rect.width() * 0.30, rect.center().y),
            Align2::LEFT_CENTER,
            "TARGET",
            heading.clone(),
            p.muted,
        );
        painter.text(
            Pos2::new(rect.left() + rect.width() * 0.66, rect.center().y),
            Align2::LEFT_CENTER,
            "DEVICES",
            heading.clone(),
            p.muted,
        );
        painter.text(
            Pos2::new(rect.left() + rect.width() * 0.82, rect.center().y),
            Align2::LEFT_CENTER,
            "FINDINGS",
            heading,
            p.muted,
        );

        ui.add_space(2.0);

        let height = (ui.available_height() - 8.0).clamp(240.0, 500.0);
        egui::ScrollArea::vertical()
            .id_salt("scan-history")
            .max_height(height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for scan in scans {
                    let selected = selected_id.as_deref() == Some(scan.id.as_str());
                    if scan_row(ui, p, scan, selected) {
                        clicked = Some(scan.id.clone());
                    }
                    ui.add_space(2.0);
                }
            });
    });

    if let Some(id) = clicked {
        app.open_scan(&id);
    }
}

fn scan_row(ui: &mut Ui, p: &Palette, scan: &netgap_storage::ScanMetadata, selected: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 36.0), Sense::click());
    let painter = ui.painter();

    if selected {
        painter.rect_filled(rect, egui::CornerRadius::same(7), p.accent_soft);
    } else if response.hovered() {
        painter.rect_filled(rect, egui::CornerRadius::same(7), p.hover);
    }

    let width = rect.width();
    painter.text(
        Pos2::new(rect.left() + 8.0, rect.center().y),
        Align2::LEFT_CENTER,
        format::short_time(&scan.created_at),
        FontId::proportional(11.0),
        p.muted,
    );
    painter.text(
        Pos2::new(rect.left() + width * 0.30, rect.center().y),
        Align2::LEFT_CENTER,
        format::truncate(&scan.target, 20),
        FontId::monospace(11.0),
        p.text,
    );
    painter.text(
        Pos2::new(rect.left() + width * 0.66, rect.center().y),
        Align2::LEFT_CENTER,
        format!("{}", scan.device_count.max(0)),
        FontId::proportional(11.5),
        p.text,
    );
    painter.text(
        Pos2::new(rect.left() + width * 0.82, rect.center().y),
        Align2::LEFT_CENTER,
        if scan.critical_count > 0 {
            format!(
                "{}  ({} critical)",
                scan.finding_count.max(0),
                scan.critical_count
            )
        } else {
            format!("{}", scan.finding_count.max(0))
        },
        FontId::proportional(11.0),
        if scan.critical_count > 0 {
            p.critical
        } else {
            p.muted
        },
    );

    response.clicked()
}

fn detail_card(app: &mut NetgapApp, ui: &mut Ui, p: &Palette, detail: &Detail) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(ui, p, "Selected scan", None);
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            widgets::health_ring(ui, p, detail.health.score, 112.0);
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(detail.health.risk_level())
                        .size(17.0)
                        .strong()
                        .color(widgets::score_color(p, detail.health.score)),
                );
                ui.label(
                    RichText::new(&detail.target)
                        .size(11.5)
                        .monospace()
                        .color(p.text),
                );
                ui.label(
                    RichText::new(format!("{} · {}", detail.interface, detail.when))
                        .size(11.0)
                        .color(p.muted),
                );
                ui.label(
                    RichText::new(format!(
                        "{} · {}",
                        format::devices(detail.devices),
                        format::findings(detail.counts.total())
                    ))
                    .size(11.0)
                    .color(p.muted),
                );
            });
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if widgets::primary_button(ui, p, "View devices") {
                app.tab = Tab::Devices;
            }
            if widgets::secondary_button(ui, p, "Export HTML") {
                app.export_report("html");
            }
        });

        ui.add_space(8.0);

        if detail.id.is_some() {
            widgets::muted(ui, p, "This scan is stored and will survive a restart.");
        }

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);
        widgets::severity_bars(ui, p, detail.counts);
    });
}

fn empty_state(app: &mut NetgapApp, ui: &mut Ui, p: &Palette) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new("Nothing recorded yet")
                .size(21.0)
                .strong()
                .color(p.text),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Scans from this window and from the command line share one history. \
                 The first one will appear here.",
            )
            .size(13.0)
            .color(p.muted),
        );
        ui.add_space(14.0);
        if widgets::primary_button(ui, p, "Scan network") {
            app.tab = Tab::Scan;
        }
    });
}
