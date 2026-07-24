//! Small drawing pieces shared by the views: cards, chips, the health ring
//! and the history chart.
//!
//! egui is immediate mode, so these are functions rather than widget types:
//! call one where the thing should appear.

use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Layout, Pos2, Rect, RichText, Sense, Shape,
    Stroke, Ui, Vec2,
};
use netgap_core::Severity;
use netgap_storage::ScanMetadata;

use crate::format::{self, SeverityCounts};
use crate::theme::Palette;

/// A rounded panel. Every card on every screen goes through this, so the
/// corners and margins cannot drift apart.
pub fn card(ui: &mut Ui, p: &Palette, add: impl FnOnce(&mut Ui)) -> egui::Response {
    let width = ui.available_width();
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width((width - 32.0).max(0.0));
            add(ui);
        })
        .response
}

pub fn section_heading(ui: &mut Ui, p: &Palette, title: &str, subtitle: Option<&str>) {
    ui.label(RichText::new(title).size(16.0).strong().color(p.text));
    if let Some(subtitle) = subtitle {
        ui.add_space(1.0);
        ui.label(RichText::new(subtitle).size(12.5).color(p.muted));
    }
}

pub fn muted(ui: &mut Ui, p: &Palette, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).size(12.5).color(p.muted));
}

/// One number with a label, for the top of the dashboard.
pub fn kpi_card(
    ui: &mut Ui,
    p: &Palette,
    label: &str,
    value: String,
    note: String,
    color: Color32,
) {
    card(ui, p, |ui| {
        ui.label(
            RichText::new(label.to_uppercase())
                .size(10.5)
                .strong()
                .color(p.muted),
        );
        ui.add_space(6.0);
        ui.label(RichText::new(value).size(31.0).strong().color(color));
        ui.add_space(2.0);
        ui.label(RichText::new(note).size(12.0).color(p.muted));
    });
}

/// A severity pill, used wherever a finding is named.
pub fn severity_chip(ui: &mut Ui, p: &Palette, severity: Severity) {
    egui::Frame::new()
        .fill(p.severity_soft(severity))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(severity.to_string())
                    .size(10.0)
                    .strong()
                    .color(p.severity(severity)),
            );
        });
}

/// A panel's clickable navigation entry.
pub fn nav_button(ui: &mut Ui, p: &Palette, selected: bool, label: &str) -> bool {
    let fill = if selected {
        p.accent_soft
    } else {
        Color32::TRANSPARENT
    };
    let color = if selected { p.accent } else { p.muted };

    let button = egui::Button::new(RichText::new(label).size(14.5).color(color))
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(9))
        .min_size(Vec2::new(ui.available_width(), 38.0));
    let response = ui.add(button);

    if selected {
        let rect = response.rect;
        let bar = Rect::from_min_size(
            Pos2::new(rect.left() + 8.0, rect.center().y - 9.0),
            Vec2::new(3.0, 18.0),
        );
        ui.painter()
            .rect_filled(bar, CornerRadius::same(2), p.accent);
    }

    response.clicked()
}

/// The score as a ring. A ring rather than a bare number because "72" means
/// nothing on its own and "72 out of 100" is readable at a glance.
pub fn health_ring(ui: &mut Ui, p: &Palette, score: u8, size: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let painter = ui.painter();
    let center = rect.center();
    let radius = size / 2.0 - 13.0;
    let thickness = 11.0;
    let color = score_color(p, score);

    painter.circle_stroke(center, radius, Stroke::new(thickness, p.track));

    if score > 0 {
        let segments = 72;
        let fraction = (score as f32 / 100.0).clamp(0.0, 1.0);
        let points: Vec<Pos2> = (0..=segments)
            .map(|i| {
                let t = i as f32 / segments as f32;
                let angle = -std::f32::consts::FRAC_PI_2 + t * fraction * std::f32::consts::TAU;
                center + Vec2::angled(angle) * radius
            })
            .collect();
        painter.add(Shape::line(points, Stroke::new(thickness, color)));
    }

    painter.text(
        center,
        Align2::CENTER_CENTER,
        format!("{}", score),
        FontId::proportional(size * 0.26),
        p.text,
    );
    painter.text(
        center + Vec2::new(0.0, size * 0.14),
        Align2::CENTER_CENTER,
        "out of 100",
        FontId::proportional(size * 0.075),
        p.muted,
    );

    response
}

pub fn score_color(p: &Palette, score: u8) -> Color32 {
    match score {
        85..=100 => p.success,
        70..=84 => p.accent,
        50..=69 => p.medium,
        30..=49 => p.high,
        _ => p.critical,
    }
}

/// Proportional bars for the four severities.
pub fn severity_bars(ui: &mut Ui, p: &Palette, counts: SeverityCounts) {
    let max = counts
        .entries()
        .iter()
        .map(|(_, count)| *count)
        .max()
        .unwrap_or(0)
        .max(1);

    for (severity, count) in counts.entries() {
        ui.horizontal(|ui| {
            ui.add_sized(
                [86.0, 18.0],
                egui::Label::new(
                    RichText::new(capitalize(&severity.to_string()))
                        .size(12.0)
                        .color(p.muted),
                ),
            );

            let width = (ui.available_width() - 48.0).max(40.0);
            let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 9.0), Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(rect, CornerRadius::same(4), p.track);

            if count > 0 {
                let filled = rect.width() * (count as f32 / max as f32);
                let bar = Rect::from_min_size(rect.min, Vec2::new(filled, rect.height()));
                painter.rect_filled(bar, CornerRadius::same(4), p.severity(severity));
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(count.to_string())
                        .size(12.5)
                        .strong()
                        .color(if count > 0 { p.text } else { p.muted }),
                );
            });
        });
        ui.add_space(4.0);
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_string() + &chars.as_str().to_ascii_lowercase(),
        None => String::new(),
    }
}

/// Findings over the last scans. Bars rather than a line: each scan is a
/// separate observation, not a continuous measurement.
pub fn trend_chart(ui: &mut Ui, p: &Palette, scans: &[ScanMetadata], height: f32) {
    let mut recent: Vec<&ScanMetadata> = scans.iter().take(12).collect();
    recent.reverse();

    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
    let painter = ui.painter();

    let baseline = rect.bottom() - 20.0;
    let chart_top = rect.top() + 8.0;
    painter.line_segment(
        [
            Pos2::new(rect.left(), baseline),
            Pos2::new(rect.right(), baseline),
        ],
        Stroke::new(1.0, p.border),
    );

    if recent.is_empty() {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "No scans yet",
            FontId::proportional(13.0),
            p.muted,
        );
        return;
    }

    let max = recent
        .iter()
        .map(|scan| scan.finding_count.max(0) as usize)
        .max()
        .unwrap_or(0)
        .max(1);

    // Room for the labels under the bars.
    let slot = rect.width() / recent.len() as f32;
    let bar_width = (slot * 0.52).clamp(7.0, 30.0);
    let chart_height = (baseline - chart_top).max(20.0);

    for (index, scan) in recent.iter().enumerate() {
        let x = rect.left() + slot * (index as f32 + 0.5);
        let findings = scan.finding_count.max(0) as usize;
        let critical = (scan.critical_count.max(0) as usize).min(findings);

        let total_height = (findings as f32 / max as f32) * chart_height;
        let bar_height = total_height.max(if findings > 0 { 3.0 } else { 0.0 });

        if bar_height > 0.0 {
            let bar = Rect::from_min_max(
                Pos2::new(x - bar_width / 2.0, baseline - bar_height),
                Pos2::new(x + bar_width / 2.0, baseline),
            );
            painter.rect_filled(bar, CornerRadius::same(3), p.accent_soft);

            let critical_height = if findings > 0 {
                (critical as f32 / findings as f32) * bar_height
            } else {
                0.0
            };
            if critical_height > 0.0 {
                let critical_bar = Rect::from_min_max(
                    Pos2::new(bar.left(), baseline - critical_height),
                    Pos2::new(bar.right(), baseline),
                );
                painter.rect_filled(critical_bar, CornerRadius::same(2), p.critical);
            }
        }

        let show_label = recent.len() <= 8 || index % 2 == 0 || index + 1 == recent.len();
        if show_label {
            painter.text(
                Pos2::new(x, baseline + 5.0),
                Align2::CENTER_TOP,
                format::date_only(&scan.created_at),
                FontId::proportional(10.0),
                p.muted,
            );
        }
    }

    painter.text(
        Pos2::new(rect.left(), chart_top),
        Align2::LEFT_TOP,
        format!("peak {} findings", max),
        FontId::proportional(10.0),
        p.muted,
    );
}

/// A horizontal progress bar. `None` means work whose length is unknown, so
/// the fill sweeps instead of pretending to know.
pub fn progress_bar(ui: &mut Ui, p: &Palette, fraction: Option<f32>, time: f64) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 8.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(4), p.track);

    match fraction {
        Some(fraction) => {
            let filled = rect.width() * fraction.clamp(0.0, 1.0);
            if filled > 0.0 {
                let bar = Rect::from_min_size(rect.min, Vec2::new(filled, rect.height()));
                painter.rect_filled(bar, CornerRadius::same(4), p.accent);
            }
        }
        None => {
            let width = rect.width() * 0.28;
            let travel = rect.width() + width;
            let x = rect.left() + (time * 0.36).rem_euclid(1.0) as f32 * travel - width;
            let swept =
                Rect::from_min_size(Pos2::new(x, rect.top()), Vec2::new(width, rect.height()))
                    .intersect(rect);
            if swept.is_positive() {
                painter.rect_filled(swept, CornerRadius::same(4), p.accent);
            }
        }
    }
}

/// A button with the accent colour, for the one action a screen is for.
pub fn primary_button(ui: &mut Ui, p: &Palette, label: &str) -> bool {
    let button = egui::Button::new(RichText::new(label).size(14.0).strong().color(p.bg))
        .fill(p.accent)
        .stroke(Stroke::NONE)
        .corner_radius(CornerRadius::same(9))
        .min_size(Vec2::new(0.0, 34.0));
    ui.add(button).clicked()
}

pub fn secondary_button(ui: &mut Ui, p: &Palette, label: &str) -> bool {
    let button = egui::Button::new(RichText::new(label).size(13.0).color(p.text))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(0.0, 30.0));
    ui.add(button).clicked()
}

/// A settings row: label on the left, control on the right.
pub fn label_row(ui: &mut Ui, p: &Palette, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [150.0, 24.0],
            egui::Label::new(RichText::new(label).size(13.0).color(p.muted)),
        );
        add(ui);
    });
}
