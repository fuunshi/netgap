//! Small drawing pieces shared by the views: cards, chips, the logo, the
//! health gauge and the history chart.
//!
//! egui is immediate mode, so these are functions rather than widget types:
//! call one where the thing should appear.

use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, CursorIcon, Layout, Painter, Pos2, Rect, RichText,
    Sense, Shape, Stroke, StrokeKind, Ui, Vec2,
};
use netgap_core::Severity;
use netgap_storage::ScanMetadata;

use crate::format::{self, SeverityCounts};
use crate::theme::{self, Palette};

/// A rounded panel. Every card on every screen goes through this, so the
/// corners and margins cannot drift apart.
pub fn card(ui: &mut Ui, p: &Palette, add: impl FnOnce(&mut Ui)) -> egui::Response {
    let width = ui.available_width();
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_min_width((width - 32.0).max(0.0));
            add(ui);
        })
        .response
}

/// The page title block: a technical eyebrow, a tracked upper-case title and
/// one sentence of context. `right` adds actions on the far side.
pub fn page_header(
    ui: &mut Ui,
    p: &Palette,
    eyebrow: &str,
    title: &str,
    subtitle: &str,
    right: impl FnOnce(&mut Ui),
) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(
                RichText::new(theme::tracked(eyebrow))
                    .font(theme::mono(9.0))
                    .color(p.accent),
            );
            ui.add_space(3.0);
            ui.label(
                RichText::new(title.to_uppercase())
                    .font(theme::display(25.0))
                    .color(p.text),
            );
            if !subtitle.is_empty() {
                ui.add_space(3.0);
                ui.label(RichText::new(subtitle).size(13.0).color(p.muted));
            }
        });

        ui.with_layout(Layout::right_to_left(Align::Center), right);
    });
}

/// The faint grid and glow behind every page. Painted before the content, so
/// cards sit on top of it.
pub fn backdrop(ui: &Ui, p: &Palette) {
    let rect = ui.max_rect();
    let painter = ui.painter();

    let step = 40.0;
    let mut x = rect.left() + step;
    while x < rect.right() {
        painter.line_segment(
            [Pos2::new(x, rect.top()), Pos2::new(x, rect.bottom())],
            Stroke::new(1.0_f32, p.grid),
        );
        x += step;
    }

    let mut y = rect.top() + step;
    while y < rect.bottom() {
        painter.line_segment(
            [Pos2::new(rect.left(), y), Pos2::new(rect.right(), y)],
            Stroke::new(1.0_f32, p.grid),
        );
        y += step;
    }
}

/// The mark: a network hexagon with one edge open. The gap is the name, and
/// the sweep pointing through it is what the scanner looks for.
pub fn logo_mark(ui: &mut Ui, p: &Palette, size: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    paint_logo(ui.painter(), rect, p);
    response
}

pub fn paint_logo(painter: &Painter, rect: Rect, p: &Palette) {
    let center = rect.center();
    let radius = rect.width() * 0.40;
    let vertices: Vec<Pos2> = (0..6)
        .map(|index| {
            let angle = std::f32::consts::TAU * index as f32 / 6.0;
            center + Vec2::angled(angle) * radius
        })
        .collect();

    painter.add(Shape::convex_polygon(
        vertices.clone(),
        p.accent_soft,
        Stroke::NONE,
    ));

    // The edge between vertices 1 and 2 stays open.
    let edge = (rect.width() * 0.032).max(1.2);
    for index in 0..6 {
        if index == 1 {
            continue;
        }

        let start = vertices[index];
        let end = vertices[(index + 1) % 6];
        painter.line_segment([start, end], Stroke::new(rect.width() * 0.11, p.glow));
        painter.line_segment([start, end], Stroke::new(edge, p.accent));
    }

    for vertex in &vertices {
        painter.circle_filled(*vertex, (rect.width() * 0.035).max(1.2), p.accent);
    }

    // A sweep from the core towards the gap, stopping just short of it.
    let gap = Pos2::new(
        (vertices[1].x + vertices[2].x) / 2.0,
        (vertices[1].y + vertices[2].y) / 2.0,
    );
    let tip = center + (gap - center) * 0.70;
    painter.line_segment([center, tip], Stroke::new(1.0_f32, p.accent_alpha(150)));
    painter.circle_filled(tip, (rect.width() * 0.038).max(1.3), p.accent);
    painter.circle_filled(center, (rect.width() * 0.055).max(1.8), p.accent);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavIcon {
    Dashboard,
    Scan,
    Devices,
    History,
}

/// A sidebar navigation entry. Painted by hand so the hover and selection
/// fills span the same box, with the same padding, at every state.
pub fn nav_item(ui: &mut Ui, p: &Palette, selected: bool, label: &str, icon: NavIcon) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 42.0), Sense::click());
    let hovered = response.hovered();
    let painter = ui.painter();

    if selected {
        painter.rect_filled(rect, CornerRadius::same(7), p.accent_soft);
        painter.rect_stroke(
            rect,
            CornerRadius::same(7),
            Stroke::new(1.0_f32, p.accent_alpha(70)),
            StrokeKind::Inside,
        );

        let bar = Rect::from_center_size(
            Pos2::new(rect.left() + 2.0, rect.center().y),
            Vec2::new(3.0, 20.0),
        );
        painter.rect_filled(bar, CornerRadius::same(2), p.accent);
    } else if hovered {
        painter.rect_filled(rect, CornerRadius::same(7), p.hover);
    }

    let color = if selected {
        p.accent
    } else if hovered {
        p.text
    } else {
        p.muted
    };
    let icon_rect = Rect::from_center_size(
        Pos2::new(rect.left() + 31.0, rect.center().y),
        Vec2::splat(16.0),
    );
    paint_icon(painter, icon_rect, icon, color, selected);

    painter.text(
        Pos2::new(rect.left() + 52.0, rect.center().y),
        Align2::LEFT_CENTER,
        theme::tracked(&label.to_uppercase()),
        theme::mono(11.5),
        color,
    );

    if selected {
        painter.text(
            Pos2::new(rect.right() - 12.0, rect.center().y),
            Align2::RIGHT_CENTER,
            "›",
            theme::mono(15.0),
            p.accent,
        );
    }

    response.on_hover_cursor(CursorIcon::PointingHand).clicked()
}

fn paint_icon(painter: &Painter, rect: Rect, icon: NavIcon, color: Color32, active: bool) {
    let stroke = Stroke::new(1.4_f32, color);
    let center = rect.center();

    match icon {
        NavIcon::Dashboard => {
            let gap = 2.5;
            let cell = (rect.width().min(rect.height()) - gap) / 2.0;
            for (column, row) in [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)] {
                let min = Pos2::new(
                    rect.left() + column * (cell + gap),
                    rect.top() + row * (cell + gap),
                );
                let tile = Rect::from_min_size(min, Vec2::splat(cell));
                if active || (column == 0.0 && row == 0.0) {
                    painter.rect_filled(tile, CornerRadius::same(1), color);
                } else {
                    painter.rect_stroke(tile, CornerRadius::same(1), stroke, StrokeKind::Inside);
                }
            }
        }
        NavIcon::Scan => {
            let radius = rect.width() * 0.42;
            painter.circle_stroke(center, radius, stroke);
            painter.circle_filled(center, rect.width() * 0.10, color);
            painter.line_segment(
                [
                    Pos2::new(center.x, center.y - radius),
                    Pos2::new(center.x, center.y - radius * 0.60),
                ],
                stroke,
            );
            painter.circle_filled(
                center + Vec2::angled(-std::f32::consts::FRAC_PI_4) * radius * 0.58,
                rect.width() * 0.07,
                color,
            );
        }
        NavIcon::Devices => {
            let top = Pos2::new(center.x, rect.top() + 2.5);
            let left = Pos2::new(rect.left() + 2.5, rect.bottom() - 3.0);
            let right = Pos2::new(rect.right() - 2.5, rect.bottom() - 3.0);
            painter.line_segment([top, left], stroke);
            painter.line_segment([top, right], stroke);
            painter.line_segment([left, right], stroke);
            for node in [top, left, right] {
                painter.circle_filled(node, 2.0, color);
            }
        }
        NavIcon::History => {
            let radius = rect.width() * 0.42;
            painter.circle_stroke(center, radius, stroke);
            painter.line_segment([center, center + Vec2::new(0.0, -radius * 0.55)], stroke);
            painter.line_segment(
                [center, center + Vec2::new(radius * 0.42, radius * 0.22)],
                stroke,
            );
            painter.circle_filled(center, 1.3, color);
        }
    }
}

/// A one-pixel rule, used to divide the sidebar without the visual weight of
/// egui's default separator.
pub fn hairline(ui: &mut Ui, p: &Palette) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::ZERO, p.border);
}

pub fn section_heading(ui: &mut Ui, p: &Palette, title: &str, subtitle: Option<&str>) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(3.0, 12.0), Sense::hover());
        ui.painter()
            .rect_filled(rect, CornerRadius::same(1), p.accent);
        ui.add_space(5.0);
        ui.label(
            RichText::new(theme::tracked(&title.to_uppercase()))
                .font(theme::mono(11.5))
                .color(p.text),
        );
    });
    if let Some(subtitle) = subtitle {
        ui.add_space(2.0);
        ui.label(RichText::new(subtitle).size(12.0).color(p.muted));
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
        let (tick, _) = ui.allocate_exact_size(Vec2::new(18.0, 2.0), Sense::hover());
        ui.painter().rect_filled(tick, CornerRadius::same(1), color);
        ui.add_space(7.0);
        ui.label(
            RichText::new(theme::tracked(&label.to_uppercase()))
                .font(theme::mono(9.0))
                .color(p.muted),
        );
        ui.add_space(3.0);
        ui.label(RichText::new(value).font(theme::display(30.0)).color(color));
        ui.add_space(2.0);
        ui.add(egui::Label::new(RichText::new(note).size(11.5).color(p.muted)).wrap());
    });
}

/// A severity pill, used wherever a finding is named.
pub fn severity_chip(ui: &mut Ui, p: &Palette, severity: Severity) {
    egui::Frame::new()
        .fill(p.severity_soft(severity))
        .corner_radius(CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(theme::tracked(&severity.to_string().to_uppercase()))
                    .font(theme::mono(9.0))
                    .color(p.severity(severity)),
            );
        });
}

/// The score as a gauge of ticks. A ring rather than a bare number because
/// "72" means nothing on its own and "72 out of 100" is readable at a glance.
/// Ticks rather than a smooth arc because it reads as an instrument.
pub fn health_ring(ui: &mut Ui, p: &Palette, score: u8, size: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let painter = ui.painter();
    let center = rect.center();
    let radius = size / 2.0 - 15.0;
    let color = score_color(p, score);
    let ticks = 60;
    let lit = ((score as f32 / 100.0) * ticks as f32).round() as usize;

    painter.circle_stroke(center, radius + 7.0, Stroke::new(1.0_f32, p.border));
    painter.circle_stroke(center, radius - 11.0, Stroke::new(1.0_f32, p.track));

    for index in 0..ticks {
        let angle =
            -std::f32::consts::FRAC_PI_2 + std::f32::consts::TAU * index as f32 / ticks as f32;
        let direction = Vec2::angled(angle);
        let major = index % 5 == 0;
        let inner = radius - if major { 7.0 } else { 4.0 };
        let width: f32 = if major { 2.3 } else { 1.3 };
        let tick_color = if index < lit { color } else { p.track };
        painter.line_segment(
            [center + direction * inner, center + direction * radius],
            Stroke::new(width, tick_color),
        );
    }

    painter.text(
        center + Vec2::new(0.0, -size * 0.02),
        Align2::CENTER_CENTER,
        format!("{score}"),
        theme::display(size * 0.24),
        p.text,
    );
    painter.text(
        center + Vec2::new(0.0, size * 0.15),
        Align2::CENTER_CENTER,
        theme::tracked("OUT OF 100"),
        theme::mono((size * 0.06).max(7.0)),
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
                    RichText::new(theme::tracked(
                        &capitalize(&severity.to_string()).to_uppercase(),
                    ))
                    .font(theme::mono(9.0))
                    .color(p.muted),
                ),
            );

            let width = (ui.available_width() - 48.0).max(40.0);
            let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 7.0), Sense::hover());
            let painter = ui.painter();
            painter.rect_filled(rect, CornerRadius::same(2), p.track);

            if count > 0 {
                let filled = rect.width() * (count as f32 / max as f32);
                let bar = Rect::from_min_size(rect.min, Vec2::new(filled, rect.height()));
                painter.rect_filled(bar, CornerRadius::same(2), p.severity(severity));
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(count.to_string())
                        .font(theme::mono(11.0))
                        .color(if count > 0 { p.text } else { p.muted }),
                );
            });
        });
        ui.add_space(5.0);
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
    let chart_top = rect.top() + 10.0;
    let chart_height = (baseline - chart_top).max(20.0);

    for step in 1..4 {
        let y = baseline - chart_height * step as f32 / 4.0;
        painter.line_segment(
            [Pos2::new(rect.left(), y), Pos2::new(rect.right(), y)],
            Stroke::new(1.0_f32, p.grid),
        );
    }

    painter.line_segment(
        [
            Pos2::new(rect.left(), baseline),
            Pos2::new(rect.right(), baseline),
        ],
        Stroke::new(1.0_f32, p.border),
    );

    if recent.is_empty() {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "No scans yet",
            theme::mono(11.0),
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
    let bar_width = (slot * 0.46).clamp(6.0, 26.0);

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
            painter.rect_filled(bar, CornerRadius::same(2), p.accent_soft);

            let cap = Rect::from_min_size(bar.min, Vec2::new(bar.width(), 2.0));
            painter.rect_filled(cap, CornerRadius::same(1), p.accent);

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
                theme::mono(8.5),
                p.muted,
            );
        }
    }

    painter.text(
        Pos2::new(rect.left(), chart_top - 6.0),
        Align2::LEFT_TOP,
        theme::tracked(&format!("PEAK {max} FINDINGS")),
        theme::mono(8.5),
        p.muted,
    );
}

/// A horizontal progress bar. `None` means work whose length is unknown, so
/// the fill sweeps instead of pretending to know.
pub fn progress_bar(ui: &mut Ui, p: &Palette, fraction: Option<f32>, time: f64) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 6.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(2), p.track);

    match fraction {
        Some(fraction) => {
            let filled = rect.width() * fraction.clamp(0.0, 1.0);
            if filled > 0.0 {
                let bar = Rect::from_min_size(rect.min, Vec2::new(filled, rect.height()));
                painter.rect_filled(bar, CornerRadius::same(2), p.accent);
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
                painter.rect_filled(swept, CornerRadius::same(2), p.accent);
            }
        }
    }
}

/// A button with the accent colour, for the one action a screen is for.
pub fn primary_button(ui: &mut Ui, p: &Palette, label: &str) -> bool {
    let text = theme::tracked(&label.to_uppercase());
    let galley = ui
        .painter()
        .layout_no_wrap(text, theme::display(11.0), p.bg);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(galley.size().x + 32.0, 34.0), Sense::click());

    let enabled = ui.is_enabled();
    let fill = if !enabled {
        p.track
    } else if response.is_pointer_button_down_on() {
        p.accent.gamma_multiply(0.82)
    } else if response.hovered() {
        p.accent.gamma_multiply(1.12)
    } else {
        p.accent
    };
    let color = if enabled { p.bg } else { p.muted };

    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(5), fill);
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);

    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand).clicked()
    } else {
        false
    }
}

pub fn secondary_button(ui: &mut Ui, p: &Palette, label: &str) -> bool {
    let text = theme::tracked(&label.to_uppercase());
    let galley = ui.painter().layout_no_wrap(text, theme::mono(10.0), p.text);
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(galley.size().x + 18.0, 30.0), Sense::click());

    let enabled = ui.is_enabled();
    let hovered = enabled && response.hovered();
    let border = if hovered { p.accent } else { p.border };
    let fill = if hovered {
        p.hover
    } else {
        Color32::TRANSPARENT
    };
    let color = if !enabled {
        p.muted
    } else if hovered {
        p.accent
    } else {
        p.text
    };

    let painter = ui.painter();
    painter.rect(
        rect,
        CornerRadius::same(5),
        fill,
        Stroke::new(1.0_f32, border),
        StrokeKind::Inside,
    );
    painter.galley(rect.center() - galley.size() / 2.0, galley, color);

    if enabled {
        response.on_hover_cursor(CursorIcon::PointingHand).clicked()
    } else {
        false
    }
}

/// The sidebar's dark/light switch: a full-width row with a sun or moon, so
/// the action is obvious without hunting for a small button.
pub fn theme_toggle(ui: &mut Ui, p: &Palette, dark: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 32.0), Sense::click());
    let hovered = response.hovered();

    let painter = ui.painter();
    painter.rect(
        rect,
        CornerRadius::same(5),
        if hovered {
            p.hover
        } else {
            Color32::TRANSPARENT
        },
        Stroke::new(1.0_f32, if hovered { p.accent } else { p.border }),
        StrokeKind::Inside,
    );

    let color = if hovered { p.accent } else { p.text };
    let center = Pos2::new(rect.left() + 17.0, rect.center().y);
    if dark {
        // A sun: switching to the light theme.
        painter.circle_stroke(center, 3.4, Stroke::new(1.2_f32, color));
        for index in 0..8 {
            let angle = std::f32::consts::TAU * index as f32 / 8.0;
            let direction = Vec2::angled(angle);
            painter.line_segment(
                [center + direction * 5.3, center + direction * 7.0],
                Stroke::new(1.2_f32, color),
            );
        }
    } else {
        // A crescent: switching to the dark theme. The second circle is
        // filled with the row's own background to carve the shape out.
        painter.circle_filled(center, 5.0, color);
        painter.circle_filled(
            center + Vec2::new(2.6, -1.8),
            4.4,
            if hovered { p.hover } else { p.panel },
        );
    }

    painter.text(
        Pos2::new(rect.left() + 32.0, rect.center().y),
        Align2::LEFT_CENTER,
        theme::tracked(if dark { "LIGHT MODE" } else { "DARK MODE" }),
        theme::mono(9.5),
        color,
    );

    response.on_hover_cursor(CursorIcon::PointingHand).clicked()
}

/// A settings row: label on the left, control on the right. Returns whatever
/// the control returns, so a caller can see the text field's response.
pub fn label_row<R>(ui: &mut Ui, p: &Palette, label: &str, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.horizontal(|ui| {
        ui.add_sized(
            [132.0, 24.0],
            egui::Label::new(
                RichText::new(theme::tracked(&label.to_uppercase()))
                    .font(theme::mono(9.5))
                    .color(p.muted),
            ),
        );
        add(ui)
    })
    .inner
}

/// Which glyph sits at the start of a text field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldIcon {
    Search,
    Target,
}

/// The id of the device search field, so `Ctrl+F` can focus it from anywhere.
pub fn search_field_id() -> egui::Id {
    egui::Id::new("device-search-field")
}

/// What a text field shows when it is empty, and the shortcut it answers to.
#[derive(Debug, Clone, Copy)]
pub struct FieldHint<'a> {
    /// Placeholder shown while the field is empty.
    pub text: &'a str,
    pub icon: FieldIcon,
    /// Painted on the right while the field is empty and unfocused.
    pub shortcut: Option<&'a str>,
}

/// A text field with a proper frame: a leading icon, a focus ring, an optional
/// shortcut hint, and a clear button once there is something to clear. egui's
/// own TextEdit is used inside, so editing, selection and IME keep working.
pub fn text_field(
    ui: &mut Ui,
    p: &Palette,
    id: egui::Id,
    text: &mut String,
    hint: FieldHint<'_>,
    width: f32,
) -> egui::Response {
    let focused = ui.memory(|memory| memory.has_focus(id));
    let mut cleared = false;

    let frame = egui::Frame::new()
        .fill(p.field)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(10, 5))
        .show(ui, |ui| {
            ui.set_width((width - 20.0).max(40.0));
            ui.horizontal(|ui| {
                let icon_color = if focused { p.accent } else { p.muted };
                let (icon_rect, _) = ui.allocate_exact_size(Vec2::splat(15.0), Sense::hover());
                paint_field_icon(ui.painter(), icon_rect, hint.icon, icon_color);
                ui.add_space(3.0);

                // Leave room for the clear button or the shortcut hint, so the
                // caret never runs underneath either.
                let reserved = if text.is_empty() {
                    if hint.shortcut.is_some() {
                        52.0
                    } else {
                        0.0
                    }
                } else {
                    22.0
                };

                let edit = ui.add(
                    egui::TextEdit::singleline(text)
                        .id(id)
                        .frame(false)
                        .margin(egui::Margin::symmetric(0, 4))
                        .desired_width((ui.available_width() - reserved).max(24.0))
                        .hint_text(RichText::new(hint.text).size(12.5).color(p.muted))
                        .font(egui::TextStyle::Monospace),
                );

                if !text.is_empty() && clear_button(ui, p) {
                    cleared = true;
                }

                edit
            })
            .inner
        });

    if cleared {
        text.clear();
        ui.memory_mut(|memory| memory.request_focus(id));
    }

    let response = frame.inner;
    let rect = frame.response.rect;
    let stroke = if response.has_focus() {
        Stroke::new(1.5_f32, p.accent)
    } else if frame.response.hovered() {
        Stroke::new(1.0_f32, p.accent_alpha(130))
    } else {
        Stroke::new(1.0_f32, p.border)
    };
    ui.painter()
        .rect_stroke(rect, CornerRadius::same(6), stroke, StrokeKind::Inside);

    if text.is_empty() {
        if let Some(shortcut) = hint.shortcut.filter(|_| !focused) {
            ui.painter().text(
                Pos2::new(rect.right() - 10.0, rect.center().y),
                Align2::RIGHT_CENTER,
                theme::tracked(&shortcut.to_uppercase()),
                theme::mono(8.0),
                p.muted,
            );
        }
    }

    response
}

fn paint_field_icon(painter: &Painter, rect: Rect, icon: FieldIcon, color: Color32) {
    let center = rect.center();
    let stroke = Stroke::new(1.3_f32, color);

    match icon {
        FieldIcon::Search => {
            let lens = center + Vec2::new(-1.0, -1.0);
            painter.circle_stroke(lens, 4.4, stroke);
            painter.line_segment(
                [lens + Vec2::new(3.2, 3.2), lens + Vec2::new(6.3, 6.3)],
                Stroke::new(1.6_f32, color),
            );
        }
        FieldIcon::Target => {
            painter.circle_stroke(center, 4.6, stroke);
            painter.circle_filled(center, 1.1, color);
            for direction in [
                Vec2::new(1.0, 0.0),
                Vec2::new(-1.0, 0.0),
                Vec2::new(0.0, 1.0),
                Vec2::new(0.0, -1.0),
            ] {
                painter.line_segment(
                    [center + direction * 5.9, center + direction * 7.4],
                    Stroke::new(1.2_f32, color),
                );
            }
        }
    }
}

fn clear_button(ui: &mut Ui, p: &Palette) -> bool {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::click());
    let color = if response.hovered() {
        p.accent
    } else {
        p.muted
    };

    if response.hovered() {
        ui.painter()
            .rect_filled(rect, CornerRadius::same(3), p.hover);
    }

    let center = rect.center();
    let arm = 3.1;
    let stroke = Stroke::new(1.2_f32, color);
    ui.painter().line_segment(
        [center + Vec2::new(-arm, -arm), center + Vec2::new(arm, arm)],
        stroke,
    );
    ui.painter().line_segment(
        [center + Vec2::new(arm, -arm), center + Vec2::new(-arm, arm)],
        stroke,
    );

    response.on_hover_cursor(CursorIcon::PointingHand).clicked()
}
