//! Colours and text sizes, in one place so every view agrees.

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};
use netgap_core::Severity;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
}

impl Theme {
    pub fn toggled(self) -> Self {
        match self {
            Theme::Dark => Theme::Light,
            Theme::Light => Theme::Dark,
        }
    }

    pub fn is_dark(self) -> bool {
        self == Theme::Dark
    }
}

/// Every colour a view may use. Views take this rather than picking constants,
/// which is what keeps light mode from being an afterthought.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub card: Color32,
    pub field: Color32,
    pub hover: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub critical: Color32,
    pub high: Color32,
    pub medium: Color32,
    pub info: Color32,
    pub success: Color32,
    pub track: Color32,
}

impl Palette {
    pub fn dark() -> Self {
        Self {
            bg: Color32::from_rgb(0x0b, 0x10, 0x17),
            panel: Color32::from_rgb(0x0f, 0x17, 0x20),
            card: Color32::from_rgb(0x14, 0x1e, 0x29),
            field: Color32::from_rgb(0x0a, 0x12, 0x1a),
            hover: Color32::from_rgb(0x1b, 0x28, 0x36),
            border: Color32::from_rgb(0x22, 0x30, 0x40),
            text: Color32::from_rgb(0xe6, 0xed, 0xf3),
            muted: Color32::from_rgb(0x8b, 0x9b, 0xab),
            accent: Color32::from_rgb(0x2d, 0xd4, 0xbf),
            accent_soft: Color32::from_rgb(0x13, 0x3a, 0x3a),
            critical: Color32::from_rgb(0xf8, 0x71, 0x71),
            high: Color32::from_rgb(0xfb, 0x92, 0x3c),
            medium: Color32::from_rgb(0xfa, 0xcc, 0x15),
            info: Color32::from_rgb(0x60, 0xa5, 0xfa),
            success: Color32::from_rgb(0x4a, 0xde, 0x80),
            track: Color32::from_rgb(0x1e, 0x29, 0x3b),
        }
    }

    pub fn light() -> Self {
        Self {
            bg: Color32::from_rgb(0xf4, 0xf6, 0xf8),
            panel: Color32::from_rgb(0xff, 0xff, 0xff),
            card: Color32::from_rgb(0xff, 0xff, 0xff),
            field: Color32::from_rgb(0xf1, 0xf5, 0xf9),
            hover: Color32::from_rgb(0xe8, 0xef, 0xf5),
            border: Color32::from_rgb(0xd9, 0xe1, 0xe9),
            text: Color32::from_rgb(0x16, 0x20, 0x2b),
            muted: Color32::from_rgb(0x5f, 0x6f, 0x7f),
            accent: Color32::from_rgb(0x0d, 0x94, 0x88),
            accent_soft: Color32::from_rgb(0xd8, 0xf3, 0xef),
            critical: Color32::from_rgb(0xdc, 0x26, 0x26),
            high: Color32::from_rgb(0xea, 0x58, 0x0c),
            medium: Color32::from_rgb(0xb4, 0x83, 0x09),
            info: Color32::from_rgb(0x02, 0x84, 0xc7),
            success: Color32::from_rgb(0x16, 0xa3, 0x4a),
            track: Color32::from_rgb(0xe2, 0xe8, 0xee),
        }
    }

    pub fn for_theme(theme: Theme) -> Self {
        match theme {
            Theme::Dark => Self::dark(),
            Theme::Light => Self::light(),
        }
    }

    pub fn severity(&self, severity: Severity) -> Color32 {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Info => self.info,
        }
    }

    /// A fill for a severity chip: the severity colour, dimmed.
    pub fn severity_soft(&self, severity: Severity) -> Color32 {
        let c = self.severity(severity);
        Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 38)
    }
}

pub fn apply(ctx: &egui::Context, theme: Theme) {
    let palette = Palette::for_theme(theme);
    let mut visuals = match theme {
        Theme::Dark => Visuals::dark(),
        Theme::Light => Visuals::light(),
    };

    visuals.panel_fill = palette.bg;
    visuals.window_fill = palette.panel;
    visuals.window_stroke = Stroke::new(1.0, palette.border);
    visuals.faint_bg_color = palette.card;
    visuals.extreme_bg_color = palette.field;
    visuals.override_text_color = Some(palette.text);
    visuals.hyperlink_color = palette.accent;
    visuals.selection.bg_fill = palette.accent_soft;
    visuals.selection.stroke = Stroke::new(1.0, palette.accent);
    visuals.widgets.noninteractive.bg_fill = palette.card;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, palette.border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette.text);
    visuals.widgets.inactive.bg_fill = palette.card;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, palette.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, palette.text);
    visuals.widgets.hovered.bg_fill = palette.hover;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, palette.accent);
    visuals.widgets.active.bg_fill = palette.accent_soft;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, palette.accent);
    visuals.widgets.open.bg_fill = palette.card;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, palette.border);
    visuals.window_corner_radius = CornerRadius::same(14);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.interact_size.y = 30.0;
    style.spacing.scroll.bar_width = 8.0;
    style.text_styles = BTreeMap::from([
        (
            TextStyle::Heading,
            FontId::new(26.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Small,
            FontId::new(12.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        ),
    ]);
    ctx.set_style(style);
}
