//! Colours, fonts and text sizes, in one place so every view agrees.
//!
//! The window is deliberately technical: a monospace display face for labels,
//! numbers and headings, soft proportional text for sentences, and a palette
//! built around one neon accent. The aim is a tool someone leaves open on a
//! second monitor, not a poster.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle,
    Visuals,
};
use netgap_core::Severity;
use std::collections::BTreeMap;
use std::sync::Arc;

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

/// The name of the bold monospace family used for headings and big numbers.
/// Registering it as its own family is how the display face gets a real bold
/// weight; egui's `RichText::strong` only changes colour.
const DISPLAY_FAMILY: &str = "netgap-display";

const MONO: &[u8] = include_bytes!("../assets/JetBrainsMono-Regular.ttf");
const MONO_BOLD: &[u8] = include_bytes!("../assets/JetBrainsMono-Bold.ttf");

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
    /// The faint grid drawn behind a page.
    pub grid: Color32,
    /// Low-alpha accent used for glows and the logo's halo.
    pub glow: Color32,
}

impl Palette {
    pub fn dark() -> Self {
        Self {
            bg: Color32::from_rgb(0x06, 0x0a, 0x0e),
            panel: Color32::from_rgb(0x08, 0x0e, 0x13),
            card: Color32::from_rgb(0x0b, 0x12, 0x18),
            field: Color32::from_rgb(0x06, 0x0b, 0x0f),
            hover: Color32::from_rgb(0x10, 0x1b, 0x22),
            border: Color32::from_rgb(0x18, 0x28, 0x30),
            text: Color32::from_rgb(0xd6, 0xe7, 0xee),
            muted: Color32::from_rgb(0x70, 0x8a, 0x99),
            accent: Color32::from_rgb(0x00, 0xf0, 0xc8),
            accent_soft: Color32::from_rgb(0x06, 0x2d, 0x2a),
            critical: Color32::from_rgb(0xff, 0x38, 0x60),
            high: Color32::from_rgb(0xff, 0x9e, 0x44),
            medium: Color32::from_rgb(0xff, 0xd8, 0x4d),
            info: Color32::from_rgb(0x4d, 0xc9, 0xf0),
            success: Color32::from_rgb(0x35, 0xff, 0x9e),
            track: Color32::from_rgb(0x12, 0x20, 0x2a),
            grid: Color32::from_rgba_unmultiplied(0x5a, 0xb4, 0xc8, 0x0a),
            glow: Color32::from_rgba_unmultiplied(0x00, 0xf0, 0xc8, 0x1a),
        }
    }

    pub fn light() -> Self {
        Self {
            bg: Color32::from_rgb(0xed, 0xf2, 0xf4),
            panel: Color32::from_rgb(0xf8, 0xfa, 0xfb),
            card: Color32::from_rgb(0xff, 0xff, 0xff),
            field: Color32::from_rgb(0xed, 0xf2, 0xf5),
            hover: Color32::from_rgb(0xe2, 0xec, 0xef),
            border: Color32::from_rgb(0xc8, 0xd6, 0xdc),
            text: Color32::from_rgb(0x08, 0x15, 0x1b),
            muted: Color32::from_rgb(0x58, 0x6f, 0x7a),
            accent: Color32::from_rgb(0x00, 0x87, 0x72),
            accent_soft: Color32::from_rgb(0xd6, 0xf5, 0xee),
            critical: Color32::from_rgb(0xd3, 0x1f, 0x45),
            high: Color32::from_rgb(0xc7, 0x5a, 0x00),
            medium: Color32::from_rgb(0x9a, 0x70, 0x00),
            info: Color32::from_rgb(0x0b, 0x7f, 0xa8),
            success: Color32::from_rgb(0x07, 0x83, 0x4a),
            track: Color32::from_rgb(0xdc, 0xe6, 0xea),
            grid: Color32::from_rgba_unmultiplied(0x0a, 0x28, 0x32, 0x0c),
            glow: Color32::from_rgba_unmultiplied(0x00, 0x87, 0x72, 0x12),
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

    /// The accent at a given opacity, for hairlines and glows.
    pub fn accent_alpha(&self, alpha: u8) -> Color32 {
        let a = self.accent;
        Color32::from_rgba_unmultiplied(a.r(), a.g(), a.b(), alpha)
    }
}

/// The monospace face, for labels and data.
pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

/// The bold monospace face, for headings and the numbers people read first.
pub fn display(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(DISPLAY_FAMILY.into()))
}

/// Upper-case text with a thin space between letters, so a small label reads
/// like a terminal header rather than body copy.
pub fn tracked(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    let mut previous: Option<char> = None;
    for ch in text.chars() {
        if let Some(previous) = previous {
            if ch != ' ' && previous != ' ' {
                out.push('\u{2009}');
            }
        }
        out.push(ch);
        previous = Some(ch);
    }
    out
}

pub fn apply(ctx: &egui::Context, theme: Theme) {
    install_fonts(ctx);

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
    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.menu_corner_radius = CornerRadius::same(8);

    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = palette.card;
    widgets.noninteractive.bg_stroke = Stroke::new(1.0, palette.border);
    widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette.text);
    widgets.noninteractive.corner_radius = CornerRadius::same(8);

    widgets.inactive.bg_fill = palette.card;
    widgets.inactive.bg_stroke = Stroke::new(1.0, palette.border);
    widgets.inactive.fg_stroke = Stroke::new(1.0, palette.text);
    widgets.inactive.corner_radius = CornerRadius::same(6);

    widgets.hovered.bg_fill = palette.hover;
    widgets.hovered.bg_stroke = Stroke::new(1.0, palette.accent);
    widgets.hovered.fg_stroke = Stroke::new(1.0, palette.text);
    widgets.hovered.corner_radius = CornerRadius::same(6);

    widgets.active.bg_fill = palette.accent_soft;
    widgets.active.bg_stroke = Stroke::new(1.0, palette.accent);
    widgets.active.fg_stroke = Stroke::new(1.0, palette.accent);
    widgets.active.corner_radius = CornerRadius::same(6);

    widgets.open.bg_fill = palette.card;
    widgets.open.bg_stroke = Stroke::new(1.0, palette.border);
    widgets.open.corner_radius = CornerRadius::same(6);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.animation_time = 0.12;
    style.spacing.item_spacing = egui::vec2(9.0, 9.0);
    style.spacing.button_padding = egui::vec2(13.0, 7.0);
    style.spacing.interact_size.y = 30.0;
    style.spacing.scroll.bar_width = 7.0;
    style.spacing.scroll.bar_inner_margin = 3.0;
    style.text_styles = BTreeMap::from([
        (TextStyle::Heading, display(27.0)),
        (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)),
        (TextStyle::Button, mono(12.0)),
        (
            TextStyle::Small,
            FontId::new(11.5, FontFamily::Proportional),
        ),
        (TextStyle::Monospace, mono(12.5)),
    ]);
    ctx.set_style(style);
}

/// Register JetBrains Mono as the monospace face and its bold cut as a
/// separate display family. Bundling the font means the window looks the same
/// on a fresh install with no fonts of its own.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "netgap-mono".to_owned(),
        Arc::new(FontData::from_static(MONO)),
    );
    fonts.font_data.insert(
        "netgap-mono-bold".to_owned(),
        Arc::new(FontData::from_static(MONO_BOLD)),
    );

    // Keep egui's own monospace (and its emoji fallbacks) behind ours, so any
    // glyph JetBrains Mono lacks still renders.
    let fallback = fonts
        .families
        .get(&FontFamily::Monospace)
        .cloned()
        .unwrap_or_default();
    let mut monospace = fallback.clone();
    monospace.insert(0, "netgap-mono".to_owned());
    fonts.families.insert(FontFamily::Monospace, monospace);

    let mut display = vec!["netgap-mono-bold".to_owned(), "netgap-mono".to_owned()];
    display.extend(
        fallback
            .iter()
            .filter(|name| name.as_str() != "netgap-mono")
            .cloned(),
    );
    fonts
        .families
        .insert(FontFamily::Name(DISPLAY_FAMILY.into()), display);

    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod tests {
    use super::tracked;

    #[test]
    fn tracking_keeps_words_together() {
        assert_eq!(tracked("NET"), "N\u{2009}E\u{2009}T");
        assert_eq!(tracked("V1.0"), "V\u{2009}1\u{2009}.\u{2009}0");
    }

    #[test]
    fn tracking_does_not_double_spaces() {
        assert_eq!(tracked("NO GAP"), "N\u{2009}O G\u{2009}A\u{2009}P");
    }
}
