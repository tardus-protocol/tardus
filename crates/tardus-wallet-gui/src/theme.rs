//! Quantus 2025 visual theme for the TARDUS desktop wallet.
//!
//! Brand palette: Haiti background, Blue Chalk text, Electric Violet
//! accent, Turbo highlight. Same palette used on the TARDUS website.
//! User-approved 2026-05-22.
//!
//! License: TARDUS-PROPRIETARY-1.0.

use eframe::egui::{
    self, FontData, FontDefinitions, FontFamily, FontId, Rounding, Stroke, TextStyle, Visuals,
};
use std::sync::Arc;

/// Quantus 2025 brand colors.
pub mod color {
    use eframe::egui::Color32;

    /// Haiti — primary background.
    pub const BG: Color32 = Color32::from_rgb(0x18, 0x10, 0x2B);
    /// Haiti elevated — surfaces, hover, panel backgrounds.
    pub const BG_ELEV: Color32 = Color32::from_rgb(0x22, 0x17, 0x39);
    /// Haiti deep — darker inner panels, code blocks.
    pub const BG_DEEP: Color32 = Color32::from_rgb(0x0E, 0x08, 0x20);

    /// Blue Chalk — primary text (full opacity).
    pub const FG: Color32 = Color32::from_rgb(0xF5, 0xF3, 0xFF);
    /// Blue Chalk @ 72% (premultiplied) — secondary text.
    /// Rendered against BG produces ~#B7B3C4 lavender-white, NOT gray.
    pub const FG_SOFT: Color32 = Color32::from_rgba_premultiplied(176, 175, 184, 184);
    /// Blue Chalk @ 52% (premultiplied) — meta / footer labels.
    pub const FG_META: Color32 = Color32::from_rgba_premultiplied(127, 126, 132, 132);

    /// Electric Violet — primary accent (CTAs, links, focus, selection).
    pub const ACCENT: Color32 = Color32::from_rgb(0x83, 0x4D, 0xFB);
    /// Electric Violet darker — hover / pressed state.
    pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0x6B, 0x3F, 0xD9);

    /// Turbo — secondary accent (status badges, "live" markers, warnings).
    pub const HIGHLIGHT: Color32 = Color32::from_rgb(0xF0, 0xE1, 0x00);

    /// Status indicators — palette-aligned, not stock egui constants.
    /// Success — desaturated turquoise-green, harmonises with violet.
    pub const STATUS_OK: Color32 = Color32::from_rgb(0x6B, 0xE3, 0xC9);
    /// Warning — Turbo yellow.
    pub const STATUS_WARN: Color32 = HIGHLIGHT;
    /// Error — pink-red, stays in the violet-warm spectrum (not stock RED).
    pub const STATUS_ERROR: Color32 = Color32::from_rgb(0xFF, 0x6B, 0x9F);

    /// Borders — Blue Chalk at low alpha for hairlines on dark BG.
    pub const BORDER: Color32 = Color32::from_rgba_premultiplied(25, 24, 26, 26);
    pub const BORDER_STRONG: Color32 = Color32::from_rgba_premultiplied(56, 53, 58, 56);
}

/// Apply the Quantus visual theme to an egui context.
/// Loads IBM Plex Mono + Sans, overrides visuals, sets text styles.
pub fn apply(ctx: &egui::Context) {
    apply_fonts(ctx);
    apply_text_styles(ctx);
    apply_visuals(ctx);
}

fn apply_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    fonts.font_data.insert(
        "plex-mono".to_owned(),
        FontData::from_static(include_bytes!(
            "../assets/fonts/IBMPlexMono-Regular.ttf"
        )),
    );
    fonts.font_data.insert(
        "plex-mono-bold".to_owned(),
        FontData::from_static(include_bytes!(
            "../assets/fonts/IBMPlexMono-Bold.ttf"
        )),
    );
    fonts.font_data.insert(
        "plex-sans".to_owned(),
        FontData::from_static(include_bytes!(
            "../assets/fonts/IBMPlexSans-Regular.ttf"
        )),
    );
    fonts.font_data.insert(
        "plex-sans-medium".to_owned(),
        FontData::from_static(include_bytes!(
            "../assets/fonts/IBMPlexSans-Medium.ttf"
        )),
    );

    // Proportional family — body text. Plex Sans first, fall back to defaults.
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "plex-sans".to_owned());

    // Monospace family — code, tab labels. Plex Mono first.
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "plex-mono".to_owned());

    // Custom family for bold headings.
    fonts.families.insert(
        FontFamily::Name(Arc::from("PlexMonoBold")),
        vec!["plex-mono-bold".to_owned(), "plex-mono".to_owned()],
    );

    ctx.set_fonts(fonts);
}

fn apply_text_styles(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    let bold_mono = FontFamily::Name(Arc::from("PlexMonoBold"));

    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(20.0, bold_mono.clone()),
    );
    style.text_styles.insert(
        TextStyle::Body,
        FontId::new(14.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(13.0, FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(13.0, FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(11.0, FontFamily::Proportional),
    );

    ctx.set_style(style);
}

fn apply_visuals(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    let no_corner = Rounding::same(0.0);

    // Surfaces
    visuals.window_fill = color::BG;
    visuals.panel_fill = color::BG;
    visuals.extreme_bg_color = color::BG_DEEP;
    visuals.faint_bg_color = color::BG_ELEV;
    visuals.code_bg_color = color::BG_DEEP;

    // Default text color — Blue Chalk (full).
    visuals.override_text_color = Some(color::FG);

    // Links — Electric Violet.
    visuals.hyperlink_color = color::ACCENT;

    // Selection — Electric Violet fill + Blue Chalk stroke.
    visuals.selection.bg_fill = color::ACCENT_SOFT;
    visuals.selection.stroke = Stroke::new(1.0, color::FG);

    // Window decoration
    visuals.window_stroke = Stroke::new(1.0, color::BORDER_STRONG);
    visuals.window_rounding = Rounding::same(2.0);

    // Widget states — noninteractive (labels, separators)
    visuals.widgets.noninteractive.bg_fill = color::BG;
    visuals.widgets.noninteractive.weak_bg_fill = color::BG;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, color::BORDER);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, color::FG_SOFT);
    visuals.widgets.noninteractive.rounding = no_corner;

    // Inactive — buttons, idle widgets
    visuals.widgets.inactive.bg_fill = color::BG_ELEV;
    visuals.widgets.inactive.weak_bg_fill = color::BG_ELEV;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, color::BORDER_STRONG);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, color::FG);
    visuals.widgets.inactive.rounding = no_corner;

    // Hovered — borders shift to Electric Violet
    visuals.widgets.hovered.bg_fill = color::BG_ELEV;
    visuals.widgets.hovered.weak_bg_fill = color::BG_ELEV;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, color::ACCENT);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, color::ACCENT);
    visuals.widgets.hovered.rounding = no_corner;

    // Active (pressed / selected) — Electric Violet fill
    visuals.widgets.active.bg_fill = color::ACCENT;
    visuals.widgets.active.weak_bg_fill = color::ACCENT;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, color::ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, color::BG);
    visuals.widgets.active.rounding = no_corner;

    // Open (dropdown / combobox)
    visuals.widgets.open.bg_fill = color::ACCENT_SOFT;
    visuals.widgets.open.weak_bg_fill = color::ACCENT_SOFT;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, color::ACCENT);
    visuals.widgets.open.fg_stroke = Stroke::new(1.0, color::FG);
    visuals.widgets.open.rounding = no_corner;

    // Status-bar colors used by egui internally
    visuals.warn_fg_color = color::STATUS_WARN;
    visuals.error_fg_color = color::STATUS_ERROR;

    ctx.set_visuals(visuals);
}
