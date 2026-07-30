//! Choosing what to scan, and watching it happen.

use eframe::egui::{self, Align2, FontId, Pos2, RichText, Sense, Stroke, Ui, Vec2};
use netgap_interfaces::InterfaceInfo;

use crate::app::{MethodChoice, NetgapApp, Tab};
use crate::format;
use crate::theme::{self, Palette};
use crate::widgets;

pub fn show(app: &mut NetgapApp, ui: &mut Ui) {
    let p = app.palette;

    widgets::page_header(
        ui,
        &p,
        "// 02 · RECON",
        "Scan network",
        "Pick an interface and say how thoroughly to look.",
        |_| {},
    );

    ui.add_space(16.0);

    if app.scanning {
        progress_card(app, ui, &p);
        ui.add_space(12.0);
    }

    if let Some(error) = app.scan_error.clone() {
        error_card(ui, &p, &error);
        ui.add_space(12.0);
    }

    if let Some(error) = app.interfaces_error.clone() {
        error_card(ui, &p, &error);
        ui.add_space(12.0);
    }

    ui.columns(2, |columns| {
        interface_card(app, &mut columns[0], &p);
        options_card(app, &mut columns[1], &p);
    });

    ui.add_space(14.0);

    if app.scanning {
        log_card(app, ui, &p);
    } else if app.latest.is_some() {
        last_result_card(app, ui, &p);
    }
}

fn interface_card(app: &mut NetgapApp, ui: &mut Ui, p: &Palette) {
    widgets::card(ui, p, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                widgets::section_heading(
                    ui,
                    p,
                    "Network interface",
                    Some("The one carrying the network you want to check."),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .checkbox(&mut app.show_all_interfaces, "Show all")
                    .changed()
                {
                    app.ensure_selection();
                }
            });
        });

        ui.add_space(10.0);

        let visible = app.visible_interfaces();
        if visible.is_empty() {
            widgets::muted(
                ui,
                p,
                "No usable interface found. Connect to a network and reload.",
            );
            if widgets::secondary_button(ui, p, "Reload interfaces") {
                app.rescan_interfaces();
            }
            return;
        }

        let mut chosen = None;
        egui::ScrollArea::vertical()
            .max_height(268.0)
            // Shrink to the number of interfaces, so a machine with one
            // interface does not leave an empty block in the card.
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for index in visible {
                    let Some(interface) = app.interfaces.get(index) else {
                        continue;
                    };
                    let selected = app.selected_interface == Some(index);
                    if interface_row(ui, p, interface, selected) {
                        chosen = Some(index);
                    }
                    ui.add_space(3.0);
                }
            });

        if let Some(index) = chosen {
            app.choose_interface(index);
        }

        if !app.show_all_interfaces {
            ui.add_space(4.0);
            widgets::muted(
                ui,
                p,
                "Bridges, tunnels and loopback are hidden. Show all to scan one.",
            );
        }
    });
}

fn interface_row(ui: &mut Ui, p: &Palette, interface: &InterfaceInfo, selected: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 54.0), Sense::click());
    let painter = ui.painter();

    if selected {
        painter.rect_filled(rect, egui::CornerRadius::same(9), p.accent_soft);
        painter.rect_stroke(
            rect,
            egui::CornerRadius::same(9),
            Stroke::new(1.0_f32, p.accent),
            egui::StrokeKind::Inside,
        );
    } else if response.hovered() {
        painter.rect_filled(rect, egui::CornerRadius::same(9), p.hover);
    }

    let radio_center = Pos2::new(rect.left() + 18.0, rect.center().y);
    painter.circle_stroke(radio_center, 7.0, Stroke::new(1.5_f32, p.muted));
    if selected {
        painter.circle_filled(radio_center, 4.0, p.accent);
    }

    painter.text(
        Pos2::new(rect.left() + 36.0, rect.top() + 15.0),
        Align2::LEFT_CENTER,
        &interface.name,
        FontId::monospace(12.5),
        p.text,
    );

    let address = interface
        .cidr
        .clone()
        .or_else(|| interface.ipv4.clone())
        .unwrap_or_else(|| "no IPv4 address".to_string());
    painter.text(
        Pos2::new(rect.left() + 36.0, rect.top() + 34.0),
        Align2::LEFT_CENTER,
        address,
        FontId::monospace(11.5),
        p.muted,
    );

    let mut tag_x = rect.right() - 8.0;
    if interface.is_default_route {
        tag_x -= 62.0;
        painter.text(
            Pos2::new(tag_x, rect.center().y),
            Align2::LEFT_CENTER,
            "gateway route",
            FontId::monospace(8.5),
            p.accent,
        );
    }
    if !interface.is_scannable() {
        painter.text(
            Pos2::new(rect.right() - 8.0, rect.center().y),
            Align2::RIGHT_CENTER,
            "not scannable",
            FontId::proportional(10.0),
            p.muted,
        );
    }

    response.clicked()
}

fn options_card(app: &mut NetgapApp, ui: &mut Ui, p: &Palette) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(ui, p, "Scan options", None);
        ui.add_space(12.0);

        let target_field = widgets::label_row(ui, p, "Target network", |ui| {
            let width = ui.available_width();
            widgets::text_field(
                ui,
                p,
                egui::Id::new("scan-target-field"),
                &mut app.target,
                widgets::FieldHint {
                    text: "192.168.1.0/24",
                    icon: widgets::FieldIcon::Target,
                    shortcut: None,
                },
                width,
            )
        });

        // Enter in the target field is the same as pressing Start.
        if target_field.lost_focus()
            && ui.input(|input| input.key_pressed(egui::Key::Enter))
            && !app.scanning
            && app.selected_interface.is_some()
            && !app.target.trim().is_empty()
        {
            app.start_scan();
        }

        ui.add_space(4.0);

        widgets::label_row(ui, p, "Discovery", |ui| {
            egui::ComboBox::from_id_salt("discovery-method")
                .width(ui.available_width())
                .selected_text(app.method.label())
                .show_ui(ui, |ui| {
                    for method in [MethodChoice::Auto, MethodChoice::Arp, MethodChoice::Tcp] {
                        ui.selectable_value(&mut app.method, method, method.label());
                    }
                });
        });

        ui.add_space(1.0);
        let color = if app.method == MethodChoice::Arp && !app.privileged {
            p.high
        } else {
            p.muted
        };
        note(
            ui,
            RichText::new(app.method.detail()).size(11.0).color(color),
        );

        if !app.privileged && app.method != MethodChoice::Tcp {
            ui.add_space(2.0);
            note(
                ui,
                RichText::new(
                    "This program has no raw-socket permission. ARP needs root or \
                     a one-time setcap; Automatic will use TCP instead.",
                )
                .size(10.5)
                .color(p.muted),
            );
        }

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        ui.label(
            RichText::new(theme::tracked("WHAT TO LOOK FOR"))
                .font(theme::mono(9.5))
                .color(p.muted),
        );
        ui.add_space(4.0);
        ui.radio_value(
            &mut app.full_scan,
            false,
            "Devices only — find hosts and names, quickly",
        );
        ui.radio_value(
            &mut app.full_scan,
            true,
            "Devices and ports — check 20 dangerous ports",
        );
        ui.add_space(2.0);
        widgets::muted(
            ui,
            p,
            if app.full_scan {
                "Port checks take longer and are what produce findings."
            } else {
                "No ports are checked, so this scan produces no findings."
            },
        );

        ui.add_space(12.0);

        let can_start =
            !app.scanning && app.selected_interface.is_some() && !app.target.trim().is_empty();

        ui.add_enabled_ui(can_start, |ui| {
            if ui
                .add_sized(
                    [ui.available_width(), 38.0],
                    egui::Button::new(
                        RichText::new(theme::tracked(if app.scanning {
                            "SCANNING…"
                        } else {
                            "START SCAN"
                        }))
                        .font(theme::display(11.0))
                        .color(p.bg),
                    )
                    .fill(p.accent)
                    .stroke(Stroke::NONE)
                    .corner_radius(egui::CornerRadius::same(5)),
                )
                .clicked()
            {
                app.start_scan();
            }
        });

        if app.selected_interface.is_none() {
            widgets::muted(ui, p, "Choose an interface to begin.");
        } else if app.target.trim().is_empty() {
            widgets::muted(ui, p, "Enter a target network to begin.");
        }
    });
}

fn progress_card(app: &mut NetgapApp, ui: &mut Ui, p: &Palette) {
    widgets::card(ui, p, |ui| {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Scanning").size(15.0).strong().color(p.text));
                ui.label(RichText::new(&app.scan_stage).size(12.5).color(p.muted));
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(started) = app.scan_started {
                    let seconds = started.elapsed().as_secs();
                    ui.label(
                        RichText::new(format!("{}:{:02}", seconds / 60, seconds % 60))
                            .size(15.0)
                            .monospace()
                            .color(p.muted),
                    );
                }
            });
        });

        ui.add_space(10.0);
        widgets::progress_bar(ui, p, None, ui.input(|input| input.time));
        ui.add_space(6.0);
        widgets::muted(
            ui,
            p,
            "A /24 network usually takes five to fifteen seconds to discover, \
             plus a few seconds per device for ports.",
        );
    });
}

fn log_card(app: &NetgapApp, ui: &mut Ui, p: &Palette) {
    widgets::card(ui, p, |ui| {
        widgets::section_heading(ui, p, "Progress", None);
        ui.add_space(8.0);

        if app.scan_log.is_empty() {
            widgets::muted(ui, p, "Waiting for the first device to answer…");
            return;
        }

        for line in app
            .scan_log
            .iter()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .iter()
            .rev()
        {
            ui.label(
                RichText::new(format!("›  {line}"))
                    .size(12.0)
                    .monospace()
                    .color(p.muted),
            );
        }
    });
}

fn last_result_card(app: &mut NetgapApp, ui: &mut Ui, p: &Palette) {
    let Some(scan) = app.latest.as_ref() else {
        return;
    };
    let devices = scan.result.devices.len();
    let findings = scan
        .result
        .devices
        .iter()
        .map(|d| d.findings.len())
        .sum::<usize>();
    let critical = scan
        .result
        .devices
        .iter()
        .flat_map(|d| d.findings.iter())
        .filter(|f| f.severity == netgap_core::Severity::Critical)
        .count();
    let when = format::relative_time(&scan.result.started_at);
    let target = scan.result.config.target.clone();

    widgets::card(ui, p, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                widgets::section_heading(
                    ui,
                    p,
                    "Last scan",
                    Some(&format!(
                        "{target} · {when} · {} already recorded",
                        format::findings(findings)
                    )),
                );
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format::devices(devices))
                            .size(13.0)
                            .strong()
                            .color(p.text),
                    );
                    if critical > 0 {
                        ui.label(
                            RichText::new(format!("· {critical} critical"))
                                .size(13.0)
                                .strong()
                                .color(p.critical),
                        );
                    }
                });
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::primary_button(ui, p, "View devices") {
                    app.tab = Tab::Devices;
                }
                if widgets::secondary_button(ui, p, "Export HTML") {
                    app.export_report("html");
                }
            });
        });
    });
}

/// A note under an option, indented to line up with the controls but wrapping
/// inside the card instead of widening it.
fn note(ui: &mut Ui, text: RichText) {
    ui.horizontal_top(|ui| {
        ui.add_space(141.0);
        ui.vertical(|ui| {
            ui.set_max_width(ui.available_width());
            ui.add(egui::Label::new(text).wrap());
        });
    });
}

fn error_card(ui: &mut Ui, p: &Palette, message: &str) {
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.critical))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.label(RichText::new("!").strong().color(p.critical));
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("The scan could not finish")
                            .size(13.0)
                            .strong()
                            .color(p.text),
                    );
                    ui.label(RichText::new(message).size(11.5).color(p.muted));
                });
            });
        });
}
