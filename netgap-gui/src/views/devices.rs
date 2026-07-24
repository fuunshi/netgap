//! The device list: what was found, and what is wrong with it.

use eframe::egui::{self, Align2, FontId, Pos2, RichText, Sense, Stroke, Ui, Vec2};
use netgap_core::{Device, Severity};

use crate::app::{NetgapApp, Tab};
use crate::format;
use crate::theme::Palette;
use crate::widgets;

pub fn show(app: &mut NetgapApp, ui: &mut Ui) {
    let p = app.palette;

    let Some(scan) = app.current() else {
        header(ui, &p, 0);
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("No scan to show")
                    .size(20.0)
                    .strong()
                    .color(p.text),
            );
            ui.label(
                RichText::new("Run a scan and its devices will be listed here.")
                    .size(13.0)
                    .color(p.muted),
            );
            ui.add_space(12.0);
            if widgets::primary_button(ui, &p, "Scan network") {
                app.tab = Tab::Scan;
            }
        });
        return;
    };

    let total = scan.result.devices.len();
    let source = scan.result.config.target.clone();
    let when = format::short_time(&scan.result.started_at);
    header(ui, &p, total);
    ui.label(
        RichText::new(format!("{source} · scanned {when}"))
            .size(12.0)
            .color(p.muted),
    );

    ui.add_space(14.0);

    if total == 0 {
        widgets::card(ui, &p, |ui| {
            ui.label(
                RichText::new("No devices answered")
                    .size(15.0)
                    .strong()
                    .color(p.text),
            );
            ui.add_space(4.0);
            widgets::muted(
                ui,
                &p,
                "The sweep found nothing. Check that the interface and target are right, \
                 and try Automatic discovery.",
            );
            ui.add_space(8.0);
            if widgets::primary_button(ui, &p, "Try another scan") {
                app.tab = Tab::Scan;
            }
        });
        return;
    }

    let filtered = filtered_devices(app);
    let selected = app
        .selected_device
        .filter(|index| filtered.contains(index))
        .or_else(|| filtered.first().copied());

    toolbar(app, ui, &p, total, filtered.len());

    ui.add_space(10.0);

    if filtered.is_empty() {
        widgets::card(ui, &p, |ui| {
            ui.label(
                RichText::new("Nothing matches")
                    .size(15.0)
                    .strong()
                    .color(p.text),
            );
            widgets::muted(ui, &p, "Clear the search or choose a lower severity.");
            if widgets::secondary_button(ui, &p, "Clear filters") {
                app.device_search.clear();
                app.severity_filter = None;
            }
        });
        return;
    }

    ui.columns(2, |columns| {
        list(app, &mut columns[0], &p, &filtered, selected);
        if let Some(index) = selected {
            details(app, &mut columns[1], &p, index);
        }
    });
}

fn header(ui: &mut Ui, p: &Palette, count: usize) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new("Devices").size(26.0).strong().color(p.text));
            if count > 0 {
                ui.label(
                    RichText::new(format!("{} found on the network", format::devices(count)))
                        .size(13.5)
                        .color(p.muted),
                );
            }
        });
    });
}

fn filtered_devices(app: &NetgapApp) -> Vec<usize> {
    let Some(scan) = app.current() else {
        return Vec::new();
    };

    let query = app.device_search.trim().to_ascii_lowercase();
    let mut indices: Vec<usize> = scan
        .result
        .devices
        .iter()
        .enumerate()
        .filter(|(_, device)| {
            if let Some(minimum) = app.severity_filter {
                match format::worst_severity(device) {
                    Some(severity) if severity >= minimum => {}
                    _ => return false,
                }
            }

            if query.is_empty() {
                return true;
            }

            let haystack = [
                device.ip.to_string(),
                device.hostname.clone().unwrap_or_default(),
                device.vendor.clone().unwrap_or_default(),
                device.device_type.clone().unwrap_or_default(),
                device.mac.clone().unwrap_or_default(),
            ]
            .join(" ")
            .to_ascii_lowercase();

            haystack.contains(&query)
        })
        .map(|(index, _)| index)
        .collect();

    // Worst first, then by address, so the thing to look at is at the top.
    indices.sort_by(|a, b| {
        let first = &scan.result.devices[*a];
        let second = &scan.result.devices[*b];
        format::worst_severity(second)
            .cmp(&format::worst_severity(first))
            .then_with(|| first.ip.cmp(&second.ip))
    });

    indices
}

fn toolbar(app: &mut NetgapApp, ui: &mut Ui, p: &Palette, total: usize, shown: usize) {
    widgets::card(ui, p, |ui| {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut app.device_search)
                    .hint_text("Search address, name or vendor…")
                    .desired_width(280.0),
            );

            ui.add_space(6.0);
            filter_chip(ui, p, &mut app.severity_filter, None, "All");
            filter_chip(
                ui,
                p,
                &mut app.severity_filter,
                Some(Severity::Critical),
                "Critical",
            );
            filter_chip(
                ui,
                p,
                &mut app.severity_filter,
                Some(Severity::High),
                "High",
            );
            filter_chip(
                ui,
                p,
                &mut app.severity_filter,
                Some(Severity::Medium),
                "Medium",
            );
            filter_chip(
                ui,
                p,
                &mut app.severity_filter,
                Some(Severity::Info),
                "Info",
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("{shown} of {total}"))
                        .size(11.5)
                        .color(p.muted),
                );
            });
        });
    });
}

fn filter_chip(
    ui: &mut Ui,
    p: &Palette,
    current: &mut Option<Severity>,
    value: Option<Severity>,
    label: &str,
) {
    let selected = *current == value;
    let color = match value {
        Some(severity) => p.severity(severity),
        None => p.text,
    };
    let text = RichText::new(label)
        .size(11.5)
        .color(if selected { color } else { p.muted });
    let button = egui::Button::new(text)
        .fill(if selected {
            p.accent_soft
        } else {
            egui::Color32::TRANSPARENT
        })
        .stroke(Stroke::new(1.0, if selected { color } else { p.border }))
        .corner_radius(egui::CornerRadius::same(12));
    if ui.add(button).clicked() {
        *current = value;
    }
}

fn list(
    app: &mut NetgapApp,
    ui: &mut Ui,
    p: &Palette,
    filtered: &[usize],
    selected: Option<usize>,
) {
    let Some(scan) = app.current() else {
        return;
    };
    let devices = &scan.result.devices;
    let mut clicked = None;

    widgets::card(ui, p, |ui| {
        widgets::section_heading(ui, p, "Devices", Some("Worst findings first"));
        ui.add_space(6.0);

        let height = (ui.available_height() - 12.0).clamp(260.0, 520.0);
        egui::ScrollArea::vertical()
            .id_salt("device-list")
            .max_height(height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for index in filtered {
                    let device = &devices[*index];
                    if device_row(ui, p, device, selected == Some(*index)) {
                        clicked = Some(*index);
                    }
                    ui.add_space(2.0);
                }
            });
    });

    if let Some(index) = clicked {
        app.selected_device = Some(index);
    }
}

fn device_row(ui: &mut Ui, p: &Palette, device: &Device, selected: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 56.0), Sense::click());
    let painter = ui.painter();

    if selected {
        painter.rect_filled(rect, egui::CornerRadius::same(9), p.accent_soft);
    } else if response.hovered() {
        painter.rect_filled(rect, egui::CornerRadius::same(9), p.hover);
    }

    let severity = device.max_severity();
    let dot = Pos2::new(rect.left() + 15.0, rect.center().y);
    match severity {
        Some(severity) => {
            painter.circle_filled(dot, 4.5, p.severity(severity));
        }
        None => {
            painter.circle_filled(dot, 4.0, p.success);
        }
    }

    painter.text(
        Pos2::new(rect.left() + 30.0, rect.top() + 16.0),
        Align2::LEFT_CENTER,
        device.ip.to_string(),
        FontId::monospace(12.0),
        p.text,
    );

    painter.text(
        Pos2::new(rect.right() - 8.0, rect.top() + 16.0),
        Align2::RIGHT_CENTER,
        if device.findings.is_empty() {
            "clear".to_string()
        } else {
            format::findings(device.findings.len())
        },
        FontId::proportional(10.5),
        if device.findings.is_empty() {
            p.success
        } else {
            severity.map_or(p.muted, |s| p.severity(s))
        },
    );

    painter.text(
        Pos2::new(rect.left() + 30.0, rect.top() + 37.0),
        Align2::LEFT_CENTER,
        format::truncate(&format::device_name(device), 26),
        FontId::proportional(12.5),
        p.text,
    );

    if !device.open_ports.is_empty() {
        painter.text(
            Pos2::new(rect.right() - 8.0, rect.top() + 37.0),
            Align2::RIGHT_CENTER,
            format!("{} open", device.open_ports.len()),
            FontId::proportional(10.5),
            p.muted,
        );
    }

    response.clicked()
}

fn details(app: &mut NetgapApp, ui: &mut Ui, p: &Palette, index: usize) {
    let Some(scan) = app.current() else {
        return;
    };
    let Some(device) = scan.result.devices.get(index) else {
        return;
    };

    // Copy the pieces the UI needs, so the export buttons can borrow `app`.
    let name = format::device_name(device);
    let subtitle = format::device_subtitle(device);
    let ip = device.ip.to_string();
    let mac = device.mac.clone();
    let vendor = device.vendor.clone();
    let os = device.os.to_string();
    let os_confidence = device.os_confidence;
    let device_type = device.device_type.clone();
    let first_seen = device.first_seen.clone();
    let ipv6 = device.ipv6_addresses.clone();
    let ports = device.open_ports.clone();
    let severity = device.max_severity();
    let mut findings: Vec<netgap_core::Finding> = device.findings.clone();
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    widgets::card(ui, p, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(name).size(19.0).strong().color(p.text));
                ui.label(RichText::new(subtitle).size(11.5).color(p.muted));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(severity) = severity {
                    widgets::severity_chip(ui, p, severity);
                }
            });
        });

        ui.add_space(10.0);

        egui::Grid::new("device-facts")
            .num_columns(2)
            .spacing([14.0, 5.0])
            .show(ui, |ui| {
                fact(ui, p, "Address", &ip);
                fact(ui, p, "MAC", mac.as_deref().unwrap_or("not known"));
                fact(
                    ui,
                    p,
                    "Vendor",
                    vendor.as_deref().unwrap_or("not identified"),
                );
                let os_text = if os_confidence > 0.0 {
                    format!("{os} ({:.0}% confident)", os_confidence * 100.0)
                } else {
                    os
                };
                fact(ui, p, "System", &os_text);
                fact(
                    ui,
                    p,
                    "Type",
                    device_type.as_deref().unwrap_or("not identified"),
                );
                fact(
                    ui,
                    p,
                    "First seen",
                    &first_seen
                        .as_deref()
                        .map(format::relative_time)
                        .unwrap_or_else(|| "this scan".to_string()),
                );
                if !ipv6.is_empty() {
                    fact(ui, p, "IPv6", &ipv6.join(", "));
                }
            });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if widgets::secondary_button(ui, p, "Copy address") {
                ui.ctx().copy_text(ip.clone());
            }
            if widgets::secondary_button(ui, p, "Export HTML") {
                app.export_report("html");
            }
            if widgets::secondary_button(ui, p, "Export CSV") {
                app.export_report("csv");
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        ui.label(
            RichText::new("Open ports")
                .size(13.0)
                .strong()
                .color(p.text),
        );
        ui.add_space(4.0);
        if ports.is_empty() {
            widgets::muted(ui, p, "No open service ports were found.");
        } else {
            ui.horizontal_wrapped(|ui| {
                for port in &ports {
                    egui::Frame::new()
                        .fill(p.field)
                        .corner_radius(egui::CornerRadius::same(5))
                        .stroke(Stroke::new(1.0, p.border))
                        .inner_margin(egui::Margin::symmetric(7, 2))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(port.to_string())
                                    .size(11.5)
                                    .monospace()
                                    .color(p.text),
                            );
                        });
                }
            });
        }

        ui.add_space(10.0);
        ui.label(
            RichText::new(format!("Findings ({})", findings.len()))
                .size(13.0)
                .strong()
                .color(p.text),
        );
        ui.add_space(6.0);

        if findings.is_empty() {
            ui.label(
                RichText::new("Nothing wrong was found on this device.")
                    .size(12.5)
                    .color(p.success),
            );
            return;
        }

        let height = (ui.available_height() - 8.0).clamp(180.0, 420.0);
        egui::ScrollArea::vertical()
            .id_salt("device-findings")
            .max_height(height)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for finding in &findings {
                    finding_card(ui, p, finding);
                    ui.add_space(6.0);
                }
            });
    });
}

fn fact(ui: &mut Ui, p: &Palette, label: &str, value: &str) {
    ui.label(RichText::new(label).size(11.5).color(p.muted));
    ui.label(RichText::new(value).size(12.0).color(p.text));
    ui.end_row();
}

fn finding_card(ui: &mut Ui, p: &Palette, finding: &netgap_core::Finding) {
    egui::Frame::new()
        .fill(p.field)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                widgets::severity_chip(ui, p, finding.severity);
                ui.vertical(|ui| {
                    ui.set_max_width(ui.available_width());
                    ui.add(
                        egui::Label::new(
                            RichText::new(&finding.title)
                                .size(12.5)
                                .strong()
                                .color(p.text),
                        )
                        .wrap(),
                    );
                    if !finding.description.is_empty() {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&finding.description)
                                    .size(11.0)
                                    .color(p.muted),
                            )
                            .wrap(),
                        );
                    }
                    if !finding.remediation.is_empty() {
                        ui.add_space(3.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("Fix: {}", finding.remediation))
                                    .size(11.0)
                                    .color(p.accent),
                            )
                            .wrap(),
                        );
                    }
                });
            });
        });
}
