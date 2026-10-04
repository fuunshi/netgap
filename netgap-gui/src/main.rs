//! Netgap's window application.
//!
//! The command line and `netgap ui` remain the tools for people who live in a
//! terminal. This is the same scanner behind a window: a dashboard for the
//! network's health, a scan screen that explains the choices, a searchable
//! device list, and the history already in the SQLite database.
//!
//! Nothing is reimplemented. Scans run through `netgap-engine`, results are
//! stored by `netgap-storage`, and the health score and plain-language issues
//! come from `netgap-core` and `netgap-report` — the same code that produces
//! `netgap report`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod format;
mod theme;
mod tray;
mod views;
mod widgets;
mod worker;

use app::{NetgapApp, Tab, TrayMode};
use theme::Theme;

const USAGE: &str =
    "usage: netgap-gui [dashboard|scan|devices|history] [--light|--dark] [--tray|--no-tray]";

fn main() -> eframe::Result {
    let mut initial_tab = Tab::Dashboard;
    let mut theme = Theme::Dark;
    let mut tray = TrayMode::Auto;

    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--light" => theme = Theme::Light,
            "--dark" => theme = Theme::Dark,
            // Start in the tray: the window is there for when it is wanted,
            // but a scanner that monitors the network belongs in the
            // background.
            "--tray" => tray = TrayMode::Hidden,
            "--no-tray" => tray = TrayMode::Off,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            value => match Tab::parse(value) {
                Some(tab) => initial_tab = tab,
                None => {
                    eprintln!("netgap-gui: unknown argument {value:?}\n{USAGE}");
                    std::process::exit(2);
                }
            },
        }
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Netgap")
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([1040.0, 680.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Netgap",
        options,
        Box::new(move |cc| Ok(Box::new(NetgapApp::new(cc, initial_tab, theme, tray)))),
    )
}
