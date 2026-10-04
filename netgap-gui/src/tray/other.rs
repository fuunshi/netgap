//! Tray support on platforms where it is not implemented yet.
//!
//! Windows and macOS have native tray APIs, but neither is wired up here: the
//! cross-platform crates for them need a build and a desktop this repository's
//! CI does not have yet. Reporting the tray as unavailable is the honest
//! answer, and it leaves the window's close button doing what it says.

use std::sync::mpsc::Receiver;

/// What the menu asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Show,
    ScanNow,
    Quit,
}

pub struct Tray;

pub fn start() -> Result<(Tray, Receiver<Event>), String> {
    Err("no tray icon on this platform yet, so closing the window quits".to_string())
}

impl Tray {
    pub fn set_tooltip(&self, _text: &str) {}

    pub fn notify(&self, _summary: &str, _body: &str) {}
}
