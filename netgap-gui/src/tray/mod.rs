//! The tray icon: what lets the window rest in the background.
//!
//! A LAN scanner that is only useful while its window is open is a scanner
//! people close. The tray is the resting state — the window hides, the icon
//! stays, and the menu has the two things that matter: scan now, and quit.
//!
//! On Linux the icon is a StatusNotifierItem served over D-Bus by the same
//! zbus stack eframe already links for accessibility, so no GTK development
//! headers are needed to build it. A desktop without a status-notifier host
//! (a bare session, a headless machine) gets `Err` from [`start`] and the
//! window keeps its ordinary close behaviour rather than disappearing into
//! something invisible.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{start, Event, Tray};

#[cfg(not(target_os = "linux"))]
mod other;
#[cfg(not(target_os = "linux"))]
pub use other::{start, Event, Tray};
