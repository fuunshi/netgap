//! The scan pipeline shared by the command line, the terminal view and the
//! window application.
//!
//! Discovery, IPv6 neighbour merging, naming and port scanning used to live
//! inside `netgap-cli`. They were UI-free already; this crate makes that
//! explicit so a second front end does not have to copy them. The CLI keeps
//! its prompts and its human-readable progress output, and the UIs ask for
//! quiet plans and render their own progress.

pub mod discovery;
pub mod enrich;
pub mod scan;
