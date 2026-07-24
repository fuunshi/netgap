//! Running a scan without blocking the window.
//!
//! eframe owns the main thread, so the scan gets its own thread with a small
//! tokio runtime. Results and progress come back over a channel that the app
//! drains once per frame.

use std::sync::mpsc::{self, Receiver};
use std::thread;

use netgap_core::ScanResult;
use netgap_engine::scan::{self, ScanProgress, ScanRequest};
use netgap_storage::ScanStore;

/// What the window needs to hear from a running scan.
pub enum WorkerEvent {
    Progress(ScanProgress),
    Done {
        result: ScanResult,
        scan_id: Option<String>,
        warning: Option<String>,
    },
    Failed(String),
}

/// Start a scan. The returned receiver ends when the thread is finished.
pub fn start(request: ScanRequest) -> Result<Receiver<WorkerEvent>, String> {
    let (sender, receiver) = mpsc::channel();

    thread::Builder::new()
        .name("netgap-scan".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = sender.send(WorkerEvent::Failed(format!(
                        "Could not start the scanner: {error}"
                    )));
                    return;
                }
            };

            let progress_sender = sender.clone();
            let outcome = runtime.block_on(scan::run(&request, move |progress| {
                let _ = progress_sender.send(WorkerEvent::Progress(progress));
            }));

            match outcome {
                Ok(result) => {
                    // Saving is part of scanning from the window: a result
                    // that disappears on close is not history.
                    let (scan_id, warning) = if result.devices.is_empty() {
                        (None, None)
                    } else {
                        match ScanStore::open_default()
                            .and_then(|mut store| store.save_scan(&result))
                        {
                            Ok(id) => (Some(id), None),
                            Err(error) => (
                                None,
                                Some(format!(
                                    "The scan finished, but its history could not be saved: {error}"
                                )),
                            ),
                        }
                    };

                    let _ = sender.send(WorkerEvent::Done {
                        result,
                        scan_id,
                        warning,
                    });
                }
                Err(error) => {
                    let _ = sender.send(WorkerEvent::Failed(format!("{error:#}")));
                }
            }
        })
        .map_err(|error| format!("Could not start the scan thread: {error}"))?;

    Ok(receiver)
}
