//! A complete scan, from a plan to a saved-shaped result.
//!
//! The CLI has its own progress printing and its `--deep` assessment stages;
//! this pipeline is the common core the UIs run: discover, merge IPv6
//! neighbours, name and classify, then optionally scan service ports. It
//! prints nothing and reports progress through a callback.

use anyhow::Result;
use chrono::Local;
use netgap_core::{Device, FindingSummary, ScanConfig, ScanResult};
use netgap_scan::{PortScanner, ScanConfig as PortScanConfig, TOP_DANGEROUS_PORTS};

use crate::discovery::{self, DiscoveryPlan};
use crate::enrich;

/// Where a scan has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Discovering,
    Enriching,
    PortScanning,
    Finished,
}

/// One progress note for the front end to render however it likes.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub stage: Stage,
    pub message: String,
}

/// What to run. The plan already names the interface, target and method.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub plan: DiscoveryPlan,
    /// Scan the dangerous service ports and attach findings. When false this
    /// is discovery only.
    pub ports: bool,
}

impl ScanRequest {
    /// Must the plan be quiet? A window has no terminal to write progress to,
    /// so this is the normal choice for a UI.
    pub fn quiet(mut self) -> Self {
        self.plan.quiet = true;
        self
    }
}

/// Run a scan and return it in the same shape `netgap scan` records.
pub async fn run<F>(request: &ScanRequest, progress: F) -> Result<ScanResult>
where
    F: Fn(ScanProgress) + Send + Sync,
{
    progress(ScanProgress {
        stage: Stage::Discovering,
        message: "Looking for devices on the network…".to_string(),
    });

    let mut devices = discovery::run(&request.plan).await?;

    // A device that answers only on IPv6 is a device on the network, and a
    // count that omits it is quietly wrong.
    enrich::run_ipv6(&mut devices, &request.plan);

    if !devices.is_empty() {
        progress(ScanProgress {
            stage: Stage::Enriching,
            message: format!(
                "Found {}. Looking up names and device types…",
                count_devices(devices.len())
            ),
        });
        enrich::enrich_devices(&request.plan, &mut devices, false).await;
    }

    if request.ports && !devices.is_empty() {
        progress(ScanProgress {
            stage: Stage::PortScanning,
            message: format!(
                "Checking service ports on {}…",
                count_devices(devices.len())
            ),
        });

        let scanner = PortScanner::new(PortScanConfig {
            ports: TOP_DANGEROUS_PORTS.to_vec(),
            timeout_ms: 2000,
            concurrency: 32,
        })
        .quiet(true)
        .zone(netgap_interfaces::interface_index(
            &request.plan.interface.name,
        ));

        scanner.scan_devices(&mut devices).await?;
    }

    let mut summary = FindingSummary::new();
    for device in &devices {
        for finding in &device.findings {
            summary.add_finding(finding.severity);
        }
    }

    let count = devices.len();
    progress(ScanProgress {
        stage: Stage::Finished,
        message: if count == 0 {
            "No devices answered on this network.".to_string()
        } else {
            format!("Finished. Found {}.", count_devices(count))
        },
    });

    Ok(ScanResult {
        started_at: Local::now().to_rfc3339(),
        config: ScanConfig {
            interface: request.plan.interface.name.clone(),
            target: request.plan.target.clone(),
            timeout_ms: if request.ports { 2000 } else { 1000 },
            concurrency: 32,
            discovery_only: !request.ports,
        },
        devices,
        summary,
    })
}

fn count_devices(count: usize) -> String {
    if count == 1 {
        "1 device".to_string()
    } else {
        format!("{} devices", count)
    }
}

/// Devices with at least one finding, which is what a summary means by
/// "affected".
pub fn affected_devices(devices: &[Device]) -> usize {
    devices
        .iter()
        .filter(|device| !device.findings.is_empty())
        .count()
}
