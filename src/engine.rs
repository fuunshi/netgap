use anyhow::Result;
use pnet::datalink::NetworkInterface;

use crate::analyzer;
use crate::discovery;
use crate::model::{ScanMode, ScanSummary};
use crate::ports;

pub async fn scan(interface: NetworkInterface, mode: ScanMode) -> Result<ScanSummary> {
    let discovered = discovery::discover_network(&interface, mode)?;

    let handles = discovered
        .into_iter()
        .map(|host| {
            let interface = interface.clone();
            tokio::task::spawn_blocking(move || ports::scan_host(&interface, host, mode))
        })
        .collect::<Vec<_>>();

    let mut hosts = Vec::new();
    for handle in handles {
        let mut report = handle.await??;
        report.gaps = analyzer::analyze_host(&report);
        hosts.push(report);
    }

    Ok(ScanSummary {
        interface: interface.name,
        mode,
        hosts,
        interfaces: discovery::list_interfaces()?,
    })
}
