//! Unprivileged host discovery over TCP.
//!
//! Used when raw sockets are unavailable. Connects to a handful of ports on
//! each host in the subnet and treats a connection *refusal* as proof of life:
//! a RST means a host is there, it simply is not listening. That makes the
//! sweep work against hosts with no open ports, which a "did anything accept?"
//! scan would miss.
//!
//! Results are enriched from the kernel neighbour table, which the connects
//! populate as a side effect.

use crate::neighbor::{enrich_macs, read_neighbor_table};
use anyhow::Result;
use netgap_core::Device;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Ports probed to decide whether a host is alive.
///
/// Chosen to cover the common LAN device classes (routers, NAS, printers,
/// workstations) while staying small enough to sweep quickly.
pub const DEFAULT_PROBE_PORTS: &[u16] = &[80, 443, 22, 445, 139, 8080, 3389, 23];

/// Configuration for an unprivileged TCP sweep.
#[derive(Debug, Clone)]
pub struct TcpSweepConfig {
    /// Hosts to probe.
    pub targets: Vec<Ipv4Addr>,
    /// Ports to probe on each host.
    pub ports: Vec<u16>,
    /// Timeout per connection attempt, in milliseconds.
    pub timeout_ms: u64,
    /// Maximum hosts probed at once.
    pub concurrency: usize,
    /// Merge hosts the kernel already knows about from the neighbour table.
    pub include_neighbors: bool,
    /// Only take neighbour entries belonging to this interface.
    pub interface_name: Option<String>,
    /// Suppress progress output (used when the sweep is a sub-step of another
    /// command that prints its own status).
    pub quiet: bool,
}

impl Default for TcpSweepConfig {
    fn default() -> Self {
        TcpSweepConfig {
            targets: Vec::new(),
            ports: DEFAULT_PROBE_PORTS.to_vec(),
            timeout_ms: 400,
            concurrency: 128,
            include_neighbors: true,
            interface_name: None,
            quiet: false,
        }
    }
}

/// What a single connection attempt told us about the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// The port accepted the connection.
    Open(u16),
    /// The host answered with RST: it is up, the port is closed.
    Refused,
    /// No answer, or the network rejected the attempt.
    Silent,
}

/// Discovers LAN hosts using ordinary TCP connects.
pub struct TcpSweeper {
    config: TcpSweepConfig,
}

impl TcpSweeper {
    /// Create a new sweeper.
    pub fn new(config: TcpSweepConfig) -> Self {
        TcpSweeper { config }
    }

    /// Probe every target and return the hosts that responded.
    pub async fn scan(&self) -> Result<Vec<Device>> {
        if !self.config.quiet {
            eprintln!(
                "🔍 TCP discovery starting ({} hosts, {} ports each, no root required)",
                self.config.targets.len(),
                self.config.ports.len()
            );
        }

        let semaphore = std::sync::Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let mut tasks = JoinSet::new();

        for ip in &self.config.targets {
            let permit = semaphore.clone().acquire_owned().await?;
            let ip = *ip;
            let ports = self.config.ports.clone();
            let timeout_duration = Duration::from_millis(self.config.timeout_ms.max(50));

            tasks.spawn(async move {
                let _permit = permit;
                (ip, probe_host(ip, &ports, timeout_duration).await)
            });

        }

        let mut devices = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((ip, probe)) = joined else { continue };
            if !probe.alive {
                continue;
            }
            // The connects that proved the host alive also revealed which of
            // the probed ports are open; keeping them gives device
            // classification something real to work from.
            let mut device = Device::new(IpAddr::V4(ip));
            for port in probe.open_ports {
                device.add_open_port(port);
            }
            devices.push(device);
        }

        // The connects above warm the kernel's ARP cache, so a neighbour-table
        // read now recovers MAC addresses (and hosts that stayed silent).
        if self.config.include_neighbors {
            let entries = read_neighbor_table();
            let matched = enrich_macs(
                &mut devices,
                &entries,
                self.config.interface_name.as_deref(),
            );

            if let Some(interface) = self.config.interface_name.as_deref() {
                let known: Vec<Ipv4Addr> = devices
                    .iter()
                    .filter_map(|device| match device.ip {
                        IpAddr::V4(ipv4) => Some(ipv4),
                        IpAddr::V6(_) => None,
                    })
                    .collect();

                for entry in entries.iter().filter(|entry| entry.iface == interface) {
                    if !self.config.targets.contains(&entry.ip) || known.contains(&entry.ip) {
                        continue;
                    }
                    let mut device = Device::new(IpAddr::V4(entry.ip));
                    device.mac = Some(entry.mac.clone());
                    devices.push(device);
                }
            }

            if matched > 0 && !self.config.quiet {
                eprintln!("   MAC addresses resolved for {} host(s)", matched);
            }
        }

        devices.sort_by_key(|device| match device.ip {
            IpAddr::V4(ipv4) => u32::from(ipv4),
            IpAddr::V6(_) => u32::MAX,
        });

        Ok(devices)
    }
}

/// What probing one host revealed.
#[derive(Debug, Default, Clone)]
struct HostProbe {
    /// The host answered on at least one port.
    alive: bool,
    /// Ports that accepted a connection.
    open_ports: Vec<u16>,
}

/// Probe one host across `ports`.
async fn probe_host(ip: Ipv4Addr, ports: &[u16], timeout_duration: Duration) -> HostProbe {
    let mut tasks = JoinSet::new();

    for port in ports {
        let port = *port;
        tasks.spawn(async move { probe_port(ip, port, timeout_duration).await });
    }

    let mut probe = HostProbe::default();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(result) = joined {
            if let Probe::Open(port) = result {
                probe.open_ports.push(port);
            }
            if classify(result) {
                probe.alive = true;
            }
        }
    }

    probe.open_ports.sort_unstable();
    probe
}

/// Connect to a single port.
async fn probe_port(ip: Ipv4Addr, port: u16, timeout_duration: Duration) -> Probe {
    match timeout(
        timeout_duration,
        TcpStream::connect((ip, port)),
    )
    .await
    {
        Ok(Ok(_)) => Probe::Open(port),
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => Probe::Refused,
        Ok(Err(_)) | Err(_) => Probe::Silent,
    }
}

/// Whether a probe result proves the host exists.
fn classify(probe: Probe) -> bool {
    matches!(probe, Probe::Open(_) | Probe::Refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refused_counts_as_alive() {
        // A RST is an answer: the host is there with the port closed.
        assert!(classify(Probe::Refused));
        assert!(classify(Probe::Open(80)));
        assert!(!classify(Probe::Silent));
    }

    #[test]
    fn test_default_config_is_lan_sized() {
        let config = TcpSweepConfig::default();
        assert_eq!(config.timeout_ms, 400);
        assert!(config.concurrency > 1);
        assert!(config.include_neighbors);
        assert!(config.ports.contains(&80));
    }

    #[tokio::test]
    async fn test_probe_port_reports_refused_on_localhost() {
        // Nothing listens on port 9; the kernel answers with RST, which must
        // classify as a live host rather than silence.
        let probe = probe_port(Ipv4Addr::LOCALHOST, 9, Duration::from_millis(500)).await;
        assert_eq!(probe, Probe::Refused);
        assert!(classify(probe));
    }

    #[tokio::test]
    async fn test_sweep_of_unroutable_host_is_empty() {
        let sweeper = TcpSweeper::new(TcpSweepConfig {
            targets: vec![Ipv4Addr::new(192, 0, 2, 123)], // TEST-NET-1, never routed
            ports: vec![80],
            timeout_ms: 150,
            concurrency: 4,
            include_neighbors: false,
            interface_name: None,
            quiet: true,
        });

        let devices = sweeper.scan().await.expect("sweep should not fail");
        assert!(devices.is_empty());
    }
}
