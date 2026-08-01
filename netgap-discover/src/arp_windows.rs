//! ARP discovery on Windows, without a packet-capture driver.
//!
//! `SendARP` in `iphlpapi` asks the system to resolve an address on the local
//! link and hands back the hardware address that answered. It needs neither
//! administrator rights nor Npcap, which is what makes it the Windows
//! equivalent of the raw-socket sweep the Unix build runs: every device that
//! is on the link answers an ARP request, whatever its firewall says about
//! TCP.

use anyhow::Result;
use netgap_core::Device;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// How the Windows ARP sweep is run.
#[derive(Debug, Clone)]
pub struct ArpSweepConfig {
    /// Addresses to resolve.
    pub targets: Vec<Ipv4Addr>,
    /// The address the requests should leave from, so a machine with more
    /// than one adapter asks on the interface that was actually chosen.
    /// `None` lets the system pick by its routing table.
    pub source: Option<Ipv4Addr>,
    /// How many addresses are asked about at once. `SendARP` blocks for as
    /// long as the link's ARP retries take when nothing answers, so this is
    /// what keeps a whole /24 to seconds instead of minutes.
    pub concurrency: usize,
}

impl Default for ArpSweepConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            source: None,
            concurrency: 32,
        }
    }
}

/// Resolve every target and return the devices that answered.
///
/// An address that stays silent is not an error; a link on which *nothing*
/// can be resolved is, because that means the sweep never had a chance and
/// the caller should try a different method.
pub async fn sweep(config: &ArpSweepConfig) -> Result<Vec<Device>> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for ip in &config.targets {
        let permit = semaphore.clone().acquire_owned().await?;
        let ip = *ip;
        let source = config.source;
        tasks.spawn_blocking(move || {
            let _permit = permit;
            (ip, platform::resolve(ip, source))
        });
    }

    let mut devices = Vec::new();
    let mut last_error = None;
    while let Some(joined) = tasks.join_next().await {
        let Ok((ip, resolution)) = joined else {
            continue;
        };
        match resolution {
            Ok(Some(mac)) => {
                let mut device = Device::new(IpAddr::V4(ip));
                device.mac = Some(format_mac(mac));
                devices.push(device);
            }
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
    }

    // Nothing on the range answering at all is worth saying out loud: it means
    // the sweep never had a chance, usually because the range belongs to a
    // different interface's network or because the network isolates clients.
    // One silent address is not an error — most of a /24 is always silent.
    if devices.is_empty() && !config.targets.is_empty() {
        let detail = last_error
            .map(|error| format!("; the system's last word was \"{error}\""))
            .unwrap_or_default();
        return Err(anyhow::anyhow!(
            "ARP got no answer from any of the {} address(es) in the range{detail}; \
             check that the range is the network this interface is on",
            config.targets.len()
        ));
    }

    devices.sort_by_key(|device| match device.ip {
        IpAddr::V4(ip) => u32::from(ip),
        IpAddr::V6(_) => u32::MAX,
    });

    Ok(devices)
}

/// Write a hardware address the way the rest of the tool does.
pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(windows)]
mod platform {
    use std::net::Ipv4Addr;

    // `SendARP` from `iphlpapi`: resolve one address on the local link.
    // Returns `NO_ERROR` and fills the buffer when the address answered. The
    // buffer is eight bytes because a hardware address may be longer than the
    // six bytes Ethernet uses; the length tells us how many were written.
    #[link(name = "Iphlpapi")]
    extern "system" {
        fn SendARP(dest_ip: u32, src_ip: u32, mac_addr: *mut u8, phy_addr_len: *mut u32) -> u32;
    }

    pub fn resolve(
        target: Ipv4Addr,
        source: Option<Ipv4Addr>,
    ) -> Result<Option<[u8; 6]>, std::io::Error> {
        let mut buffer = [0u8; 8];
        let mut length = buffer.len() as u32;

        // `IPAddr` is a ULONG holding the address in network byte order, so
        // the four octets sit in memory in address order — the same value
        // `inet_addr` returns on this platform.
        let status = unsafe {
            SendARP(
                u32::from_ne_bytes(target.octets()),
                source.map_or(0, |ip| u32::from_ne_bytes(ip.octets())),
                buffer.as_mut_ptr(),
                &mut length,
            )
        };

        // `ERROR_BAD_NET_NAME` (67) and friends mean the system refused to try,
        // which is worth reporting; a silent address returns NO_ERROR with a
        // zero-length or zeroed answer.
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        if length < 6 {
            return Ok(None);
        }

        let mac = [
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5],
        ];
        Ok((mac != [0u8; 6]).then_some(mac))
    }
}

#[cfg(not(windows))]
mod platform {
    use std::net::Ipv4Addr;

    /// Never resolves anything off Windows. The engine only asks for this
    /// sweep on Windows; the stub keeps the module compiling elsewhere so its
    /// parsing and formatting can still be tested.
    pub fn resolve(
        _target: Ipv4Addr,
        _source: Option<Ipv4Addr>,
    ) -> Result<Option<[u8; 6]>, std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SendARP is only available on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_are_written_consistently() {
        assert_eq!(
            format_mac([0xc4, 0xb2, 0x5b, 0x0a, 0x03, 0x26]),
            "C4:B2:5B:0A:03:26"
        );
    }

    #[tokio::test]
    async fn an_empty_target_list_is_an_empty_sweep() {
        // Nothing to ask about is not a failure: the sweep simply has no
        // devices to report.
        let empty = sweep(&ArpSweepConfig::default())
            .await
            .expect("empty is fine");
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn a_range_where_nothing_answers_is_reported() {
        // Off Windows every attempt fails, which is the same shape as a range
        // on another network: the caller is told rather than handed an empty
        // list that looks like a quiet network.
        let config = ArpSweepConfig {
            targets: vec![Ipv4Addr::new(192, 168, 99, 7)],
            ..ArpSweepConfig::default()
        };
        let error = sweep(&config).await.expect_err("nothing answered");
        assert!(
            error.to_string().contains("no answer"),
            "unexpected message: {error}"
        );
    }
}
