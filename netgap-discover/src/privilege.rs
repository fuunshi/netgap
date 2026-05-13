//! Raw-socket privilege detection.
//!
//! ARP discovery opens an `AF_PACKET` socket, which needs `CAP_NET_RAW`. That
//! capability comes from root or from a file capability
//! (`setcap cap_net_raw+ep`), so checking `geteuid() == 0` alone under-reports.
//! On Linux we read the effective capability set instead, with no extra
//! dependency.

/// Bit position of `CAP_NET_RAW` in the capability bitmask.
#[cfg(target_os = "linux")]
const CAP_NET_RAW: u32 = 13;

/// Whether this process can probably open a raw socket.
///
/// Optimistic by design: when the capability set cannot be read the caller
/// should still attempt the channel, and treat a `PermissionDenied` from
/// [`super::DiscoveryError::PrivilegeRequired`] as authoritative.
pub fn has_cap_net_raw() -> bool {
    #[cfg(target_os = "linux")]
    {
        parse_cap_net_raw(&read_proc_self_status()).unwrap_or(true)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Other platforms have no /proc; the channel open decides.
        true
    }
}

/// Extract the `CAP_NET_RAW` bit from `/proc/self/status` contents.
#[cfg(target_os = "linux")]
fn parse_cap_net_raw(status: &str) -> Option<bool> {
    let bits = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))?
        .trim();
    let mask = u64::from_str_radix(bits, 16).ok()?;
    Some(mask & (1u64 << CAP_NET_RAW) != 0)
}

#[cfg(target_os = "linux")]
fn read_proc_self_status() -> String {
    std::fs::read_to_string("/proc/self/status").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_cap_net_raw() {
        // No capabilities set.
        assert_eq!(parse_cap_net_raw("Name:\tnetgap\nCapEff:\t0000000000000000\n"), Some(false));
        // CAP_NET_RAW (bit 13) set.
        assert_eq!(parse_cap_net_raw("CapEff:\t0000000000002000\n"), Some(true));
        // Full capability set, as root has.
        assert_eq!(parse_cap_net_raw("CapEff:\t000001ffffffffff\n"), Some(true));
        // Unparseable input yields no opinion.
        assert_eq!(parse_cap_net_raw("Name:\tnetgap\n"), None);
    }

    #[test]
    fn test_has_cap_net_raw_does_not_panic() {
        let _ = has_cap_net_raw();
    }
}
