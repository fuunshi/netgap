//! Hostname resolution for discovered devices.
//!
//! Uses reverse DNS (PTR). Many home routers register their DHCP clients in
//! their DNS, so this names phones, laptops and printers on those networks.
//! On networks without that, lookups simply return nothing — devices keep
//! `hostname = None` and the report shows a dash rather than inventing a name.

use netgap_core::Device;
use std::net::IpAddr;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Resolve names for devices that do not have one yet.
///
/// Lookups run concurrently and are abandoned after `budget`; a slow or
/// unresponsive resolver must not hold up the scan. Returns how many names were
/// recovered.
pub async fn resolve_hostnames(devices: &mut [Device], budget: Duration) -> usize {
    let pending: Vec<IpAddr> = devices
        .iter()
        .filter(|device| device.hostname.is_none())
        .map(|device| device.ip)
        .collect();

    if pending.is_empty() {
        return 0;
    }

    let mut lookups = JoinSet::new();
    for ip in pending {
        lookups.spawn(async move {
            // getnameinfo blocks, so it runs on the blocking pool where the
            // timeout can abandon waiting for it without stalling the runtime.
            let resolved = tokio::task::spawn_blocking(move || reverse_lookup(ip)).await;
            (ip, resolved.ok().flatten())
        });
    }

    let mut resolved = Vec::new();
    let deadline = tokio::time::Instant::now() + budget;
    while let Ok(Some(joined)) = timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        lookups.join_next(),
    )
    .await
    {
        if let Ok((ip, Some(name))) = joined {
            resolved.push((ip, name));
        }
    }
    lookups.abort_all();

    let found = resolved.len();
    for (ip, name) in resolved {
        for device in devices.iter_mut().filter(|device| device.ip == ip) {
            device.hostname = Some(name.clone());
        }
    }

    found
}

/// Reverse-resolve one address, rejecting names that carry no information.
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&ip).ok()?;
    let name = name.trim().trim_end_matches('.').to_string();

    if name.is_empty() || !is_informative(&name, ip) {
        return None;
    }

    Some(name)
}

/// Whether a resolved name tells us anything beyond the address itself.
///
/// Resolvers answer with placeholders like `192-168-1-5.local` or systemd's
/// `_gateway` when they have no real name, which would be noise in the table.
fn is_informative(name: &str, ip: IpAddr) -> bool {
    let name = name.to_ascii_lowercase();

    if name == "_gateway" || name == "localhost" {
        return false;
    }

    // Numeric placeholder forms: dashes or dots between the address octets.
    let dashed = ip.to_string().replace('.', "-");
    if name.starts_with(&dashed) {
        return false;
    }

    // A name that is only the address, however punctuated.
    let digits_and_punct = name
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '_'));
    !digits_and_punct
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_placeholders_are_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));

        assert!(!is_informative("_gateway", ip));
        assert!(!is_informative("localhost", ip));
        assert!(!is_informative("192-168-1-5.local", ip));
        assert!(!is_informative("192.168.1.5", ip));
        assert!(!is_informative("192168105", ip));
    }

    #[test]
    fn test_real_names_are_kept() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));

        assert!(is_informative("printer.local", ip));
        assert!(is_informative("andrews-iphone.lan", ip));
        assert!(is_informative("nas", ip));
    }

    #[test]
    fn test_resolve_loopback_is_not_informative() {
        // Whatever the resolver answers for loopback, it must not be reported
        // as a device name.
        if let Some(name) = reverse_lookup(IpAddr::V4(Ipv4Addr::LOCALHOST)) {
            assert!(is_informative(&name, IpAddr::V4(Ipv4Addr::LOCALHOST)));
        }
    }

    #[tokio::test]
    async fn test_resolve_hostnames_skips_devices_that_have_one() {
        let mut device = Device::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        device.hostname = Some("already-named".to_string());

        let mut devices = vec![device];
        let resolved = resolve_hostnames(&mut devices, Duration::from_millis(50)).await;

        assert_eq!(resolved, 0);
        assert_eq!(devices[0].hostname.as_deref(), Some("already-named"));
    }
}
