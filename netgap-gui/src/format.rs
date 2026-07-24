//! Turning scan data into the short strings a dashboard can show.

use chrono::{DateTime, Local, Utc};
use netgap_core::{Device, ScanResult, Severity};

/// How many findings of each severity a scan contains.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn of(result: &ScanResult) -> Self {
        let mut counts = Self::default();
        for device in &result.devices {
            for finding in &device.findings {
                match finding.severity {
                    Severity::Critical => counts.critical += 1,
                    Severity::High => counts.high += 1,
                    Severity::Medium => counts.medium += 1,
                    Severity::Info => counts.info += 1,
                }
            }
        }
        counts
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.info
    }

    pub fn entries(&self) -> [(Severity, usize); 4] {
        [
            (Severity::Critical, self.critical),
            (Severity::High, self.high),
            (Severity::Medium, self.medium),
            (Severity::Info, self.info),
        ]
    }
}

/// The worst finding on a device, which is how a list summarises it.
pub fn worst_severity(device: &Device) -> Option<Severity> {
    device.findings.iter().map(|finding| finding.severity).max()
}

/// A name a person can use for a device, in order of how much it tells them.
pub fn device_name(device: &Device) -> String {
    if let Some(hostname) = device.hostname.as_deref().filter(|s| !s.is_empty()) {
        return hostname.to_string();
    }
    if let Some(kind) = device.device_type.as_deref().filter(|s| !s.is_empty()) {
        return kind.to_string();
    }
    "Unknown device".to_string()
}

/// A second line under the IP: vendor and type, when either is known.
pub fn device_subtitle(device: &Device) -> String {
    let mut parts = Vec::new();
    if let Some(kind) = device.device_type.as_deref().filter(|s| !s.is_empty()) {
        if Some(kind) != device.hostname.as_deref() {
            parts.push(kind.to_string());
        }
    }
    if let Some(vendor) = device.vendor.as_deref().filter(|s| !s.is_empty()) {
        parts.push(vendor.to_string());
    }
    if parts.is_empty() {
        device
            .mac
            .clone()
            .unwrap_or_else(|| "no vendor information".into())
    } else {
        parts.join(" · ")
    }
}

pub fn plural(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{} {}", count, singular)
    } else {
        format!("{} {}", count, plural)
    }
}

pub fn devices(count: usize) -> String {
    plural(count, "device", "devices")
}

pub fn findings(count: usize) -> String {
    plural(count, "finding", "findings")
}

/// A timestamp in the reader's local time, at a glance.
pub fn short_time(timestamp: &str) -> String {
    match DateTime::parse_from_rfc3339(timestamp) {
        Ok(time) => time
            .with_timezone(&Local)
            .format("%b %d, %H:%M")
            .to_string(),
        Err(_) => timestamp.chars().take(16).collect(),
    }
}

/// How long ago something happened, in words rather than arithmetic.
pub fn relative_time(timestamp: &str) -> String {
    let Ok(time) = DateTime::parse_from_rfc3339(timestamp) else {
        return short_time(timestamp);
    };

    let seconds = Utc::now()
        .signed_duration_since(time.with_timezone(&Utc))
        .num_seconds()
        .max(0);

    match seconds {
        0..=59 => "just now".to_string(),
        60..=3_599 => format!("{} min ago", seconds / 60),
        3_600..=86_399 => format!("{} h ago", seconds / 3_600),
        86_400..=604_799 => format!("{} d ago", seconds / 86_400),
        _ => short_time(timestamp),
    }
}

/// A date-only label for the history's older entries.
pub fn date_only(timestamp: &str) -> String {
    match DateTime::parse_from_rfc3339(timestamp) {
        Ok(time) => time.with_timezone(&Local).format("%b %d").to_string(),
        Err(_) => timestamp.chars().take(10).collect(),
    }
}

/// Truncate with an ellipsis, counting characters rather than bytes.
pub fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{}…", kept)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::{Device, Finding, FindingSummary, ScanConfig, ScanResult};
    use std::net::{IpAddr, Ipv4Addr};

    fn device(hostname: Option<&str>, device_type: Option<&str>, vendor: Option<&str>) -> Device {
        Device {
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            vendor: vendor.map(str::to_string),
            os: netgap_core::OsType::Unknown,
            os_confidence: 0.0,
            hostname: hostname.map(str::to_string),
            first_seen: None,
            device_type: device_type.map(str::to_string),
            ipv6_addresses: Vec::new(),
            open_ports: Vec::new(),
            findings: Vec::new(),
        }
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            id: format!("test-{severity}"),
            title: "Test finding".into(),
            description: String::new(),
            severity,
            ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            port: Some(445),
            service: Some("SMB".into()),
            remediation: String::new(),
            confidence: 1.0,
        }
    }

    #[test]
    fn names_fall_back_in_order() {
        assert_eq!(
            device_name(&device(Some("printer.lan"), Some("Printer"), None)),
            "printer.lan"
        );
        assert_eq!(
            device_name(&device(None, Some("Printer"), Some("HP"))),
            "Printer"
        );
        assert_eq!(
            device_name(&device(None, None, Some("HP"))),
            "Unknown device"
        );
    }

    #[test]
    fn subtitle_does_not_repeat_the_name() {
        let subtitle = device_subtitle(&device(Some("Printer"), Some("Printer"), Some("HP")));
        assert_eq!(subtitle, "HP");
        let subtitle = device_subtitle(&device(Some("printer.lan"), Some("Printer"), Some("HP")));
        assert_eq!(subtitle, "Printer · HP");
    }

    #[test]
    fn plural_is_not_sloppy() {
        assert_eq!(plural(1, "device", "devices"), "1 device");
        assert_eq!(plural(0, "device", "devices"), "0 devices");
        assert_eq!(plural(2, "device", "devices"), "2 devices");
    }

    #[test]
    fn counts_severities_and_ignores_device_boundaries() {
        let mut first = device(None, None, None);
        first.findings = vec![finding(Severity::Critical), finding(Severity::High)];
        let mut second = device(None, None, None);
        second.findings = vec![finding(Severity::Medium), finding(Severity::Info)];

        let result = ScanResult {
            started_at: "2026-11-03T10:00:00+00:00".into(),
            config: ScanConfig {
                interface: "eth0".into(),
                target: "192.168.1.0/24".into(),
                timeout_ms: 1000,
                concurrency: 32,
                discovery_only: false,
            },
            devices: vec![first, second],
            summary: FindingSummary::new(),
        };

        let counts = SeverityCounts::of(&result);
        assert_eq!(counts.critical, 1);
        assert_eq!(counts.high, 1);
        assert_eq!(counts.medium, 1);
        assert_eq!(counts.info, 1);
        assert_eq!(counts.total(), 4);
    }

    #[test]
    fn worst_severity_is_the_highest_not_the_last() {
        let mut sample = device(None, None, None);
        sample.findings = vec![finding(Severity::Critical), finding(Severity::Info)];
        assert_eq!(worst_severity(&sample), Some(Severity::Critical));
        assert_eq!(worst_severity(&device(Some("x"), None, None)), None);
    }

    #[test]
    fn relative_time_is_readable() {
        let now = Utc::now();
        let five_minutes = (now - chrono::Duration::minutes(5)).to_rfc3339();
        assert_eq!(relative_time(&five_minutes), "5 min ago");

        let two_hours = (now - chrono::Duration::hours(2)).to_rfc3339();
        assert_eq!(relative_time(&two_hours), "2 h ago");
    }

    #[test]
    fn bad_timestamps_do_not_panic() {
        assert_eq!(short_time("not a date"), "not a date");
        assert_eq!(relative_time("not a date"), "not a date");
        assert_eq!(date_only("2026-11-03"), "2026-11-03");
    }

    #[test]
    fn truncation_respects_character_boundaries() {
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hello!", 5), "hell…");
        assert_eq!(truncate("héllo", 3), "hé…");
    }
}
