//! Trend analysis and historical comparison for network security scans.
//!
//! This module tracks network changes over time, detects new devices/services,
//! identifies vulnerability regressions, and calculates network health scores.

use chrono::Utc;
use netgap_core::{ScanResult, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a snapshot of network state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub scan_id: String,
    pub timestamp: String,
    pub device_count: usize,
    pub total_ports: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub devices_by_ip: HashMap<String, DeviceSnapshot>,
}

impl ScanHistory {
    /// Create a history entry from a scan result.
    pub fn from_scan_result(scan_id: String, result: &ScanResult) -> Self {
        let mut devices_by_ip = HashMap::new();
        let mut total_ports = 0;
        let mut critical_findings = 0;
        let mut high_findings = 0;

        for device in &result.devices {
            total_ports += device.open_ports.len();

            let mut crit = 0;
            let mut high = 0;
            for finding in &device.findings {
                match finding.severity {
                    Severity::Critical => crit += 1,
                    Severity::High => high += 1,
                    _ => {}
                }
            }
            critical_findings += crit;
            high_findings += high;

            devices_by_ip.insert(
                device.ip.to_string(),
                DeviceSnapshot {
                    ip: device.ip.to_string(),
                    mac: device.mac.clone(),
                    hostname: device.hostname.clone(),
                    open_ports: device.open_ports.clone(),
                    port_count: device.open_ports.len(),
                    critical_vulns: crit,
                    high_vulns: high,
                },
            );
        }

        ScanHistory {
            scan_id,
            timestamp: Utc::now().to_rfc3339(),
            device_count: result.devices.len(),
            total_ports,
            critical_findings,
            high_findings,
            devices_by_ip,
        }
    }
}

/// Snapshot of a single device for history comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSnapshot {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
    pub port_count: usize,
    pub critical_vulns: usize,
    pub high_vulns: usize,
}

/// Detected changes between two scans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkChange {
    NewDevice {
        ip: String,
        hostname: Option<String>,
    },
    DeviceGone {
        ip: String,
    },
    NewService {
        ip: String,
        port: u16,
    },
    ServiceClosed {
        ip: String,
        port: u16,
    },
    CriticalVulnDetected {
        ip: String,
        count: usize,
    },
    VulnerabilityImproved {
        ip: String,
    },
    VulnerabilityRegressed {
        ip: String,
    },
}

impl std::fmt::Display for NetworkChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkChange::NewDevice { ip, hostname } => {
                if let Some(h) = hostname {
                    write!(f, "NEW DEVICE: {} ({})", ip, h)
                } else {
                    write!(f, "NEW DEVICE: {}", ip)
                }
            }
            NetworkChange::DeviceGone { ip } => write!(f, "DEVICE OFFLINE: {}", ip),
            NetworkChange::NewService { ip, port } => write!(f, "NEW SERVICE: {}:{}", ip, port),
            NetworkChange::ServiceClosed { ip, port } => {
                write!(f, "SERVICE CLOSED: {}:{}", ip, port)
            }
            NetworkChange::CriticalVulnDetected { ip, count } => {
                write!(f, "CRITICAL VULN: {} found {} critical issue(s)", ip, count)
            }
            NetworkChange::VulnerabilityImproved { ip } => {
                write!(f, "IMPROVEMENT: {} reduced vulnerability count", ip)
            }
            NetworkChange::VulnerabilityRegressed { ip } => {
                write!(f, "REGRESSION: {} increased vulnerability count", ip)
            }
        }
    }
}

/// Change detection between two scans.
pub struct ChangeDetection;

impl ChangeDetection {
    /// Compare two scan histories and detect changes.
    pub fn detect_changes(previous: &ScanHistory, current: &ScanHistory) -> Vec<NetworkChange> {
        let mut changes = Vec::new();

        // Detect new devices
        for (ip, device) in &current.devices_by_ip {
            if !previous.devices_by_ip.contains_key(ip) {
                changes.push(NetworkChange::NewDevice {
                    ip: ip.clone(),
                    hostname: device.hostname.clone(),
                });
            }
        }

        // Detect offline devices
        for ip in previous.devices_by_ip.keys() {
            if !current.devices_by_ip.contains_key(ip) {
                changes.push(NetworkChange::DeviceGone { ip: ip.clone() });
            }
        }

        // Detect new services and regressions
        for (ip, curr_device) in &current.devices_by_ip {
            if let Some(prev_device) = previous.devices_by_ip.get(ip) {
                // New services
                for port in &curr_device.open_ports {
                    if !prev_device.open_ports.contains(port) {
                        changes.push(NetworkChange::NewService {
                            ip: ip.clone(),
                            port: *port,
                        });
                    }
                }

                // Closed services
                for port in &prev_device.open_ports {
                    if !curr_device.open_ports.contains(port) {
                        changes.push(NetworkChange::ServiceClosed {
                            ip: ip.clone(),
                            port: *port,
                        });
                    }
                }

                // Critical vulns detected
                if curr_device.critical_vulns > prev_device.critical_vulns {
                    changes.push(NetworkChange::CriticalVulnDetected {
                        ip: ip.clone(),
                        count: curr_device.critical_vulns - prev_device.critical_vulns,
                    });
                }

                // Vulnerability improvements
                if curr_device.high_vulns < prev_device.high_vulns
                    && curr_device.critical_vulns == prev_device.critical_vulns
                {
                    changes.push(NetworkChange::VulnerabilityImproved { ip: ip.clone() });
                }

                // Vulnerability regressions
                if curr_device.high_vulns > prev_device.high_vulns
                    || curr_device.critical_vulns > prev_device.critical_vulns
                {
                    changes.push(NetworkChange::VulnerabilityRegressed { ip: ip.clone() });
                }
            }
        }

        changes
    }
}

/// Network health score (0-100 scale).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct HealthScore {
    pub score: u8,
    pub port_factor: u8,
    pub vuln_factor: u8,
    pub device_factor: u8,
}

impl HealthScore {
    /// Calculate health score from scan history.
    /// Formula: 100 - (port_penalty + vuln_penalty + device_penalty)
    pub fn calculate(history: &ScanHistory) -> Self {
        // Port penalty: 1 point per open port (cap at 30)
        let port_penalty = (history.total_ports as u8).min(30);

        // Vulnerability penalty: 20 points for critical, 10 for high (cap at 50)
        let vuln_penalty =
            (history.critical_findings as u8 * 20 + history.high_findings as u8 * 10).min(50);

        // Device penalty: 1 point per device (cap at 20)
        let device_penalty = (history.device_count as u8).min(20);

        let total_penalty = (port_penalty + vuln_penalty + device_penalty).min(100);
        let score = (100_u16.saturating_sub(total_penalty as u16)) as u8;

        HealthScore {
            score,
            port_factor: port_penalty,
            vuln_factor: vuln_penalty,
            device_factor: device_penalty,
        }
    }

    /// Categorize health score into risk level.
    pub fn risk_level(&self) -> &'static str {
        match self.score {
            85..=100 => "Excellent",
            70..=84 => "Good",
            50..=69 => "Fair",
            30..=49 => "Poor",
            _ => "Critical",
        }
    }
}

/// Alert triggered by network changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: String,
    pub severity: String,
    pub message: String,
    pub change: String,
}

impl Alert {
    /// Create alert from network change.
    pub fn from_change(change: &NetworkChange) -> Self {
        let (severity, message) = match change {
            NetworkChange::NewDevice { .. } => ("info", "New device appeared on network"),
            NetworkChange::DeviceGone { .. } => ("info", "Device went offline"),
            NetworkChange::NewService { .. } => ("medium", "New service detected"),
            NetworkChange::ServiceClosed { .. } => ("low", "Service closed"),
            NetworkChange::CriticalVulnDetected { .. } => {
                ("critical", "Critical vulnerability detected")
            }
            NetworkChange::VulnerabilityImproved { .. } => ("low", "Vulnerability improved"),
            NetworkChange::VulnerabilityRegressed { .. } => ("high", "Vulnerability regressed"),
        };

        Alert {
            id: format!("alert-{}", chrono::Local::now().timestamp_millis()),
            timestamp: Utc::now().to_rfc3339(),
            severity: severity.to_string(),
            message: message.to_string(),
            change: change.to_string(),
        }
    }
}

/// Alert rule for triggering alerts based on conditions.
pub struct AlertRule {
    pub name: String,
    pub condition: AlertCondition,
}

/// Alert trigger condition.
#[derive(Debug, Clone)]
pub enum AlertCondition {
    CriticalVulnDetected,
    HealthScoreDrop { threshold: u8 },
    NewDevice,
    DeviceOffline,
    MultipleNewServices { count: usize },
}

impl AlertRule {
    /// Evaluate if rule should trigger based on changes and health change.
    pub fn should_trigger(&self, changes: &[NetworkChange], health_drop: Option<i16>) -> bool {
        match &self.condition {
            AlertCondition::CriticalVulnDetected => changes
                .iter()
                .any(|c| matches!(c, NetworkChange::CriticalVulnDetected { .. })),
            AlertCondition::HealthScoreDrop { threshold } => {
                if let Some(drop) = health_drop {
                    drop >= *threshold as i16
                } else {
                    false
                }
            }
            AlertCondition::NewDevice => changes
                .iter()
                .any(|c| matches!(c, NetworkChange::NewDevice { .. })),
            AlertCondition::DeviceOffline => changes
                .iter()
                .any(|c| matches!(c, NetworkChange::DeviceGone { .. })),
            AlertCondition::MultipleNewServices { count } => {
                let new_services = changes
                    .iter()
                    .filter(|c| matches!(c, NetworkChange::NewService { .. }))
                    .count();
                new_services >= *count
            }
        }
    }
}

impl AlertRule {
    /// Create default critical vulnerability alert rule.
    pub fn critical_vulnerability() -> Self {
        AlertRule {
            name: "Critical Vulnerability Detected".to_string(),
            condition: AlertCondition::CriticalVulnDetected,
        }
    }

    /// Create default health drop alert rule.
    pub fn health_drop(threshold: u8) -> Self {
        AlertRule {
            name: format!("Health Score Dropped {} Points", threshold),
            condition: AlertCondition::HealthScoreDrop { threshold },
        }
    }

    /// Create default new device alert rule.
    pub fn new_device() -> Self {
        AlertRule {
            name: "New Device Detected".to_string(),
            condition: AlertCondition::NewDevice,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_history(
        id: &str,
        device_count: usize,
        total_ports: usize,
        critical: usize,
        high: usize,
    ) -> ScanHistory {
        ScanHistory {
            scan_id: id.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            device_count,
            total_ports,
            critical_findings: critical,
            high_findings: high,
            devices_by_ip: HashMap::new(),
        }
    }

    #[test]
    fn test_change_detection_new_device() {
        let mut prev = create_test_history("prev", 1, 2, 0, 0);
        let mut curr = create_test_history("curr", 2, 4, 0, 0);

        prev.devices_by_ip.insert(
            "192.168.1.1".to_string(),
            DeviceSnapshot {
                ip: "192.168.1.1".to_string(),
                mac: None,
                hostname: None,
                open_ports: vec![22, 80],
                port_count: 2,
                critical_vulns: 0,
                high_vulns: 0,
            },
        );

        curr.devices_by_ip.insert(
            "192.168.1.1".to_string(),
            DeviceSnapshot {
                ip: "192.168.1.1".to_string(),
                mac: None,
                hostname: None,
                open_ports: vec![22, 80],
                port_count: 2,
                critical_vulns: 0,
                high_vulns: 0,
            },
        );

        curr.devices_by_ip.insert(
            "192.168.1.2".to_string(),
            DeviceSnapshot {
                ip: "192.168.1.2".to_string(),
                mac: None,
                hostname: Some("newhost".to_string()),
                open_ports: vec![22, 443],
                port_count: 2,
                critical_vulns: 0,
                high_vulns: 0,
            },
        );

        let changes = ChangeDetection::detect_changes(&prev, &curr);
        assert!(changes
            .iter()
            .any(|c| matches!(c, NetworkChange::NewDevice { ip, .. } if ip == "192.168.1.2")));
    }

    #[test]
    fn test_change_detection_device_offline() {
        let mut prev = create_test_history("prev", 2, 4, 0, 0);
        let curr = create_test_history("curr", 1, 2, 0, 0);

        prev.devices_by_ip.insert(
            "192.168.1.1".to_string(),
            DeviceSnapshot {
                ip: "192.168.1.1".to_string(),
                mac: None,
                hostname: None,
                open_ports: vec![22, 80],
                port_count: 2,
                critical_vulns: 0,
                high_vulns: 0,
            },
        );

        prev.devices_by_ip.insert(
            "192.168.1.2".to_string(),
            DeviceSnapshot {
                ip: "192.168.1.2".to_string(),
                mac: None,
                hostname: None,
                open_ports: vec![22, 443],
                port_count: 2,
                critical_vulns: 0,
                high_vulns: 0,
            },
        );

        let changes = ChangeDetection::detect_changes(&prev, &curr);
        assert!(changes
            .iter()
            .any(|c| matches!(c, NetworkChange::DeviceGone { .. })));
    }

    #[test]
    fn test_change_detection_new_service() {
        let mut prev = create_test_history("prev", 1, 1, 0, 0);
        let mut curr = create_test_history("curr", 1, 2, 0, 0);

        prev.devices_by_ip.insert(
            "192.168.1.1".to_string(),
            DeviceSnapshot {
                ip: "192.168.1.1".to_string(),
                mac: None,
                hostname: None,
                open_ports: vec![22],
                port_count: 1,
                critical_vulns: 0,
                high_vulns: 0,
            },
        );

        curr.devices_by_ip.insert(
            "192.168.1.1".to_string(),
            DeviceSnapshot {
                ip: "192.168.1.1".to_string(),
                mac: None,
                hostname: None,
                open_ports: vec![22, 80],
                port_count: 2,
                critical_vulns: 0,
                high_vulns: 0,
            },
        );

        let changes = ChangeDetection::detect_changes(&prev, &curr);
        assert!(changes
            .iter()
            .any(|c| matches!(c, NetworkChange::NewService { port: 80, .. })));
    }

    #[test]
    fn test_health_score_calculation() {
        let history = create_test_history("test", 5, 10, 2, 3);
        let score = HealthScore::calculate(&history);

        assert!(score.score > 0);
        assert!(score.score <= 100);
        assert_eq!(score.port_factor, 10);
        assert_eq!(score.vuln_factor, 50); // capped at 50
        assert_eq!(score.device_factor, 5);
    }

    #[test]
    fn test_health_score_risk_levels() {
        assert_eq!(
            HealthScore {
                score: 90,
                port_factor: 5,
                vuln_factor: 5,
                device_factor: 0
            }
            .risk_level(),
            "Excellent"
        );
        assert_eq!(
            HealthScore {
                score: 75,
                port_factor: 10,
                vuln_factor: 15,
                device_factor: 0
            }
            .risk_level(),
            "Good"
        );
        assert_eq!(
            HealthScore {
                score: 55,
                port_factor: 20,
                vuln_factor: 25,
                device_factor: 0
            }
            .risk_level(),
            "Fair"
        );
        assert_eq!(
            HealthScore {
                score: 35,
                port_factor: 30,
                vuln_factor: 35,
                device_factor: 0
            }
            .risk_level(),
            "Poor"
        );
    }

    #[test]
    fn test_alert_from_change() {
        let change = NetworkChange::CriticalVulnDetected {
            ip: "192.168.1.1".to_string(),
            count: 2,
        };
        let alert = Alert::from_change(&change);

        assert_eq!(alert.severity, "critical");
        assert!(alert.message.contains("Critical"));
    }

    #[test]
    fn test_alert_rule_critical_vuln() {
        let rule = AlertRule::critical_vulnerability();
        let changes = vec![NetworkChange::CriticalVulnDetected {
            ip: "192.168.1.1".to_string(),
            count: 1,
        }];

        assert!(rule.should_trigger(&changes, None));
    }

    #[test]
    fn test_alert_rule_health_drop() {
        let rule = AlertRule::health_drop(10);
        assert!(rule.should_trigger(&[], Some(15)));
        assert!(!rule.should_trigger(&[], Some(5)));
    }
}
