//! Reporting and visualization engine.
//!
//! This module provides multiple output formats for scan results:
//! - Terminal table with color coding
//! - JSON for machine-readable output and piping
//! - Human-readable summary

use netgap_core::{ScanResult, Severity};

pub mod discovery;
pub mod summary;
use anyhow::Result;
pub use discovery::{format_discovery, DiscoveryContext};
pub use summary::{Issue, RiskSummary};

/// Report formatter with multiple output options.
pub struct ReportFormatter;

impl ReportFormatter {
    /// Format results as human-readable terminal table with colors.
    pub fn format_terminal(result: &ScanResult) -> Result<String> {
        let mut output = String::new();

        output.push_str("╔════════════════════════════════════════════════════════════════════╗\n");
        output.push_str("║                     NETGAP SECURITY SCAN REPORT                    ║\n");
        output
            .push_str("╚════════════════════════════════════════════════════════════════════╝\n\n");

        output.push_str("📊 Scan Summary\n");
        output.push_str(&format!("  Started:  {}\n", result.started_at));
        output.push_str(&format!("  Target:   {}\n", result.config.target));
        output.push_str(&format!("  Interface: {}\n\n", result.config.interface));

        // The conclusion first, in words. Everything below this is the detail
        // that supports it, and most readers will not need it.
        output.push_str(&RiskSummary::from_result(result).render());

        output.push_str(&format!(
            "Findings: {} Total | 🔴 {} Critical | 🟠 {} High | 🟡 {} Medium | 🔵 {} Info\n\n",
            result.summary.total(),
            result.summary.critical,
            result.summary.high,
            result.summary.medium,
            result.summary.info
        ));

        // Device-by-device findings
        if result.devices.is_empty() {
            output.push_str("✓ No devices found on target network\n");
            return Ok(output);
        }

        for device in &result.devices {
            output.push_str(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
            );
            output.push_str(&format!("Device: {}\n", device.ip));

            if let Some(mac) = &device.mac {
                output.push_str(&format!("  MAC: {}\n", mac));
            }

            if let Some(vendor) = &device.vendor {
                output.push_str(&format!("  Vendor: {}\n", vendor));
            }

            if let Some(device_type) = &device.device_type {
                output.push_str(&format!("  Type: {}\n", device_type));
            }

            if let Some(hostname) = &device.hostname {
                output.push_str(&format!("  Name: {}\n", hostname));
            }

            if !device.open_ports.is_empty() {
                output.push_str(&format!(
                    "  Open Ports: {}\n",
                    device
                        .open_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }

            output.push('\n');

            if device.findings.is_empty() {
                output.push_str("  ✓ No security findings\n");
            } else {
                output.push_str("  Findings:\n");

                // Sort findings by severity, worst first
                let mut sorted_findings = device.findings.clone();
                sorted_findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));

                for finding in sorted_findings {
                    let severity_icon = match finding.severity {
                        Severity::Critical => "🔴",
                        Severity::High => "🟠",
                        Severity::Medium => "🟡",
                        Severity::Info => "🔵",
                    };

                    output.push_str(&format!(
                        "    {} [{}] {}\n",
                        severity_icon, finding.severity, finding.title
                    ));

                    output.push_str(&format!("       {}\n", finding.description));
                    output.push_str(&format!("       ⚒ Fix: {}\n", finding.remediation));
                    output.push('\n');
                }
            }
        }

        output
            .push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        output.push_str("✓ Scan complete. Secure your network!\n");

        Ok(output)
    }

    /// Format results as JSON for machine-readable output.
    pub fn format_json(result: &ScanResult) -> Result<String> {
        let json = serde_json::to_string_pretty(result)?;
        Ok(json)
    }

    /// Format results as summary text.
    pub fn format_summary(result: &ScanResult) -> Result<String> {
        let mut output = String::new();

        output.push_str("Netgap Scan Results\n");
        output.push_str("===================\n\n");

        output.push_str(&format!("Target: {}\n", result.config.target));
        output.push_str(&format!("Devices scanned: {}\n", result.devices.len()));

        // The same conclusion the full report leads with: a summary that is
        // only counts is a summary of the scan, not of the network.
        output.push_str(&RiskSummary::from_result(result).render());

        output.push_str(&format!(
            "Findings: {} (Critical: {}, High: {}, Medium: {}, Info: {})\n\n",
            result.summary.total(),
            result.summary.critical,
            result.summary.high,
            result.summary.medium,
            result.summary.info
        ));

        if result.summary.critical > 0 {
            output.push_str("🔴 CRITICAL ISSUES FOUND - IMMEDIATE ACTION REQUIRED\n");
            for device in &result.devices {
                for finding in &device.findings {
                    if finding.severity == Severity::Critical {
                        output.push_str(&format!(
                            "  • {} ({}): {}\n",
                            device.ip, finding.title, finding.remediation
                        ));
                    }
                }
            }
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::{FindingSummary, ScanConfig};

    #[test]
    fn test_format_terminal_empty() {
        let result = ScanResult {
            started_at: "2024-05-04T00:00:00Z".to_string(),
            config: ScanConfig {
                interface: "eth0".to_string(),
                target: "192.168.1.0/24".to_string(),
                timeout_ms: 3000,
                concurrency: 32,
                discovery_only: false,
            },
            devices: vec![],
            summary: FindingSummary::new(),
        };

        let formatted = ReportFormatter::format_terminal(&result).expect("Format failed");
        assert!(formatted.contains("No devices found"));
    }

    #[test]
    fn test_format_json_serializes() {
        let result = ScanResult {
            started_at: "2024-05-04T00:00:00Z".to_string(),
            config: ScanConfig {
                interface: "eth0".to_string(),
                target: "192.168.1.0/24".to_string(),
                timeout_ms: 3000,
                concurrency: 32,
                discovery_only: false,
            },
            devices: vec![],
            summary: FindingSummary::new(),
        };

        let json = ReportFormatter::format_json(&result).expect("Format failed");
        assert!(json.contains("\"interface\""));
        assert!(json.contains("\"target\""));
    }

    #[test]
    fn test_format_summary() {
        let result = ScanResult {
            started_at: "2024-05-04T00:00:00Z".to_string(),
            config: ScanConfig {
                interface: "eth0".to_string(),
                target: "192.168.1.0/24".to_string(),
                timeout_ms: 3000,
                concurrency: 32,
                discovery_only: false,
            },
            devices: vec![],
            summary: FindingSummary::new(),
        };

        let summary = ReportFormatter::format_summary(&result).expect("Format failed");
        assert!(summary.contains("Target: 192.168.1.0/24"));
    }
}
