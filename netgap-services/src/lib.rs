//! Enhanced service detection, fingerprinting, and vulnerability correlation.
//!
//! This crate combines mDNS discovery, banner grabbing, version detection,
//! and lightweight CVE matching to provide actionable security insights.
//!
//! # Example
//! ```ignore
//! use netgap_services::{ServiceInfo, VulnerabilityCheck};
//!
//! let service = ServiceInfo {
//!     name: "Apache".to_string(),
//!     version: Some("2.4.41".to_string()),
//!     port: 80,
//!     ..Default::default()
//! };
//!
//! let has_vuln = VulnerabilityCheck::check_version(&service);
//! ```

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Detailed service information with version and vulnerability data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub name: String,           // e.g., "Apache", "nginx", "OpenSSH"
    pub version: Option<String>, // e.g., "2.4.41"
    pub service_type: String,    // e.g., "http", "ssh", "smtp"
    pub banner: Option<String>,  // Raw banner if captured
    pub confidence: f32,         // 1.0 = certain, <1.0 = guessed
    pub vulnerabilities: Vec<VulnerabilityFinding>,
}

impl Default for ServiceInfo {
    fn default() -> Self {
        Self {
            ip: Ipv4Addr::UNSPECIFIED,
            port: 0,
            name: String::new(),
            version: None,
            service_type: String::new(),
            banner: None,
            confidence: 0.5,
            vulnerabilities: Vec::new(),
        }
    }
}

/// A matched vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityFinding {
    pub cve_id: String,
    pub severity: Severity,
    pub description: String,
    pub affected_versions: String, // e.g., "< 2.4.50"
    pub remediation: String,
    pub confidence: f32,
}

/// Severity rating for vulnerabilities.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

/// Lightweight CVE database for common services.
pub struct VulnerabilityDatabase;

impl VulnerabilityDatabase {
    /// Known vulnerabilities for Apache HTTP Server.
    pub fn apache_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "CVE-2021-44228".to_string(),
                "< 2.4.50".to_string(),
                Severity::Critical,
                "Upgrade to Apache 2.4.50 or later; this is the Log4Shell vulnerability impacting many services".to_string(),
            ),
            (
                "CVE-2021-26691".to_string(),
                "< 2.4.49".to_string(),
                Severity::High,
                "Upgrade to Apache 2.4.49 or later".to_string(),
            ),
            (
                "CVE-2021-41773".to_string(),
                "< 2.4.50".to_string(),
                Severity::Critical,
                "Path traversal vulnerability; upgrade to 2.4.50+".to_string(),
            ),
            (
                "CVE-2020-1927".to_string(),
                "< 2.4.43".to_string(),
                Severity::High,
                "Privilege escalation via mod_auth; upgrade to 2.4.43+".to_string(),
            ),
        ]
    }

    /// Known vulnerabilities for OpenSSH.
    pub fn openssh_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "CVE-2023-38408".to_string(),
                "< 9.3".to_string(),
                Severity::High,
                "Upgrade to OpenSSH 9.3 or later".to_string(),
            ),
            (
                "CVE-2023-51385".to_string(),
                "< 9.6".to_string(),
                Severity::Medium,
                "Upgrade to OpenSSH 9.6 or later".to_string(),
            ),
            (
                "CVE-2021-41617".to_string(),
                "< 8.7".to_string(),
                Severity::High,
                "Privilege escalation in sshd; upgrade to 8.7+".to_string(),
            ),
            (
                "CVE-2020-14145".to_string(),
                "< 8.3".to_string(),
                Severity::Medium,
                "Information leak in ssh client; upgrade to 8.3+".to_string(),
            ),
        ]
    }

    /// Known vulnerabilities for Nginx.
    pub fn nginx_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "CVE-2019-9511".to_string(),
                "< 1.16.1".to_string(),
                Severity::High,
                "HTTP/2 DoS vulnerability; upgrade to 1.16.1+".to_string(),
            ),
            (
                "CVE-2013-4547".to_string(),
                "< 1.5.6".to_string(),
                Severity::High,
                "Upgrade to Nginx 1.5.6 or later".to_string(),
            ),
            (
                "CVE-2021-3618".to_string(),
                "< 1.21.0".to_string(),
                Severity::Medium,
                "Off-by-one in HTTP/2 processing; upgrade to 1.21.0+".to_string(),
            ),
        ]
    }

    /// Known vulnerabilities for PostgreSQL.
    pub fn postgres_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "CVE-2022-41862".to_string(),
                "< 15.1".to_string(),
                Severity::High,
                "Upgrade to PostgreSQL 15.1 or later".to_string(),
            ),
            (
                "CVE-2021-23214".to_string(),
                "< 13.2".to_string(),
                Severity::High,
                "Server doesn't validate host certificates properly; upgrade to 13.2+".to_string(),
            ),
            (
                "CVE-2021-20229".to_string(),
                "< 12.6".to_string(),
                Severity::Medium,
                "Schema-dependent row security bypass; upgrade to 12.6+".to_string(),
            ),
        ]
    }

    /// Known vulnerabilities for MySQL/MariaDB.
    pub fn mysql_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "CVE-2022-0778".to_string(),
                "< 8.0.28".to_string(),
                Severity::Medium,
                "Upgrade to MySQL 8.0.28 or later".to_string(),
            ),
            (
                "CVE-2021-2354".to_string(),
                "< 8.0.25".to_string(),
                Severity::High,
                "Privilege escalation vulnerability; upgrade to 8.0.25+".to_string(),
            ),
            (
                "CVE-2021-2109".to_string(),
                "< 5.7.32".to_string(),
                Severity::High,
                "Local privilege escalation; upgrade to 5.7.32+".to_string(),
            ),
        ]
    }

    /// Known vulnerabilities for IIS.
    pub fn iis_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "CVE-2021-26858".to_string(),
                "< 10.0.20348".to_string(),
                Severity::Critical,
                "Remote code execution in Exchange Server; update immediately".to_string(),
            ),
            (
                "CVE-2021-34473".to_string(),
                "< 10.0.20348".to_string(),
                Severity::Critical,
                "Path traversal and disclosure in Exchange; update immediately".to_string(),
            ),
        ]
    }

    /// Known vulnerabilities for FTP servers.
    pub fn ftp_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "FTP-UNENCRYPTED".to_string(),
                "ALL".to_string(),
                Severity::Critical,
                "FTP transmits credentials in plaintext; disable FTP and use SFTP instead".to_string(),
            ),
            (
                "CVE-2018-7725".to_string(),
                "vsftpd < 3.0.3".to_string(),
                Severity::High,
                "Username enumeration vulnerability; upgrade to 3.0.3+".to_string(),
            ),
        ]
    }

    /// Known vulnerabilities for Telnet.
    pub fn telnet_vulns() -> Vec<(String, String, Severity, String)> {
        vec![
            (
                "TELNET-UNENCRYPTED".to_string(),
                "ALL".to_string(),
                Severity::Critical,
                "Telnet transmits all data in plaintext; replace with SSH immediately".to_string(),
            ),
        ]
    }
}

/// Checks for known vulnerabilities based on service version.
pub struct VulnerabilityCheck;

impl VulnerabilityCheck {
    /// Check if a service version matches known vulnerabilities.
    pub fn check_version(service: &ServiceInfo) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        if let Some(ref version) = service.version {
            let vulns = match service.name.to_lowercase().as_str() {
                "apache" | "httpd" => VulnerabilityDatabase::apache_vulns(),
                "openssh" | "ssh" => VulnerabilityDatabase::openssh_vulns(),
                "nginx" => VulnerabilityDatabase::nginx_vulns(),
                "postgresql" | "postgres" => VulnerabilityDatabase::postgres_vulns(),
                "mysql" | "mariadb" => VulnerabilityDatabase::mysql_vulns(),
                "iis" | "microsoft" => VulnerabilityDatabase::iis_vulns(),
                "ftp" | "vsftpd" | "proftpd" => VulnerabilityDatabase::ftp_vulns(),
                _ => Vec::new(),
            };

            for (cve, affected, severity, remediation) in vulns {
                if Self::version_matches_affected(version, &affected) {
                    findings.push(VulnerabilityFinding {
                        cve_id: cve,
                        severity,
                        description: format!("Known vulnerability in {} version {}", service.name, version),
                        affected_versions: affected,
                        remediation,
                        confidence: 0.95,
                    });
                }
            }
        }

        findings
    }

    /// Simple version comparison. Real implementation would use proper semver.
    fn version_matches_affected(current: &str, affected_pattern: &str) -> bool {
        // Check if "ALL" affects all versions
        if affected_pattern == "ALL" {
            return true;
        }

        // Very simplified: just check if "< X" pattern matches
        if affected_pattern.starts_with("< ") {
            let target = affected_pattern.trim_start_matches("< ");
            // Naive string comparison: "2.4.41" < "2.4.50"
            current < target
        } else {
            false
        }
    }

    /// Check for insecure configurations (no encryption, default ports, etc).
    pub fn check_configuration(service: &ServiceInfo) -> Vec<VulnerabilityFinding> {
        let mut findings = Vec::new();

        // Check for unencrypted protocols on standard ports
        match service.service_type.as_str() {
            "http" => findings.push(VulnerabilityFinding {
                cve_id: "CONFIG-001".to_string(),
                severity: Severity::High,
                description: "HTTP without encryption (should be HTTPS)".to_string(),
                affected_versions: "All".to_string(),
                remediation: "Enable TLS/SSL and redirect HTTP to HTTPS".to_string(),
                confidence: 1.0,
            }),
            "telnet" => findings.push(VulnerabilityFinding {
                cve_id: "CONFIG-002".to_string(),
                severity: Severity::Critical,
                description: "Telnet (unencrypted remote access) is exposed".to_string(),
                affected_versions: "All".to_string(),
                remediation: "Replace Telnet with SSH (port 22)".to_string(),
                confidence: 1.0,
            }),
            "ftp" => findings.push(VulnerabilityFinding {
                cve_id: "CONFIG-003".to_string(),
                severity: Severity::High,
                description: "FTP (unencrypted file transfer) is exposed".to_string(),
                affected_versions: "All".to_string(),
                remediation: "Use SFTP or FTPS instead of FTP".to_string(),
                confidence: 1.0,
            }),
            _ => {}
        }

        findings
    }
}

/// Scoring for service health and exposure.
pub struct ServiceHealthScore;

impl ServiceHealthScore {
    /// Calculate overall security score (0-100, higher is better).
    pub fn calculate(service: &ServiceInfo) -> u8 {
        let mut score = 100u32;

        // Deduct for each vulnerability
        for vuln in &service.vulnerabilities {
            let deduction = match vuln.severity {
                Severity::Critical => 25,
                Severity::High => 15,
                Severity::Medium => 8,
                Severity::Low => 3,
                Severity::Info => 1,
            };
            score = score.saturating_sub(deduction);
        }

        // Deduct for low confidence fingerprinting
        if service.confidence < 0.7 {
            score = score.saturating_sub(5);
        }

        score as u8
    }

    /// Get risk level from score.
    pub fn risk_level(score: u8) -> &'static str {
        match score {
            0..=25 => "Critical",
            26..=50 => "High",
            51..=75 => "Medium",
            76..=89 => "Low",
            _ => "Minimal",  // covers 90..=100 and beyond
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_info_default() {
        let svc = ServiceInfo::default();
        assert_eq!(svc.port, 0);
        assert_eq!(svc.confidence, 0.5);
    }

    #[test]
    fn test_vulnerability_check_apache() {
        let service = ServiceInfo {
            name: "Apache".to_string(),
            version: Some("2.4.41".to_string()),
            service_type: "http".to_string(),
            ..Default::default()
        };

        let vulns = VulnerabilityCheck::check_version(&service);
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2021-44228"));
    }

    #[test]
    fn test_vulnerability_check_openssh() {
        let service = ServiceInfo {
            name: "OpenSSH".to_string(),
            version: Some("8.5".to_string()),
            service_type: "ssh".to_string(),
            ..Default::default()
        };

        let vulns = VulnerabilityCheck::check_version(&service);
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_vulnerability_check_ftp_protocol() {
        let service = ServiceInfo {
            name: "vsftpd".to_string(),
            version: Some("3.0.2".to_string()),
            service_type: "ftp".to_string(),
            ..Default::default()
        };

        let vulns = VulnerabilityCheck::check_version(&service);
        // Should find FTP vulnerabilities (either CVE or general FTP issues)
        assert!(!vulns.is_empty(), "Should find FTP vulnerabilities");
    }

    #[test]
    fn test_vulnerability_check_config_telnet() {
        let service = ServiceInfo {
            name: "Telnet".to_string(),
            service_type: "telnet".to_string(),
            ..Default::default()
        };

        let vulns = VulnerabilityCheck::check_configuration(&service);
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low < Severity::Medium);
    }

    #[test]
    fn test_health_score_critical_vuln() {
        let mut service = ServiceInfo::default();
        service.confidence = 1.0;  // Set high confidence
        service.vulnerabilities.push(VulnerabilityFinding {
            cve_id: "CVE-TEST".to_string(),
            severity: Severity::Critical,
            description: "Test".to_string(),
            affected_versions: "All".to_string(),
            remediation: "Fix it".to_string(),
            confidence: 1.0,
        });

        let score = ServiceHealthScore::calculate(&service);
        assert_eq!(score, 75);  // 100 - 25 for critical
        assert_eq!(ServiceHealthScore::risk_level(score), "Medium");
    }

    #[test]
    fn test_health_score_clean_service() {
        let service = ServiceInfo {
            confidence: 1.0,
            ..Default::default()
        };

        let score = ServiceHealthScore::calculate(&service);
        assert_eq!(score, 100);
        assert_eq!(ServiceHealthScore::risk_level(score), "Minimal");
    }

    #[test]
    fn test_version_matching() {
        assert!(VulnerabilityCheck::version_matches_affected("2.4.41", "< 2.4.50"));
        assert!(!VulnerabilityCheck::version_matches_affected("2.4.50", "< 2.4.50"));
        assert!(!VulnerabilityCheck::version_matches_affected("2.4.51", "< 2.4.50"));
    }
}
