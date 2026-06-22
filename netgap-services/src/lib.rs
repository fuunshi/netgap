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

use netgap_core::version::compare_versions;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::net::Ipv4Addr;

/// Detailed service information with version and vulnerability data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub name: String,            // e.g., "Apache", "nginx", "OpenSSH"
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

/// Map a product name reported by a probe onto the name this crate's CVE
/// database is keyed by.
///
/// Probes report what the service calls itself ("Microsoft-IIS", "Apache"),
/// while the database groups by canonical product ("IIS", "Apache"). Getting
/// this wrong means looking up the right version in the wrong table and
/// reporting nothing at all.
pub fn canonical_service_name(product: &str) -> Option<&'static str> {
    let lowered = product.trim().to_ascii_lowercase();
    if lowered.is_empty() {
        return None;
    }

    // Longest/most specific matches first, so "microsoft-iis" is not read as a
    // generic Microsoft product.
    const ALIASES: &[(&str, &str)] = &[
        ("microsoft-iis", "IIS"),
        ("iis", "IIS"),
        ("apache", "Apache"),
        ("httpd", "Apache"),
        ("nginx", "nginx"),
        ("openssh", "OpenSSH"),
        ("dropbear", "OpenSSH"),
        ("sun_ssh", "OpenSSH"),
        ("mysql", "MySQL"),
        ("mariadb", "MariaDB"),
        ("postgres", "PostgreSQL"),
        ("proftpd", "ProFTPD"),
        ("vsftpd", "vsftpd"),
        ("pure-ftpd", "vsftpd"),
    ];

    ALIASES
        .iter()
        .find(|(needle, _)| lowered.contains(needle))
        .map(|(_, canonical)| *canonical)
}

/// Severity rating for vulnerabilities.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
            // Was CVE-2021-44228 with a 2.4.50 range. That is Log4Shell, a
            // Log4j (Java) issue with no httpd version range at all: the entry
            // was wrong and would have been acted on. The httpd flaw in that
            // range is the incomplete fix for the path traversal below.
            (
                "CVE-2021-42013".to_string(),
                ">= 2.4.49, < 2.4.51".to_string(),
                Severity::Critical,
                "Path traversal and remote code execution; upgrade to Apache 2.4.51 or later"
                    .to_string(),
            ),
            (
                "CVE-2021-26691".to_string(),
                "< 2.4.49".to_string(),
                Severity::High,
                "Heap overflow in mod_session; upgrade to Apache 2.4.49 or later".to_string(),
            ),
            (
                "CVE-2021-41773".to_string(),
                ">= 2.4.49, < 2.4.50".to_string(),
                Severity::Critical,
                "Path traversal vulnerability; upgrade to Apache 2.4.50 or later".to_string(),
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
                "FTP transmits credentials in plaintext; disable FTP and use SFTP instead"
                    .to_string(),
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
        vec![(
            "TELNET-UNENCRYPTED".to_string(),
            "ALL".to_string(),
            Severity::Critical,
            "Telnet transmits all data in plaintext; replace with SSH immediately".to_string(),
        )]
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
                        description: format!(
                            "Known vulnerability in {} version {}",
                            service.name, version
                        ),
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
        let pattern = affected_pattern.trim();

        if pattern.eq_ignore_ascii_case("ALL") {
            return true;
        }

        // A range may be bounded at both ends: ">= 2.4.49, < 2.4.51". Every
        // clause must hold, which is what lets an entry describe a window
        // rather than everything older than a version.
        if pattern.contains(',') {
            return pattern
                .split(',')
                .map(str::trim)
                .filter(|clause| !clause.is_empty())
                .all(|clause| Self::version_matches_affected(current, clause));
        }

        // Single clauses are written "< 2.4.50", "<= 9.3", ">= 1.2" or "1.2.3".
        // Two-character operators first, so "<=" is not read as "<".
        type OperatorCheck = fn(Ordering) -> bool;
        let operators: [(&str, OperatorCheck); 5] = [
            ("<=", |ordering| ordering != Ordering::Greater),
            (">=", |ordering| ordering != Ordering::Less),
            ("<", |ordering| ordering == Ordering::Less),
            (">", |ordering| ordering == Ordering::Greater),
            ("=", |ordering| ordering == Ordering::Equal),
        ];

        for (prefix, matches) in operators {
            let Some(target) = pattern.strip_prefix(prefix) else {
                continue;
            };
            let target = target.trim();
            if target.is_empty() {
                return false;
            }
            return matches(compare_versions(current, target));
        }

        // No operator: an exact version.
        compare_versions(current, pattern) == Ordering::Equal
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
            _ => "Minimal", // covers 90..=100 and beyond
        }
    }
}

/// Confidence scoring for service detection accuracy.
pub struct ConfidenceScorer;

impl ConfidenceScorer {
    /// Calculate confidence score for a service based on detection method.
    ///
    /// Detection methods ranked by confidence:
    /// - Banner grab with exact match: 0.95-1.0
    /// - mDNS advertised service: 0.85-0.95
    /// - Port-based heuristic: 0.6-0.75
    /// - TCP response pattern: 0.5-0.65
    /// - Unconfirmed port: 0.3-0.5
    pub fn calculate_confidence(
        has_banner: bool,
        has_version: bool,
        has_mdns: bool,
        port: u16,
    ) -> f32 {
        let mut score = 0.5f32; // Base score

        // Banner grab is highest confidence
        if has_banner {
            score = 0.95;
            // Exact version from banner increases confidence
            if has_version {
                score = 0.98;
            }
        }
        // mDNS is very reliable
        else if has_mdns {
            score = 0.90;
            if has_version {
                score = 0.93;
            }
        }
        // Port-based heuristics
        else if Self::is_well_known_port(port) {
            score = 0.75;
            if has_version {
                score = 0.80;
            }
        }

        score.clamp(0.0, 1.0)
    }

    /// Check if port is well-known (reliable for service identification).
    fn is_well_known_port(port: u16) -> bool {
        matches!(
            port,
            22 | 25 | 80 | 110 | 143 | 443 | 445 | 587 | 993 | 995 | 3306 | 5432 | 6379 | 8080
        )
    }

    /// Get confidence category as string.
    pub fn confidence_level(confidence: f32) -> &'static str {
        match confidence {
            c if c >= 0.95 => "Very High",
            c if c >= 0.85 => "High",
            c if c >= 0.70 => "Good",
            c if c >= 0.50 => "Fair",
            _ => "Low",
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
        // 2.4.41 predates the 2.4.49-2.4.50 window, so the path traversal must
        // not be reported for it.
        assert!(!vulns.iter().any(|v| v.cve_id == "CVE-2021-42013"));
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2021-26691"));
    }

    #[test]
    fn test_vulnerability_check_apache_2429_window() {
        // 2.4.49 is inside the affected window and must be reported.
        let service = ServiceInfo {
            name: "Apache".to_string(),
            version: Some("2.4.49".to_string()),
            service_type: "http".to_string(),
            ..Default::default()
        };

        let vulns = VulnerabilityCheck::check_version(&service);
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2021-42013"));
        assert!(vulns.iter().any(|v| v.cve_id == "CVE-2021-41773"));
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
        let mut service = ServiceInfo {
            confidence: 1.0,
            ..ServiceInfo::default()
        };
        service.vulnerabilities.push(VulnerabilityFinding {
            cve_id: "CVE-TEST".to_string(),
            severity: Severity::Critical,
            description: "Test".to_string(),
            affected_versions: "All".to_string(),
            remediation: "Fix it".to_string(),
            confidence: 1.0,
        });

        let score = ServiceHealthScore::calculate(&service);
        assert_eq!(score, 75); // 100 - 25 for critical
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
    fn test_version_comparison_is_numeric_not_lexicographic() {
        // The bug this replaces: as strings, "2.4.9" sorts *after* "2.4.10".
        assert_eq!(compare_versions("2.4.9", "2.4.10"), Ordering::Less);
        assert_eq!(compare_versions("2.4.10", "2.4.9"), Ordering::Greater);

        // Any leading-digit comparison: 10 is newer than 9, not older.
        assert_eq!(compare_versions("10.6.12", "9.6"), Ordering::Greater);
        assert_eq!(compare_versions("8.0.32", "15.1"), Ordering::Less);

        assert_eq!(compare_versions("9.3", "9.3"), Ordering::Equal);
        // Trailing zeros carry no information.
        assert_eq!(compare_versions("1.18.0", "1.18"), Ordering::Equal);
        // A textual component is older than a numeric one.
        assert_eq!(compare_versions("7.4p1", "7.4.1"), Ordering::Less);
    }

    #[test]
    fn test_two_sided_ranges() {
        // CVE-2021-42013 affects exactly 2.4.49 and 2.4.50.
        let range = ">= 2.4.49, < 2.4.51";

        assert!(VulnerabilityCheck::version_matches_affected(
            "2.4.49", range
        ));
        assert!(VulnerabilityCheck::version_matches_affected(
            "2.4.50", range
        ));
        assert!(!VulnerabilityCheck::version_matches_affected(
            "2.4.48", range
        ));
        assert!(!VulnerabilityCheck::version_matches_affected(
            "2.4.51", range
        ));
        assert!(!VulnerabilityCheck::version_matches_affected(
            "2.2.0", range
        ));
    }

    #[test]
    fn test_apache_findings_do_not_cite_log4shell() {
        // CVE-2021-44228 is Log4Shell, a Log4j issue with no httpd version
        // range. Reporting it against an Apache version would be fabrication.
        let cves: Vec<String> = VulnerabilityDatabase::apache_vulns()
            .into_iter()
            .map(|(cve, ..)| cve)
            .collect();

        assert!(
            !cves.iter().any(|cve| cve == "CVE-2021-44228"),
            "Log4Shell must not be attributed to an Apache httpd version"
        );
        assert!(cves.iter().any(|cve| cve == "CVE-2021-42013"));
    }

    #[test]
    fn test_version_matching_uses_the_comparison() {
        // Regression: this returned false, so a vulnerable host looked clean.
        assert!(VulnerabilityCheck::version_matches_affected(
            "2.4.9", "< 2.4.10"
        ));
        assert!(VulnerabilityCheck::version_matches_affected(
            "2.4.49", "< 2.4.50"
        ));
        assert!(VulnerabilityCheck::version_matches_affected(
            "7.4p1", "< 9.3"
        ));

        assert!(!VulnerabilityCheck::version_matches_affected(
            "9.6", "< 9.3"
        ));
        assert!(!VulnerabilityCheck::version_matches_affected(
            "15.1", "< 15.1"
        ));

        // Other range forms.
        assert!(VulnerabilityCheck::version_matches_affected(
            "9.3", "<= 9.3"
        ));
        assert!(VulnerabilityCheck::version_matches_affected(
            "9.4", ">= 9.3"
        ));
        assert!(VulnerabilityCheck::version_matches_affected(
            "2.4.41", "2.4.41"
        ));
        assert!(!VulnerabilityCheck::version_matches_affected(
            "2.4.41", "2.4.42"
        ));
        assert!(VulnerabilityCheck::version_matches_affected(
            "anything", "ALL"
        ));
    }

    #[test]
    fn test_canonical_service_name_matches_the_database_vocabulary() {
        // Products as probes report them.
        assert_eq!(canonical_service_name("Apache"), Some("Apache"));
        assert_eq!(canonical_service_name("Microsoft-IIS"), Some("IIS"));
        assert_eq!(canonical_service_name("OpenSSH"), Some("OpenSSH"));
        assert_eq!(canonical_service_name("nginx"), Some("nginx"));
        assert_eq!(canonical_service_name("MariaDB"), Some("MariaDB"));
        assert_eq!(canonical_service_name("ProFTPD"), Some("ProFTPD"));

        // Unknown products must not be forced into a bucket.
        assert_eq!(canonical_service_name("cloudflare"), None);
        assert_eq!(canonical_service_name(""), None);
    }

    #[test]
    fn test_version_matching() {
        assert!(VulnerabilityCheck::version_matches_affected(
            "2.4.41", "< 2.4.50"
        ));
        assert!(!VulnerabilityCheck::version_matches_affected(
            "2.4.50", "< 2.4.50"
        ));
        assert!(!VulnerabilityCheck::version_matches_affected(
            "2.4.51", "< 2.4.50"
        ));
    }

    #[test]
    fn test_confidence_score_banner() {
        let score = ConfidenceScorer::calculate_confidence(true, true, false, 80);
        assert!(score >= 0.95);
    }

    #[test]
    fn test_confidence_score_mdns() {
        let score = ConfidenceScorer::calculate_confidence(false, false, true, 80);
        assert!((0.85..0.95).contains(&score));
    }

    #[test]
    fn test_confidence_score_port_heuristic() {
        let score = ConfidenceScorer::calculate_confidence(false, false, false, 22);
        assert!((0.70..0.85).contains(&score));
    }

    #[test]
    fn test_confidence_level_categorization() {
        assert_eq!(ConfidenceScorer::confidence_level(0.99), "Very High");
        assert_eq!(ConfidenceScorer::confidence_level(0.90), "High");
        assert_eq!(ConfidenceScorer::confidence_level(0.75), "Good");
        assert_eq!(ConfidenceScorer::confidence_level(0.60), "Fair");
        assert_eq!(ConfidenceScorer::confidence_level(0.30), "Low");
    }
}
