//! The plain-language summary at the top of a scan report.
//!
//! The findings table below it is written for someone who already knows what
//! SMB is. This is written for the person who owns the network, and it answers
//! three questions in order: what is wrong, why it matters, and what to do
//! about it.
//!
//! It leads with the worst thing rather than the first thing: a scan of a
//! twenty-device network can produce thirty findings, and the two that matter
//! are what a reader needs to see without scrolling.

use colored::Colorize;
use netgap_core::{Device, Finding, HealthScore, IssueKind, ScanResult, Severity};
use std::collections::HashMap;
use std::net::IpAddr;

/// One problem, in plain language, and which devices it affects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub kind: IssueKind,
    pub severity: Severity,
    /// What is wrong: "File sharing is switched on for 2 computers."
    pub what: String,
    /// Why it matters: "It is how ransomware moves between computers."
    pub why: &'static str,
    /// What to do: "Turn file sharing off where it is not needed."
    pub action: &'static str,
    /// Addresses, worst first, so the reader can find the device in the table.
    pub devices: Vec<IpAddr>,
}

/// The summary: a score, a verdict, and the problems worth naming.
#[derive(Debug, Clone)]
pub struct RiskSummary {
    pub score: HealthScore,
    pub issues: Vec<Issue>,
    /// Findings from checks this summary has no advice for.
    pub other_findings: usize,
    pub devices: usize,
}

impl RiskSummary {
    /// Read a scan result and say what it means.
    pub fn from_result(result: &ScanResult) -> RiskSummary {
        let mut grouped: HashMap<IssueKind, Vec<(&Device, &Finding)>> = HashMap::new();
        let mut other_findings = 0;

        for device in &result.devices {
            for finding in &device.findings {
                // Informational findings are not problems to act on. A
                // self-signed certificate on a home router is the usual one,
                // and it is normal there.
                if finding.severity == Severity::Info {
                    continue;
                }

                match IssueKind::of(finding) {
                    // Findings from checks this summary knows nothing about
                    // are counted rather than described. Inventing advice for
                    // them would be worse than pointing at the detail.
                    IssueKind::Other => other_findings += 1,
                    kind => grouped.entry(kind).or_default().push((device, finding)),
                }
            }
        }

        let mut issues: Vec<Issue> = grouped
            .into_iter()
            .map(|(kind, findings)| {
                let severity = findings
                    .iter()
                    .map(|(_, finding)| finding.severity)
                    .max()
                    .unwrap_or(Severity::Info);

                let mut devices: Vec<IpAddr> =
                    findings.iter().map(|(device, _)| device.ip).collect();
                devices.sort();
                devices.dedup();

                let product = findings.iter().find_map(|(_, finding)| product_of(finding));

                Issue {
                    kind,
                    severity,
                    what: describe(kind, &devices, product.as_deref()),
                    why: why_it_matters(kind),
                    action: what_to_do(kind),
                    devices,
                }
            })
            .collect();

        // Worst first, then the ones affecting the most devices.
        issues.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then(right.devices.len().cmp(&left.devices.len()))
                .then(left.devices.first().cmp(&right.devices.first()))
        });

        RiskSummary {
            score: HealthScore::from_result(result),
            issues,
            other_findings,
            devices: result.devices.len(),
        }
    }

    /// Whether anything at all was found.
    pub fn is_clear(&self) -> bool {
        self.issues.is_empty() && self.other_findings == 0
    }

    /// Render the summary block, including a trailing blank line.
    pub fn render(&self) -> String {
        let mut out = String::new();

        let score = match self.score.score {
            85..=100 => format!("{}", self.score.score).green().bold(),
            70..=84 => format!("{}", self.score.score).yellow().bold(),
            _ => format!("{}", self.score.score).red().bold(),
        };
        out.push_str(&format!(
            "  {}/100 — {}\n\n",
            score,
            self.score.verdict().bold()
        ));

        if self.is_clear() {
            out.push_str(&format!(
                "  {}\n\n",
                "Nothing this scan checks is wrong. That is not the same as a clean bill of \
                 health: it covers what is reachable from this network, not whether every device \
                 is up to date."
                    .dimmed()
            ));
            return out;
        }

        // Three is what someone reads. The rest stay in the report below.
        const LEADING: usize = 3;

        if self.issues.is_empty() {
            out.push_str(&format!(
                "  {}\n\n",
                format!(
                    "{} finding(s) came from checks this summary does not describe; they are \
                     listed per device below.",
                    self.other_findings
                )
                .dimmed()
            ));
            return out;
        }

        out.push_str(&format!("  {}\n\n", "What matters most:".bold()));

        for issue in self.issues.iter().take(LEADING) {
            out.push_str(&format!(
                "    {} {}\n",
                severity_mark(issue.severity),
                issue.what.bold()
            ));
            out.push_str(&format!(
                "      {}\n",
                format!("on {}", join_addresses(&issue.devices)).dimmed()
            ));
            // Wrapped to a width a terminal will not re-wrap: the advice is
            // the part a reader is meant to act on, and it should not arrive
            // folded at a column nobody chose.
            for line in wrap_lines(issue.why, INNER_WIDTH) {
                out.push_str(&format!("      {}\n", line));
            }

            let mut advice = wrap_lines(issue.action, INNER_WIDTH).into_iter();
            if let Some(first) = advice.next() {
                out.push_str(&format!("      {} {}\n", "→".green(), first));
            }
            for line in advice {
                out.push_str(&format!("      {}\n", line));
            }

            out.push('\n');
        }

        let remaining = self.issues.len().saturating_sub(LEADING) + self.other_findings;
        if remaining > 0 {
            out.push_str(&format!(
                "    {}\n\n",
                format!("… and {} more, listed per device below.", remaining).dimmed()
            ));
        }

        out
    }
}

/// The problem as a sentence, with the count and any product name folded in.
fn describe(kind: IssueKind, devices: &[IpAddr], product: Option<&str>) -> String {
    let count = devices.len();

    match kind {
        IssueKind::FileSharing => format!(
            "File sharing (SMB) is switched on for {}",
            count_of(count, "computer", "computers")
        ),
        IssueKind::PlainTextLogin => format!(
            "{} {} logins sent without encryption (Telnet or FTP)",
            count_of(count, "device", "devices"),
            verb(count, "accepts", "accept")
        ),
        IssueKind::RemoteAccess => format!(
            "Remote desktop is reachable on {}",
            count_of(count, "computer", "computers")
        ),
        IssueKind::Database => format!(
            "{} {} reachable on the network",
            count_of(count, "database", "databases"),
            verb(count, "is", "are")
        ),
        IssueKind::RouterAdmin => {
            "The router's settings page can be reached without encryption".to_string()
        }
        IssueKind::Upnp => "UPnP is enabled on the router".to_string(),
        IssueKind::NetworkManagement => format!(
            "{} {} SNMP, describing {} to anyone who asks",
            count_of(count, "device", "devices"),
            verb(count, "answers", "answer"),
            verb(count, "itself", "themselves")
        ),
        IssueKind::WeakEncryption => format!(
            "{} {} outdated or broken encryption",
            count_of(count, "device", "devices"),
            verb(count, "offers", "offer")
        ),
        IssueKind::KnownFlaws => match product {
            Some(product) => format!(
                "{} {} known security flaws ({})",
                count_of(count, "device", "devices"),
                verb(count, "has", "have"),
                product
            ),
            None => format!(
                "{} {} software with known security flaws",
                count_of(count, "device", "devices"),
                verb(count, "has", "have")
            ),
        },
        IssueKind::AddressConflict => {
            "An address changed hands, or two devices are using one".to_string()
        }
        IssueKind::Other => "Something needs a look".to_string(),
    }
}

/// "1 computer", "3 computers".
fn count_of(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// The verb form that agrees with the count.
///
/// Written out rather than assembled, because a sentence that reads "2
/// databases is reachable" is the kind that makes a reader distrust everything
/// around it.
fn verb<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 {
        singular
    } else {
        plural
    }
}

/// Why the problem matters, in one line a non-technical reader can act on.
fn why_it_matters(kind: IssueKind) -> &'static str {
    match kind {
        IssueKind::FileSharing => {
            "It is how ransomware spreads from one computer to the next on a home network."
        }
        IssueKind::PlainTextLogin => {
            "Anyone who can watch the network traffic can read the password."
        }
        IssueKind::RemoteAccess => {
            "If the password is weak, someone else can take over the computer."
        }
        IssueKind::Database => {
            "It usually holds everything the network's applications know, and is often set up to \
             trust whoever connects."
        }
        IssueKind::RouterAdmin => {
            "Someone on the network could read or change the router's settings, including its \
             Wi-Fi password."
        }
        IssueKind::Upnp => {
            "Any program on the network can open a hole in the router's firewall without asking."
        }
        IssueKind::NetworkManagement => {
            "It gives away the device's model, software version and traffic counters."
        }
        IssueKind::WeakEncryption => {
            "Traffic to and from the device can be read or altered in transit."
        }
        IssueKind::KnownFlaws => {
            "These are published, so anyone can look up how to use them against the device."
        }
        IssueKind::AddressConflict => "Traffic meant for one device can be delivered to another.",
        IssueKind::Other => "See the detail below.",
    }
}

/// What to do, phrased as the thing to try first.
fn what_to_do(kind: IssueKind) -> &'static str {
    match kind {
        IssueKind::FileSharing => {
            "Turn file sharing off on the computers that do not need it, and password-protect \
             the folders that are shared on purpose."
        }
        IssueKind::PlainTextLogin => "Use SSH instead of Telnet, and SFTP or SCP instead of FTP.",
        IssueKind::RemoteAccess => {
            "Turn remote desktop off unless it is used, and set a strong password if it is."
        }
        IssueKind::Database => "Restrict it to the machines that need it, and set a password.",
        IssueKind::RouterAdmin => {
            "In the router settings, turn on HTTPS for the admin page and switch off remote \
             administration."
        }
        IssueKind::Upnp => {
            "In the router settings, turn UPnP off — unless a games console needs it."
        }
        IssueKind::NetworkManagement => {
            "Disable SNMP on the device, or set a community string that is not the default."
        }
        IssueKind::WeakEncryption => {
            "Update the device's software or firmware; a device old enough to offer TLS 1.0 may \
             no longer be supported."
        }
        IssueKind::KnownFlaws => {
            "Update the software to the fixed version; the affected version is listed with each \
             finding below."
        }
        IssueKind::AddressConflict => {
            "Check the router's DHCP range, and give fixed addresses to devices set by hand."
        }
        IssueKind::Other => "See the finding below.",
    }
}

/// The product a finding is about, when it names one worth repeating.
fn product_of(finding: &Finding) -> Option<String> {
    // Vulnerability findings carry the product and version in `service` — the
    // product name is what makes the sentence concrete.
    if finding.id.starts_with("cve-") || finding.id.starts_with("nvd-") {
        return finding.service.clone();
    }

    None
}

fn severity_mark(severity: Severity) -> String {
    match severity {
        Severity::Critical => "🔴".to_string(),
        Severity::High => "🟠".to_string(),
        Severity::Medium => "🟡".to_string(),
        Severity::Info => "🔵".to_string(),
    }
}

/// Width the advice is wrapped to, inside the six-space indent. Chosen to fit
/// an eighty-column terminal with room to spare.
const INNER_WIDTH: usize = 72;

/// Wrap text on spaces, at or before `width` columns.
///
/// A word longer than the width is left whole: breaking it would be worse than
/// overflowing, since the reader can still see what it says.
fn wrap_lines(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
}

/// Addresses, shortened when there are many so the line stays readable.
fn join_addresses(addresses: &[IpAddr]) -> String {
    const MOST: usize = 4;

    if addresses.is_empty() {
        return "no device".to_string();
    }

    let shown: Vec<String> = addresses
        .iter()
        .take(MOST)
        .map(|address| address.to_string())
        .collect();

    if addresses.len() > MOST {
        format!("{} and {} others", shown.join(", "), addresses.len() - MOST)
    } else {
        shown.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::{Device, Finding, FindingSummary, ScanConfig, ScanResult, Severity};

    fn finding(id: &str, severity: Severity, port: Option<u16>, service: Option<&str>) -> Finding {
        Finding {
            id: id.to_string(),
            title: format!("Finding {id}"),
            description: "…".to_string(),
            severity,
            ip: "192.168.111.10".parse().expect("a valid address"),
            port,
            service: service.map(str::to_string),
            remediation: "Update it".to_string(),
            confidence: 1.0,
        }
    }

    fn device(ip: &str, findings: Vec<Finding>) -> Device {
        let mut device = Device::new(ip.parse().expect("a valid address"));
        device.findings = findings;
        device
    }

    fn result(devices: Vec<Device>) -> ScanResult {
        ScanResult {
            started_at: "2026-10-01T00:00:00Z".to_string(),
            config: ScanConfig {
                interface: "wlan0".to_string(),
                target: "192.168.111.0/24".to_string(),
                timeout_ms: 1000,
                concurrency: 8,
                discovery_only: false,
            },
            devices,
            summary: FindingSummary::new(),
        }
    }

    fn smb(ip: &str) -> Device {
        device(
            ip,
            vec![finding(
                "open_port_445",
                Severity::High,
                Some(445),
                Some("SMB"),
            )],
        )
    }

    /// The case from a real scan: one Windows machine, both SMB ports open.
    #[test]
    fn test_smb_on_two_ports_is_one_issue() {
        let summary = RiskSummary::from_result(&result(vec![device(
            "192.168.111.10",
            vec![
                finding("open_port_445", Severity::High, Some(445), Some("SMB")),
                finding("open_port_139", Severity::High, Some(139), Some("NetBIOS")),
            ],
        )]));

        assert_eq!(summary.issues.len(), 1, "one problem, not two");
        assert_eq!(summary.issues[0].kind, IssueKind::FileSharing);
    }

    #[test]
    fn test_the_count_is_in_the_sentence() {
        let summary =
            RiskSummary::from_result(&result(vec![smb("192.168.111.10"), smb("192.168.111.11")]));

        assert_eq!(summary.issues.len(), 1);
        assert_eq!(summary.issues[0].devices.len(), 2);
        assert_eq!(
            summary.issues[0].what,
            "File sharing (SMB) is switched on for 2 computers"
        );
    }

    #[test]
    fn test_one_device_reads_as_one() {
        let summary = RiskSummary::from_result(&result(vec![smb("192.168.111.10")]));

        assert_eq!(
            summary.issues[0].what,
            "File sharing (SMB) is switched on for 1 computer"
        );
    }

    /// A sentence that says "2 databases is reachable" costs the reader's
    /// trust in everything around it, so agreement is pinned here for every
    /// kind that counts devices.
    #[test]
    fn test_sentences_agree_with_the_count() {
        let singular = RiskSummary::from_result(&result(vec![device(
            "192.168.111.10",
            vec![
                finding("open_port_3306", Severity::High, Some(3306), Some("MySQL")),
                finding(
                    "telnet_23_exposed",
                    Severity::Critical,
                    Some(23),
                    Some("Telnet"),
                ),
                finding(
                    "snmp_161_exposed",
                    Severity::Medium,
                    Some(161),
                    Some("SNMP"),
                ),
                finding("tls-legacy", Severity::High, Some(443), Some("https")),
                finding(
                    "cve-CVE-2021-41773",
                    Severity::High,
                    Some(80),
                    Some("Apache"),
                ),
                finding("open_port_445", Severity::High, Some(445), Some("SMB")),
            ],
        )]));

        let plural = RiskSummary::from_result(&result(vec![
            device(
                "192.168.111.10",
                vec![
                    finding("open_port_3306", Severity::High, Some(3306), Some("MySQL")),
                    finding(
                        "telnet_23_exposed",
                        Severity::Critical,
                        Some(23),
                        Some("Telnet"),
                    ),
                    finding(
                        "snmp_161_exposed",
                        Severity::Medium,
                        Some(161),
                        Some("SNMP"),
                    ),
                    finding("tls-legacy", Severity::High, Some(443), Some("https")),
                    finding(
                        "cve-CVE-2021-41773",
                        Severity::High,
                        Some(80),
                        Some("Apache"),
                    ),
                    finding("open_port_445", Severity::High, Some(445), Some("SMB")),
                ],
            ),
            device(
                "192.168.111.11",
                vec![
                    finding("open_port_3306", Severity::High, Some(3306), Some("MySQL")),
                    finding(
                        "telnet_23_exposed",
                        Severity::Critical,
                        Some(23),
                        Some("Telnet"),
                    ),
                    finding(
                        "snmp_161_exposed",
                        Severity::Medium,
                        Some(161),
                        Some("SNMP"),
                    ),
                    finding("tls-legacy", Severity::High, Some(443), Some("https")),
                    finding(
                        "cve-CVE-2021-41773",
                        Severity::High,
                        Some(80),
                        Some("Apache"),
                    ),
                    finding("open_port_445", Severity::High, Some(445), Some("SMB")),
                ],
            ),
        ]));

        let sentence = |summary: &RiskSummary, kind: IssueKind| -> String {
            summary
                .issues
                .iter()
                .find(|issue| issue.kind == kind)
                .unwrap_or_else(|| panic!("no issue of kind {kind:?}"))
                .what
                .clone()
        };

        assert_eq!(
            sentence(&singular, IssueKind::Database),
            "1 database is reachable on the network"
        );
        assert_eq!(
            sentence(&plural, IssueKind::Database),
            "2 databases are reachable on the network"
        );

        assert_eq!(
            sentence(&singular, IssueKind::PlainTextLogin),
            "1 device accepts logins sent without encryption (Telnet or FTP)"
        );
        assert_eq!(
            sentence(&plural, IssueKind::PlainTextLogin),
            "2 devices accept logins sent without encryption (Telnet or FTP)"
        );

        assert_eq!(
            sentence(&singular, IssueKind::NetworkManagement),
            "1 device answers SNMP, describing itself to anyone who asks"
        );
        assert_eq!(
            sentence(&plural, IssueKind::NetworkManagement),
            "2 devices answer SNMP, describing themselves to anyone who asks"
        );

        assert_eq!(
            sentence(&singular, IssueKind::WeakEncryption),
            "1 device offers outdated or broken encryption"
        );
        assert_eq!(
            sentence(&plural, IssueKind::WeakEncryption),
            "2 devices offer outdated or broken encryption"
        );

        assert_eq!(
            sentence(&singular, IssueKind::KnownFlaws),
            "1 device has known security flaws (Apache)"
        );
        assert_eq!(
            sentence(&plural, IssueKind::KnownFlaws),
            "2 devices have known security flaws (Apache)"
        );

        // The kinds that name a thing rather than counting devices never
        // change with the count.
        assert_eq!(
            sentence(&singular, IssueKind::FileSharing),
            "File sharing (SMB) is switched on for 1 computer"
        );
        assert_eq!(
            sentence(&plural, IssueKind::FileSharing),
            "File sharing (SMB) is switched on for 2 computers"
        );
    }

    /// A router with Telnet open is the worst thing a home scan can find, and
    /// it has to outrank a laptop sharing files.
    #[test]
    fn test_the_worst_problem_is_listed_first() {
        let summary = RiskSummary::from_result(&result(vec![
            smb("192.168.111.10"),
            device(
                "192.168.111.1",
                vec![finding(
                    "telnet_23_exposed",
                    Severity::Critical,
                    Some(23),
                    Some("Telnet"),
                )],
            ),
        ]));

        assert_eq!(summary.issues[0].kind, IssueKind::PlainTextLogin);
        assert_eq!(summary.issues[0].severity, Severity::Critical);
    }

    /// Informational findings are not problems. A self-signed certificate is
    /// the usual one, and it is normal on a home network.
    #[test]
    fn test_informational_findings_are_not_raised() {
        let summary = RiskSummary::from_result(&result(vec![device(
            "192.168.111.1",
            vec![finding(
                "tls-self-signed",
                Severity::Info,
                Some(443),
                Some("https"),
            )],
        )]));

        assert!(summary.is_clear());
        assert_eq!(summary.score.score, 100);
    }

    #[test]
    fn test_the_score_does_not_fall_because_the_network_is_big() {
        // Nineteen devices with nothing wrong is a healthy network, whatever
        // its size.
        let devices: Vec<Device> = (1..=19)
            .map(|last| device(&format!("192.168.111.{last}"), Vec::new()))
            .collect();

        let summary = RiskSummary::from_result(&result(devices));

        assert_eq!(summary.score.score, 100);
        assert!(summary.is_clear());
    }

    #[test]
    fn test_a_clean_scan_says_what_it_did_not_check() {
        let summary = RiskSummary::from_result(&result(vec![device("192.168.111.10", Vec::new())]));
        let rendered = summary.render();

        assert!(rendered.contains("100/100"));
        assert!(
            rendered.contains("not the same as a clean bill of health"),
            "a perfect score must not overclaim: {rendered}"
        );
    }

    #[test]
    fn test_every_issue_renders_with_advice() {
        let summary = RiskSummary::from_result(&result(vec![device(
            "192.168.111.1",
            vec![
                finding(
                    "telnet_23_exposed",
                    Severity::Critical,
                    Some(23),
                    Some("Telnet"),
                ),
                finding("open_port_445", Severity::High, Some(445), Some("SMB")),
                finding("gateway_upnp_exposed", Severity::Medium, None, None),
                finding(
                    "cve-CVE-2021-41773",
                    Severity::High,
                    Some(80),
                    Some("Apache 2.4.49"),
                ),
            ],
        )]));

        let rendered = summary.render();
        for issue in &summary.issues {
            assert!(!issue.why.is_empty());
            assert!(!issue.action.is_empty());
        }
        assert!(rendered.contains("What matters most"));
        // Only the leading issues are spelled out; the rest are counted.
        assert!(
            rendered.contains("more, listed per device below"),
            "{rendered}"
        );
    }

    /// Findings the classifier does not recognise must still be counted, not
    /// silently dropped.
    #[test]
    fn test_unknown_findings_are_counted_but_not_described() {
        let summary = RiskSummary::from_result(&result(vec![device(
            "192.168.111.10",
            vec![finding("something_new", Severity::High, Some(9999), None)],
        )]));

        assert_eq!(summary.other_findings, 1);
        assert!(summary.issues.is_empty());
        assert!(!summary.is_clear());
        assert!(summary
            .render()
            .contains("checks this summary does not describe"));
    }

    #[test]
    fn test_a_product_name_reaches_the_sentence() {
        let summary = RiskSummary::from_result(&result(vec![device(
            "192.168.111.10",
            vec![finding(
                "cve-CVE-2021-41773",
                Severity::High,
                Some(80),
                Some("Apache 2.4.49"),
            )],
        )]));

        assert_eq!(
            summary.issues[0].what,
            "1 device has known security flaws (Apache 2.4.49)"
        );
    }
}
