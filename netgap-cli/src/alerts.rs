//! Alerts that leave the machine.
//!
//! A monitor that only prints is one you have to be watching. This sends what
//! changed to a webhook — Slack, Discord, Mattermost, or any endpoint that
//! takes JSON — so the network can be checked on a timer and the answer
//! arrives where the person actually is.
//!
//! Two decisions shape it:
//!
//! * **Alerts are about change, not state.** A scan every fifteen minutes
//!   finds the same open port every fifteen minutes, and a monitor that
//!   repeats itself is one that gets muted. What is sent is what is different
//!   from the last recorded scan.
//! * **The list is short by default.** Alerting on every new device means
//!   alerting every time a guest joins the Wi-Fi or a phone randomizes its
//!   address, which is the fastest way to teach someone to ignore alerts.

use anyhow::{anyhow, Context, Result};
use netgap_core::{paths, HealthScore, ScanResult};
use netgap_trends::{AlertCondition, AlertRule, NetworkChange, ScanHistory};
use netgap_webhooks::{WebhookAlert, WebhookConfig, WebhookDeliveryManager, WebhookProvider};
use std::collections::HashSet;
use std::path::PathBuf;

/// What the user configured, read from `alerts.toml` in the config directory.
#[derive(Debug, Clone)]
pub struct AlertSettings {
    pub url: String,
    pub provider: WebhookProvider,
    /// Whether a plain `http://` endpoint was deliberately allowed.
    pub allow_http: bool,
    /// Whether alerts are switched on. Kept separate from the URL so
    /// silencing them does not throw the configuration away.
    pub enabled: bool,
    pub rules: Rules,
}

/// Which changes are worth interrupting someone for.
#[derive(Debug, Clone)]
pub struct Rules {
    /// A critical finding that was not there last time. On by default.
    pub critical: bool,
    /// A device that has not been seen before. Off by default: guests,
    /// visitors, and phones that randomize their address all look like this.
    pub new_device: bool,
    /// A device that has stopped appearing. Off by default: phones sleep.
    pub device_offline: bool,
    /// Alert when the health score falls by this much in one scan.
    pub health_drop: Option<u8>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            critical: true,
            new_device: false,
            device_offline: false,
            health_drop: None,
        }
    }
}

impl AlertSettings {
    /// Where the settings live.
    pub fn path() -> Option<PathBuf> {
        paths::config_dir().map(|dir| dir.join("alerts.toml"))
    }

    /// Load them, or `None` when alerts have not been set up.
    pub fn load() -> Result<Option<AlertSettings>> {
        // The environment wins, so a cron job or container can point at a
        // different endpoint without a config file.
        if let Ok(url) = std::env::var("NETGAP_ALERT_URL") {
            if !url.trim().is_empty() {
                let provider = std::env::var("NETGAP_ALERT_PROVIDER")
                    .ok()
                    .map(|name| parse_provider(&name))
                    .transpose()?
                    .unwrap_or(WebhookProvider::Generic);

                return Ok(Some(AlertSettings {
                    allow_http: std::env::var("NETGAP_ALERT_ALLOW_HTTP").is_ok(),
                    enabled: true,
                    url,
                    provider,
                    rules: Rules::default(),
                }));
            }
        }

        let Some(path) = AlertSettings::path() else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }

        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        AlertSettings::from_toml(&text).map(Some)
    }

    /// Parse the file. Kept separate from reading it so the format can be
    /// tested, and so a bad file produces a message naming the problem.
    pub fn from_toml(text: &str) -> Result<AlertSettings> {
        let value: toml::Value = toml::from_str(text).context("alerts.toml is not valid TOML")?;

        let url = value
            .get("url")
            .and_then(|url| url.as_str())
            .ok_or_else(|| anyhow!("alerts.toml needs a `url`"))?
            .to_string();

        let provider = value
            .get("provider")
            .and_then(|provider| provider.as_str())
            .map(parse_provider)
            .transpose()?
            .unwrap_or(WebhookProvider::Generic);

        let allow_http = value
            .get("allow_http")
            .and_then(|allow| allow.as_bool())
            .unwrap_or(false);

        let enabled = value
            .get("enabled")
            .and_then(|enabled| enabled.as_bool())
            .unwrap_or(true);

        let mut rules = Rules::default();
        if let Some(table) = value.get("rules").and_then(|rules| rules.as_table()) {
            if let Some(critical) = table.get("critical").and_then(|flag| flag.as_bool()) {
                rules.critical = critical;
            }
            if let Some(new_device) = table.get("new_device").and_then(|flag| flag.as_bool()) {
                rules.new_device = new_device;
            }
            if let Some(offline) = table.get("device_offline").and_then(|flag| flag.as_bool()) {
                rules.device_offline = offline;
            }
            if let Some(drop) = table.get("health_drop").and_then(|drop| drop.as_integer()) {
                rules.health_drop = Some(drop.clamp(1, 100) as u8);
            }
        }

        let settings = AlertSettings {
            url,
            provider,
            allow_http,
            enabled,
            rules,
        };
        settings.check_url()?;
        Ok(settings)
    }

    /// The file as it would be written.
    pub fn to_toml(&self) -> String {
        let mut text = String::new();
        text.push_str("# Where netgap sends alerts. Treated as a secret: anyone\n");
        text.push_str("# holding this URL can post to the same place.\n");
        text.push_str(&format!("url = \"{}\"\n", self.url.replace('"', "\\\"")));
        text.push_str(&format!("provider = \"{}\"\n", self.provider.as_str()));
        if !self.enabled {
            text.push_str("enabled = false\n");
        }
        if self.allow_http {
            text.push_str("allow_http = true\n");
        }
        text.push_str("\n[rules]\n");
        text.push_str("# A critical finding that was not there last time.\n");
        text.push_str(&format!("critical = {}\n", self.rules.critical));
        text.push_str("# A device not seen before. Off by default: guests, and\n");
        text.push_str("# phones that randomize their address, look the same.\n");
        text.push_str(&format!("new_device = {}\n", self.rules.new_device));
        text.push_str(&format!("device_offline = {}\n", self.rules.device_offline));
        if let Some(drop) = self.rules.health_drop {
            text.push_str(&format!("health_drop = {drop}\n"));
        }
        text
    }

    /// Save it, readable only by its owner.
    pub fn save(&self) -> Result<PathBuf> {
        let path = AlertSettings::path()
            .ok_or_else(|| anyhow!("no config directory (set HOME or NETGAP_CONFIG_DIR)"))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        std::fs::write(&path, self.to_toml())
            .with_context(|| format!("writing {}", path.display()))?;

        // The URL is a credential for most providers. A file that anyone on
        // the machine can read is a credential anyone on the machine has.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restricting {}", path.display()))?;
        }

        Ok(path)
    }

    /// Refuse to send network details somewhere unprotected, unless the user
    /// said they meant it.
    pub fn check_url(&self) -> Result<()> {
        check_url(&self.url, self.allow_http)
    }

    /// The manager that delivers to this endpoint.
    pub fn manager(&self) -> WebhookDeliveryManager {
        let mut config = WebhookConfig::new(&self.url).with_provider(self.provider);
        // An alert is worth a couple of tries; it is not worth blocking a
        // scheduled scan for a minute while an endpoint is down.
        config = config.with_timeout(10).with_retry(2, 500);
        WebhookDeliveryManager::new(config)
    }

    /// The rules, with the ones the user turned off left out.
    fn enabled_rules(&self) -> Vec<AlertRule> {
        let mut rules = Vec::new();
        if self.rules.critical {
            // Both, because "tell me when something appears that was not
            // there before" covers a critical exposure and an SMB share
            // equally, and a user who asked for the first did not mean to
            // hear nothing about the second.
            rules.push(AlertRule::critical_vulnerability());
            rules.push(AlertRule {
                name: "New security findings".to_string(),
                condition: AlertCondition::VulnerabilityRegressed,
            });
        }
        if self.rules.new_device {
            rules.push(AlertRule::new_device());
        }
        if self.rules.device_offline {
            rules.push(AlertRule {
                name: "A device stopped appearing".to_string(),
                condition: AlertCondition::DeviceOffline,
            });
        }
        if let Some(threshold) = self.rules.health_drop {
            rules.push(AlertRule::health_drop(threshold));
        }
        rules
    }
}

/// The switches `netgap alert` was given. Each is `None` when the flag was not
/// passed, so a change to one setting leaves the others alone.
#[derive(Debug, Default, Clone)]
pub struct AlertChanges {
    pub url: Option<String>,
    pub provider: Option<String>,
    pub allow_http: bool,
    pub critical: Option<bool>,
    pub new_device: Option<bool>,
    pub device_offline: Option<bool>,
    pub health_drop: Option<u8>,
    pub off: bool,
}

impl AlertChanges {
    /// Whether this run changes nothing, and is only asking what is set.
    pub fn is_display_only(&self) -> bool {
        self.url.is_none()
            && self.provider.is_none()
            && !self.allow_http
            && self.critical.is_none()
            && self.new_device.is_none()
            && self.device_offline.is_none()
            && self.health_drop.is_none()
            && !self.off
    }

    /// Apply them to whatever is configured, and save the result.
    ///
    /// Returns `None` when the result is "no alerts at all", which is the case
    /// for turning them off before one was ever set up.
    pub fn apply(self) -> Result<Option<AlertSettings>> {
        let existing = AlertSettings::load()?;

        let mut settings = match existing {
            Some(settings) => settings,
            None => {
                let Some(url) = self.url.clone() else {
                    return Ok(None);
                };
                AlertSettings {
                    url,
                    provider: WebhookProvider::Generic,
                    allow_http: self.allow_http,
                    enabled: true,
                    rules: Rules::default(),
                }
            }
        };

        if let Some(url) = &self.url {
            settings.url = url.trim().to_string();
            // Setting a URL is the act of turning alerts on.
            settings.enabled = true;
        }
        if let Some(provider) = &self.provider {
            settings.provider = parse_provider(provider)?;
        }
        if self.allow_http {
            settings.allow_http = true;
        }
        if let Some(critical) = self.critical {
            settings.rules.critical = critical;
        }
        if let Some(new_device) = self.new_device {
            settings.rules.new_device = new_device;
        }
        if let Some(offline) = self.device_offline {
            settings.rules.device_offline = offline;
        }
        if let Some(drop) = self.health_drop {
            settings.rules.health_drop = Some(drop.clamp(1, 100));
        }
        if self.off {
            settings.enabled = false;
        }

        settings.check_url()?;
        settings.save()?;
        Ok(Some(settings))
    }

    /// A plain-language account of what this run changed.
    pub fn describe(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if let Some(url) = &self.url {
            notes.push(format!("Sending alerts to {}", mask_url(url)));
        }
        if let Some(provider) = &self.provider {
            notes.push(format!("Message format: {provider}"));
        }
        if let Some(value) = self.critical {
            notes.push(on_off("critical findings", value));
        }
        if let Some(value) = self.new_device {
            notes.push(on_off("new devices", value));
        }
        if let Some(value) = self.device_offline {
            notes.push(on_off("devices going offline", value));
        }
        if let Some(drop) = self.health_drop {
            notes.push(format!("Health score drops of {drop} points or more"));
        }
        if self.off {
            notes.push("Alerts switched off (the URL is kept)".to_string());
        }
        notes
    }
}

/// "Alerting about X: on" / "…: off".
fn on_off(what: &str, enabled: bool) -> String {
    format!(
        "Alerting about {what}: {}",
        if enabled { "on" } else { "off" }
    )
}

/// Whether an endpoint is acceptable to send to.
pub fn check_url(url: &str, allow_http: bool) -> Result<()> {
    let url = url.trim();
    if url.is_empty() {
        return Err(anyhow!("the webhook URL is empty"));
    }
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://") {
        if allow_http {
            return Ok(());
        }
        return Err(anyhow!(
            "refusing to send alerts over plain http, which would put your network's \
             addresses on the wire in the clear — pass --allow-http if the endpoint is \
             on this machine or you accept that"
        ));
    }
    Err(anyhow!(
        "the webhook URL must start with https:// (or http:// with --allow-http)"
    ))
}

/// Parse a provider name, naming the alternatives when it does not match.
pub fn parse_provider(name: &str) -> Result<WebhookProvider> {
    match name.trim().to_ascii_lowercase().as_str() {
        "generic" | "json" => Ok(WebhookProvider::Generic),
        "slack" => Ok(WebhookProvider::Slack),
        "discord" => Ok(WebhookProvider::Discord),
        "mattermost" | "matter-most" => Ok(WebhookProvider::MatterMost),
        other => Err(anyhow!(
            "unknown provider '{other}' — use generic, slack, discord or mattermost"
        )),
    }
}

/// A URL with its secret part hidden, for showing back to the user.
///
/// Provider URLs carry their credential in the path, so the path is what a
/// screenshot or a pasted terminal transcript would give away.
pub fn mask_url(url: &str) -> String {
    let trimmed = url.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("", trimmed),
    };
    let host = rest.split('/').next().unwrap_or(rest);

    if scheme.is_empty() {
        return host.to_string();
    }
    format!("{scheme}://{host}/…")
}

/// What was sent, for the caller to report.
pub struct AlertOutcome {
    pub sent: bool,
    /// The changes the alert was about.
    pub changes: Vec<NetworkChange>,
    pub error: Option<String>,
}

/// Decide whether this scan is worth an alert, and send it if so.
///
/// `previous` is the last recorded scan of the same target, when there is one.
/// Without it there is nothing to compare against, and nothing to say that
/// has not already been said.
pub async fn alert_on_changes(
    settings: &AlertSettings,
    previous: Option<&ScanResult>,
    current: &ScanResult,
) -> AlertOutcome {
    if !settings.enabled {
        return AlertOutcome {
            sent: false,
            changes: Vec::new(),
            error: None,
        };
    }

    let Some(previous) = previous else {
        return AlertOutcome {
            sent: false,
            changes: Vec::new(),
            error: None,
        };
    };

    let previous_history = ScanHistory::from_scan_result("previous".to_string(), previous);
    let current_history = ScanHistory::from_scan_result("current".to_string(), current);
    let changes =
        netgap_trends::ChangeDetection::detect_changes(&previous_history, &current_history);

    let previous_score = HealthScore::from_result(previous);
    let current_score = HealthScore::from_result(current);
    let drop = if current_score.score < previous_score.score {
        Some((previous_score.score - current_score.score) as i16)
    } else {
        None
    };

    // A rule that fires decides whether to send at all; the changes it is
    // about are what goes in the message.
    let rules = settings.enabled_rules();
    let mut worth_sending: Vec<NetworkChange> = Vec::new();
    let mut seen = HashSet::new();

    for rule in &rules {
        if !rule.should_trigger(&changes, drop) {
            continue;
        }
        for change in changes.iter().filter(|change| rule.matches(change)) {
            if seen.insert(change.to_string()) {
                worth_sending.push(change.clone());
            }
        }
    }

    // A device that gained a critical finding produces both changes, because
    // the change detector reports them independently. The critical one says
    // the same thing more precisely, so the other is dropped rather than
    // repeated in the same message.
    let critical_devices: HashSet<String> = worth_sending
        .iter()
        .filter_map(|change| match change {
            NetworkChange::CriticalVulnDetected { ip, .. } => Some(ip.clone()),
            _ => None,
        })
        .collect();

    worth_sending.retain(|change| match change {
        NetworkChange::VulnerabilityRegressed { ip } => !critical_devices.contains(ip),
        _ => true,
    });

    // A health drop is about the score rather than any one change, so it can
    // be worth sending on its own.
    let health_only = worth_sending.is_empty()
        && drop.is_some()
        && rules
            .iter()
            .any(|rule| matches!(rule.condition, AlertCondition::HealthScoreDrop { .. }));

    if worth_sending.is_empty() && !health_only {
        return AlertOutcome {
            sent: false,
            changes: Vec::new(),
            error: None,
        };
    }

    let alert = build_alert(&worth_sending, drop, current);
    match settings.manager().send(&alert).await {
        Ok(()) => AlertOutcome {
            sent: true,
            changes: worth_sending,
            error: None,
        },
        Err(error) => AlertOutcome {
            sent: false,
            changes: worth_sending,
            error: Some(error.to_string()),
        },
    }
}

/// The message itself: what changed, in sentences rather than port numbers.
pub fn build_alert(
    changes: &[NetworkChange],
    drop: Option<i16>,
    current: &ScanResult,
) -> WebhookAlert {
    let mut addresses: Vec<String> = Vec::new();
    let mut lines: Vec<String> = Vec::new();

    for change in changes {
        lines.push(describe(change, current));
        if let Some(address) = address_of(change) {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }

    if let Some(drop) = drop {
        lines.push(format!(
            "The network's health score fell by {drop} points, to {}.",
            HealthScore::from_result(current).score
        ));
    }

    let title = match changes.len() {
        0 => "Network health changed".to_string(),
        // One change gets its own headline rather than a count of one.
        1 => headline(&changes[0]),
        count => format!("{count} changes on your network"),
    };

    let severity = worst_severity(changes);
    let target = current.config.target.clone();
    let description = format!(
        "{}\n\nNetwork: {} (scanned {})",
        lines.join("\n"),
        target,
        current.started_at
    );

    WebhookAlert::new(&severity, &title, &description).affecting(&addresses)
}

/// A short headline for one change, for the subject line of the message.
///
/// Built here rather than cut out of the description: an address contains
/// dots, so taking the first sentence of a sentence-shaped string splits an
/// IP in half.
fn headline(change: &NetworkChange) -> String {
    match change {
        NetworkChange::CriticalVulnDetected { ip, count } => {
            format!("{count} critical security finding(s) on {ip}")
        }
        NetworkChange::VulnerabilityRegressed { ip } => {
            format!("New security findings on {ip}")
        }
        NetworkChange::VulnerabilityImproved { ip } => {
            format!("Fewer security findings on {ip}")
        }
        NetworkChange::NewDevice { ip, .. } => format!("A new device joined: {ip}"),
        NetworkChange::DeviceGone { ip } => format!("{ip} stopped answering"),
        NetworkChange::NewService { ip, port } => format!("{ip} opened port {port}"),
        NetworkChange::ServiceClosed { ip, port } => format!("{ip} closed port {port}"),
    }
}

/// One change, as a sentence a person can read without a glossary.
fn describe(change: &NetworkChange, current: &ScanResult) -> String {
    match change {
        NetworkChange::CriticalVulnDetected { ip, count } => format!(
            "{ip} now has {count} critical security finding(s) that were not there before{}.",
            findings_note(current, ip)
        ),
        NetworkChange::VulnerabilityRegressed { ip } => format!(
            "{ip} has security findings it did not have before{}.",
            findings_note(current, ip)
        ),
        NetworkChange::VulnerabilityImproved { ip } => {
            format!("{ip} has fewer security findings than before.")
        }
        NetworkChange::NewDevice { ip, hostname } => match hostname {
            Some(name) => format!("A device that has not been seen before joined: {ip} ({name})."),
            None => format!("A device that has not been seen before joined: {ip}."),
        },
        NetworkChange::DeviceGone { ip } => {
            format!("{ip} did not answer this time, though it was there before.")
        }
        NetworkChange::NewService { ip, port } => format!(
            "{ip} started answering on port {port}{}.",
            service_note(current, ip, *port)
        ),
        NetworkChange::ServiceClosed { ip, port } => {
            format!("{ip} stopped answering on port {port}.")
        }
    }
}

/// What the findings on a device actually are.
///
/// An alert that says a machine "has new findings" makes the reader open the
/// report to find out what happened, which on a phone at midnight is the same
/// as not being told. The names are shortened and capped so the message stays
/// readable.
fn findings_note(current: &ScanResult, ip: &str) -> String {
    const MOST: usize = 3;

    let findings: Vec<String> = current
        .devices
        .iter()
        .filter(|device| device.ip.to_string() == ip)
        .flat_map(|device| device.findings.iter())
        .map(|finding| finding.title.clone())
        .collect();

    if findings.is_empty() {
        return String::new();
    }

    let shown = findings
        .iter()
        .take(MOST)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");

    if findings.len() > MOST {
        format!(": {shown}; and {} more", findings.len() - MOST)
    } else {
        format!(": {shown}")
    }
}

/// The service name behind a port, when the scan identified one.
fn service_note(current: &ScanResult, ip: &str, port: u16) -> String {
    let found = current
        .devices
        .iter()
        .filter(|device| device.ip.to_string() == ip)
        .flat_map(|device| device.findings.iter())
        .find(|finding| finding.port == Some(port))
        .and_then(|finding| finding.service.clone());

    match found {
        Some(service) => format!(" ({service})"),
        None => String::new(),
    }
}

/// The address a change is about.
fn address_of(change: &NetworkChange) -> Option<String> {
    match change {
        NetworkChange::NewDevice { ip, .. }
        | NetworkChange::DeviceGone { ip }
        | NetworkChange::NewService { ip, .. }
        | NetworkChange::ServiceClosed { ip, .. }
        | NetworkChange::CriticalVulnDetected { ip, .. }
        | NetworkChange::VulnerabilityImproved { ip }
        | NetworkChange::VulnerabilityRegressed { ip } => Some(ip.clone()),
    }
}

/// The severity a change deserves, which is what the receiving client colours
/// the message by.
fn severity_of(change: &NetworkChange) -> &'static str {
    match change {
        NetworkChange::CriticalVulnDetected { .. } => "Critical",
        NetworkChange::VulnerabilityRegressed { .. } => "High",
        NetworkChange::NewService { .. } => "Medium",
        // Not alarms: a device that joined or left is information the user
        // asked to be told about, not a problem to act on.
        NetworkChange::NewDevice { .. } | NetworkChange::DeviceGone { .. } => "Info",
        NetworkChange::ServiceClosed { .. } | NetworkChange::VulnerabilityImproved { .. } => "Info",
    }
}

/// The worst severity in the set, so one critical finding is not buried under
/// the new devices reported alongside it.
fn worst_severity(changes: &[NetworkChange]) -> String {
    let rank = |severity: &str| match severity {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        _ => 1,
    };

    changes
        .iter()
        .map(severity_of)
        .max_by_key(|severity| rank(severity))
        .unwrap_or("Info")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::{Device, Finding, FindingSummary, ScanConfig, Severity};

    fn scan(devices: Vec<Device>) -> ScanResult {
        let mut summary = FindingSummary::new();
        for device in &devices {
            for finding in &device.findings {
                summary.add_finding(finding.severity);
            }
        }
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
            summary,
        }
    }

    fn device(ip: &str, findings: Vec<Finding>) -> Device {
        let mut device = Device::new(ip.parse().expect("a valid address"));
        device.mac = Some("AA:BB:CC:DD:EE:FF".to_string());
        device.findings = findings;
        device
    }

    fn critical(ip: &str) -> Finding {
        Finding {
            id: "telnet_23_exposed".to_string(),
            title: "TELNET EXPOSED".to_string(),
            description: "Telnet is open.".to_string(),
            severity: Severity::Critical,
            ip: ip.parse().expect("a valid address"),
            port: Some(23),
            service: Some("Telnet".to_string()),
            remediation: "Use SSH.".to_string(),
            confidence: 1.0,
        }
    }

    fn settings() -> AlertSettings {
        AlertSettings {
            url: "https://example.test/hook".to_string(),
            provider: WebhookProvider::Generic,
            allow_http: false,
            enabled: true,
            rules: Rules::default(),
        }
    }

    #[test]
    fn test_settings_round_trip_through_the_file_format() {
        let mut settings = settings();
        settings.provider = WebhookProvider::Slack;
        settings.rules.new_device = true;
        settings.rules.health_drop = Some(15);

        let parsed = AlertSettings::from_toml(&settings.to_toml()).expect("parse");

        assert_eq!(parsed.url, settings.url);
        assert_eq!(parsed.provider, WebhookProvider::Slack);
        assert!(parsed.rules.new_device);
        assert_eq!(parsed.rules.health_drop, Some(15));
        // Left out of the file, so it comes back as the default.
        assert!(parsed.rules.critical);
        assert!(!parsed.rules.device_offline);
    }

    /// The URL is a credential for most providers, so the copy shown back to
    /// the user — in a terminal they may screenshot — hides it.
    #[test]
    fn test_showing_the_url_hides_its_secret() {
        let masked = mask_url("https://hooks.slack.com/services/T00/B00/XXXXYYYY");
        assert_eq!(masked, "https://hooks.slack.com/…");
        assert!(!masked.contains("XXXXYYYY"));
    }

    #[test]
    fn test_plain_http_is_refused_unless_asked_for() {
        assert!(check_url("https://example.test/hook", false).is_ok());
        assert!(check_url("http://example.test/hook", false).is_err());
        assert!(check_url("http://192.168.1.5:8080/hook", true).is_ok());
        assert!(check_url("ftp://example.test", false).is_err());
        assert!(check_url("", false).is_err());
    }

    #[test]
    fn test_an_unknown_provider_names_the_alternatives() {
        let error = parse_provider("teams").expect_err("should fail");
        let message = error.to_string();
        for expected in ["slack", "discord", "mattermost", "generic"] {
            assert!(message.contains(expected), "{message}");
        }
    }

    /// The point of alerting on change: a network that is unchanged says
    /// nothing, however bad it was to begin with.
    #[tokio::test]
    async fn test_nothing_is_sent_when_nothing_changed() {
        let before = scan(vec![device(
            "192.168.111.10",
            vec![critical("192.168.111.10")],
        )]);
        let after = before.clone();

        let outcome = alert_on_changes(&settings(), Some(&before), &after).await;

        assert!(!outcome.sent);
        assert!(outcome.changes.is_empty());
        assert!(
            outcome.error.is_none(),
            "and it must not have tried to send"
        );
    }

    #[tokio::test]
    async fn test_no_previous_scan_means_nothing_to_compare() {
        let current = scan(vec![device(
            "192.168.111.10",
            vec![critical("192.168.111.10")],
        )]);

        let outcome = alert_on_changes(&settings(), None, &current).await;

        assert!(!outcome.sent);
        assert!(outcome.error.is_none());
    }

    /// A new critical finding on a known device is the case this exists for.
    #[tokio::test]
    async fn test_a_new_critical_finding_is_worth_sending() {
        let before = scan(vec![device("192.168.111.10", Vec::new())]);
        let after = scan(vec![device(
            "192.168.111.10",
            vec![critical("192.168.111.10")],
        )]);

        let outcome = alert_on_changes(&settings(), Some(&before), &after).await;

        // The endpoint does not exist, so delivery fails — what is being
        // tested is that it decided to send at all.
        assert_eq!(outcome.changes.len(), 1);
        assert!(matches!(
            outcome.changes[0],
            NetworkChange::CriticalVulnDetected { .. }
        ));
        assert!(
            outcome.error.is_some(),
            "delivery should have been attempted"
        );
    }

    /// A new device is off by default, because guests and randomized
    /// addresses make it the noisiest alert there is.
    #[tokio::test]
    async fn test_a_new_device_is_not_sent_by_default() {
        let before = scan(vec![device("192.168.111.10", Vec::new())]);
        let after = scan(vec![
            device("192.168.111.10", Vec::new()),
            device("192.168.111.11", Vec::new()),
        ]);

        let outcome = alert_on_changes(&settings(), Some(&before), &after).await;
        assert!(outcome.changes.is_empty(), "no alert by default");
        assert!(outcome.error.is_none());
    }

    #[tokio::test]
    async fn test_a_new_device_is_sent_when_asked_for() {
        let before = scan(vec![device("192.168.111.10", Vec::new())]);
        let after = scan(vec![
            device("192.168.111.10", Vec::new()),
            device("192.168.111.11", Vec::new()),
        ]);

        let mut settings = settings();
        settings.rules.new_device = true;

        let outcome = alert_on_changes(&settings, Some(&before), &after).await;

        assert_eq!(outcome.changes.len(), 1);
        assert!(matches!(
            outcome.changes[0],
            NetworkChange::NewDevice { .. }
        ));
    }

    #[test]
    fn test_the_message_reads_as_sentences() {
        let current = scan(vec![device(
            "192.168.111.10",
            vec![critical("192.168.111.10")],
        )]);
        let changes = vec![NetworkChange::CriticalVulnDetected {
            ip: "192.168.111.10".to_string(),
            count: 1,
        }];

        let alert = build_alert(&changes, None, &current);

        assert_eq!(alert.severity, "Critical");
        assert!(alert.title.contains("192.168.111.10"));
        assert!(
            alert.description.contains("critical security finding"),
            "{}",
            alert.description
        );
        assert!(
            alert.description.contains("TELNET EXPOSED"),
            "the alert should say what was found: {}",
            alert.description
        );
        assert_eq!(alert.affected, vec!["192.168.111.10".to_string()]);
        // No CVE is involved, and the alert must not imply one.
        assert!(alert.cve_id.is_none());
    }

    /// The change detector reports a critical finding twice — once as critical
    /// and once as a regression — and the message must not say it twice.
    #[tokio::test]
    async fn test_one_event_is_reported_once() {
        let before = scan(vec![device("192.168.111.10", Vec::new())]);
        let after = scan(vec![device(
            "192.168.111.10",
            vec![critical("192.168.111.10")],
        )]);

        let outcome = alert_on_changes(&settings(), Some(&before), &after).await;

        assert_eq!(outcome.changes.len(), 1, "{:?}", outcome.changes);
        assert!(matches!(
            outcome.changes[0],
            NetworkChange::CriticalVulnDetected { .. }
        ));
    }

    #[test]
    fn test_one_critical_is_not_buried_by_new_devices() {
        let current = scan(vec![device(
            "192.168.111.10",
            vec![critical("192.168.111.10")],
        )]);
        let changes = vec![
            NetworkChange::NewDevice {
                ip: "192.168.111.20".to_string(),
                hostname: None,
            },
            NetworkChange::CriticalVulnDetected {
                ip: "192.168.111.10".to_string(),
                count: 1,
            },
        ];

        let alert = build_alert(&changes, None, &current);
        assert_eq!(alert.severity, "Critical");
    }

    /// A drop in the score can happen with no single change explaining it.
    #[test]
    fn test_a_health_drop_alone_still_makes_a_message() {
        let current = scan(vec![device(
            "192.168.111.10",
            vec![critical("192.168.111.10")],
        )]);

        let alert = build_alert(&[], Some(24), &current);

        assert!(alert.title.contains("health") || alert.title.contains("Network"));
        assert!(alert.description.contains("fell by 24 points"));
    }
}
