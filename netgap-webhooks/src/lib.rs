use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

/// Webhook provider types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookProvider {
    Generic,
    Slack,
    Discord,
    MatterMost,
}

impl WebhookProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            WebhookProvider::Generic => "generic",
            WebhookProvider::Slack => "slack",
            WebhookProvider::Discord => "discord",
            WebhookProvider::MatterMost => "mattermost",
        }
    }
}

/// Webhook Alert Payload
///
/// Most of what this scanner finds is not a CVE — an open Telnet port, file
/// sharing left on, a device that appeared on the network — so the payload
/// leads with a title and a description, and carries CVE fields only when the
/// finding actually has one. An alert that says "CVE: open_port_445, CVSS: 0.0"
/// is worse than one that says what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAlert {
    pub alert_id: String,
    pub severity: String, // Critical, High, Medium, Low, Info
    pub title: String,
    pub description: String,
    /// Addresses this is about, in the order they were found.
    pub affected: Vec<String>,
    pub affected_service: Option<String>,
    /// Present only when a CVE is what was found.
    pub cve_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub timestamp: String, // ISO8601
    pub remediation: Option<String>,
    pub reference_url: Option<String>,
}

impl WebhookAlert {
    /// An alert about something that happened, with no CVE attached.
    pub fn new(severity: &str, title: &str, description: &str) -> Self {
        Self {
            // Stable per alert kind and severity, so a receiver can group or
            // deduplicate repeats.
            alert_id: format!("netgap-{}-{}", severity.to_lowercase(), slug(title)),
            severity: severity.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            affected: Vec::new(),
            affected_service: None,
            cve_id: None,
            cvss_score: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            remediation: None,
            reference_url: None,
        }
    }

    /// An alert about a published vulnerability.
    pub fn for_cve(severity: &str, cve_id: &str, cvss_score: f32, description: &str) -> Self {
        let mut alert = WebhookAlert::new(severity, cve_id, description);
        alert.alert_id = format!("netgap-{cve_id}");
        alert.cve_id = Some(cve_id.to_string());
        alert.cvss_score = Some(cvss_score);
        alert.reference_url = Some(format!("https://nvd.nist.gov/vuln/detail/{cve_id}"));
        alert
    }

    pub fn affecting(mut self, addresses: &[String]) -> Self {
        self.affected = addresses.to_vec();
        self
    }

    pub fn with_service(mut self, service: &str) -> Self {
        self.affected_service = Some(service.to_string());
        self
    }

    pub fn with_remediation(mut self, remediation: &str) -> Self {
        self.remediation = Some(remediation.to_string());
        self
    }

    pub fn with_reference(mut self, url: &str) -> Self {
        self.reference_url = Some(url.to_string());
        self
    }

    /// The addresses as one line, for the providers that print a single field.
    pub fn affected_summary(&self) -> String {
        match self.affected.len() {
            0 => "—".to_string(),
            1 => self.affected[0].clone(),
            count => format!("{} (+{} more)", self.affected[0], count - 1),
        }
    }
}

/// A short identifier safe to put in an alert id.
fn slug(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// Webhook Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub provider: WebhookProvider,
    pub enabled: bool,
    pub timeout_secs: u64,
    pub retry_attempts: u32,
    pub retry_backoff_ms: u64,
}

impl WebhookConfig {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            provider: WebhookProvider::Generic,
            enabled: true,
            timeout_secs: 5,
            retry_attempts: 3,
            retry_backoff_ms: 1000,
        }
    }

    pub fn with_provider(mut self, provider: WebhookProvider) -> Self {
        self.provider = provider;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_retry(mut self, attempts: u32, backoff_ms: u64) -> Self {
        self.retry_attempts = attempts;
        self.retry_backoff_ms = backoff_ms;
        self
    }
}

/// Webhook Delivery Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    Pending,
    Sending,
    Success,
    Failed,
    Retrying,
}

/// Webhook Delivery Record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub alert_id: String,
    pub webhook_url: String,
    pub status: DeliveryStatus,
    pub attempt: u32,
    pub sent_at: Option<String>,
    pub error: Option<String>,
}

impl WebhookDelivery {
    pub fn new(alert_id: &str, webhook_url: &str) -> Self {
        Self {
            alert_id: alert_id.to_string(),
            webhook_url: webhook_url.to_string(),
            status: DeliveryStatus::Pending,
            attempt: 0,
            sent_at: None,
            error: None,
        }
    }

    pub fn mark_sending(&mut self) {
        self.status = DeliveryStatus::Sending;
        self.attempt += 1;
    }

    pub fn mark_success(&mut self) {
        self.status = DeliveryStatus::Success;
        self.sent_at = Some(chrono::Utc::now().to_rfc3339());
        self.error = None;
    }

    pub fn mark_failed(&mut self, error: &str) {
        self.status = DeliveryStatus::Failed;
        self.error = Some(error.to_string());
    }

    pub fn mark_retrying(&mut self) {
        self.status = DeliveryStatus::Retrying;
    }
}

/// Webhook Delivery Manager (handles retry logic)
pub struct WebhookDeliveryManager {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookDeliveryManager {
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    pub async fn send(&self, alert: &WebhookAlert) -> Result<()> {
        if !self.config.enabled {
            return Err(anyhow!("Webhook is disabled"));
        }

        let payload = self.format_payload(alert)?;
        let mut last_error = None;

        for attempt in 1..=self.config.retry_attempts {
            match self.send_with_timeout(&payload).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    last_error = Some(format!("Attempt {}: {}", attempt, e));
                    if attempt < self.config.retry_attempts {
                        let backoff = self.config.retry_backoff_ms * (2_u64.pow(attempt - 1));
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                    }
                }
            }
        }

        Err(anyhow!(
            "Webhook delivery failed after {} attempts: {}",
            self.config.retry_attempts,
            last_error.unwrap_or_default()
        ))
    }

    async fn send_with_timeout(&self, payload: &str) -> Result<()> {
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let future = self
            .client
            .post(&self.config.url)
            .json(&serde_json::from_str::<serde_json::Value>(payload)?)
            .send();

        match tokio::time::timeout(timeout, future).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(anyhow!("Webhook returned status: {}", response.status()))
                }
            }
            Ok(Err(e)) => Err(anyhow!("Request failed: {}", e)),
            Err(_) => Err(anyhow!(
                "Request timeout after {} seconds",
                self.config.timeout_secs
            )),
        }
    }

    fn format_payload(&self, alert: &WebhookAlert) -> Result<String> {
        match self.config.provider {
            WebhookProvider::Generic => self.format_generic(alert),
            WebhookProvider::Slack => self.format_slack(alert),
            WebhookProvider::Discord => self.format_discord(alert),
            WebhookProvider::MatterMost => self.format_mattermost(alert),
        }
    }

    fn format_generic(&self, alert: &WebhookAlert) -> Result<String> {
        serde_json::to_string(alert).map_err(|e| anyhow!("Failed to format alert: {}", e))
    }

    fn format_slack(&self, alert: &WebhookAlert) -> Result<String> {
        let mut fields = vec![
            json!({"title": "Affected", "value": alert.affected_summary(), "short": true}),
            json!({"title": "Time", "value": alert.timestamp.clone(), "short": true}),
            json!({"title": "What to do", "value": alert.remediation.clone().unwrap_or_else(|| "See the scan report".to_string()), "short": false}),
        ];
        // Only when there is one. An empty CVE row teaches the reader to
        // ignore the field.
        if let Some(cve) = &alert.cve_id {
            fields.insert(0, json!({"title": "CVE", "value": cve, "short": true}));
        }
        if let Some(score) = alert.cvss_score {
            fields.insert(
                1,
                json!({"title": "CVSS Score", "value": format!("{score:.1}"), "short": true}),
            );
        }

        let payload = serde_json::json!({
            "text": format!("{} {}", self.severity_mark(&alert.severity), alert.title),
            "attachments": [{
                "color": self.severity_color(&alert.severity),
                "text": alert.description.clone(),
                "fields": fields,
            }]
        });
        serde_json::to_string(&payload)
            .map_err(|e| anyhow!("Failed to format Slack message: {}", e))
    }

    fn format_discord(&self, alert: &WebhookAlert) -> Result<String> {
        let mut fields = vec![
            json!({"name": "Affected", "value": alert.affected_summary(), "inline": true}),
            json!({"name": "What to do", "value": alert.remediation.clone().unwrap_or_else(|| "See the scan report".to_string()), "inline": false}),
            json!({"name": "Time", "value": alert.timestamp.clone(), "inline": false}),
        ];
        if let Some(cve) = &alert.cve_id {
            fields.insert(0, json!({"name": "CVE", "value": cve, "inline": true}));
        }
        if let Some(score) = alert.cvss_score {
            fields.insert(
                1,
                json!({"name": "CVSS Score", "value": format!("{score:.1}"), "inline": true}),
            );
        }

        let payload = serde_json::json!({
            "content": format!("{} {}", self.severity_mark(&alert.severity), alert.title),
            "embeds": [{
                "title": alert.title.clone(),
                "description": alert.description.clone(),
                "color": self.severity_color_decimal(&alert.severity),
                "fields": fields,
            }]
        });
        serde_json::to_string(&payload)
            .map_err(|e| anyhow!("Failed to format Discord message: {}", e))
    }

    fn format_mattermost(&self, alert: &WebhookAlert) -> Result<String> {
        let mut fields = vec![
            json!({"title": "Affected", "value": alert.affected_summary(), "short": true}),
            json!({"title": "What to do", "value": alert.remediation.clone().unwrap_or_else(|| "See the scan report".to_string()), "short": false}),
        ];
        if let Some(cve) = &alert.cve_id {
            fields.insert(0, json!({"title": "CVE", "value": cve, "short": true}));
        }

        let payload = serde_json::json!({
            "text": format!("{} {}", self.severity_mark(&alert.severity), alert.title),
            "attachments": [{
                "color": self.severity_color(&alert.severity),
                "text": alert.description.clone(),
                "fields": fields,
            }]
        });
        serde_json::to_string(&payload)
            .map_err(|e| anyhow!("Failed to format Mattermost message: {}", e))
    }

    /// The mark that goes in front of the headline. Text rather than an emoji
    /// for the severities that matter, so the message still reads in a client
    /// that strips them.
    fn severity_mark(&self, severity: &str) -> &'static str {
        match severity {
            "Critical" => "🚨 CRITICAL:",
            "High" => "🟠 HIGH:",
            "Medium" => "🟡 MEDIUM:",
            _ => "ℹ️ INFO:",
        }
    }

    fn severity_color(&self, severity: &str) -> &'static str {
        match severity {
            "Critical" => "#FF0000",
            "High" => "#FF6600",
            "Medium" => "#FFCC00",
            "Low" => "#0099FF",
            _ => "#999999",
        }
    }

    fn severity_color_decimal(&self, severity: &str) -> u32 {
        match severity {
            "Critical" => 16711680, // Red
            "High" => 16737792,     // Orange
            "Medium" => 16776960,   // Yellow
            "Low" => 39423,         // Blue
            _ => 10066329,          // Gray
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Most of what this scanner finds is not a vulnerability with a
    /// catalogue entry, and the alert must not pretend otherwise.
    #[test]
    fn test_a_finding_that_is_not_a_cve_carries_no_cve_fields() {
        let alert = WebhookAlert::new(
            "High",
            "File sharing is switched on for 2 computers",
            "SMB is reachable on two machines.",
        )
        .affecting(&["192.168.1.10".to_string(), "192.168.1.11".to_string()]);

        assert_eq!(alert.severity, "High");
        assert!(alert.cve_id.is_none());
        assert!(alert.cvss_score.is_none());
        assert_eq!(alert.affected_summary(), "192.168.1.10 (+1 more)");

        let manager = WebhookDeliveryManager::new(WebhookConfig::new("https://example.test"));
        let payload = manager.format_payload(&alert).expect("payload");
        assert!(
            !payload.contains("CVE"),
            "no empty CVE row should be rendered: {payload}"
        );
        assert!(payload.contains("File sharing"));
    }

    #[test]
    fn test_a_cve_alert_carries_its_reference() {
        let alert = WebhookAlert::for_cve("Critical", "CVE-2021-44228", 10.0, "Log4Shell");

        assert_eq!(alert.cve_id.as_deref(), Some("CVE-2021-44228"));
        assert_eq!(alert.cvss_score, Some(10.0));
        assert!(alert
            .reference_url
            .as_deref()
            .is_some_and(|url| url.ends_with("CVE-2021-44228")));

        // The identifier is stable for the same vulnerability, so a receiver
        // can tell a repeat from a new alert.
        let again = WebhookAlert::for_cve("Critical", "CVE-2021-44228", 10.0, "Log4Shell");
        assert_eq!(alert.alert_id, again.alert_id);
    }

    #[test]
    fn test_webhook_alert_builder() {
        let alert = WebhookAlert::new("High", "SSH is exposed", "Port 22 is reachable.")
            .affecting(&["192.168.1.50".to_string()])
            .with_service("OpenSSH")
            .with_remediation("Restrict it to machines that need it.");

        assert_eq!(alert.affected_service.as_deref(), Some("OpenSSH"));
        assert!(alert.remediation.is_some());
        assert_eq!(alert.affected_summary(), "192.168.1.50");
    }

    #[test]
    fn test_webhook_config() {
        let config = WebhookConfig::new("https://hooks.slack.com/services/xxx")
            .with_provider(WebhookProvider::Slack)
            .with_timeout(10)
            .with_retry(5, 2000);

        assert_eq!(config.provider, WebhookProvider::Slack);
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.retry_attempts, 5);
    }

    #[test]
    fn test_webhook_delivery_status_transitions() {
        let mut delivery = WebhookDelivery::new("alert-1", "https://test.com/webhook");
        assert_eq!(delivery.status, DeliveryStatus::Pending);

        delivery.mark_sending();
        assert_eq!(delivery.status, DeliveryStatus::Sending);
        assert_eq!(delivery.attempt, 1);

        delivery.mark_success();
        assert_eq!(delivery.status, DeliveryStatus::Success);
        assert!(delivery.sent_at.is_some());
        assert!(delivery.error.is_none());
    }

    #[test]
    fn test_webhook_delivery_failure() {
        let mut delivery = WebhookDelivery::new("alert-1", "https://test.com/webhook");
        delivery.mark_sending();
        delivery.mark_failed("Connection timeout");

        assert_eq!(delivery.status, DeliveryStatus::Failed);
        assert!(delivery.error.is_some());
    }

    #[test]
    fn test_webhook_manager_payload_formatting() {
        let config =
            WebhookConfig::new("https://test.com/webhook").with_provider(WebhookProvider::Generic);
        let manager = WebhookDeliveryManager::new(config);
        let alert = WebhookAlert::for_cve("Critical", "CVE-2021-44228", 9.8, "Log4Shell")
            .affecting(&["192.168.1.1".to_string()]);

        let payload = manager.format_generic(&alert).unwrap();
        assert!(payload.contains("CVE-2021-44228"));
        assert!(payload.contains("9.8"));
        assert!(payload.contains("192.168.1.1"));
    }

    /// Every provider has to render an alert that came from a plain finding,
    /// because that is most of them.
    #[test]
    fn test_every_provider_renders_an_alert_without_a_cve() {
        let alert = WebhookAlert::new(
            "High",
            "File sharing is switched on",
            "SMB is reachable on one computer.",
        )
        .affecting(&["192.168.1.10".to_string()]);

        // The generic payload is JSON for another program, where a null field
        // is an honest "not set".
        let generic = WebhookDeliveryManager::new(WebhookConfig::new("https://example.test"));
        let parsed: serde_json::Value =
            serde_json::from_str(&generic.format_payload(&alert).expect("generic payload"))
                .expect("valid json");
        assert_eq!(parsed["title"], "File sharing is switched on");
        assert!(parsed["cve_id"].is_null());

        // The chat providers render text for a person, where a literal "null"
        // would be a bug rather than a value.
        for provider in [
            WebhookProvider::Slack,
            WebhookProvider::Discord,
            WebhookProvider::MatterMost,
        ] {
            let manager = WebhookDeliveryManager::new(
                WebhookConfig::new("https://example.test").with_provider(provider),
            );
            let payload = manager
                .format_payload(&alert)
                .unwrap_or_else(|error| panic!("{provider:?} failed: {error}"));

            assert!(payload.contains("File sharing"), "{provider:?}: {payload}");
            assert!(
                !payload.contains("null"),
                "{provider:?} rendered an absent field: {payload}"
            );
            assert!(
                !payload.contains("CVE"),
                "{provider:?} showed a CVE row for a finding with no CVE: {payload}"
            );
        }
    }
}
