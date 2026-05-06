use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use anyhow::{anyhow, Result};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAlert {
    pub alert_id: String,
    pub severity: String,              // Critical, High, Medium, Low, Info
    pub cvss_score: f32,               // 0.0-10.0
    pub cve_id: String,                // CVE-2021-44228
    pub description: String,
    pub affected_ip: String,
    pub affected_service: Option<String>,
    pub timestamp: String,             // ISO8601
    pub remediation: Option<String>,
    pub reference_url: Option<String>,
}

impl WebhookAlert {
    pub fn new(
        severity: &str,
        cvss_score: f32,
        cve_id: &str,
        description: &str,
        affected_ip: &str,
    ) -> Self {
        Self {
            alert_id: format!("{}-{}", cve_id, affected_ip),
            severity: severity.to_string(),
            cvss_score,
            cve_id: cve_id.to_string(),
            description: description.to_string(),
            affected_ip: affected_ip.to_string(),
            affected_service: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            remediation: None,
            reference_url: None,
        }
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
            match self
                .send_with_timeout(&payload)
                .await
            {
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
        let future = self.client.post(&self.config.url).json(&serde_json::from_str::<serde_json::Value>(payload)?).send();

        match tokio::time::timeout(timeout, future).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "Webhook returned status: {}",
                        response.status()
                    ))
                }
            }
            Ok(Err(e)) => Err(anyhow!("Request failed: {}", e)),
            Err(_) => Err(anyhow!("Request timeout after {} seconds", self.config.timeout_secs)),
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
        let payload = serde_json::json!({
            "text": format!("🚨 {} Security Alert", alert.severity),
            "attachments": [{
                "color": self.severity_color(&alert.severity),
                "fields": [
                    {"title": "CVE", "value": alert.cve_id, "short": true},
                    {"title": "CVSS Score", "value": alert.cvss_score.to_string(), "short": true},
                    {"title": "Affected IP", "value": alert.affected_ip, "short": true},
                    {"title": "Service", "value": alert.affected_service.clone().unwrap_or_else(|| "Unknown".to_string()), "short": true},
                    {"title": "Description", "value": alert.description.clone(), "short": false},
                    {"title": "Remediation", "value": alert.remediation.clone().unwrap_or_else(|| "See reference URL".to_string()), "short": false},
                    {"title": "Reference", "value": alert.reference_url.clone().unwrap_or_else(|| "N/A".to_string()), "short": false},
                    {"title": "Time", "value": alert.timestamp.clone(), "short": false},
                ]
            }]
        });
        serde_json::to_string(&payload).map_err(|e| anyhow!("Failed to format Slack message: {}", e))
    }

    fn format_discord(&self, alert: &WebhookAlert) -> Result<String> {
        let payload = serde_json::json!({
            "content": format!("🚨 {} Security Alert", alert.severity),
            "embeds": [{
                "title": alert.cve_id.clone(),
                "description": alert.description.clone(),
                "color": self.severity_color_decimal(&alert.severity),
                "fields": [
                    {"name": "CVSS Score", "value": alert.cvss_score.to_string(), "inline": true},
                    {"name": "Affected IP", "value": alert.affected_ip.clone(), "inline": true},
                    {"name": "Service", "value": alert.affected_service.clone().unwrap_or_else(|| "Unknown".to_string()), "inline": true},
                    {"name": "Remediation", "value": alert.remediation.clone().unwrap_or_else(|| "See reference".to_string()), "inline": false},
                ]
            }]
        });
        serde_json::to_string(&payload).map_err(|e| anyhow!("Failed to format Discord message: {}", e))
    }

    fn format_mattermost(&self, alert: &WebhookAlert) -> Result<String> {
        let payload = serde_json::json!({
            "text": format!("🚨 {} Security Alert: {}", alert.severity, alert.cve_id),
            "attachments": [{
                "color": self.severity_color(&alert.severity),
                "text": alert.description.clone(),
                "fields": [
                    {"title": "CVSS Score", "value": alert.cvss_score.to_string(), "short": true},
                    {"title": "Affected IP", "value": alert.affected_ip.clone(), "short": true},
                    {"title": "Service", "value": alert.affected_service.clone().unwrap_or_else(|| "Unknown".to_string()), "short": true},
                    {"title": "Remediation", "value": alert.remediation.clone().unwrap_or_else(|| "See reference".to_string()), "short": false},
                ]
            }]
        });
        serde_json::to_string(&payload).map_err(|e| anyhow!("Failed to format Mattermost message: {}", e))
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
            "Critical" => 16711680,  // Red
            "High" => 16737792,      // Orange
            "Medium" => 16776960,    // Yellow
            "Low" => 39423,          // Blue
            _ => 10066329,           // Gray
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_alert_creation() {
        let alert = WebhookAlert::new("Critical", 9.8, "CVE-2021-44228", "Log4j RCE", "192.168.1.100");
        assert_eq!(alert.severity, "Critical");
        assert_eq!(alert.cvss_score, 9.8);
        assert_eq!(alert.cve_id, "CVE-2021-44228");
    }

    #[test]
    fn test_webhook_alert_builder() {
        let alert = WebhookAlert::new("High", 7.5, "CVE-2023-01234", "SSH weakness", "192.168.1.50")
            .with_service("OpenSSH")
            .with_remediation("Update to latest version")
            .with_reference("https://nvd.nist.gov/vuln/detail/CVE-2023-01234");

        assert_eq!(alert.affected_service.unwrap(), "OpenSSH");
        assert!(alert.remediation.is_some());
        assert!(alert.reference_url.is_some());
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
        let config = WebhookConfig::new("https://test.com/webhook").with_provider(WebhookProvider::Generic);
        let manager = WebhookDeliveryManager::new(config);
        let alert = WebhookAlert::new("Critical", 9.8, "CVE-2021-44228", "Test", "192.168.1.1");

        let payload = manager.format_generic(&alert).unwrap();
        assert!(payload.contains("CVE-2021-44228"));
        assert!(payload.contains("9.8"));
    }
}
