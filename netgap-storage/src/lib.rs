//! Scan result persistence and historical analysis.
//!
//! This module provides SQLite-backed storage for scan results with support for:
//! - Persistent scan history with timestamps
//! - Device and finding queries
//! - Scan comparison (diff between consecutive scans)
//! - Export to various formats

use netgap_core::{ScanResult, Severity};
use anyhow::{anyhow, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

/// Scan store backed by SQLite
pub struct ScanStore {
    conn: Connection,
}

impl ScanStore {
    /// Create or open scan database at default location
    pub fn default() -> Result<Self> {
        let db_path = Self::default_db_path()?;
        Self::open(&db_path)
    }

    /// Open or create database at specified path
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let store = ScanStore { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Get default database path (~/.config/netgap/scans.db)
    fn default_db_path() -> Result<PathBuf> {
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"))?;
        Ok(PathBuf::from(home)
            .join(".config/netgap")
            .join("scans.db"))
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                interface TEXT NOT NULL,
                target TEXT NOT NULL,
                device_count INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT,
                vendor TEXT,
                os TEXT,
                hostname TEXT,
                open_ports TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id),
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );

            CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
        )?;

        Ok(())
    }

    /// Save a scan result to the database
    pub fn save_scan(&mut self, result: &ScanResult) -> Result<String> {
        let scan_id = format!("scan-{}", chrono::Utc::now().timestamp_millis());
        let now = Utc::now().to_rfc3339();

        let mut stmt = self.conn.prepare(
            "INSERT INTO scans (id, started_at, interface, target, device_count, finding_count, critical_count, high_count, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )?;

        let mut critical_count = 0;
        let mut high_count = 0;
        for device in &result.devices {
            for finding in &device.findings {
                match finding.severity {
                    Severity::Critical => critical_count += 1,
                    Severity::High => high_count += 1,
                    _ => {}
                }
            }
        }

        stmt.execute(params![
            &scan_id,
            &result.started_at,
            &result.config.interface,
            &result.config.target,
            result.devices.len(),
            result.summary.total(),
            critical_count,
            high_count,
            now
        ])?;

        // Save devices and findings
        for device in &result.devices {
            let device_id = format!("{}-{}", scan_id, device.ip);
            let open_ports = device
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");

            let mut device_stmt = self.conn.prepare(
                "INSERT INTO devices (id, scan_id, ip, mac, vendor, os, hostname, open_ports, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?;

            device_stmt.execute(params![
                &device_id,
                &scan_id,
                device.ip.to_string(),
                device.mac.clone(),
                device.vendor.clone(),
                device.os.to_string(),
                device.hostname.clone(),
                open_ports,
                now
            ])?;

            // Save findings for this device
            for finding in &device.findings {
                let finding_id = format!("{}-{}", device_id, finding.id);
                let mut finding_stmt = self.conn.prepare(
                    "INSERT INTO findings (id, scan_id, device_id, title, severity, port, service, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                )?;

                finding_stmt.execute(params![
                    &finding_id,
                    &scan_id,
                    &device_id,
                    &finding.title,
                    finding.severity.to_string(),
                    finding.port,
                    &finding.service,
                    now
                ])?;
            }
        }

        Ok(scan_id)
    }

    /// Load scan metadata by ID
    pub fn load_scan_metadata(&self, scan_id: &str) -> Result<Option<ScanMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT started_at, interface, target, device_count, finding_count, critical_count, high_count, created_at
             FROM scans WHERE id = ?",
        )?;

        let metadata = stmt
            .query_row(params![scan_id], |row| {
                Ok(ScanMetadata {
                    id: scan_id.to_string(),
                    started_at: row.get(0)?,
                    interface: row.get(1)?,
                    target: row.get(2)?,
                    device_count: row.get(3)?,
                    finding_count: row.get(4)?,
                    critical_count: row.get(5)?,
                    high_count: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })
            .optional()?;

        Ok(metadata)
    }

    /// List all scans
    pub fn list_scans(&self) -> Result<Vec<ScanMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, interface, target, device_count, finding_count, critical_count, high_count, created_at
             FROM scans ORDER BY created_at DESC",
        )?;

        let scans = stmt
            .query_map([], |row| {
                Ok(ScanMetadata {
                    id: row.get(0)?,
                    started_at: row.get(1)?,
                    interface: row.get(2)?,
                    target: row.get(3)?,
                    device_count: row.get(4)?,
                    finding_count: row.get(5)?,
                    critical_count: row.get(6)?,
                    high_count: row.get(7)?,
                    created_at: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(scans)
    }

    /// Get critical findings across all scans
    pub fn get_critical_findings(&self) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT f.title, d.ip, f.port FROM findings f
             JOIN devices d ON f.device_id = d.id
             WHERE f.severity = 'CRITICAL'
             ORDER BY f.created_at DESC LIMIT 50",
        )?;

        let findings = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i32>>(2)?.map(|p| p.to_string()).unwrap_or_default(),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(findings)
    }

    /// Export findings to CSV format
    pub fn export_csv(&self, scan_id: &str) -> Result<String> {
        let mut csv = String::from("IP,Port,Service,Severity,Title\n");

        let mut stmt = self.conn.prepare(
            "SELECT d.ip, f.port, f.service, f.severity, f.title
             FROM findings f
             JOIN devices d ON f.device_id = d.id
             WHERE f.scan_id = ?
             ORDER BY f.severity DESC",
        )?;

        stmt.query_map(params![scan_id], |row| {
            let ip: String = row.get(0)?;
            let port: Option<i32> = row.get(1)?;
            let service: Option<String> = row.get(2)?;
            let severity: String = row.get(3)?;
            let title: String = row.get(4)?;

            let port_str = port.map(|p| p.to_string()).unwrap_or_default();
            let service_str = service.unwrap_or_default();
            csv.push_str(&format!(
                "{},{},{},{},{}\n",
                ip, port_str, service_str, severity, title
            ));

            Ok(())
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(csv)
    }

    /// Export findings to Markdown format
    pub fn export_markdown(&self, scan_id: &str) -> Result<String> {
        let metadata = self.load_scan_metadata(scan_id)?
            .ok_or(anyhow!("Scan not found: {}", scan_id))?;

        let mut md = String::new();
        md.push_str(&format!("# Network Security Scan Report\n\n"));
        md.push_str(&format!("**Scan ID:** {}\n", metadata.id));
        md.push_str(&format!("**Date:** {}\n", metadata.created_at));
        md.push_str(&format!("**Interface:** {}\n", metadata.interface));
        md.push_str(&format!("**Target:** {}\n", metadata.target));
        md.push_str(&format!("**Devices Found:** {}\n", metadata.device_count));
        md.push_str(&format!("**Total Findings:** {}\n\n", metadata.finding_count));

        // Severity summary
        md.push_str("## Summary by Severity\n\n");
        md.push_str(&format!("- 🔴 **Critical:** {}\n", metadata.critical_count));
        md.push_str(&format!("- 🟠 **High:** {}\n\n", metadata.high_count));

        // Findings by device
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT d.ip, COUNT(f.id) as count
             FROM devices d
             LEFT JOIN findings f ON d.id = f.device_id AND f.scan_id = ?
             WHERE d.scan_id = ?
             GROUP BY d.id
             ORDER BY count DESC, d.ip"
        )?;

        let devices = stmt.query_map(params![scan_id, scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

        if !devices.is_empty() {
            md.push_str("## Findings by Device\n\n");
            
            for (ip, count) in devices {
                md.push_str(&format!("### {} ({} findings)\n\n", ip, count));

                let mut findings_stmt = self.conn.prepare(
                    "SELECT f.title, f.severity, f.description, f.remediation
                     FROM findings f
                     JOIN devices d ON f.device_id = d.id
                     WHERE f.scan_id = ? AND d.ip = ?
                     ORDER BY 
                       CASE f.severity
                         WHEN 'CRITICAL' THEN 1
                         WHEN 'HIGH' THEN 2
                         WHEN 'MEDIUM' THEN 3
                         ELSE 4
                       END"
                )?;

                let findings = findings_stmt.query_map(params![scan_id, ip], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;

                for (title, severity, desc, remediation) in findings {
                    let emoji = match severity.as_str() {
                        "CRITICAL" => "🔴",
                        "HIGH" => "🟠",
                        "MEDIUM" => "🟡",
                        _ => "ℹ️",
                    };
                    md.push_str(&format!("{} **[{}] {}**\n", emoji, severity, title));
                    if let Some(d) = desc {
                        md.push_str(&format!("- Description: {}\n", d));
                    }
                    if let Some(r) = remediation {
                        md.push_str(&format!("- Remediation: {}\n", r));
                    }
                    md.push_str("\n");
                }
            }
        }

        Ok(md)
    }

    /// Export findings to HTML format
    pub fn export_html(&self, scan_id: &str) -> Result<String> {
        let metadata = self.load_scan_metadata(scan_id)?
            .ok_or(anyhow!("Scan not found: {}", scan_id))?;

        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<meta charset='utf-8'>\n");
        html.push_str("<meta name='viewport' content='width=device-width'>\n");
        html.push_str("<title>Network Scan Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2em; background: #f5f5f5; }\n");
        html.push_str(".container { max-width: 900px; margin: 0 auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html.push_str("h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 0.5em; }\n");
        html.push_str("h2 { color: #555; margin-top: 1.5em; }\n");
        html.push_str(".metadata { background: #f9f9f9; padding: 1em; border-radius: 4px; margin-bottom: 1.5em; }\n");
        html.push_str(".metadata-item { margin: 0.5em 0; }\n");
        html.push_str(".summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1em; margin-bottom: 2em; }\n");
        html.push_str(".summary-box { background: #f0f8ff; padding: 1em; border-radius: 4px; border-left: 4px solid; text-align: center; }\n");
        html.push_str(".summary-box.critical { border-color: #dc3545; background: #fff5f5; }\n");
        html.push_str(".summary-box.high { border-color: #fd7e14; background: #fff9f5; }\n");
        html.push_str(".summary-box.medium { border-color: #ffc107; background: #fffbf0; }\n");
        html.push_str(".summary-box.info { border-color: #17a2b8; background: #f0f9fb; }\n");
        html.push_str(".finding { margin-bottom: 1.5em; padding: 1em; border-left: 4px solid; border-radius: 4px; background: #fafafa; }\n");
        html.push_str(".finding.critical { border-color: #dc3545; background: #fff5f5; }\n");
        html.push_str(".finding.high { border-color: #fd7e14; background: #fff9f5; }\n");
        html.push_str(".finding.medium { border-color: #ffc107; background: #fffbf0; }\n");
        html.push_str(".finding.info { border-color: #17a2b8; background: #f0f9fb; }\n");
        html.push_str(".finding-title { font-weight: bold; margin: 0.5em 0; }\n");
        html.push_str(".finding-detail { margin: 0.25em 0; font-size: 0.95em; }\n");
        html.push_str(".device-section { margin-top: 2em; }\n");
        html.push_str("</style>\n</head>\n<body>\n");

        html.push_str("<div class='container'>\n");
        html.push_str(&format!("<h1>🔍 Network Security Scan Report</h1>\n"));

        // Metadata
        html.push_str("<div class='metadata'>\n");
        html.push_str(&format!("<div class='metadata-item'><strong>Scan ID:</strong> {}</div>\n", metadata.id));
        html.push_str(&format!("<div class='metadata-item'><strong>Date:</strong> {}</div>\n", metadata.created_at));
        html.push_str(&format!("<div class='metadata-item'><strong>Interface:</strong> {}</div>\n", metadata.interface));
        html.push_str(&format!("<div class='metadata-item'><strong>Target:</strong> {}</div>\n", metadata.target));
        html.push_str("</div>\n");

        // Summary boxes
        html.push_str("<div class='summary'>\n");
        html.push_str(&format!("<div class='summary-box critical'><div style='font-size: 2em'>🔴</div><div>{}</div><div style='font-size: 0.9em'>Critical</div></div>\n", metadata.critical_count));
        html.push_str(&format!("<div class='summary-box high'><div style='font-size: 2em'>🟠</div><div>{}</div><div style='font-size: 0.9em'>High</div></div>\n", metadata.high_count));
        html.push_str(&format!("<div class='summary-box info'><div style='font-size: 2em'>📱</div><div>{}</div><div style='font-size: 0.9em'>Devices</div></div>\n", metadata.device_count));
        html.push_str(&format!("<div class='summary-box info'><div style='font-size: 2em'>📋</div><div>{}</div><div style='font-size: 0.9em'>Total Findings</div></div>\n", metadata.finding_count));
        html.push_str("</div>\n");

        // Findings by device
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT d.ip, COUNT(f.id) as count
             FROM devices d
             LEFT JOIN findings f ON d.id = f.device_id AND f.scan_id = ?
             WHERE d.scan_id = ?
             GROUP BY d.id
             ORDER BY count DESC, d.ip"
        )?;

        let devices = stmt.query_map(params![scan_id, scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

        if !devices.is_empty() {
            html.push_str("<h2>Findings by Device</h2>\n");
            
            for (ip, count) in devices {
                html.push_str(&format!("<div class='device-section'><h3>{} ({} findings)</h3>\n", ip, count));

                let mut findings_stmt = self.conn.prepare(
                    "SELECT f.title, f.severity, f.description, f.remediation
                     FROM findings f
                     JOIN devices d ON f.device_id = d.id
                     WHERE f.scan_id = ? AND d.ip = ?
                     ORDER BY 
                       CASE f.severity
                         WHEN 'CRITICAL' THEN 1
                         WHEN 'HIGH' THEN 2
                         WHEN 'MEDIUM' THEN 3
                         ELSE 4
                       END"
                )?;

                let findings = findings_stmt.query_map(params![scan_id, ip], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;

                for (title, severity, desc, remediation) in findings {
                    let severity_class = severity.to_lowercase();
                    html.push_str(&format!("<div class='finding {}'>\n", severity_class));
                    html.push_str(&format!("<div class='finding-title'>[{}] {}</div>\n", severity, title));
                    if let Some(d) = desc {
                        html.push_str(&format!("<div class='finding-detail'><strong>Details:</strong> {}</div>\n", d));
                    }
                    if let Some(r) = remediation {
                        html.push_str(&format!("<div class='finding-detail'><strong>Remediation:</strong> {}</div>\n", r));
                    }
                    html.push_str("</div>\n");
                }
                html.push_str("</div>\n");
            }
        }

        html.push_str("</div>\n");
        html.push_str("</body>\n</html>\n");
        Ok(html)
    }

    /// Compare two scans and return differences
    pub fn compare_scans(&self, scan1_id: &str, scan2_id: &str) -> Result<ScanComparison> {
        let metadata1 = self.load_scan_metadata(scan1_id)?
            .ok_or(anyhow!("Scan not found: {}", scan1_id))?;
        let metadata2 = self.load_scan_metadata(scan2_id)?
            .ok_or(anyhow!("Scan not found: {}", scan2_id))?;

        // New devices in scan2
        let mut stmt = self.conn.prepare(
            "SELECT d.ip FROM devices d
             WHERE d.scan_id = ?
             AND d.ip NOT IN (SELECT ip FROM devices WHERE scan_id = ?)"
        )?;
        let new_devices = stmt.query_map(params![scan2_id, scan1_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;

        // Removed devices
        let mut stmt = self.conn.prepare(
            "SELECT d.ip FROM devices d
             WHERE d.scan_id = ?
             AND d.ip NOT IN (SELECT ip FROM devices WHERE scan_id = ?)"
        )?;
        let removed_devices = stmt.query_map(params![scan1_id, scan2_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;

        // New critical findings
        let mut stmt = self.conn.prepare(
            "SELECT f.title, d.ip FROM findings f
             JOIN devices d ON f.device_id = d.id
             WHERE f.scan_id = ?
             AND f.severity = 'CRITICAL'"
        )?;
        let new_critical = stmt.query_map(params![scan2_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

        // Resolved critical findings
        let mut stmt = self.conn.prepare(
            "SELECT f.title, d.ip FROM findings f
             JOIN devices d ON f.device_id = d.id
             WHERE f.scan_id = ?
             AND f.severity = 'CRITICAL'
             AND f.title NOT IN (
               SELECT title FROM findings WHERE scan_id = ? AND severity = 'CRITICAL'
             )"
        )?;
        let resolved_findings = stmt.query_map(params![scan1_id, scan2_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(ScanComparison {
            scan1_id: metadata1.id,
            scan1_date: metadata1.created_at,
            scan2_id: metadata2.id,
            scan2_date: metadata2.created_at,
            new_devices,
            removed_devices,
            new_critical,
            resolved_findings,
        })
    }
}

/// Metadata about a stored scan
#[derive(Debug, Clone)]
pub struct ScanMetadata {
    pub id: String,
    pub started_at: String,
    pub interface: String,
    pub target: String,
    pub device_count: i32,
    pub finding_count: i32,
    pub critical_count: i32,
    pub high_count: i32,
    pub created_at: String,
}

/// Comparison between two scans
#[derive(Debug, Clone)]
pub struct ScanComparison {
    pub scan1_id: String,
    pub scan1_date: String,
    pub scan2_id: String,
    pub scan2_date: String,
    pub new_devices: Vec<String>,
    pub removed_devices: Vec<String>,
    pub new_critical: Vec<(String, String)>,  // (finding_title, ip)
    pub resolved_findings: Vec<(String, String)>,  // (finding_title, ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_store_creation() {
        let result = ScanStore::open(Path::new(":memory:"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_scan_metadata_parsing() {
        let metadata = ScanMetadata {
            id: "scan-001".to_string(),
            started_at: Utc::now().to_rfc3339(),
            interface: "eth0".to_string(),
            target: "192.168.1.0/24".to_string(),
            device_count: 10,
            finding_count: 5,
            critical_count: 1,
            high_count: 2,
            created_at: Utc::now().to_rfc3339(),
        };

        assert_eq!(metadata.critical_count, 1);
        assert!(metadata.device_count > 0);
    }
}
