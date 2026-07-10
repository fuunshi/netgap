//! Scan result persistence and historical analysis.
//!
//! This module provides SQLite-backed storage for scan results with support for:
//! - Persistent scan history with timestamps
//! - Device and finding queries
//! - Scan comparison (diff between consecutive scans)
//! - Export to various formats

use anyhow::{anyhow, Result};
use chrono::Utc;
use netgap_core::{
    html::escape, Device, Finding, FindingSummary, OsType, ScanConfig, ScanResult, Severity,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Scan store backed by SQLite
pub struct ScanStore {
    conn: Connection,
}

impl ScanStore {
    /// Create or open the scan database at its default location
    /// (`~/.config/netgap/scans.db`, or `$NETGAP_CONFIG_DIR/scans.db`).
    pub fn open_default() -> Result<Self> {
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

    /// Get default database path (~/.config/netgap/scans.db).
    ///
    /// Honours `NETGAP_CONFIG_DIR`, which keeps tests off the real database.
    fn default_db_path() -> Result<PathBuf> {
        netgap_core::paths::scans_db_path()
            .ok_or_else(|| anyhow!("Could not determine the netgap config directory"))
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
                device_type TEXT,
                open_ports TEXT,
                first_seen TEXT,
                last_seen TEXT,
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
                description TEXT,
                remediation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id),
                FOREIGN KEY(device_id) REFERENCES devices(id)
            );

            -- One row per device ever seen, keyed by MAC (or IP when no MAC
            -- is known). The per-scan device rows say what was there; this
            -- table says when it first appeared, which is what lets a later
            -- scan report what it has not seen before.
            CREATE TABLE IF NOT EXISTS device_seen (
                identity TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1,
                last_ip TEXT,
                last_mac TEXT,
                last_hostname TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
        )?;

        // Databases created before these columns existed need them added in
        // place; the exports select them. A duplicate-column error just means
        // the migration already ran.
        for column in ["description", "remediation"] {
            let _ = self.conn.execute(
                &format!("ALTER TABLE findings ADD COLUMN {column} TEXT"),
                [],
            );
        }
        let _ = self
            .conn
            .execute("ALTER TABLE devices ADD COLUMN device_type TEXT", []);
        for column in ["first_seen", "last_seen", "ipv6_addresses"] {
            let _ = self
                .conn
                .execute(&format!("ALTER TABLE devices ADD COLUMN {column} TEXT"), []);
        }

        Ok(())
    }

    /// Save a scan result to the database.
    ///
    /// Also records each device in the cross-scan history, so a later scan can
    /// tell what it has not seen before.
    pub fn save_scan(&mut self, result: &ScanResult) -> Result<String> {
        let scan_id = self.unique_scan_id()?;
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

            // First sighting ever, or the one already recorded.
            let (first_seen, last_seen) = self.record_sighting(device, &now)?;

            let ipv6_addresses = device.ipv6_addresses.join(",");

            let mut device_stmt = self.conn.prepare(
                "INSERT INTO devices (id, scan_id, ip, mac, vendor, os, hostname, device_type, open_ports, first_seen, last_seen, ipv6_addresses, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?;

            device_stmt.execute(params![
                &device_id,
                &scan_id,
                device.ip.to_string(),
                device.mac.clone(),
                device.vendor.clone(),
                device.os.to_string(),
                device.hostname.clone(),
                device.device_type.clone(),
                open_ports,
                &first_seen,
                &last_seen,
                ipv6_addresses,
                now
            ])?;

            // Save findings for this device. `INSERT OR REPLACE` keeps two
            // checks that produce the same finding id from colliding.
            for finding in &device.findings {
                let finding_id = format!("{}-{}", device_id, finding.id);
                let mut finding_stmt = self.conn.prepare(
                    "INSERT OR REPLACE INTO findings
                       (id, scan_id, device_id, title, severity, port, service, description, remediation, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )?;

                finding_stmt.execute(params![
                    &finding_id,
                    &scan_id,
                    &device_id,
                    &finding.title,
                    finding.severity.to_string(),
                    finding.port,
                    &finding.service,
                    &finding.description,
                    &finding.remediation,
                    now
                ])?;
            }
        }

        Ok(scan_id)
    }

    /// Rebuild a full [`ScanResult`] from storage.
    ///
    /// Lets `netgap report` render any of the formatters against a saved scan
    /// instead of re-running one.
    pub fn load_scan(&self, scan_id: &str) -> Result<ScanResult> {
        use netgap_core::Severity as CoreSeverity;

        let metadata = self
            .load_scan_metadata(scan_id)?
            .ok_or_else(|| anyhow!("Scan not found: {}", scan_id))?;

        // Findings are stored flat; group them by device first.
        let mut findings_by_device: HashMap<String, Vec<(Finding, CoreSeverity)>> = HashMap::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT device_id, id, title, severity, port, service, description, remediation
                 FROM findings WHERE scan_id = ? ORDER BY severity DESC, title",
            )?;

            let rows = stmt.query_map(params![scan_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })?;

            for row in rows {
                let (device_id, id, title, severity, port, service, description, remediation) =
                    row?;
                let severity = severity_from_str(&severity);
                let finding = Finding {
                    id,
                    title,
                    description: description.unwrap_or_default(),
                    severity,
                    // Filled in once the owning device's address is known.
                    ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    port: port.map(|port| port as u16),
                    service,
                    remediation: remediation.unwrap_or_default(),
                    confidence: 1.0,
                };
                findings_by_device
                    .entry(device_id)
                    .or_default()
                    .push((finding, severity));
            }
        }

        let mut summary = FindingSummary::new();
        let mut devices = Vec::new();

        {
            let mut stmt = self.conn.prepare(
                "SELECT id, ip, mac, vendor, os, hostname, device_type, open_ports, first_seen, ipv6_addresses
                 FROM devices WHERE scan_id = ? ORDER BY ip",
            )?;

            let rows = stmt.query_map(params![scan_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                ))
            })?;

            for row in rows {
                let (
                    device_id,
                    ip,
                    mac,
                    vendor,
                    os,
                    hostname,
                    device_type,
                    open_ports,
                    first_seen,
                    ipv6_addresses,
                ) = row?;
                let ip: IpAddr = ip
                    .parse()
                    .map_err(|_| anyhow!("Stored device address '{}' is not valid", ip))?;

                let mut device = Device::new(ip);
                device.mac = mac;
                device.vendor = vendor;
                device.os = os_from_str(os.as_deref());
                device.hostname = hostname;
                device.device_type = device_type;
                device.first_seen = first_seen;
                device.ipv6_addresses = ipv6_addresses
                    .as_deref()
                    .unwrap_or_default()
                    .split(',')
                    .map(str::trim)
                    .filter(|address| !address.is_empty())
                    .map(str::to_string)
                    .collect();
                device.open_ports = open_ports
                    .as_deref()
                    .unwrap_or_default()
                    .split(',')
                    .filter_map(|port| port.trim().parse::<u16>().ok())
                    .collect();
                device.open_ports.sort_unstable();

                if let Some(findings) = findings_by_device.remove(&device_id) {
                    for (mut finding, severity) in findings {
                        finding.ip = ip;
                        summary.add_finding(severity);
                        device.findings.push(finding);
                    }
                }

                devices.push(device);
            }
        }

        let defaults = ScanConfig::default();

        Ok(ScanResult {
            started_at: metadata.started_at,
            config: ScanConfig {
                interface: metadata.interface,
                target: metadata.target,
                timeout_ms: defaults.timeout_ms,
                concurrency: defaults.concurrency,
                discovery_only: false,
            },
            devices,
            summary,
        })
    }

    /// An unused scan identifier.
    ///
    /// Millisecond timestamps collide when two scans are saved in the same
    /// millisecond — a scan straight after a discovery, or watch mode saving
    /// in a loop — and the second insert would fail on the primary key. A
    /// suffix is added until the identifier is free.
    fn unique_scan_id(&self) -> Result<String> {
        let base = format!("scan-{}", chrono::Utc::now().timestamp_millis());

        if !self.scan_exists(&base)? {
            return Ok(base);
        }

        for suffix in 1..1000 {
            let candidate = format!("{base}-{suffix}");
            if !self.scan_exists(&candidate)? {
                return Ok(candidate);
            }
        }

        Err(anyhow!("could not allocate a unique scan id"))
    }

    /// Whether a scan with this identifier exists.
    fn scan_exists(&self, scan_id: &str) -> Result<bool> {
        let exists: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM scans WHERE id = ?",
                params![scan_id],
                |row| row.get(0),
            )
            .optional()?;

        Ok(exists.is_some())
    }

    /// Note that a device was seen, returning when it was first and last seen.
    ///
    /// A device already in the history keeps its original `first_seen`; only
    /// the last-sighted fields move.
    fn record_sighting(&self, device: &Device, now: &str) -> Result<(String, String)> {
        let identity = device.identity();

        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT first_seen FROM device_seen WHERE identity = ?",
                params![&identity],
                |row| row.get(0),
            )
            .optional()?;

        let first_seen = existing.unwrap_or_else(|| now.to_string());

        self.conn.execute(
            "INSERT INTO device_seen (identity, first_seen, last_seen, times_seen, last_ip, last_mac, last_hostname)
             VALUES (?, ?, ?, 1, ?, ?, ?)
             ON CONFLICT(identity) DO UPDATE SET
               last_seen = excluded.last_seen,
               times_seen = times_seen + 1,
               last_ip = excluded.last_ip,
               last_mac = excluded.last_mac,
               last_hostname = excluded.last_hostname",
            params![
                &identity,
                &first_seen,
                now,
                device.ip.to_string(),
                device.mac.clone(),
                device.hostname.clone()
            ],
        )?;

        Ok((first_seen, now.to_string()))
    }

    /// Every device the store has ever seen, keyed by identity.
    pub fn device_history(&self) -> Result<HashMap<String, SeenRecord>> {
        let mut statement = self.conn.prepare(
            "SELECT identity, first_seen, last_seen, times_seen, last_ip, last_mac, last_hostname
             FROM device_seen",
        )?;

        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                SeenRecord {
                    first_seen: row.get(1)?,
                    last_seen: row.get(2)?,
                    times_seen: row.get::<_, i64>(3)?.max(0) as u32,
                    last_ip: row.get(4)?,
                    last_mac: row.get(5)?,
                    last_hostname: row.get(6)?,
                },
            ))
        })?;

        let mut history = HashMap::new();
        for row in rows {
            let (identity, record) = row?;
            history.insert(identity, record);
        }

        Ok(history)
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
                    row.get::<_, Option<i32>>(2)?
                        .map(|p| p.to_string())
                        .unwrap_or_default(),
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
        let metadata = self
            .load_scan_metadata(scan_id)?
            .ok_or(anyhow!("Scan not found: {}", scan_id))?;

        let mut md = String::new();
        md.push_str("# Network Security Scan Report\n\n");
        md.push_str(&format!("**Scan ID:** {}\n", metadata.id));
        md.push_str(&format!("**Date:** {}\n", metadata.created_at));
        md.push_str(&format!("**Interface:** {}\n", metadata.interface));
        md.push_str(&format!("**Target:** {}\n", metadata.target));
        md.push_str(&format!("**Devices Found:** {}\n", metadata.device_count));
        md.push_str(&format!(
            "**Total Findings:** {}\n\n",
            metadata.finding_count
        ));

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
             ORDER BY count DESC, d.ip",
        )?;

        let devices = stmt
            .query_map(params![scan_id, scan_id], |row| {
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
                       END",
                )?;

                let findings = findings_stmt
                    .query_map(params![scan_id, ip], |row| {
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
                    md.push('\n');
                }
            }
        }

        Ok(md)
    }

    /// Export findings to HTML format
    pub fn export_html(&self, scan_id: &str) -> Result<String> {
        let metadata = self
            .load_scan_metadata(scan_id)?
            .ok_or(anyhow!("Scan not found: {}", scan_id))?;

        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<meta charset='utf-8'>\n");
        html.push_str("<meta name='viewport' content='width=device-width'>\n");
        html.push_str("<title>Network Scan Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 2em; background: #f5f5f5; }\n");
        html.push_str(".container { max-width: 900px; margin: 0 auto; background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html.push_str(
            "h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 0.5em; }\n",
        );
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
        html.push_str("<h1>🔍 Network Security Scan Report</h1>\n");

        // Metadata
        html.push_str("<div class='metadata'>\n");
        html.push_str(&format!(
            "<div class='metadata-item'><strong>Scan ID:</strong> {}</div>\n",
            escape(&metadata.id)
        ));
        html.push_str(&format!(
            "<div class='metadata-item'><strong>Date:</strong> {}</div>\n",
            escape(&metadata.created_at)
        ));
        html.push_str(&format!(
            "<div class='metadata-item'><strong>Interface:</strong> {}</div>\n",
            escape(&metadata.interface)
        ));
        html.push_str(&format!(
            "<div class='metadata-item'><strong>Target:</strong> {}</div>\n",
            escape(&metadata.target)
        ));
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
             ORDER BY count DESC, d.ip",
        )?;

        let devices = stmt
            .query_map(params![scan_id, scan_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        if !devices.is_empty() {
            html.push_str("<h2>Findings by Device</h2>\n");

            for (ip, count) in devices {
                html.push_str(&format!(
                    "<div class='device-section'><h3>{} ({} findings)</h3>\n",
                    escape(&ip),
                    count
                ));

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
                       END",
                )?;

                let findings = findings_stmt
                    .query_map(params![scan_id, ip], |row| {
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
                    html.push_str(&format!(
                        "<div class='finding-title'>[{}] {}</div>\n",
                        escape(&severity),
                        escape(&title)
                    ));
                    if let Some(d) = desc {
                        html.push_str(&format!(
                            "<div class='finding-detail'><strong>Details:</strong> {}</div>\n",
                            escape(&d)
                        ));
                    }
                    if let Some(r) = remediation {
                        html.push_str(&format!(
                            "<div class='finding-detail'><strong>Remediation:</strong> {}</div>\n",
                            escape(&r)
                        ));
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
        let metadata1 = self
            .load_scan_metadata(scan1_id)?
            .ok_or(anyhow!("Scan not found: {}", scan1_id))?;
        let metadata2 = self
            .load_scan_metadata(scan2_id)?
            .ok_or(anyhow!("Scan not found: {}", scan2_id))?;

        // New devices in scan2
        let mut stmt = self.conn.prepare(
            "SELECT d.ip FROM devices d
             WHERE d.scan_id = ?
             AND d.ip NOT IN (SELECT ip FROM devices WHERE scan_id = ?)",
        )?;
        let new_devices = stmt
            .query_map(params![scan2_id, scan1_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;

        // Removed devices
        let mut stmt = self.conn.prepare(
            "SELECT d.ip FROM devices d
             WHERE d.scan_id = ?
             AND d.ip NOT IN (SELECT ip FROM devices WHERE scan_id = ?)",
        )?;
        let removed_devices = stmt
            .query_map(params![scan1_id, scan2_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;

        // New critical findings
        let mut stmt = self.conn.prepare(
            "SELECT f.title, d.ip FROM findings f
             JOIN devices d ON f.device_id = d.id
             WHERE f.scan_id = ?
             AND f.severity = 'CRITICAL'",
        )?;
        let new_critical = stmt
            .query_map(params![scan2_id], |row| {
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
             )",
        )?;
        let resolved_findings = stmt
            .query_map(params![scan1_id, scan2_id], |row| {
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
    pub new_critical: Vec<(String, String)>, // (finding_title, ip)
    pub resolved_findings: Vec<(String, String)>, // (finding_title, ip)
}

/// When a device was first and last seen, across every scan in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRecord {
    /// RFC 3339 timestamp of the first sighting.
    pub first_seen: String,
    /// RFC 3339 timestamp of the most recent sighting.
    pub last_seen: String,
    /// How many scans have included this device.
    pub times_seen: u32,
    pub last_ip: Option<String>,
    pub last_mac: Option<String>,
    pub last_hostname: Option<String>,
}

/// Map a stored severity string back to the core enum.
fn severity_from_str(severity: &str) -> Severity {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        _ => Severity::Info,
    }
}

/// Map a stored OS string back to the core enum.
fn os_from_str(os: Option<&str>) -> OsType {
    match os.unwrap_or_default() {
        "Windows" => OsType::Windows,
        "Linux" => OsType::Linux,
        "macOS" => OsType::MacOS,
        "iOS" => OsType::iOS,
        "Android" => OsType::Android,
        _ => OsType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_result() -> ScanResult {
        let mut device = Device::new("192.168.1.10".parse().expect("valid ip"));
        device.mac = Some("AA:BB:CC:DD:EE:FF".to_string());
        device.vendor = Some("Acme".to_string());
        device.os = OsType::Linux;
        device.hostname = Some("nas.local".to_string());
        device.device_type = Some("NAS / file server".to_string());
        device.open_ports = vec![22, 80];
        device.add_finding(Finding {
            id: "open_port_23".to_string(),
            title: "TELNET EXPOSED".to_string(),
            description: "Telnet is open in cleartext.".to_string(),
            severity: Severity::Critical,
            ip: device.ip,
            port: Some(23),
            service: Some("Telnet".to_string()),
            remediation: "Disable Telnet.".to_string(),
            confidence: 1.0,
        });

        let mut summary = FindingSummary::new();
        summary.add_finding(Severity::Critical);

        ScanResult {
            started_at: Utc::now().to_rfc3339(),
            config: ScanConfig {
                interface: "wlan0".to_string(),
                target: "192.168.1.0/24".to_string(),
                timeout_ms: 2000,
                concurrency: 32,
                discovery_only: false,
            },
            devices: vec![device],
            summary,
        }
    }

    #[test]
    fn test_scan_store_creation() {
        let result = ScanStore::open(Path::new(":memory:"));
        assert!(result.is_ok());
    }

    /// Banner text and certificate subjects reach a report straight from the
    /// device it describes, so an exported page has to treat them as text.
    #[test]
    fn test_exported_html_escapes_what_a_device_said() {
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");

        let mut result = sample_result();
        result.devices[0].hostname = Some("<script>alert('x')</script>".to_string());
        result.devices[0].findings[0].title = "<img src=x onerror=alert(1)>".to_string();
        result.devices[0].findings[0].description = "\"><svg onload=alert(2)>".to_string();

        let scan_id = store.save_scan(&result).expect("save");
        let html = store.export_html(&scan_id).expect("export");

        assert!(!html.contains("<script"), "script tag survived");
        assert!(!html.contains("<img"), "img tag survived");
        assert!(!html.contains("<svg"), "svg tag survived");
        // The finding text is rendered, so the escaped form should be there.
        assert!(
            html.contains("&lt;img src=x onerror=alert(1)&gt;"),
            "the finding should still be readable as text"
        );
    }

    #[test]
    fn test_first_scan_marks_every_device_new() {
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");
        let scan_id = store.save_scan(&sample_result()).expect("save");

        let loaded = store.load_scan(&scan_id).expect("load");
        // Nothing was seen before, so first_seen is this scan's timestamp.
        assert!(loaded.devices[0].first_seen.is_some());

        let history = store.device_history().expect("history");
        assert_eq!(history.len(), 1);
        let record = history.get("AA:BB:CC:DD:EE:FF").expect("recorded by MAC");
        assert_eq!(record.times_seen, 1);
        assert_eq!(record.first_seen, record.last_seen);
    }

    #[test]
    fn test_a_second_scan_keeps_the_original_first_seen() {
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");

        let first_id = store.save_scan(&sample_result()).expect("first save");
        let first = store.load_scan(&first_id).expect("load").devices[0]
            .first_seen
            .clone()
            .expect("first seen");

        let second_id = store.save_scan(&sample_result()).expect("second save");
        let second = store.load_scan(&second_id).expect("load").devices[0]
            .first_seen
            .clone()
            .expect("first seen");

        // The device was known, so its first sighting must not move.
        assert_eq!(first, second);

        let history = store.device_history().expect("history");
        let record = history.get("AA:BB:CC:DD:EE:FF").expect("recorded");
        assert_eq!(record.times_seen, 2, "both scans count as sightings");
        assert!(record.last_seen >= record.first_seen);
    }

    #[test]
    fn test_scans_saved_in_the_same_millisecond_do_not_collide() {
        // Two saves back to back land in the same millisecond, which used to
        // fail the second on the primary key.
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");

        let first = store.save_scan(&sample_result()).expect("first save");
        let second = store.save_scan(&sample_result()).expect("second save");

        assert_ne!(first, second, "identifiers must be unique");
        assert_eq!(store.list_scans().expect("list").len(), 2);
    }

    #[test]
    fn test_devices_without_a_mac_are_tracked_by_address() {
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");
        let mut result = sample_result();
        result.devices[0].mac = None;

        store.save_scan(&result).expect("save");
        let history = store.device_history().expect("history");

        assert!(history.contains_key("ip:192.168.1.10"));
    }

    #[test]
    fn test_history_is_empty_before_any_scan() {
        let store = ScanStore::open(Path::new(":memory:")).expect("open store");
        assert!(store.device_history().expect("history").is_empty());
    }

    #[test]
    fn test_save_and_load_scan_roundtrip() {
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");
        let result = sample_result();

        let scan_id = store.save_scan(&result).expect("save scan");
        let loaded = store.load_scan(&scan_id).expect("load scan");

        assert_eq!(loaded.devices.len(), 1);
        assert_eq!(loaded.config.interface, "wlan0");
        assert_eq!(loaded.config.target, "192.168.1.0/24");

        let device = &loaded.devices[0];
        assert_eq!(device.mac.as_deref(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(device.vendor.as_deref(), Some("Acme"));
        assert_eq!(device.hostname.as_deref(), Some("nas.local"));
        assert_eq!(device.device_type.as_deref(), Some("NAS / file server"));
        assert_eq!(device.os, OsType::Linux);
        assert_eq!(device.open_ports, vec![22, 80]);

        assert_eq!(device.findings.len(), 1);
        let finding = &device.findings[0];
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.title, "TELNET EXPOSED");
        assert_eq!(finding.description, "Telnet is open in cleartext.");
        assert_eq!(finding.remediation, "Disable Telnet.");
        assert_eq!(finding.port, Some(23));
        // The IP is reconstructed from the owning device.
        assert_eq!(finding.ip, device.ip);

        assert_eq!(loaded.summary.critical, 1);
        assert_eq!(loaded.summary.total(), 1);
    }

    /// Regression: the markdown/HTML exports select `f.description` and
    /// `f.remediation`, which the schema did not store. This failed the moment
    /// scans were actually persisted.
    #[test]
    fn test_exports_include_description_and_remediation() {
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");
        let scan_id = store.save_scan(&sample_result()).expect("save scan");

        let markdown = store.export_markdown(&scan_id).expect("markdown export");
        assert!(markdown.contains("Telnet is open in cleartext."));
        assert!(markdown.contains("Disable Telnet."));

        let html = store.export_html(&scan_id).expect("html export");
        assert!(html.contains("TELNET EXPOSED"));

        let csv = store.export_csv(&scan_id).expect("csv export");
        assert!(csv.contains("TELNET EXPOSED"));
    }

    #[test]
    fn test_duplicate_finding_ids_do_not_collide() {
        let mut store = ScanStore::open(Path::new(":memory:")).expect("open store");
        let mut result = sample_result();
        // Same id twice on the same device: the composite primary key would
        // previously have rejected the second insert.
        let duplicate = result.devices[0].findings[0].clone();
        result.devices[0].findings.push(duplicate);

        let scan_id = store.save_scan(&result).expect("save scan");
        let loaded = store.load_scan(&scan_id).expect("load scan");
        assert_eq!(loaded.devices[0].findings.len(), 1);
    }

    #[test]
    fn test_load_scan_missing_id_errors() {
        let store = ScanStore::open(Path::new(":memory:")).expect("open store");
        assert!(store.load_scan("scan-does-not-exist").is_err());
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
