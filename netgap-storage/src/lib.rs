//! Scan result persistence and historical analysis.
//!
//! This module provides SQLite-backed storage for scan results with support for:
//! - Persistent scan history with timestamps
//! - Device and finding queries
//! - Scan comparison (diff between consecutive scans)
//! - Export to various formats

use netgap_core::{Device, Finding, ScanResult, Severity};
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
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
