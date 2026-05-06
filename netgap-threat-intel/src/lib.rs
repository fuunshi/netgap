use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{anyhow, Result};

/// CVSS Severity Levels (NIST scale)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CvssSeverity {
    None,       // 0.0
    Low,        // 0.1-3.9
    Medium,     // 4.0-6.9
    High,       // 7.0-8.9
    Critical,   // 9.0-10.0
}

impl CvssSeverity {
    pub fn from_score(score: f32) -> Self {
        match score {
            0.0 => CvssSeverity::None,
            x if (0.1..=3.9).contains(&x) => CvssSeverity::Low,
            x if (4.0..=6.9).contains(&x) => CvssSeverity::Medium,
            x if (7.0..=8.9).contains(&x) => CvssSeverity::High,
            x if (9.0..=10.0).contains(&x) => CvssSeverity::Critical,
            _ => CvssSeverity::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CvssSeverity::None => "None",
            CvssSeverity::Low => "Low",
            CvssSeverity::Medium => "Medium",
            CvssSeverity::High => "High",
            CvssSeverity::Critical => "Critical",
        }
    }
}

/// CVE Entry from NVD Database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub cve_id: String,                    // CVE-2021-44228
    pub cvss_score: f32,                   // 0.0-10.0
    pub cvss_vector: String,               // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    pub description: String,               // Full description
    pub affected_products: Vec<String>,    // e.g., ["Log4j"]
    pub affected_versions: Vec<String>,    // e.g., ["2.0-beta9 through 2.15.0"]
    pub references: Vec<String>,           // URLs to details
    pub published_date: String,            // ISO8601
    pub last_modified: String,             // ISO8601
}

impl CveEntry {
    pub fn severity(&self) -> CvssSeverity {
        CvssSeverity::from_score(self.cvss_score)
    }

    pub fn is_critical(&self) -> bool {
        self.severity() == CvssSeverity::Critical
    }

    pub fn is_high_or_critical(&self) -> bool {
        self.severity() >= CvssSeverity::High
    }
}

/// Local CVE Database Cache
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvdDatabase {
    pub entries: HashMap<String, CveEntry>,
    pub last_updated: Option<String>,
    pub entry_count: usize,
}

impl NvdDatabase {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_entry(&mut self, entry: CveEntry) {
        let cve_id = entry.cve_id.clone();
        self.entries.insert(cve_id, entry);
        self.entry_count = self.entries.len();
    }

    pub fn get(&self, cve_id: &str) -> Option<&CveEntry> {
        self.entries.get(cve_id)
    }

    pub fn find_by_product(&self, product: &str) -> Vec<&CveEntry> {
        self.entries
            .values()
            .filter(|entry| {
                entry
                    .affected_products
                    .iter()
                    .any(|p| p.to_lowercase().contains(&product.to_lowercase()))
            })
            .collect()
    }

    pub fn critical_count(&self) -> usize {
        self.entries.values().filter(|e| e.is_critical()).count()
    }

    pub fn high_or_critical_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.is_high_or_critical())
            .count()
    }
}

/// Local Cache Manager for persistent storage
pub struct LocalCacheManager {
    cache_path: PathBuf,
}

impl LocalCacheManager {
    pub fn new(cache_dir: &Path) -> Result<Self> {
        fs::create_dir_all(cache_dir)
            .map_err(|e| anyhow!("Failed to create cache directory: {}", e))?;
        Ok(Self {
            cache_path: cache_dir.join("nvd_cache.json"),
        })
    }

    pub fn save(&self, db: &NvdDatabase) -> Result<()> {
        let json = serde_json::to_string_pretty(db)
            .map_err(|e| anyhow!("Failed to serialize database: {}", e))?;
        fs::write(&self.cache_path, json)
            .map_err(|e| anyhow!("Failed to write cache file: {}", e))?;
        Ok(())
    }

    pub fn load(&self) -> Result<NvdDatabase> {
        if !self.cache_path.exists() {
            return Ok(NvdDatabase::new());
        }
        let json = fs::read_to_string(&self.cache_path)
            .map_err(|e| anyhow!("Failed to read cache file: {}", e))?;
        serde_json::from_str(&json).map_err(|e| anyhow!("Failed to parse cache JSON: {}", e))
    }

    pub fn clear(&self) -> Result<()> {
        if self.cache_path.exists() {
            fs::remove_file(&self.cache_path)
                .map_err(|e| anyhow!("Failed to clear cache: {}", e))?;
        }
        Ok(())
    }

    pub fn cache_size(&self) -> Result<u64> {
        if !self.cache_path.exists() {
            return Ok(0);
        }
        let metadata = fs::metadata(&self.cache_path)
            .map_err(|e| anyhow!("Failed to get cache metadata: {}", e))?;
        Ok(metadata.len())
    }
}

/// NVD API Client for downloading CVE data
pub struct NvdClient {
    client: reqwest::Client,
}

impl NvdClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Fetch sample CVE data for demonstration/testing
    pub async fn fetch_sample_cves() -> Result<NvdDatabase> {
        let mut db = NvdDatabase::new();

        // Sample: Log4j RCE
        db.add_entry(CveEntry {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_score: 10.0,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            description: "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.".to_string(),
            affected_products: vec!["Log4j".to_string()],
            affected_versions: vec!["2.0-beta9 through 2.15.0".to_string()],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()],
            published_date: "2021-12-10".to_string(),
            last_modified: "2023-11-07".to_string(),
        });

        // Sample: SSH weak config
        db.add_entry(CveEntry {
            cve_id: "CVE-2023-01234".to_string(),
            cvss_score: 7.5,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
            description: "OpenSSH versions allowing weak password authentication".to_string(),
            affected_products: vec!["OpenSSH".to_string()],
            affected_versions: vec!["7.0 through 8.5".to_string()],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-01234".to_string()],
            published_date: "2023-01-15".to_string(),
            last_modified: "2023-06-20".to_string(),
        });

        // Sample: FTP plaintext
        db.add_entry(CveEntry {
            cve_id: "CVE-2020-05678".to_string(),
            cvss_score: 8.1,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string(),
            description: "ProFTPD versions transmit credentials in plaintext".to_string(),
            affected_products: vec!["ProFTPD".to_string()],
            affected_versions: vec!["1.3.6 and earlier".to_string()],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-05678".to_string()],
            published_date: "2020-03-10".to_string(),
            last_modified: "2022-01-05".to_string(),
        });

        db.last_updated = Some(chrono::Utc::now().to_rfc3339());

        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_severity_from_score() {
        assert_eq!(CvssSeverity::from_score(0.0), CvssSeverity::None);
        assert_eq!(CvssSeverity::from_score(2.5), CvssSeverity::Low);
        assert_eq!(CvssSeverity::from_score(5.5), CvssSeverity::Medium);
        assert_eq!(CvssSeverity::from_score(7.5), CvssSeverity::High);
        assert_eq!(CvssSeverity::from_score(9.5), CvssSeverity::Critical);
    }

    #[test]
    fn test_cve_entry_severity() {
        let cve = CveEntry {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_score: 10.0,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            description: "Test".to_string(),
            affected_products: vec!["Test".to_string()],
            affected_versions: vec!["1.0".to_string()],
            references: vec!["http://test.com".to_string()],
            published_date: "2021-12-10".to_string(),
            last_modified: "2023-11-07".to_string(),
        };

        assert!(cve.is_critical());
        assert!(cve.is_high_or_critical());
    }

    #[test]
    fn test_nvd_database_add_and_get() {
        let mut db = NvdDatabase::new();
        let cve = CveEntry {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_score: 9.8,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            description: "Test".to_string(),
            affected_products: vec!["Log4j".to_string()],
            affected_versions: vec!["2.0-beta9 through 2.15.0".to_string()],
            references: vec!["https://test.com".to_string()],
            published_date: "2021-12-10".to_string(),
            last_modified: "2023-11-07".to_string(),
        };

        db.add_entry(cve);
        assert_eq!(db.entry_count, 1);
        assert!(db.get("CVE-2021-44228").is_some());
        assert!(db.get("CVE-2021-99999").is_none());
    }

    #[test]
    fn test_nvd_database_find_by_product() {
        let mut db = NvdDatabase::new();
        db.add_entry(CveEntry {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_score: 9.8,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            description: "Test".to_string(),
            affected_products: vec!["Log4j".to_string()],
            affected_versions: vec!["2.0-beta9 through 2.15.0".to_string()],
            references: vec!["https://test.com".to_string()],
            published_date: "2021-12-10".to_string(),
            last_modified: "2023-11-07".to_string(),
        });

        let results = db.find_by_product("log4j");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cve_id, "CVE-2021-44228");
    }

    #[tokio::test]
    async fn test_nvd_client_fetch_sample() {
        let db = NvdClient::fetch_sample_cves().await.unwrap();
        assert_eq!(db.entry_count, 3);
        assert_eq!(db.critical_count(), 1);
        assert_eq!(db.high_or_critical_count(), 3);
    }

    #[test]
    fn test_local_cache_manager() {
        use std::fs;
        let temp_dir = std::env::temp_dir().join("netgap_test_cache");
        let _ = fs::remove_dir_all(&temp_dir);

        let manager = LocalCacheManager::new(&temp_dir).unwrap();
        let mut db = NvdDatabase::new();
        db.add_entry(CveEntry {
            cve_id: "CVE-2021-44228".to_string(),
            cvss_score: 9.8,
            cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            description: "Test".to_string(),
            affected_products: vec!["Log4j".to_string()],
            affected_versions: vec!["2.0-beta9 through 2.15.0".to_string()],
            references: vec!["https://test.com".to_string()],
            published_date: "2021-12-10".to_string(),
            last_modified: "2023-11-07".to_string(),
        });

        manager.save(&db).unwrap();
        let loaded = manager.load().unwrap();
        assert_eq!(loaded.entry_count, 1);
        assert!(loaded.get("CVE-2021-44228").is_some());

        let size = manager.cache_size().unwrap();
        assert!(size > 0);

        manager.clear().unwrap();
        let size_after = manager.cache_size().unwrap();
        assert_eq!(size_after, 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
