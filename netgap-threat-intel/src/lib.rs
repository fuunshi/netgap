//! NVD (National Vulnerability Database) client and local CVE cache.
//!
//! The bundled database in `netgap-services` is a handful of hand-written
//! entries. This crate is the real source: it queries the NVD API v2 for the
//! products a scan identified, converts each CVE's CPE match criteria into
//! version windows, and keeps the result in a local cache so later scans need
//! no network.
//!
//! Two deliberate properties:
//!
//! * **Offline by default.** Scanning never requires network access; lookups
//!   read the cache. Fetching is a separate, explicit action.
//! * **Nothing is invented.** A CVE that is not in the cache is not reported.
//!   The previous version of this crate shipped `fetch_sample_cves`, which
//!   returned entries with fabricated identifiers ("CVE-2023-01234") — data
//!   that looked real and was not, in a tool whose output people act on.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// NVD API v2 endpoint for CVE lookups.
pub const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// CVSS Severity Levels (NIST scale)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CvssSeverity {
    None,     // 0.0
    Low,      // 0.1-3.9
    Medium,   // 4.0-6.9
    High,     // 7.0-8.9
    Critical, // 9.0-10.0
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

impl std::fmt::Display for CvssSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A version window a CVE applies to, as published in its CPE match criteria.
///
/// NVD expresses these as open-ended bounds rather than a single range, so the
/// struct mirrors that: any bound may be absent, and a window with no bounds at
/// all means "every version".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_excluding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_excluding: Option<String>,
    /// An exact version, when the CPE names one instead of a window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
}

impl VersionRange {
    /// Whether a detected version falls inside this window.
    pub fn contains(&self, version: &str) -> bool {
        use netgap_core::version::compare_versions;
        use std::cmp::Ordering;

        if let Some(exact) = &self.exact {
            return compare_versions(version, exact) == Ordering::Equal;
        }

        if let Some(start) = &self.start_including {
            if compare_versions(version, start) == Ordering::Less {
                return false;
            }
        }
        if let Some(start) = &self.start_excluding {
            if compare_versions(version, start) != Ordering::Greater {
                return false;
            }
        }
        if let Some(end) = &self.end_including {
            if compare_versions(version, end) == Ordering::Greater {
                return false;
            }
        }
        if let Some(end) = &self.end_excluding {
            if compare_versions(version, end) != Ordering::Less {
                return false;
            }
        }

        true
    }

    /// A human-readable rendering, e.g. ">= 2.4.49, < 2.4.51".
    pub fn describe(&self) -> String {
        if let Some(exact) = &self.exact {
            return exact.clone();
        }

        let mut parts = Vec::new();
        if let Some(start) = &self.start_including {
            parts.push(format!(">= {start}"));
        }
        if let Some(start) = &self.start_excluding {
            parts.push(format!("> {start}"));
        }
        if let Some(end) = &self.end_including {
            parts.push(format!("<= {end}"));
        }
        if let Some(end) = &self.end_excluding {
            parts.push(format!("< {end}"));
        }

        if parts.is_empty() {
            "all versions".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// One product and version window a CVE applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedProduct {
    /// CPE vendor, e.g. "apache".
    pub vendor: String,
    /// CPE product, e.g. "http_server".
    pub product: String,
    pub range: VersionRange,
}

/// CVE Entry from the NVD database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub cve_id: String,
    pub cvss_score: f32,
    pub cvss_vector: String,
    pub severity: CvssSeverity,
    pub description: String,
    pub affected: Vec<AffectedProduct>,
    pub references: Vec<String>,
    pub published_date: String,
    pub last_modified: String,
}

impl CveEntry {
    pub fn is_critical(&self) -> bool {
        self.severity == CvssSeverity::Critical
    }

    pub fn is_high_or_critical(&self) -> bool {
        self.severity >= CvssSeverity::High
    }

    /// Whether this CVE applies to a version of the given product.
    ///
    /// `product` is matched against the CPE product name, case-insensitively
    /// and ignoring separators, so a probe's "http_server" or "http-server"
    /// both find `cpe:2.3:a:apache:http_server`.
    pub fn applies_to(&self, product: &str, version: &str) -> bool {
        let wanted = normalize_product(product);

        self.affected.iter().any(|affected| {
            normalize_product(&affected.product) == wanted && affected.range.contains(version)
        })
    }

    /// The windows this CVE applies to for a product, for display.
    pub fn ranges_for(&self, product: &str) -> Vec<String> {
        let wanted = normalize_product(product);

        self.affected
            .iter()
            .filter(|affected| normalize_product(&affected.product) == wanted)
            .map(|affected| affected.range.describe())
            .collect()
    }

    /// The highest severity this entry can be reported at.
    pub fn severity(&self) -> CvssSeverity {
        self.severity
    }
}

/// Local CVE database cache.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NvdDatabase {
    pub entries: HashMap<String, CveEntry>,
    pub last_updated: Option<String>,
    pub entry_count: usize,
    /// Which `vendor:product:version` queries have populated this cache.
    ///
    /// The cache holds what was *asked for*, not a mirror of NVD. Matching a
    /// version that was never queried against it can only under-report, so the
    /// caller needs to be able to tell the difference.
    #[serde(default)]
    pub queried_versions: HashMap<String, String>,
}

/// Key for [`NvdDatabase::queried_versions`].
pub fn version_query_key(vendor: &str, product: &str, version: &str) -> String {
    format!(
        "{}:{}:{}",
        vendor.to_lowercase(),
        product.to_lowercase(),
        version
    )
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

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether this cache was populated for a specific product version.
    pub fn has_queried(&self, vendor: &str, product: &str, version: &str) -> bool {
        self.queried_versions
            .contains_key(&version_query_key(vendor, product, version))
    }

    /// Record that a product version has been fetched.
    pub fn mark_queried(&mut self, vendor: &str, product: &str, version: &str) {
        self.queried_versions.insert(
            version_query_key(vendor, product, version),
            chrono::Utc::now().to_rfc3339(),
        );
    }

    /// CVEs that apply to a version of a product.
    ///
    /// Sorted most severe first, then by identifier, so a caller can present
    /// the worst first without re-sorting.
    pub fn matching(&self, product: &str, version: &str) -> Vec<&CveEntry> {
        let mut matches: Vec<&CveEntry> = self
            .entries
            .values()
            .filter(|entry| entry.applies_to(product, version))
            .collect();

        matches.sort_by(|a, b| {
            b.cvss_score
                .partial_cmp(&a.cvss_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.cve_id.cmp(&b.cve_id))
        });

        matches
    }

    /// Every CVE naming a product, regardless of version.
    pub fn find_by_product(&self, product: &str) -> Vec<&CveEntry> {
        let wanted = normalize_product(product);

        self.entries
            .values()
            .filter(|entry| {
                entry
                    .affected
                    .iter()
                    .any(|affected| normalize_product(&affected.product) == wanted)
            })
            .collect()
    }

    /// Products this database holds entries for, with counts.
    pub fn products(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for entry in self.entries.values() {
            for affected in &entry.affected {
                *counts.entry(affected.product.clone()).or_insert(0) += 1;
            }
        }
        counts
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

/// Normalize a product name for comparison: lowercase, separators removed.
fn normalize_product(product: &str) -> String {
    product
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Local cache manager for persistent storage.
pub struct LocalCacheManager {
    cache_path: PathBuf,
}

impl LocalCacheManager {
    /// Use the default location (`$NETGAP_CONFIG_DIR/nvd_cache.json`).
    pub fn default_location() -> Result<Self> {
        let dir = netgap_core::paths::config_dir()
            .ok_or_else(|| anyhow!("Could not determine the netgap config directory"))?;
        Self::new(&dir)
    }

    pub fn new(cache_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(cache_dir)
            .map_err(|e| anyhow!("Failed to create cache directory: {}", e))?;
        Ok(Self {
            cache_path: cache_dir.join("nvd_cache.json"),
        })
    }

    /// Where the cache lives.
    pub fn path(&self) -> &Path {
        &self.cache_path
    }

    pub fn save(&self, db: &NvdDatabase) -> Result<()> {
        let json = serde_json::to_string_pretty(db)
            .map_err(|e| anyhow!("Failed to serialize database: {}", e))?;
        std::fs::write(&self.cache_path, json)
            .map_err(|e| anyhow!("Failed to write cache file: {}", e))?;
        Ok(())
    }

    /// Load the cache; a missing file is an empty database, not an error.
    pub fn load(&self) -> Result<NvdDatabase> {
        if !self.cache_path.exists() {
            return Ok(NvdDatabase::new());
        }
        let json = std::fs::read_to_string(&self.cache_path)
            .map_err(|e| anyhow!("Failed to read cache file: {}", e))?;
        serde_json::from_str(&json).map_err(|e| anyhow!("Failed to parse cache JSON: {}", e))
    }

    pub fn clear(&self) -> Result<()> {
        if self.cache_path.exists() {
            std::fs::remove_file(&self.cache_path)
                .map_err(|e| anyhow!("Failed to clear cache: {}", e))?;
        }
        Ok(())
    }

    pub fn cache_size(&self) -> Result<u64> {
        if !self.cache_path.exists() {
            return Ok(0);
        }
        let metadata = std::fs::metadata(&self.cache_path)
            .map_err(|e| anyhow!("Failed to get cache metadata: {}", e))?;
        Ok(metadata.len())
    }
}

/// The products a scan can look up, mapped to their CPE identifiers.
///
/// NVD identifies software by CPE (`cpe:2.3:a:<vendor>:<product>`), which is
/// not derivable from the product string a service reports — "OpenSSH" is
/// `openbsd:openssh`, "Apache" is `apache:http_server`. Guessing from
/// free text would silently return nothing, so the mapping is explicit and the
/// list is limited to what the probes can identify.
pub const KNOWN_CPE_PRODUCTS: &[(&str, &str, &str)] = &[
    // (probe product, cpe vendor, cpe product)
    ("Apache", "apache", "http_server"),
    ("nginx", "nginx", "nginx"),
    ("OpenSSH", "openbsd", "openssh"),
    ("MySQL", "oracle", "mysql"),
    ("MariaDB", "mariadb", "mariadb"),
    ("PostgreSQL", "postgresql", "postgresql"),
    ("ProFTPD", "proftpd", "proftpd"),
    ("vsftpd", "vsftpd", "vsftpd"),
    ("Dovecot", "dovecot", "dovecot"),
    ("Postfix", "postfix", "postfix"),
    ("Exim", "exim", "exim"),
    ("Redis", "redis", "redis"),
    ("IIS", "microsoft", "internet_information_services"),
];

/// Look up the CPE identifiers for a product name.
pub fn cpe_for_product(product: &str) -> Option<(&'static str, &'static str)> {
    let wanted = normalize_product(product);

    KNOWN_CPE_PRODUCTS
        .iter()
        .find(|(name, _, _)| normalize_product(name) == wanted)
        .map(|(_, vendor, cpe_product)| (*vendor, *cpe_product))
}

/// Client for the NVD API v2.
pub struct NvdClient {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl Default for NvdClient {
    fn default() -> Self {
        Self::new()
    }
}

impl NvdClient {
    /// Create a client, taking an API key from `NVD_API_KEY` when present.
    ///
    /// Without a key the API allows five requests per thirty seconds, which is
    /// workable because results are cached; a key raises that to fifty.
    pub fn new() -> Self {
        let api_key = std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty());
        Self {
            client: reqwest::Client::builder()
                .user_agent(concat!("netgap/", env!("CARGO_PKG_VERSION")))
                .build()
                .unwrap_or_default(),
            api_key,
        }
    }

    /// Whether an API key is configured.
    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }

    /// Fetch the CVEs that apply to one product version.
    ///
    /// This is the lookup a scanner actually wants. NVD applies its own CPE
    /// matching server-side — including the version windows that a plain
    /// product query cannot evaluate — so the result is the applicable set
    /// rather than the product's entire history.
    ///
    /// Asking for a product instead (`fetch_product`) returns every CVE ever
    /// filed against it, oldest first, which for anything long-lived means
    /// pages of entries from the 1990s.
    pub async fn fetch_for_version(
        &self,
        vendor: &str,
        product: &str,
        version: &str,
        limit: usize,
    ) -> Result<Vec<CveEntry>> {
        let cpe_name = format!("cpe:2.3:a:{vendor}:{product}:{version}");
        let url = format!(
            "{NVD_API}?cpeName={}&resultsPerPage={}",
            urlencode(&cpe_name),
            limit.clamp(1, 2000)
        );

        let mut request = self.client.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().await.context("querying the NVD API")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!(
                "NVD API returned {} for {cpe_name}{}",
                status,
                if matches!(status.as_u16(), 403 | 429) {
                    " (rate limited — set NVD_API_KEY for a higher quota)"
                } else {
                    ""
                }
            ));
        }

        let body = response.text().await.context("reading the NVD response")?;
        parse_response(&body)
    }

    /// Fetch CVEs for a product, newest kept.
    ///
    /// The API returns results oldest first and offers no sort parameter, so a
    /// limit truncates to the *oldest* entries — the opposite of useful for a
    /// product with a long history. Results are therefore sorted here and the
    /// newest `limit` kept, and callers with a specific version in hand should
    /// prefer [`Self::fetch_for_version`], which does not have this problem.
    pub async fn fetch_product(
        &self,
        vendor: &str,
        product: &str,
        limit: usize,
    ) -> Result<Vec<CveEntry>> {
        let match_string = format!("cpe:2.3:a:{vendor}:{product}");
        let url = format!("{NVD_API}?virtualMatchString={}&resultsPerPage={}", urlencode(&match_string), limit.min(2000));

        let mut request = self.client.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().await.context("querying the NVD API")?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow!(
                "NVD API returned {} for {vendor}:{product}{}",
                status,
                if status.as_u16() == 403 || status.as_u16() == 429 {
                    " (rate limited — set NVD_API_KEY for a higher quota)"
                } else {
                    ""
                }
            ));
        }

        let body = response.text().await.context("reading the NVD response")?;
        let mut entries = parse_response(&body)?;
        entries.sort_by(|a, b| b.published_date.cmp(&a.published_date));
        entries.truncate(limit.clamp(1, 2000));
        Ok(entries)
    }

    /// Fetch entries for every product in [`KNOWN_CPE_PRODUCTS`].
    ///
    /// NVD rate limits are per-request, so this waits between calls when no API
    /// key is configured. `progress` is called before each product.
    pub async fn fetch_known_products<F>(&self, per_product: usize, mut progress: F) -> Result<NvdDatabase>
    where
        F: FnMut(&str, usize, usize),
    {
        let mut db = NvdDatabase::new();
        let total = KNOWN_CPE_PRODUCTS.len();

        for (index, (name, vendor, product)) in KNOWN_CPE_PRODUCTS.iter().enumerate() {
            progress(name, index + 1, total);

            match self.fetch_product(vendor, product, per_product).await {
                Ok(entries) => {
                    for entry in entries {
                        db.add_entry(entry);
                    }
                }
                Err(error) => {
                    // One product failing must not lose the others.
                    eprintln!("  ⚠️  {name}: {error}");
                }
            }

            // Stay inside the unauthenticated rate limit.
            if !self.has_api_key() && index + 1 < total {
                tokio::time::sleep(std::time::Duration::from_secs(7)).await;
            }
        }

        db.last_updated = Some(chrono::Utc::now().to_rfc3339());
        Ok(db)
    }
}

/// Percent-encode the characters that appear in CPE match strings.
fn urlencode(value: &str) -> String {
    value
        .replace(':', "%3A")
        .replace('*', "%2A")
        .replace('/', "%2F")
        .replace(' ', "%20")
}

/// Parse an NVD API v2 response body.
///
/// Written defensively on purpose: the API mixes schema versions within a
/// single response (CVSS v3.1, v2 and SSVC entries appear side by side, and
/// only some carry `cvssData`), so a missing or unexpected field must be
/// skipped rather than fail the whole fetch.
pub fn parse_response(body: &str) -> Result<Vec<CveEntry>> {
    let document: serde_json::Value =
        serde_json::from_str(body).context("parsing the NVD response as JSON")?;

    let vulnerabilities = document
        .get("vulnerabilities")
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow!("NVD response has no 'vulnerabilities' array"))?;

    Ok(vulnerabilities
        .iter()
        .filter_map(|item| item.get("cve"))
        .filter_map(parse_cve)
        .collect())
}

/// Convert one `cve` object into a [`CveEntry`], or `None` if unusable.
fn parse_cve(cve: &serde_json::Value) -> Option<CveEntry> {
    let cve_id = cve.get("id")?.as_str()?.to_string();

    let description = cve
        .get("descriptions")
        .and_then(|value| value.as_array())
        .and_then(|list| {
            list.iter()
                .find(|entry| entry.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .or_else(|| list.first())
        })
        .and_then(|entry| entry.get("value"))
        .and_then(|value| value.as_str())
        .unwrap_or_default()
        .to_string();

    let (cvss_score, cvss_vector) = extract_cvss(cve);

    let affected = extract_affected(cve);
    // A CVE with no usable CPE criteria cannot be matched to anything; keeping
    // it would only pad the cache.
    if affected.is_empty() {
        return None;
    }

    let references = cve
        .get("references")
        .and_then(|value| value.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|entry| entry.get("url").and_then(|url| url.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Some(CveEntry {
        cve_id,
        cvss_score,
        cvss_vector,
        severity: CvssSeverity::from_score(cvss_score),
        description,
        affected,
        references,
        published_date: cve
            .get("published")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        last_modified: cve
            .get("lastModified")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
    })
}

/// Pull the best available CVSS score and vector.
///
/// Several metric schemas can be present at once; v3.1 is preferred, then v3.0,
/// then v2. Entries without `cvssData` (SSVC, for instance) are skipped.
fn extract_cvss(cve: &serde_json::Value) -> (f32, String) {
    let Some(metrics) = cve.get("metrics").and_then(|value| value.as_object()) else {
        return (0.0, String::new());
    };

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let Some(entries) = metrics.get(key).and_then(|value| value.as_array()) else {
            continue;
        };

        // Prefer the NVD-assessed ("Primary") metric when the CNA supplied one too.
        let chosen = entries
            .iter()
            .find(|entry| entry.get("type").and_then(|t| t.as_str()) == Some("Primary"))
            .or_else(|| entries.first());

        if let Some(cvss_data) = chosen.and_then(|entry| entry.get("cvssData")) {
            let score = cvss_data
                .get("baseScore")
                .and_then(|value| value.as_f64())
                .unwrap_or(0.0) as f32;
            let vector = cvss_data
                .get("vectorString")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();

            if score > 0.0 {
                return (score, vector);
            }
        }
    }

    (0.0, String::new())
}

/// Collect the vulnerable products and version windows from the CPE matches.
fn extract_affected(cve: &serde_json::Value) -> Vec<AffectedProduct> {
    let mut affected = Vec::new();

    let Some(configurations) = cve.get("configurations").and_then(|value| value.as_array()) else {
        return affected;
    };

    for configuration in configurations {
        let Some(nodes) = configuration.get("nodes").and_then(|value| value.as_array()) else {
            continue;
        };

        for node in nodes {
            let Some(matches) = node.get("cpeMatch").and_then(|value| value.as_array()) else {
                continue;
            };

            for cpe_match in matches {
                // `vulnerable: false` describes the platform a CVE runs on,
                // not something that is itself vulnerable.
                if cpe_match.get("vulnerable").and_then(|v| v.as_bool()) != Some(true) {
                    continue;
                }
                let Some(criteria) = cpe_match.get("criteria").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some((vendor, product, cpe_version)) = parse_cpe(criteria) else {
                    continue;
                };

                let range = VersionRange {
                    start_including: string_field(cpe_match, "versionStartIncluding"),
                    start_excluding: string_field(cpe_match, "versionStartExcluding"),
                    end_including: string_field(cpe_match, "versionEndIncluding"),
                    end_excluding: string_field(cpe_match, "versionEndExcluding"),
                    // CPE uses "*" for "any version" and "-" for "not applicable".
                    exact: cpe_version
                        .filter(|version| *version != "*" && *version != "-")
                        .map(str::to_string),
                };

                let product = AffectedProduct {
                    vendor,
                    product,
                    range,
                };
                if !affected.contains(&product) {
                    affected.push(product);
                }
            }
        }
    }

    affected
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// Split a CPE 2.3 string into vendor, product and version.
///
/// `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*` gives
/// `("apache", "http_server", Some("2.4.49"))`.
pub fn parse_cpe(criteria: &str) -> Option<(String, String, Option<&str>)> {
    let parts: Vec<&str> = criteria.split(':').collect();
    // cpe, 2.3, part, vendor, product, version, ...
    if parts.len() < 6 || parts[0] != "cpe" {
        return None;
    }
    if !matches!(parts[2], "a" | "o" | "h") {
        // Only application, OS and hardware parts are comparable this way.
        return None;
    }

    Some((
        parts[3].to_string(),
        parts[4].to_string(),
        Some(parts[5]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real NVD entry (trimmed) with a version window rather than an exact
    /// version — the shape OpenSSH CVEs use.
    const RANGE_ENTRY: &str = r#"
    {
      "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
      "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-01-01T00:00:00.000",
      "vulnerabilities": [{
        "cve": {
          "id": "CVE-2000-0143",
          "published": "2000-02-11T05:00:00.000",
          "lastModified": "2026-06-16T21:51:05.360",
          "vulnStatus": "Modified",
          "descriptions": [{"lang": "en", "value": "The SSH protocol server sshd allows local users without shell access to redirect a TCP connection."}],
          "metrics": {"cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "2.0", "vectorString": "AV:L/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 4.6}}]},
          "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
             {"vulnerable": true, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndIncluding": "1.2.1"}
          ]}]}],
          "references": [{"url": "http://www.osvdb.org/1201"}]
        }
      }]
    }"#;

    /// An entry with an exact-version CPE and a CVSS v3.1 metric.
    const EXACT_ENTRY: &str = r#"
    {
      "vulnerabilities": [{
        "cve": {
          "id": "CVE-2021-41773",
          "published": "2021-10-05T20:15:07.000",
          "lastModified": "2025-01-01T00:00:00.000",
          "descriptions": [{"lang": "en", "value": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49."}],
          "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8}}],
             "ssvcV203": [{"source": "nvd@nist.gov", "ssvcData": {"id": "CVE-2021-41773"}}]},
          "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
             {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
          ]}]}],
          "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}]
        }
      }]
    }"#;

    fn entry(json: &str) -> CveEntry {
        parse_response(json).expect("parses").into_iter().next().expect("one entry")
    }

    #[test]
    fn test_cvss_severity_from_score() {
        assert_eq!(CvssSeverity::from_score(0.0), CvssSeverity::None);
        assert_eq!(CvssSeverity::from_score(2.5), CvssSeverity::Low);
        assert_eq!(CvssSeverity::from_score(5.5), CvssSeverity::Medium);
        assert_eq!(CvssSeverity::from_score(7.5), CvssSeverity::High);
        assert_eq!(CvssSeverity::from_score(9.5), CvssSeverity::Critical);
    }

    #[test]
    fn test_parse_range_entry() {
        let entry = entry(RANGE_ENTRY);

        assert_eq!(entry.cve_id, "CVE-2000-0143");
        assert_eq!(entry.cvss_score, 4.6);
        assert_eq!(entry.severity, CvssSeverity::Medium);
        assert_eq!(entry.affected.len(), 1);
        assert_eq!(entry.affected[0].vendor, "openbsd");
        assert_eq!(entry.affected[0].product, "openssh");
        assert_eq!(entry.affected[0].range.end_including.as_deref(), Some("1.2.1"));
        assert_eq!(entry.references.len(), 1);
    }

    #[test]
    fn test_parse_exact_entry_ignores_ssvc_metrics() {
        // The SSVC entry has no cvssData; parsing must skip it rather than fail.
        let entry = entry(EXACT_ENTRY);

        assert_eq!(entry.cve_id, "CVE-2021-41773");
        assert_eq!(entry.cvss_score, 9.8);
        assert_eq!(entry.severity, CvssSeverity::Critical);
        assert!(entry.cvss_vector.starts_with("CVSS:3.1"));
        assert_eq!(entry.affected[0].range.exact.as_deref(), Some("2.4.49"));
    }

    #[test]
    fn test_range_matching() {
        let entry = entry(EXACT_ENTRY);
        // An exact-version CPE matches only that version.
        assert!(entry.applies_to("http_server", "2.4.49"));
        assert!(!entry.applies_to("http_server", "2.4.50"));
        assert!(!entry.applies_to("nginx", "2.4.49"));
    }

    #[test]
    fn test_open_ended_range_matching() {
        let entry = entry(RANGE_ENTRY);

        assert!(entry.applies_to("openssh", "1.2.1"));
        assert!(entry.applies_to("openssh", "1.0"));
        assert!(!entry.applies_to("openssh", "1.2.2"));
        assert!(!entry.applies_to("openssh", "9.6"));
    }

    #[test]
    fn test_version_range_contains_bounds() {
        let range = VersionRange {
            start_including: Some("2.4.49".to_string()),
            end_excluding: Some("2.4.51".to_string()),
            ..Default::default()
        };

        assert!(range.contains("2.4.49"));
        assert!(range.contains("2.4.50"));
        assert!(!range.contains("2.4.48"));
        assert!(!range.contains("2.4.51"));
        assert_eq!(range.describe(), ">= 2.4.49, < 2.4.51");
    }

    #[test]
    fn test_version_range_with_no_bounds_is_everything() {
        let range = VersionRange::default();
        assert!(range.contains("1.0"));
        assert!(range.contains("99.9"));
        assert_eq!(range.describe(), "all versions");
    }

    #[test]
    fn test_non_vulnerable_cpe_matches_are_ignored() {
        // `vulnerable: false` describes the platform, not the flaw.
        let json = r#"
        {"vulnerabilities": [{"cve": {
          "id": "CVE-2020-0001",
          "descriptions": [{"lang": "en", "value": "test"}],
          "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", "versionEndExcluding": "5.0"},
            {"vulnerable": true, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.16.1"}
          ]}]}]
        }}]}"#;

        let entry = entry(json);
        assert_eq!(entry.affected.len(), 1);
        assert_eq!(entry.affected[0].product, "nginx");
    }

    #[test]
    fn test_entry_without_cpe_criteria_is_dropped() {
        // Nothing to match against: it would only pad the cache.
        let json = r#"
        {"vulnerabilities": [{"cve": {
          "id": "CVE-2020-0002",
          "descriptions": [{"lang": "en", "value": "no configurations"}]
        }}]}"#;

        assert!(parse_response(json).expect("parses").is_empty());
    }

    #[test]
    fn test_parse_response_rejects_non_nvd_json() {
        assert!(parse_response("{}").is_err());
        assert!(parse_response("not json").is_err());
    }

    #[test]
    fn test_parse_cpe() {
        assert_eq!(
            parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
            Some(("apache".to_string(), "http_server".to_string(), Some("2.4.49")))
        );
        assert_eq!(
            parse_cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
            Some(("openbsd".to_string(), "openssh".to_string(), Some("*")))
        );
        assert_eq!(parse_cpe("not-a-cpe"), None);
        assert_eq!(parse_cpe("cpe:2.3::bad"), None);
    }

    #[test]
    fn test_database_matching_sorts_by_severity() {
        let mut db = NvdDatabase::new();
        db.add_entry(entry(EXACT_ENTRY));
        db.add_entry(entry(RANGE_ENTRY));

        let matches = db.matching("http_server", "2.4.49");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].cve_id, "CVE-2021-41773");

        assert!(db.matching("http_server", "2.4.51").is_empty());
        assert_eq!(db.critical_count(), 1);
    }

    #[test]
    fn test_cpe_lookup_for_probe_products() {
        assert_eq!(cpe_for_product("Apache"), Some(("apache", "http_server")));
        assert_eq!(cpe_for_product("OpenSSH"), Some(("openbsd", "openssh")));
        assert_eq!(cpe_for_product("MariaDB"), Some(("mariadb", "mariadb")));
        // Case and separators are not the caller's problem.
        assert_eq!(cpe_for_product("apache"), Some(("apache", "http_server")));
        assert_eq!(cpe_for_product("Cloudflare"), None);
    }

    #[test]
    fn test_urlencode_covers_cpe_characters() {
        assert_eq!(
            urlencode("cpe:2.3:a:apache:http_server"),
            "cpe%3A2.3%3Aa%3Aapache%3Ahttp_server"
        );
    }

    #[test]
    fn test_version_query_bookkeeping() {
        let mut db = NvdDatabase::new();
        assert!(!db.has_queried("apache", "http_server", "2.4.49"));

        db.mark_queried("apache", "http_server", "2.4.49");

        assert!(db.has_queried("apache", "http_server", "2.4.49"));
        // A nearby version is a different query and must not be assumed covered.
        assert!(!db.has_queried("apache", "http_server", "2.4.51"));
        assert!(!db.has_queried("apache", "http_server", "2.4.50"));
    }

    #[test]
    fn test_query_bookkeeping_survives_a_cache_round_trip() {
        let temp_dir =
            std::env::temp_dir().join(format!("netgap_test_queries_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manager = LocalCacheManager::new(&temp_dir).expect("cache manager");
        let mut db = NvdDatabase::new();
        db.add_entry(entry(EXACT_ENTRY));
        db.mark_queried("apache", "http_server", "2.4.49");
        manager.save(&db).expect("save");

        let loaded = manager.load().expect("load");
        assert!(loaded.has_queried("apache", "http_server", "2.4.49"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_local_cache_manager() {
        let temp_dir = std::env::temp_dir().join(format!("netgap_test_cache_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);

        let manager = LocalCacheManager::new(&temp_dir).expect("cache manager");
        let mut db = NvdDatabase::new();
        db.add_entry(entry(EXACT_ENTRY));
        db.last_updated = Some("2026-01-01T00:00:00Z".to_string());

        manager.save(&db).expect("save");
        let loaded = manager.load().expect("load");

        assert_eq!(loaded.entry_count, 1);
        assert!(loaded.get("CVE-2021-41773").is_some());
        assert_eq!(loaded.last_updated.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert!(manager.cache_size().expect("size") > 0);

        manager.clear().expect("clear");
        assert_eq!(manager.cache_size().expect("size"), 0);

        // A missing cache is an empty database, not a failure.
        assert!(manager.load().expect("load empty").is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Live NVD query. Ignored by default because it needs network access and
    /// is subject to the API's rate limits.
    #[tokio::test]
    #[ignore = "requires network access to the NVD API"]
    async fn test_live_fetch_known_product() {
        let client = NvdClient::new();
        let entries = client
            .fetch_product("apache", "http_server", 20)
            .await
            .expect("fetch");

        assert!(!entries.is_empty());
        assert!(entries.iter().all(|entry| entry.cve_id.starts_with("CVE-")));
    }
}
