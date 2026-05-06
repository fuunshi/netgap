# Phase 4: External Threat Intelligence — Implementation Plan

**Goal**: Integrate external CVE databases and enable advanced vulnerability analysis

**Status**: Planning

## Architecture Overview

Phase 4 builds on Phase 3 foundation to add external threat data:

```
Phase 3 Scanning Pipeline
        ↓
    Phase 4 Enrichment
        ├─ NVD CVE Database (static/cached)
        ├─ Advanced Vulnerability Matching
        ├─ Risk Scoring Refinement
        └─ External Alert Hooks (webhooks, etc.)
```

## Milestones

### M1: NVD Integration Framework
- Implement CVE data structure from NVD format
- Create local CVE cache (JSON file)
- Parse NVD format into internal structures
- 5 tests for CVE parsing

### M2: Advanced Matching
- Enhanced version matching (semver comparison)
- CVSS score integration
- Affected product/vendor matching
- 4 tests for matching logic

### M3: Risk Scoring
- CVSS-based severity (not just Critical/High/Medium)
- Network exposure scoring
- Business impact factors
- 3 tests for scoring

### M4: Webhook Alerts
- Webhook delivery framework
- Alert formatting for external systems
- Retry logic for failed deliveries
- 3 tests for webhook logic

### M5: CLI Integration
- New `--threat-intel` flag
- CVE database download/update
- Enhanced report output with CVSS
- Feature flag for all M1-M4

## New Crates

### `netgap-threat-intel`
Handles external threat data:
- CVE data structures and parsing
- NVD format support
- Local cache management
- Advanced matching algorithms

### `netgap-webhooks`
Alert delivery framework:
- Webhook configuration
- Alert formatting
- Retry logic
- Provider support (generic, Slack, etc.)

## Implementation Plan

### Phase 4 M1: NVD Integration Framework
**Deliverables**:
- CVE struct with full NVD fields (ID, CVSS, description, references)
- NvdDatabase for storing CVEs
- JSON parsing from NVD format
- LocalCacheManager for file-based storage
- 5 tests

**Commits**: 1 commit

### Phase 4 M2: Advanced Matching
**Deliverables**:
- Semver version comparison
- Product/vendor matching
- Affected configuration matching
- Fallback to keyword search
- 4 tests

**Commits**: 1 commit

### Phase 4 M3: Risk Scoring
**Deliverables**:
- CVSS score handling (0-10 scale)
- Network exposure factors
- Impact scoring (exploitability, impact vector)
- Risk level mapping (Critical/High/Medium/Low/Info)
- 3 tests

**Commits**: 1 commit

### Phase 4 M4: Webhook Alerts
**Deliverables**:
- WebhookConfig struct
- AlertFormatter for different providers
- Retry logic with exponential backoff
- Provider adapters (generic, Slack stub)
- 3 tests

**Commits**: 1 commit

### Phase 4 M5: CLI Integration
**Deliverables**:
- `--threat-intel` flag for scans
- `netgap threat-intel` subcommand
- CVE database status/update
- Enhanced report output
- 0 new tests (feature integration)

**Commits**: 1 commit

## Total Deliverables

- 2 new crates (netgap-threat-intel, netgap-webhooks)
- 15 new tests
- 5 commits
- Final test count: 78 + 15 = 93 tests

## Dependencies

### New External Crates
- `reqwest` - HTTP client for downloading CVE data
- `semver` - Semantic version comparison
- `regex` - Pattern matching for CVE data

### Internal Dependencies
- netgap-core (for Finding, Severity)
- netgap-trends (for Alert structures)

## Data Structures

### CVE Entry (from NVD)
```rust
pub struct CveEntry {
    pub cve_id: String,           // CVE-2021-44228
    pub cvss_score: f32,          // 9.8
    pub cvss_vector: String,      // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    pub description: String,       // Full description
    pub affected_products: Vec<String>,
    pub affected_versions: Vec<String>,
    pub references: Vec<String>,
    pub published_date: String,
    pub last_modified: String,
}

pub enum CvssSeverity {
    None,           // 0.0
    Low,            // 0.1-3.9
    Medium,         // 4.0-6.9
    High,           // 7.0-8.9
    Critical,       // 9.0-10.0
}
```

### Webhook Alert
```rust
pub struct WebhookAlert {
    pub id: String,
    pub severity: String,
    pub cvss_score: f32,
    pub cve_id: String,
    pub description: String,
    pub affected_ip: String,
    pub timestamp: String,
    pub action_url: Option<String>,
}
```

## CLI Design

```bash
# View threat intelligence status
netgap threat-intel status
netgap threat-intel download    # Download latest CVE data

# Scan with threat intelligence
netgap scan --threat-intel

# Configure webhooks
netgap config webhook set https://hooks.slack.com/...
netgap config webhook test      # Send test alert

# Enhanced report
netgap report --threat-intel    # Include CVSS scores
```

## Safety & Performance

**Safety**:
- Validate NVD JSON format before parsing
- Sanitize webhook payloads
- Rate-limit external API calls
- Timeout external requests (5s default)

**Performance**:
- Cache CVE data locally (1GB max)
- Binary search for version matching
- Lazy load threat intel (optional flag)
- Async webhook delivery with queue

## Known Limitations (Deferred)

1. Real-time CVE stream (streaming API integration)
2. Machine learning risk scoring
3. Threat actor tracking
4. Advanced CVSS vector analysis
5. Integration with multiple threat feeds

---

## Success Criteria

- ✅ Can download and parse NVD CVE data
- ✅ Advanced version matching works for edge cases
- ✅ CVSS scores integrated into reporting
- ✅ Webhooks deliver alerts reliably
- ✅ All 15 new tests passing
- ✅ CLI commands intuitive and documented
