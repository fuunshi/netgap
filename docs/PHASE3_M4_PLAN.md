# Phase 3 M4: Trend Analysis & Alerting — Implementation Plan

**Goal**: Add historical tracking, change detection, and alerting to netgap

**Deliverables**:
- Scan history persistence (SQLite)
- Device appearance/disappearance alerts
- Service change detection
- Vulnerability regression alerts
- Network health scoring
- `netgap watch --interval` continuous monitoring
- Alert rule framework

## Architecture

### New Crate: `netgap-trends`
Handles historical analysis and trend computation:
- `ScanHistory`: Stores multiple scans with timestamps
- `TrendAnalysis`: Compares consecutive scans
- `ChangeDetection`: Identifies new/removed devices and services
- `HealthScore`: Computes network security health (0-100)
- `AlertRule`: Framework for triggering alerts

### New Crate: `netgap-alerts`
Alert management and notification:
- `Alert`: Alert struct with severity and description
- `AlertRule`: Define when alerts should trigger
- `AlertEngine`: Evaluate rules against changes
- Support for different output formats (CLI, JSON, webhook stubs)

### Enhanced Crates
- `netgap-storage`: Add scan history querying (list scans, compare by date range)
- `netgap-cli`: Add `watch` subcommand with `--interval` flag

## Milestones

### M4a: Scan History & Storage (1 commit)
- Create `netgap-trends` crate
- Implement `ScanHistory` struct
- Add `list_scans()`, `get_scan_by_id()`, `compare_scans()` to `ScanStore`
- 5 tests for history operations
- Status: Store multiple scans, retrieve any scan

### M4b: Change Detection (1 commit)
- Implement `ChangeDetection` module
- Detect new devices, removed devices
- Detect new services on existing devices
- Detect removed services
- Detect severity regressions (vulnerabilities got worse)
- 4 tests for change detection
- Status: Identify network changes between scans

### M4c: Health Scoring & Alerts (1 commit)
- Implement `HealthScore` calculation (0-100 scale)
- Factors: open port count, vulnerability severity, service count
- Implement `AlertRule` framework
- Create default alert rules (critical vuln detected, new device, health drop)
- 4 tests for alerting
- Status: Calculate health and trigger alerts

### M4d: CLI Integration & Watch Mode (1 commit)
- Add `netgap watch` subcommand with `--interval 60` flag
- Implement continuous scanning loop
- Display changes and alerts after each scan
- Format alerts with timestamps and severity
- Status: Full continuous monitoring

## Test Plan

Total: 13 new tests in Phase 3 M4
- ScanHistory tests (3): list, retrieve, compare
- ChangeDetection tests (3): new devices, new services, severity changes
- HealthScore tests (3): baseline, degradation, improvement
- AlertRule tests (4): trigger conditions, change detection, severity classification

## Commits

1. **M4a**: Scan history storage (5 tests)
2. **M4b**: Change detection (4 tests)
3. **M4c**: Health scoring & alerts (4 tests)
4. **M4d**: Watch mode CLI integration (no new tests, feature)

## CLI Design

```bash
# Watch mode
netgap watch                    # Default 60s interval
netgap watch --interval 30      # Custom interval
netgap watch -i eth0 --interval 30  # With interface selection

# Output format per scan:
Phase 1: Device Discovery
---
✓ Discovered 5 device(s)

Phase 2: Port Scanning
---
⚠ Changes detected:
  • NEW: Device 192.168.1.42 (iPhone)
  • NEW SERVICE: 192.168.1.10:8080 (http)
  • GONE: 192.168.1.99 (offline)

Network Health Score: 73/100 ↓ -5 points
  ✓ No critical vulnerabilities
  ⚠ 2 high severity findings
  • 8 open ports (was 6)
  • 12 services discovered

Next scan in 59s...
```
