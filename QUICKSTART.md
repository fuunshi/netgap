# Netgap Quick Start Guide

A production-ready network security scanner built in Rust. Discover devices, identify vulnerabilities, and generate comprehensive reports.

## Build & Install

```bash
# Build the project
cargo build --release

# The binary is at: ./target/release/netgap
```

## Basic Commands

### List Network Interfaces

```bash
./target/release/netgap interfaces
```

Shows:
- Interface names (eth0, wlan0, etc.)
- IPv4 addresses
- MAC addresses
- UP/DOWN status

Allows interactive selection with persistent preferences.

### Run a Security Scan

```bash
# Standard scan (auto-detects interface)
./target/release/netgap scan

# Specify interface and target
./target/release/netgap scan -i eth0 -t 192.168.1.0/24

# Quick scan (ARP + top 20 ports)
./target/release/netgap scan --quick

# Deep scan (all checks enabled)
./target/release/netgap scan --deep

# JSON output for piping
./target/release/netgap scan --format json | jq .
```

### Generate Reports

```bash
# Show latest scan results
./target/release/netgap report

# List all historical scans
./target/release/netgap report --history

# Export as Markdown
./target/release/netgap scan --format table
./target/release/netgap report --format markdown > report.md

# Export as HTML
./target/release/netgap report --format html > report.html

# Export as CSV
./target/release/netgap report --format csv > findings.csv

# Compare two scans (shows changes between scans)
./target/release/netgap report --scan-id <id1> --compare <id2>
```

## Scan Results Explained

Netgap performs a multi-layer assessment:

### 1. **Device Discovery**
- Uses ARP scanning to find all active devices on the network
- Extracts MAC addresses and IP information

### 2. **Device Fingerprinting**
- **MAC OUI Lookup:** Identifies device manufacturer from MAC address
- **TTL Detection:** Guesses OS (Windows=128, Linux/macOS=64)
- **Banner Parsing:** Extracts service versions from HTTP/SSH responses
- **Device Type:** Infers router, camera, printer, computer, phone, etc.

### 3. **Port Scanning**
- Async TCP connect scanning to top 20 dangerous ports
- Service fingerprinting on open ports
- Timeout-based rate limiting to avoid router crashes

### 4. **Vulnerability Assessment**
Each device gets checked for:
- **🔴 Telnet Exposed** (Critical) - Remote shell access
- **🔴 FTP Exposed** (Critical) - Unencrypted file transfer
- **🔴 SMBv1 Exposed** (Critical) - Ransomware risk
- **🟠 SNMP Accessible** (High) - Network enumeration
- **🟡 HTTP Admin Panel** (Medium) - Unencrypted credentials

### 5. **Protocol Probes**
Custom probes extract detailed information:
- **HTTP:** Server headers, versions, redirect chains
- **HTTPS:** SSL/TLS versions, certificate info
- **SSH:** OpenSSH version, key exchange details
- **FTP:** Anonymous login support
- **SNMP:** Community string detection
- **Telnet:** Service confirmation

## Output Formats

### Terminal Table (default)
```
IP            Severity  Finding
──────────────────────────────────
192.168.1.1   CRITICAL  Telnet Exposed
192.168.1.5   HIGH      FTP Exposed
192.168.1.10  MEDIUM    HTTP Admin
```

### JSON
Perfect for scripting and automation:
```json
{
  "timestamp": "2024-05-04T16:46:57Z",
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "manufacturer": "Cisco",
      "os_type": "Linux",
      "findings": [
        {
          "title": "Telnet Exposed",
          "severity": "CRITICAL",
          "remediation": "Disable Telnet, use SSH instead"
        }
      ]
    }
  ]
}
```

### Markdown
Human-readable reports with sections:
```markdown
# Network Security Scan Report

**Scan ID:** scan-1714854417000
**Date:** 2024-05-04T16:46:57Z
**Interface:** eth0
**Target:** 192.168.1.0/24
**Devices Found:** 5
**Total Findings:** 8

## Summary by Severity
- 🔴 **Critical:** 2
- 🟠 **High:** 1

## Findings by Device
### 192.168.1.1 (3 findings)
🔴 **[CRITICAL] Telnet Exposed**
- Description: Telnet service listening on port 23
- Remediation: Disable Telnet, use SSH instead
```

### HTML
Interactive styled reports with color-coded severity:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Network Scan Report</title>
  <style>
    /* Professional styling with color-coded severity */
  </style>
</head>
<body>
  <!-- Formatted findings with summary boxes -->
</body>
</html>
```

### CSV
Spreadsheet-compatible export:
```
IP,Port,Service,Severity,Title
192.168.1.1,23,Telnet,CRITICAL,Telnet Exposed
192.168.1.5,21,FTP,CRITICAL,FTP Exposed
192.168.1.10,80,HTTP,MEDIUM,HTTP Admin Panel
```

## Scan Persistence

All scan results are automatically saved to SQLite:

```
~/.config/netgap/scans.db
```

### Database Schema
- **scans**: Metadata for each scan (date, interface, target, summary)
- **devices**: Discovered devices with fingerprint info
- **findings**: Vulnerabilities detected on each device

### Historical Analysis

```bash
# List all scans
./target/release/netgap report --history

# Load specific scan
./target/release/netgap report --scan-id scan-1714854417000

# Compare two scans (network changes)
./target/release/netgap report --scan-id scan-1 --compare scan-2
```

## Troubleshooting

### "No interfaces found"
- Your system has no active network interfaces
- Check network status: `ip link show` (Linux) or `ipconfig` (Windows)

### "Permission denied" on raw sockets
- Some features require elevated privileges
- Try: `sudo ./target/release/netgap scan`

### Scan is slow
- Use `--quick` flag for faster scans
- Reduce target CIDR range (e.g., /25 instead of /24)

### False positives in fingerprinting
- Confidence scores (0.0-1.0) indicate reliability
- OS detection via TTL is heuristic-based

## Architecture

```
┌─────────────────────────────────────────┐
│  netgap-cli (CLI entrypoint)            │
├─────────────────────────────────────────┤
│  netgap-report (Format output)          │
│  netgap-storage (SQLite persistence)    │
├─────────────────────────────────────────┤
│  netgap-assess (Check vulnerabilities)  │
│  netgap-fingerprint (Identify devices)  │
│  netgap-probes (Protocol detection)     │
├─────────────────────────────────────────┤
│  netgap-discover (Find devices)         │
│  netgap-scan (Port scan)                │
│  netgap-interfaces (NIC enumeration)    │
├─────────────────────────────────────────┤
│  netgap-core (Shared types)             │
└─────────────────────────────────────────┘
```

## Configuration

Interface preferences are saved to:
```
~/.config/netgap/interface_preference
```

Delete this file to reset interface selection.

## Performance

- **Device Discovery:** ~5-10 seconds for /24 network (256 IPs)
- **Port Scanning:** ~2-5 seconds per device (20 ports, async)
- **Full Assessment:** ~30 seconds for 5-10 devices
- **Concurrent Connections:** 32 (configurable)

## Next Steps

1. **Try a scan:** `./target/release/netgap scan --quick`
2. **View results:** `./target/release/netgap report --format markdown`
3. **Compare over time:** Run scans weekly and compare changes
4. **Export reports:** Generate CSV/HTML for stakeholders

## License

MIT - See LICENSE file

---

**Need help?** Check out the comprehensive documentation in PHASE2_COMPLETE.md
