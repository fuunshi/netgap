# 🔍 Netgap - Network Security Scanner

A production-ready network security scanner written in Rust. Discover devices on your local network, identify vulnerabilities, and generate comprehensive security reports.

**Current Status:** ✅ Phase 2 Complete | 38 tests passing | Production-ready

## Quick Features

- 📡 **Device Discovery** - ARP scanning to find all active devices
- 🔐 **Vulnerability Assessment** - Detects Telnet, FTP, SMB, SNMP, HTTP exposure
- 📊 **Device Fingerprinting** - MAC OUI, TTL-based OS detection, banner grabbing
- 💾 **Result Persistence** - SQLite-backed scan history with analysis
- 📈 **Report Generation** - Multiple formats: Terminal, JSON, Markdown, HTML, CSV
- 🔄 **Scan Comparison** - Detect network changes between scans

## Getting Started

### Build
```bash
cargo build --release
```

### Run a Scan
```bash
./target/release/netgap scan --quick
```

### View Results
```bash
./target/release/netgap report --format markdown
./target/release/netgap report --format html > report.html
```

### Compare Scans
```bash
./target/release/netgap report --history
./target/release/netgap report --scan-id scan-1 --compare scan-2
```

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Complete user guide with examples
- **[PHASE1_COMPLETE.md](PHASE1_COMPLETE.md)** - Phase 1 foundation (CLI, interfaces, scanning)
- **[PHASE2_COMPLETE.md](PHASE2_COMPLETE.md)** - Phase 2 enhancements (fingerprinting, assessment, storage)

## Architecture

10 specialized Rust crates working in harmony:

```
netgap-cli ── netgap-report ── netgap-storage
                    ↑
netgap-assess ── netgap-probes ── netgap-fingerprint
                    ↑
netgap-discover ── netgap-scan ── netgap-interfaces
                    ↑
            netgap-core (types)
```

## What Gets Scanned

### Device Fingerprinting
- MAC address lookup (20+ vendor database)
- TTL-based OS detection
- HTTP/SSH banner parsing
- Device type classification (router, camera, printer, etc.)

### Vulnerability Checks
- **🔴 Telnet Exposed** - Remote shell access (Critical)
- **🔴 FTP Exposed** - Unencrypted file transfer (Critical)
- **🔴 SMB Exposed** - Network share access (Critical)
- **🟠 SNMP Accessible** - Network enumeration (High)
- **🟡 HTTP Admin Panel** - Unencrypted credentials (Medium)

### Protocol Probes
- HTTP (headers, versions, redirects)
- HTTPS (SSL/TLS versions)
- SSH (version, key exchange)
- FTP (anonymous access)
- SNMP (community strings)
- Telnet (service confirmation)

## Test Coverage

**38 tests passing** across 10 crates:

| Crate | Purpose | Tests |
|-------|---------|-------|
| netgap-core | Shared types | 6 |
| netgap-interfaces | NIC enumeration | 5 |
| netgap-discover | IP discovery | 4 |
| netgap-scan | Port scanning | 4 |
| netgap-report | Output formatting | 2 |
| netgap-fingerprint | Device fingerprinting | 7 |
| netgap-assess | Vulnerability checks | 6 |
| netgap-probes | Protocol probes | 2 |
| netgap-storage | Result persistence | 2 |

## Performance

- Device discovery: 5-10 seconds (/24 network)
- Port scanning: 2-5 seconds per device
- Full assessment: ~30 seconds for 5-10 devices

## Key Design Decisions

✅ **Serde-First** - All types serialize for mobile FFI compatibility
✅ **Async-Native** - tokio-based concurrent I/O
✅ **Trait-Based** - Pluggable checks and probes for extensibility
✅ **Workspace Org** - Each subsystem is an independent crate
✅ **Zero Unsafe** - Except where required (socket operations)
✅ **No External TUI** - Interactive menus use stdin/stdout

## CLI Commands

```bash
# List interfaces
netgap interfaces

# Run scan
netgap scan -i eth0 -t 192.168.1.0/24
netgap scan --quick          # Fast mode
netgap scan --deep           # All checks

# Reports
netgap report                # Latest scan
netgap report --history      # All scans
netgap report --format markdown  # Export format
netgap report --scan-id <id1> --compare <id2>  # Compare
```

## Storage

All scan results saved to:
```
~/.config/netgap/scans.db
```

SQLite database with tables:
- `scans` - Metadata (date, interface, target)
- `devices` - Discovered devices with fingerprints
- `findings` - Vulnerabilities detected

## Example Output

### Terminal Report
```
IP            Device                OS        Findings
192.168.1.1   Cisco Router          Linux     Telnet, SNMP
192.168.1.5   Canon Printer         Linux     HTTP exposed
192.168.1.100 MacBook Pro           macOS     None
```

### JSON Export
```json
{
  "timestamp": "2024-05-04T16:46:57Z",
  "devices": [{
    "ip": "192.168.1.1",
    "manufacturer": "Cisco",
    "os_type": "Linux",
    "findings": [{
      "title": "Telnet Exposed",
      "severity": "CRITICAL"
    }]
  }]
}
```

### Markdown Report
```markdown
# Network Security Scan

**Date:** 2024-05-04
**Interface:** eth0
**Devices:** 5
**Critical Issues:** 2

## 192.168.1.1 (Cisco Router)
🔴 **[CRITICAL] Telnet Exposed**
- Remediation: Disable Telnet, use SSH
```

## Future Enhancements

Phase 3 possibilities:
- Raw socket ARP scanning (100% device discovery)
- mDNS/Bonjour discovery
- UPnP exposure scanning
- Passive WiFi scanning
- Mobile app bridges (uniffi-rs)
- Web UI dashboard

## Requirements

- Rust 1.70+
- Linux/macOS/Windows
- Network access (no sudo required for basic scanning)

## Building

```bash
# Development
cargo build

# Release (optimized)
cargo build --release

# Run tests
cargo test

# Build docs
cargo doc --open
```

## License

MIT

## Architecture Notes

Netgap is built with mobile portability in mind from day one:

- **Core/Shell Split** - `netgap-core` contains pure logic, zero I/O
- **Serialization-First** - All types implement Serde for FFI
- **Trait Abstraction** - Interface selection, checks, probes are pluggable
- **No Global State** - Everything thread-safe and testable

This allows the same scanning engine to power:
- CLI tool (current)
- Android app (uniffi bridges)
- iOS app (uniffi bridges)
- Web service (actix-web)

## Troubleshooting

**"No interfaces found"**
- System has no active network interfaces
- Check: `ip link show` (Linux) or `ipconfig` (Windows)

**Slow scans**
- Use `--quick` flag to skip deep checks
- Reduce target range (e.g., /25 instead of /24)

**Permission issues**
- Try: `sudo ./target/release/netgap scan`
- Some raw socket operations need elevated privileges

## Contributing

Contributions welcome! The codebase is modular and well-tested:

1. Add tests first (TDD approach)
2. Implement feature in appropriate crate
3. Ensure all tests pass: `cargo test`
4. Update documentation

See [PHASE2_COMPLETE.md](PHASE2_COMPLETE.md) for architecture details.

---

**Ready to scan?** Start with [QUICKSTART.md](QUICKSTART.md)

**Want technical details?** See [PHASE2_COMPLETE.md](PHASE2_COMPLETE.md)
