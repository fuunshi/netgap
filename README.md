# 🔍 Netgap - Network Security Scanner

A production-ready network security scanner written in Rust. Discover devices on your local network, identify vulnerabilities, and generate comprehensive security reports.

[![CI](https://github.com/fuunshi/netgap/actions/workflows/ci.yml/badge.svg)](https://github.com/fuunshi/netgap/actions/workflows/ci.yml)

**Current Status:** ✅ 495 tests passing | LAN scanning verified on Linux | tests, lints and dependency audit run in CI

## Quick Features

- 🪟 **Window Application** - A point-and-click interface for people who do not use terminals, with a dashboard, scan screen, device list and history
- 📡 **Device Discovery** - ARP sweep of the local link (no extra rights on Windows; root or `CAP_NET_RAW` on Linux/macOS), with an unprivileged TCP fallback
- 🔐 **Vulnerability Assessment** - Detects Telnet, FTP, SMB, SNMP, HTTP exposure
- 📊 **Device Fingerprinting** - MAC OUI, TTL-based OS detection, banner grabbing
- 💾 **Result Persistence** - SQLite-backed scan history with analysis
- 📈 **Report Generation** - Multiple formats: Terminal, JSON, Markdown, HTML, CSV
- 🔄 **Scan Comparison** - Detect network changes between scans
- 🏷️ **Device Identification** - Names, vendors and types, with a trusted-device list
- 📡 **mDNS Discovery** - Asks devices to name themselves (printers, TVs, speakers)
- 🔒 **TLS Inspection** - Certificates, expiry, self-signed, legacy protocol support
- 🆕 **Device History** - Reports what has appeared on the network since last time
- 🛡️ **Gateway Checks** - Admin interface exposure, and the ports UPnP has actually published to the internet
- 🌐 **IPv6 Coverage** - Link-local devices and the IPv6 default gateway are scanned through the interface they live on, then checked like anything else
- 🗄️ **File Server Checks** - Whether a server still accepts SMBv1, and whether it requires signing, asked before anyone logs in
- 🔓 **Open Services** - Whether FTP lets anyone in, a Redis or MongoDB server has no password, or a device answers SNMP with the factory `public` community
- 🚨 **Address Conflicts** - Alerts when an address, especially the gateway's, changes hands
- 🕵️ **Rogue DHCP** - Asks the network who hands out addresses, and says if it is not the router
- 🖥️ **Interactive View** - A plain full-screen UI for picking an interface, scanning and browsing results

## Getting Started

### Download

Each release publishes two downloads per platform, because they are two ways
to use the same scanner, and Debian packages of both for Linux:

| Download | What it is | How to run it |
| --- | --- | --- |
| `netgap-<version>-linux-x86_64.tar.gz`<br>`netgap-<version>-windows-x86_64.zip` | The engine and command line: `netgap scan`, `netgap ui`, `netgap report`. One binary, nothing else to install. | `./netgap scan` |
| `netgap-gui-<version>-linux-x86_64.tar.gz`<br>`netgap-gui-<version>-windows-x86_64.zip` | The window application. | Windows: unpack and double-click `netgap-gui.exe`. Linux: unpack and run `./install.sh` once, then open **Netgap** from your applications menu (or run `./netgap-gui` directly). |
| `netgap_<version>_amd64.deb`<br>`netgap-gui_<version>_amd64.deb` | The same two programs as Debian/Ubuntu packages, for a system where the package manager should own the files. | `sudo apt install ./netgap-gui_<version>_amd64.deb`, then **Netgap** appears in the applications menu and `netgap` is on `PATH`. |

Both read and write the same scan history (`~/.config/netgap/scans.db`), so a
scan started in the window shows up in `netgap report`, and the other way
around.

### Build from Source

```bash
cargo build --release
```

This produces two binaries, and they are separate programs on purpose:

```bash
./target/release/netgap       # the engine and command line (also `netgap ui`)
./target/release/netgap-gui   # the window application
```

The Debian packages the release carries are built from those binaries by a
script, so they can be built here too:

```bash
packaging/deb/build.sh netgap 1.0.0 ./target/release/netgap ./dist
packaging/deb/build.sh netgap-gui 1.0.0 ./target/release/netgap-gui ./dist
sudo apt install ./dist/netgap-gui_1.0.0_amd64.deb
```

### Open the Window Application
```bash
./target/release/netgap-gui

# Open straight onto a screen, if preferred
./target/release/netgap-gui history
```

A dashboard of the network's health, the devices that were found, and every
scan already in the database. Pick an interface, press **Start scan**, and
watch it run — no flags to remember. **Scan network** is one click from the
dashboard, **Devices** searches by address, name or vendor and shows each
device's own record — when it first appeared, and what it opened or closed
since — and **History** charts the findings recorded over time. Light and dark
modes are both built in, and a scan started here is saved to the same history
`netgap report` reads.

For the command line there is also an interactive terminal view:

### Or Use the Interactive Terminal View
```bash
./target/release/netgap ui
```

Arrow keys move, Enter opens, Esc goes back, `?` lists every key. The first
screen lists the real network interfaces (press `a` for bridges and tunnels),
the next chooses discovery method and whether to scan ports, and the results
screen shows each device with its vendor, ports and findings. Scans started
here go into the same history `netgap report` reads.

### Run a Scan
```bash
# Auto-detects the LAN interface and target network
./target/release/netgap scan

# Fastest: find devices, skip port scanning
./target/release/netgap scan --quick -y

# Everything: banners + vulnerability assessment
./target/release/netgap scan --deep -y
```

Discovery uses ARP, which is the most complete sweep. On Linux and macOS it
wants root or `CAP_NET_RAW`; on Windows it goes through the system's own
`SendARP` and needs nothing at all. Without the capability netgap falls back
to an unprivileged TCP sweep, explains the trade-off, and lets you continue or
re-run under sudo.

### See What's On Your Network
```bash
# Colourised table: who is connected, what each device is, what's unrecognised
./target/release/netgap discover

# Add device names and types by probing service ports too
./target/release/netgap discover --identify

# Mark everything currently connected as trusted
./target/release/netgap discover --trust-all
```

### View Results
```bash
./target/release/netgap report --format markdown
./target/release/netgap report --format html > report.html
```

### Compare Scans
```bash
./target/release/netgap diff              # what changed since the previous scan
./target/release/netgap diff <from> <to>  # or between any two
./target/release/netgap report --history
./target/release/netgap report --scan-id scan-1 --compare scan-2
```

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Complete user guide with examples
- **[docs/ROADMAP.md](docs/ROADMAP.md)** - What is done, what is not, and why
- **[docs/](docs/)** - Development history: phase records and plans

## Architecture

18 specialized Rust crates working in harmony:

```
                    netgap-cli     netgap-gui
                          \          /
                        netgap-engine
                     /        |        \
         netgap-discover  netgap-scan  netgap-fingerprint
                     \        |        /
                 netgap-interfaces   netgap-core (types)

netgap-gui ── netgap-report ── netgap-storage
netgap-assess ── netgap-probes ── netgap-fingerprint
```

`netgap-engine` is the scan pipeline itself — plan, discover, merge IPv6
neighbours, enrich names and vendors, optionally scan ports. The command line,
`netgap ui` and the window application all call it, so the three front ends
cannot drift apart.

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

**495 tests passing** across the workspace:

| Crate | Purpose | Tests |
|-------|---------|-------|
| netgap-core | Shared types, health scoring, HTML escaping | 18 |
| netgap-interfaces | NIC enumeration, LAN-aware selection and the IPv6 gateway | 23 |
| netgap-discover | ARP sweep, TCP fallback, IPv6 neighbours, conflicts | 73 |
| netgap-scan | Port scanning, zone-aware IPv6 and risk classification | 10 |
| netgap-report | Terminal, summary and HTML formatting | 30 |
| netgap-fingerprint | Device fingerprinting | 24 |
| netgap-assess | Vulnerability, gateway, file-server and open-service checks | 27 |
| netgap-probes | Service, version, TLS, UPnP, SMB, FTP, Redis, MongoDB and SNMP probes | 65 |
| netgap-storage | Result persistence and device history | 15 |
| netgap-services | Service/CVE database | 19 |
| netgap-trends | History and change detection | 8 |
| netgap-mdns | mDNS service discovery | 15 |
| netgap-raw-sockets | Raw ARP framework (not yet wired up) | 7 |
| netgap-threat-intel | NVD client and CVE cache | 17 |
| netgap-webhooks | Alert delivery | 8 |
| netgap-engine | Scan pipeline shared by the CLI, terminal UI and window | 0 |
| netgap-cli | Commands, config and profiles, doctor, upnp, diff, inventory, alerts, discovery and the interactive UI | 101 |
| netgap-gui | Window application, tray icon, scheduled scans and their display formatting | 35 |

## Performance

- Device discovery: 5-10 seconds (/24 network)
- Port scanning: 2-5 seconds per device
- Full assessment: ~30 seconds for 5-10 devices

## Key Design Decisions

✅ **Serde-First** - All types serialize for mobile FFI compatibility
✅ **Async-Native** - tokio-based concurrent I/O
✅ **Trait-Based** - Pluggable checks and probes for extensibility
✅ **Workspace Org** - Each subsystem is an independent crate
✅ **One Scan Pipeline** - `netgap-engine` is shared by the CLI, terminal UI and window, so behaviour cannot diverge
✅ **Zero Unsafe** - Except where required (socket operations)
✅ **Small Terminal UI** - crossterm only; no widget framework to keep patched
✅ **Window Without a Web Server** - `netgap-gui` is a native application; scanning a home network needs no account or local server

## CLI Commands

```bash
# Full-screen interactive view: interfaces, scans, devices and findings
netgap ui

# List interfaces (marks loopback, virtual and default-route devices)
netgap interfaces

# Check that a scan will work here before running one
netgap doctor                     # interface, privileges, target, link, setup
netgap doctor --no-probe          # settings only: send no packets
netgap doctor --target 10.0.0.0/24  # check a range you did not auto-detect

# Discover devices and report what they are
netgap discover                   # report for humans
netgap discover --format json     # full metadata, machine-readable
netgap discover --identify        # probe ports to sharpen device types
netgap discover --mdns            # ask devices to name themselves over mDNS
netgap discover --no-save         # report without recording it in the history

# What the router has published through UPnP, if it answers
netgap upnp                       # the ports UPnP opened to the internet
netgap upnp --json                # machine-readable (exits 1 if anything is published)
netgap upnp --gateway 10.0.0.2    # a second router, or one off the default route

# Live CVE data (optional; scanning works without it)
netgap threat-intel update     # download CVE data for known products
netgap threat-intel status     # inspect the local cache
netgap scan --threat-intel     # match findings against it, offline

# Trusted devices
netgap trusted                    # list
netgap trust <mac> "label"        # add (an IP works if it is already known)
netgap untrust <mac>              # remove

# Carry that list to another machine, or keep a copy of it
netgap inventory export                   # JSON on standard output
netgap inventory export ~/netgap.json     # to a file, readable only by you
netgap inventory import ~/netgap.json     # add these devices; labels refresh
netgap inventory import ~/netgap.json --replace  # the file is the whole list

# Run scan
netgap scan -i eth0 -t 192.168.1.0/24
netgap scan --quick          # Discovery only, no port scanning
netgap scan --deep           # Implies --fingerprint and --assess
netgap scan -y               # Skip the sudo prompt, use the TCP fallback
netgap scan --discovery arp  # Force a method: auto (default), arp or tcp
netgap scan --no-save        # Do not write to scan history

# Reports (scans are saved automatically)
netgap report                    # Latest scan, terminal table
netgap report --history          # All scans
netgap report --format json      # json, summary, markdown, html, csv
netgap report --scan-id <id1> --compare <id2>  # Compare

# What changed between two scans (exits 1 when anything did)
netgap diff                      # the previous scan against the latest
netgap diff <id>                 # since that scan, up to the latest
netgap diff <from> <to>          # between any two (ids, or "previous")
netgap diff --json               # machine-readable, for a script or CI step
```

## Profiles and the Config File

A scan that does the same thing every run should not need the same six flags
every run. Three profiles ship built in:

| Profile | What it does |
|---------|--------------|
| `quick` | Discovery only — who is on the network, no port scanning |
| `home` | Discovery, mDNS names, and the checks that need no credentials |
| `audit` | Everything: deep scan, fingerprinting, assessment, mDNS, NVD matching |

```bash
netgap scan --profile home       # the everyday scan
netgap scan --profile audit -y   # the thorough one
```

Settings that are the same every time go in `~/.config/netgap/config.toml`,
beside `scans.db` and `alerts.toml`:

```toml
profile = "home"        # used when --profile is not given

[defaults]              # below the profile, above the built-in default
interface = "wlx90610ca31294"
max_hosts = 1024

[profiles.home]         # adjust a built-in by name...
assess = false

[profiles.paranoid]     # ...or define one of your own
deep = true
threat_intel = true
```

Precedence is explicit flag, then profile, then `[defaults]`, then the
built-in default. Anything typed on the command line wins outright, which is
why the flags take an optional value: `netgap scan --profile audit
--assess=false` is a deep scan without the assessment, and `--quick=false` is
how a script overrides a profile that turns it on.

```bash
netgap config                    # the file, the active profile, every effective setting and where it came from
netgap config --profile audit    # what that profile would produce here
netgap config --path             # just the path
```

The file feeds `netgap scan`. `discover` and `watch` still take their settings
from their flags alone, so a change here cannot silently alter a scheduled job.

## Window Application

```bash
netgap-gui                    # dashboard
netgap-gui scan               # open on the scan screen
netgap-gui devices            # open on the device list
netgap-gui history            # open on the recorded scans
netgap-gui --light            # light theme (dark is the default)
netgap-gui --tray             # put an icon in the tray (the default)
netgap-gui --no-tray          # no tray icon
netgap-gui --monitor=15       # scan every 15 minutes from the start
```

Settings, choices and results live in the window; the only thing it writes
outside the database is an exported report, saved to `~/netgap-<id>.html` or
`.csv` when you press **Export**.

### The tray icon

Where the desktop has a status-notifier area, the window puts an icon there.
Its menu has **Open Netgap**, **Scan now** and **Quit**, and the tooltip
carries the last scan's result. From the menu, **Scan now** runs the same scan
as the button on the scan screen and saves it to the same history.

There is no "close to tray". On Wayland the compositor stops sending frame
callbacks to a window it is not drawing — hidden, minimised, or covered by
another window — and winit then discards the redraw requests waiting for one,
so egui's update loop stalls. A window that hid itself could not be brought
back, even by the app that hid it; a tray click was queued and never
answered. Closing the window quits. Scheduled scans are unaffected, because
they run on their own thread (below).

The icon is a StatusNotifierItem served over D-Bus, so the build needs no GTK
development headers. On a session with no status-notifier host — a bare
Wayland session, a machine with no desktop — starting the icon fails and the
window runs without one. Native tray icons for Windows and macOS are not
wired up yet.

### Scheduled scans

Tick **Scan on a schedule** on the Scan screen — or start with
`netgap-gui --monitor=15` — and the window scans again on that interval with
the interface, target and options already chosen. Each run is saved to the
history like any other scan, so the device timeline fills in while the window
is covered or minimised.

The clock and the scan live on a thread of their own, not in the window's
frame loop. A window that is not being drawn gets no frames at all, so a
schedule kept inside one would stop the moment the window was covered; on its
own thread it keeps scanning, saving and notifying.

What a scheduled scan says is what changed, not what it found: the comparison
is `netgap-trends`, the same one `netgap watch` prints and `netgap alert`
sends. A scheduled run compares against the last scan recorded on disk —
including one the command line recorded — and reports:

- a critical finding that was not there before,
- a port that opened or closed on a device already seen,
- a health score that fell by five points or more.

A new device is recorded as a change but not reported: a guest's phone and a
randomising address look exactly like one. The tooltip carries the headline.
When the window is not in front, a desktop notification lists the changes;
when it is, the same line appears as a toast. A scheduled scan never moves the
window off the screen being read.

The schedule lives in memory: closing the window or restarting resets it to
off. Webhooks are still the command line's job (`netgap alert`); the window
sends desktop notifications only.

## Alerts

A scanner you have to remember to run is not a monitor. Point netgap at a
webhook once and it will tell you when something changes:

```bash
netgap alert --url https://hooks.slack.com/services/... --provider slack
netgap alert --test                    # prove it works before trusting it
netgap alert                           # show what is configured
```

Alerts fire from `netgap scan`, so anything that runs a scan can alert:
cron, a systemd timer, a CI job. Only *changes* are sent — a scan every
fifteen minutes that finds the same open port every fifteen minutes stays
quiet, because a monitor that repeats itself is one you mute.

By default it alerts on a serious finding that was not there last time,
and on a known device opening *or* closing a port — a new one is the first
sign of a service, or of a machine that has been taken over, and a port that
stops answering is how a firewall change or a compromise shows up. The other
triggers are off by default, because they are noisy on real networks:

```bash
netgap alert --new-device        # a device that has not been seen before
netgap alert --device-offline    # a device that stopped answering
netgap alert --no-port-change    # stop reporting port changes
netgap alert --health-drop 20    # the score fell by 20 points or more
netgap alert --off               # stop, keeping the URL
```

Every scan of the network compares against the previous scan *of the same
network*, so scanning two subnets does not make each look new to the other.
`--no-save` disables alerts, since there is then no history to compare with.

The URL is treated as a secret: it is written `0600` and shown masked. Plain
`http://` is refused unless you pass `--allow-http`, because the alert
describes your network in detail.

### Running it on a schedule

```bash
# crontab -e — every 15 minutes, no prompts, failures kept in a log
*/15 * * * * /usr/local/bin/netgap scan -y >>"$HOME/.netgap-cron.log" 2>&1
```

`-y` skips the privilege prompt so it works unattended; without raw-socket
capability it falls back to the TCP sweep and still alerts on what it finds.
The output goes to a log rather than nowhere, so a webhook that stops
delivering leaves a trace. Do not pass `--no-save`: the comparison against
the previous scan is what makes an alert mean something.
For a systemd timer:

```ini
# ~/.config/systemd/user/netgap-watch.service
[Unit]
Description=Check the network for changes
[Service]
Type=oneshot
ExecStart=%h/.cargo/bin/netgap scan -y
```

```ini
# ~/.config/systemd/user/netgap-watch.timer
[Unit]
Description=Run the network check every 15 minutes
[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
[Install]
WantedBy=timers.target
```

```bash
systemctl --user enable --now netgap-watch.timer
```

A machine with `CAP_NET_RAW` — or running as root — gets the full ARP sweep
and finds more devices than the unprivileged fallback. On Windows the same
sweep is always available and needs no privileges.

## Storage

All scan results are saved automatically to:
```
~/.config/netgap/scans.db
```
Override the location with `NETGAP_CONFIG_DIR`. `netgap watch` keeps history
in memory only, to avoid writing a row every interval.

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

Known gaps:
- `netgap-raw-sockets` is a framework stub, not yet wired into the CLI
- TTL-based OS fingerprinting is not implemented
- Rogue AP / evil-twin detection (needs monitor mode and a different permission model)
- Passive WiFi scanning
- The config file feeds `netgap scan`; `discover` and `watch` still read flags
- Desktop packaging (winget, Homebrew, `.deb`/`.rpm`, Nix), signed releases, and native
  tray icons on Windows and macOS
- Mobile app bridges (uniffi-rs)
- Web UI dashboard (the desktop window is `netgap-gui`; a browser interface is still open)

## Requirements

- Rust 1.70+
- Linux/macOS/Windows
- Network access
- A desktop session with OpenGL for the window application (`netgap-gui`); the
  command line and `netgap ui` need only a terminal
- Root (or `setcap cap_net_raw+ep`) for full ARP discovery on Linux and macOS;
  Windows has the full sweep without either. Without the capability netgap
  falls back to an unprivileged TCP sweep that finds fewer hosts and resolves
  MAC addresses only for hosts already in the kernel neighbour table

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

MIT **or** Apache-2.0, at your choice — pick whichever suits you.

- [LICENSE-MIT](LICENSE-MIT)
- [LICENSE-APACHE](LICENSE-APACHE)

The Apache option is there for its explicit patent grant and trademark clause,
which many companies require before using a tool internally.

Netgap is a scanner: run it only against networks you own or have permission
to test. Nothing in the licence grants that permission, and neither licence
restricts what the software may be pointed at.

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

**"ARP discovery needs root"**
- On Linux and macOS the unprivileged TCP fallback is running. For a complete
  sweep: `sudo ./target/release/netgap scan`
- Or grant the capability once: `sudo setcap cap_net_raw+ep ./target/release/netgap`
- On Windows this message does not apply: ARP runs unprivileged through
  `SendARP`, so a scan that finds nothing is about the target range or the
  network, not privileges

## Contributing

Contributions welcome! The codebase is modular and well-tested:

1. Add tests first (TDD approach)
2. Implement feature in appropriate crate
3. Ensure all tests pass: `cargo test`
4. Update documentation

See [docs/PHASE2_COMPLETE.md](docs/PHASE2_COMPLETE.md) for architecture details.

---

**Ready to scan?** Start with [QUICKSTART.md](QUICKSTART.md)

**Want technical details?** See [docs/PHASE2_COMPLETE.md](docs/PHASE2_COMPLETE.md)
