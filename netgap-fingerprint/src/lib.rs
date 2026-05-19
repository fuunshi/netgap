//! Device fingerprinting engine.
//!
//! This module implements advanced device fingerprinting including:
//! - MAC address OUI (Organizationally Unique Identifier) vendor lookup
//! - TTL-based operating system detection
//! - Service version extraction from banners
//! - Device name and capability inference
//! - Banner grabbing for HTTP, SSH, SMTP, FTP protocols

pub mod oui;

use netgap_core::{Device, OsType};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Network positions that identify a device without guessing.
#[derive(Debug, Clone, Default)]
pub struct ClassifyContext {
    /// The network's default gateway, if known.
    pub gateway: Option<IpAddr>,
    /// The address of the machine running the scan.
    pub local: Option<IpAddr>,
}

/// A best-effort device classification.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceClassification {
    /// Human-readable label, e.g. "Router / gateway".
    pub label: String,
    /// How much to trust the label (0.0-1.0).
    pub confidence: f32,
}

impl DeviceClassification {
    /// A label the caller should present as a guess rather than a fact.
    pub fn is_guess(&self) -> bool {
        self.confidence < 0.9
    }
}

/// Whether a MAC was randomized by the device for privacy.
pub use netgap_core::mac::is_randomized_mac;

/// Classify a device from its network position, services, MAC and vendor.
///
/// Signals are applied most-reliable first: position and open ports are
/// observed facts, vendor and MAC randomization are inferences, and the result
/// says which it is via [`DeviceClassification::confidence`].
pub fn classify_device(device: &Device, context: &ClassifyContext) -> DeviceClassification {
    // Positions are facts.
    if context.local == Some(device.ip) {
        return DeviceClassification {
            label: "This device".to_string(),
            confidence: 1.0,
        };
    }
    if context.gateway == Some(device.ip) {
        return DeviceClassification {
            label: "Router / gateway".to_string(),
            confidence: 1.0,
        };
    }

    // Open ports are observed facts about what the host offers.
    if let Some(classification) = classify_by_ports(&device.open_ports) {
        return classification;
    }

    // Vendor OUI, when the vendor is in the database at all.
    if let Some(label) = device.vendor.as_deref().and_then(classify_vendor) {
        return DeviceClassification {
            label: label.to_string(),
            confidence: 0.5,
        };
    }

    // Hostname often names the device class outright.
    if let Some(label) = device.hostname.as_deref().and_then(classify_hostname) {
        return DeviceClassification {
            label: label.to_string(),
            confidence: 0.4,
        };
    }

    if device.mac.as_deref().is_some_and(is_randomized_mac) {
        return DeviceClassification {
            label: "Phone / laptop (private MAC)".to_string(),
            confidence: 0.4,
        };
    }

    DeviceClassification {
        label: "Unknown device".to_string(),
        confidence: 0.1,
    }
}

/// Classify from the services a host exposes.
fn classify_by_ports(ports: &[u16]) -> Option<DeviceClassification> {
    if ports.is_empty() {
        return None;
    }

    let has = |port: u16| ports.contains(&port);
    let label = if has(9100) || has(631) || has(515) || has(5357) {
        "Printer"
    } else if has(554) || has(8554) {
        "IP camera"
    } else if has(2049) || has(548) || has(5000) {
        "NAS / file server"
    } else {
        match Fingerprinter::guess_device_type(ports) {
            "Unknown Device" => return None,
            other => other,
        }
    };

    Some(DeviceClassification {
        label: label.to_string(),
        confidence: 0.8,
    })
}

/// Map a vendor name to a device class.
fn classify_vendor(vendor: &str) -> Option<&'static str> {
    let vendor = vendor.to_ascii_lowercase();

    const ROUTERS: &[&str] = &[
        "cisco", "netgear", "tp-link", "d-link", "asus", "avm", "ubiquiti", "mikrotik", "aruba",
        "juniper", "ruijie", "huawei", "zte", "ruckus", "extreme networks", "meraki", "cambium",
        "sagemcom", "technicolor", "arcadyan", "sercomm",
    ];
    const PRINTERS: &[&str] = &["canon", "epson", "brother", "xerox", "lexmark", "ricoh", "kyocera"];
    const COMPUTERS: &[&str] = &["dell", "lenovo", "supermicro", "intel", "realtek", "microsoft", "oracle", "qemu", "vmware"];
    const IOT: &[&str] = &["espressif", "tuya", "shelly", "sonoff", "raspberry"];
    const SMART: &[&str] = &["amazon", "roku", "sonos", "nest"];

    if ROUTERS.iter().any(|needle| vendor.contains(needle)) {
        return Some("Router / access point");
    }
    if PRINTERS.iter().any(|needle| vendor.contains(needle)) {
        return Some("Printer");
    }
    if COMPUTERS.iter().any(|needle| vendor.contains(needle)) {
        return Some("Computer");
    }
    if IOT.iter().any(|needle| vendor.contains(needle)) {
        return Some("IoT device");
    }
    if SMART.iter().any(|needle| vendor.contains(needle)) {
        return Some("Smart home device");
    }
    if vendor.contains("apple") || vendor.contains("samsung") || vendor.contains("google") {
        return Some("Phone / tablet / computer");
    }
    if vendor.contains("docker") || vendor.contains("iana") || vendor.contains("virtualbox") {
        return Some("Virtual interface");
    }

    None
}

/// Classify from a hostname's conventional prefixes.
fn classify_hostname(hostname: &str) -> Option<&'static str> {
    let name = hostname.to_ascii_lowercase();

    const PATTERNS: &[(&str, &str)] = &[
        ("iphone", "Phone"),
        ("ipad", "Tablet"),
        ("android", "Phone / tablet"),
        ("galaxy", "Phone / tablet"),
        ("pixel", "Phone"),
        ("macbook", "Laptop"),
        ("imac", "Desktop"),
        ("laptop", "Laptop"),
        ("desktop", "Desktop"),
        ("printer", "Printer"),
        ("hp-", "Printer"),
        ("cam", "IP camera"),
        ("tv", "Smart TV"),
        ("chromecast", "Media device"),
        ("router", "Router / gateway"),
        ("gateway", "Router / gateway"),
        ("nas", "NAS / file server"),
        ("server", "Server"),
        ("raspberry", "Single-board computer"),
        ("esp", "IoT device"),
    ];

    PATTERNS
        .iter()
        .find(|(needle, _)| name.contains(needle))
        .map(|(_, label)| *label)
}

/// Fingerprinter for device OS and vendor identification.
///
/// Vendor data comes from the bundled IEEE registry ([`oui`]), so this holds no
/// per-instance state.
#[derive(Debug, Clone, Copy)]
pub struct Fingerprinter;

/// Banner grabbing result with service identification.
#[derive(Debug, Clone)]
pub struct BannerGrabResult {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub banner: String,
    pub service_name: Option<String>,
    pub version: Option<String>,
    pub confidence: f32,
}

impl Fingerprinter {
    /// Create a new fingerprinter.
    pub fn new() -> Self {
        Fingerprinter
    }

    /// Look up vendor name from MAC address.
    ///
    /// Returns `None` for locally administered (randomized) addresses and for
    /// assignments the IEEE has not published.
    pub fn lookup_vendor(&self, mac: &str) -> Option<String> {
        oui::lookup(mac).map(str::to_string)
    }

    /// How many OUI assignments the bundled registry holds.
    pub fn vendor_database_size() -> usize {
        oui::vendor_count()
    }

    /// Detect OS type from TTL value.
    /// 
    /// Common TTL values:
    /// - Windows: 128
    /// - Linux: 64
    /// - macOS: 64
    /// - iOS: 64
    /// - Android: 64
    /// - Network devices: Often 255 or 30
    pub fn detect_os_from_ttl(ttl: u8) -> (OsType, f32) {
        match ttl {
            128 => (OsType::Windows, 0.85),
            64 => (OsType::Linux, 0.75), // Could be Linux, macOS, iOS, or Android
            32 => (OsType::Windows, 0.70), // Windows after one router hop
            255 => (OsType::Unknown, 0.50), // Network device or special case
            1..=63 => (OsType::Linux, 0.60), // Likely Linux with TTL decrement
            _ => (OsType::Unknown, 0.20),
        }
    }

    /// Fingerprint a device using various heuristics.
    pub fn fingerprint_device(&self, device: &mut Device) {
        // Try to get vendor from MAC
        if let Some(mac) = &device.mac {
            if let Some(vendor) = self.lookup_vendor(mac) {
                device.vendor = Some(vendor);
            }
        }

        // TTL-based OS detection needs an ICMP echo, which is a follow-up.
        // Only record "unknown" when nothing better has been established —
        // overwriting a real guess here would discard it.
        if device.os == OsType::Unknown {
            device.os_confidence = 0.0;
        }
    }

    /// Extract HTTP server header to identify service version.
    pub fn parse_http_server_header(header: &str) -> Option<String> {
        // Example: "Apache/2.4.41 (Ubuntu)" or "nginx/1.18.0"
        if header.contains("Apache") {
            if let Some(start) = header.find("Apache/") {
                if let Some(end) = header[start..].find(' ') {
                    return Some(header[start..start + end].to_string());
                }
            }
        } else if header.contains("nginx") {
            if let Some(start) = header.find("nginx/") {
                if let Some(end) = header[start..].find(' ') {
                    return Some(header[start..start + end].to_string());
                } else {
                    return Some(header[start..].to_string());
                }
            }
        } else if header.contains("IIS") {
            if let Some(start) = header.find("IIS/") {
                if let Some(end) = header[start..].find(' ') {
                    return Some(header[start..start + end].to_string());
                } else {
                    return Some(header[start..].to_string());
                }
            }
        }

        Some(header.to_string())
    }

    /// Extract SSH version from banner (e.g., "OpenSSH_7.4p1 Debian-10+deb9u6").
    pub fn parse_ssh_banner(banner: &str) -> Option<String> {
        // Format: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6
        if let Some(start) = banner.find("OpenSSH") {
            if let Some(space) = banner[start..].find(' ') {
                return Some(banner[start..start + space].to_string());
            } else {
                return Some(banner[start..].to_string());
            }
        }

        None
    }

    /// Guess device type from open ports and services.
    pub fn guess_device_type(open_ports: &[u16]) -> &'static str {
        let has_ssh = open_ports.contains(&22);
        let has_http = open_ports.contains(&80);
        let has_smb = open_ports.contains(&445) || open_ports.contains(&139);
        let has_rdp = open_ports.contains(&3389);
        let has_database = open_ports.contains(&3306) || open_ports.contains(&5432);

        match (has_rdp, has_smb, has_ssh, has_http, has_database) {
            (true, true, _, _, _) => "Windows Workstation",
            (true, _, _, _, _) => "Windows Server/Workstation",
            (false, true, false, _, _) => "Windows File Server",
            (false, true, true, _, _) => "Network Attached Storage (NAS)",
            (false, false, true, true, _) => "Linux Web Server",
            (false, false, true, false, true) => "Linux Database Server",
            (false, false, true, false, false) => "Linux Server/Router",
            (false, false, false, true, _) => "Web Service/Camera/IoT",
            (false, false, false, false, true) => "Dedicated Database Server",
            _ => "Unknown Device",
        }
    }

    /// Attempt to grab HTTP banner from a service.
    pub async fn grab_http_banner(ip: &str, port: u16) -> Option<BannerGrabResult> {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
        let connect_future = TcpStream::connect(addr);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            connect_future
        ).await.ok()?.ok()?;

        let request = "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).await.ok()?;

        let mut buffer = vec![0; 4096];
        let n = stream.read(&mut buffer).await.ok()?;
        let response = String::from_utf8_lossy(&buffer[..n]);

        // Extract Server header
        for line in response.lines() {
            if line.to_lowercase().starts_with("server:") {
                let banner = line.trim_start_matches("Server:").trim().to_string();
                let (service_name, version) = Self::identify_http_service(&banner);
                return Some(BannerGrabResult {
                    ip: ip.to_string(),
                    port,
                    protocol: "HTTP".to_string(),
                    banner: banner.clone(),
                    service_name,
                    version,
                    confidence: 0.9,
                });
            }
        }

        None
    }

    /// Attempt to grab SSH banner from a service.
    pub async fn grab_ssh_banner(ip: &str, port: u16) -> Option<BannerGrabResult> {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
        let connect_future = TcpStream::connect(addr);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            connect_future
        ).await.ok()?.ok()?;

        let mut buffer = vec![0; 256];
        let n = stream.read(&mut buffer).await.ok()?;
        let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

        // SSH format: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6
        if banner.starts_with("SSH-") {
            let (service_name, version) = Self::identify_ssh_service(&banner);
            return Some(BannerGrabResult {
                ip: ip.to_string(),
                port,
                protocol: "SSH".to_string(),
                banner: banner.clone(),
                service_name,
                version,
                confidence: 0.95,
            });
        }

        None
    }

    /// Attempt to grab FTP banner from a service.
    pub async fn grab_ftp_banner(ip: &str, port: u16) -> Option<BannerGrabResult> {
        let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
        let connect_future = TcpStream::connect(addr);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            connect_future
        ).await.ok()?.ok()?;

        let mut buffer = vec![0; 256];
        let n = stream.read(&mut buffer).await.ok()?;
        let banner = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

        // FTP format: 220 FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.17)
        if banner.starts_with("220") {
            let (service_name, version) = Self::identify_ftp_service(&banner);
            return Some(BannerGrabResult {
                ip: ip.to_string(),
                port,
                protocol: "FTP".to_string(),
                banner: banner.clone(),
                service_name,
                version,
                confidence: 0.85,
            });
        }

        None
    }

    /// Identify HTTP service from Server header.
    fn identify_http_service(banner: &str) -> (Option<String>, Option<String>) {
        if banner.contains("Apache") {
            let version = Self::extract_version(banner, "Apache/");
            (Some("Apache".to_string()), version)
        } else if banner.contains("nginx") {
            let version = Self::extract_version(banner, "nginx/");
            (Some("nginx".to_string()), version)
        } else if banner.contains("IIS") {
            let version = Self::extract_version(banner, "IIS/");
            (Some("IIS".to_string()), version)
        } else if banner.contains("LiteSpeed") {
            let version = Self::extract_version(banner, "LiteSpeed/");
            (Some("LiteSpeed".to_string()), version)
        } else if banner.contains("Caddy") {
            (Some("Caddy".to_string()), None)
        } else {
            (None, None)
        }
    }

    /// Identify SSH service from banner.
    fn identify_ssh_service(banner: &str) -> (Option<String>, Option<String>) {
        if banner.contains("OpenSSH") {
            let version = Self::extract_version(banner, "OpenSSH_");
            (Some("OpenSSH".to_string()), version)
        } else if banner.contains("libssh") {
            let version = Self::extract_version(banner, "libssh_");
            (Some("libssh".to_string()), version)
        } else {
            (None, None)
        }
    }

    /// Identify FTP service from banner.
    fn identify_ftp_service(banner: &str) -> (Option<String>, Option<String>) {
        if banner.contains("vsftpd") || banner.contains("vsFTPd") {
            let version = Self::extract_version(banner, "vsFTPd");
            (Some("vsftpd".to_string()), version)
        } else if banner.contains("ProFTPD") {
            let version = Self::extract_version(banner, "ProFTPD");
            (Some("ProFTPD".to_string()), version)
        } else if banner.contains("FileZilla") {
            let version = Self::extract_version(banner, "FileZilla");
            (Some("FileZilla".to_string()), version)
        } else {
            (None, None)
        }
    }

    /// Extract version string from banner using a marker.
    fn extract_version(banner: &str, marker: &str) -> Option<String> {
        if let Some(start) = banner.find(marker) {
            let remainder = &banner[start + marker.len()..];
            // Get until space, /, or end of string
            let end = remainder
                .find(' ')
                .or_else(|| remainder.find('/'))
                .unwrap_or(remainder.len());
            let version = remainder[..end].trim();
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
        None
    }
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oui_lookup() {
        let fp = Fingerprinter::new();

        // From the bundled IEEE registry, not a hand-written table.
        let vendor = fp.lookup_vendor("00:00:0C:AA:BB:CC");
        assert_eq!(vendor, Some("Cisco Systems".to_string()));

        // Locally administered: never in the registry by design.
        let vendor = fp.lookup_vendor("A2:2D:98:D1:F6:8F");
        assert_eq!(vendor, None);

        let vendor = fp.lookup_vendor("FF:FF:FF:AA:BB:CC");
        assert_eq!(vendor, None);
    }

    #[test]
    fn test_oui_case_insensitive() {
        let fp = Fingerprinter::new();

        // Should work with lowercase
        let vendor = fp.lookup_vendor("00:00:0c:aa:bb:cc");
        assert_eq!(vendor, Some("Cisco Systems".to_string()));
    }

    #[test]
    fn test_ttl_detection() {
        let (os, confidence) = Fingerprinter::detect_os_from_ttl(128);
        assert_eq!(os, OsType::Windows);
        assert!(confidence > 0.8);

        let (os, confidence) = Fingerprinter::detect_os_from_ttl(64);
        assert_eq!(os, OsType::Linux);
        assert!(confidence > 0.7);
    }

    #[test]
    fn test_parse_http_server_header() {
        let header = "Apache/2.4.41 (Ubuntu)";
        let parsed = Fingerprinter::parse_http_server_header(header);
        assert_eq!(parsed, Some("Apache/2.4.41".to_string()));

        let header = "nginx/1.18.0";
        let parsed = Fingerprinter::parse_http_server_header(header);
        assert_eq!(parsed, Some("nginx/1.18.0".to_string()));

        let header = "Microsoft-IIS/10.0";
        let parsed = Fingerprinter::parse_http_server_header(header);
        assert!(parsed.is_some());
    }

    #[test]
    fn test_parse_ssh_banner() {
        let banner = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6";
        let parsed = Fingerprinter::parse_ssh_banner(banner);
        assert_eq!(parsed, Some("OpenSSH_7.4p1".to_string()));
    }

    #[test]
    fn test_guess_device_type() {
        let ports = vec![22, 80, 443];
        let device_type = Fingerprinter::guess_device_type(&ports);
        assert_eq!(device_type, "Linux Web Server");

        let ports = vec![3389, 445, 139];
        let device_type = Fingerprinter::guess_device_type(&ports);
        assert_eq!(device_type, "Windows Workstation");

        let ports = vec![22, 445, 139];
        let device_type = Fingerprinter::guess_device_type(&ports);
        assert_eq!(device_type, "Network Attached Storage (NAS)");
    }

    #[test]
    fn test_is_randomized_mac() {
        // Locally administered bit set: privacy addresses seen on real LANs.
        for mac in ["A2:2D:98:D1:F6:8F", "fa:b6:9b:92:72:8d", "4A:6A:DA:CF:4A:B5", "EE:5F:71:AA:ED:D0"] {
            assert!(is_randomized_mac(mac), "{mac} should be randomized");
        }
        // Globally unique, vendor-assigned.
        for mac in ["C4:B2:5B:0A:03:26", "90:61:0C:A3:12:94", "DC:46:28:56:3B:9B"] {
            assert!(!is_randomized_mac(mac), "{mac} should not be randomized");
        }
        assert!(!is_randomized_mac("nonsense"));
    }

    fn device(ip: &str, mac: Option<&str>, ports: &[u16]) -> Device {
        let mut device = Device::new(ip.parse().expect("valid ip"));
        device.mac = mac.map(str::to_string);
        device.open_ports = ports.to_vec();
        device
    }

    #[test]
    fn test_classify_network_position_is_certain() {
        let context = ClassifyContext {
            gateway: Some("192.168.1.1".parse().unwrap()),
            local: Some("192.168.1.50".parse().unwrap()),
        };

        let gateway = classify_device(&device("192.168.1.1", None, &[]), &context);
        assert_eq!(gateway.label, "Router / gateway");
        assert_eq!(gateway.confidence, 1.0);
        assert!(!gateway.is_guess());

        let local = classify_device(&device("192.168.1.50", None, &[]), &context);
        assert_eq!(local.label, "This device");
        assert_eq!(local.confidence, 1.0);
    }

    #[test]
    fn test_classify_by_ports() {
        let context = ClassifyContext::default();

        let printer = classify_device(&device("192.168.1.20", None, &[9100, 631]), &context);
        assert_eq!(printer.label, "Printer");

        let camera = classify_device(&device("192.168.1.21", None, &[554]), &context);
        assert_eq!(camera.label, "IP camera");

        let nas = classify_device(&device("192.168.1.22", None, &[2049, 445]), &context);
        assert_eq!(nas.label, "NAS / file server");

        let windows = classify_device(&device("192.168.1.23", None, &[3389, 445]), &context);
        assert_eq!(windows.label, "Windows Workstation");
    }

    #[test]
    fn test_classify_falls_back_to_randomized_mac() {
        let context = ClassifyContext::default();
        // No ports, no vendor, no name: the private MAC is the only signal.
        let classification =
            classify_device(&device("192.168.1.30", Some("A2:2D:98:D1:F6:8F"), &[]), &context);
        assert_eq!(classification.label, "Phone / laptop (private MAC)");
        assert!(classification.is_guess());
    }

    #[test]
    fn test_classify_unknown_device() {
        let context = ClassifyContext::default();
        let classification =
            classify_device(&device("192.168.1.40", Some("C4:B2:5B:0A:03:26"), &[]), &context);
        assert_eq!(classification.label, "Unknown device");
        assert!(classification.is_guess());
    }

    #[test]
    fn test_classify_from_hostname() {
        let context = ClassifyContext::default();
        let mut device = device("192.168.1.41", Some("C4:B2:5B:0A:03:26"), &[]);
        device.hostname = Some("android-7f3a".to_string());
        assert_eq!(classify_device(&device, &context).label, "Phone / tablet");
    }

    #[test]
    fn test_fingerprint_device_preserves_detected_os() {
        let fingerprinter = Fingerprinter::new();
        let mut device = Device::new("192.168.1.1".parse().expect("valid ip"));
        device.mac = Some("00:11:22:33:44:55".to_string());
        device.os = OsType::Linux;
        device.os_confidence = 0.8;

        fingerprinter.fingerprint_device(&mut device);

        assert_eq!(device.os, OsType::Linux);
        assert_eq!(device.os_confidence, 0.8);
    }

    #[test]
    fn test_fingerprint_device() {
        let fp = Fingerprinter::new();
        let mut device = Device::new("192.168.1.1".parse().unwrap());
        device.mac = Some("00:00:0C:AA:BB:CC".to_string());

        fp.fingerprint_device(&mut device);

        assert_eq!(device.vendor, Some("Cisco Systems".to_string()));
    }

    #[test]
    fn test_identify_http_service() {
        let (name, version) = Fingerprinter::identify_http_service("Apache/2.4.41 (Ubuntu)");
        assert_eq!(name, Some("Apache".to_string()));
        assert_eq!(version, Some("2.4.41".to_string()));

        let (name, version) = Fingerprinter::identify_http_service("nginx/1.18.0");
        assert_eq!(name, Some("nginx".to_string()));
        assert_eq!(version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_identify_ssh_service() {
        let (name, version) = Fingerprinter::identify_ssh_service("SSH-2.0-OpenSSH_7.4p1");
        assert_eq!(name, Some("OpenSSH".to_string()));
        assert_eq!(version, Some("7.4p1".to_string()));
    }

    #[test]
    fn test_identify_ftp_service() {
        let (name, _) = Fingerprinter::identify_ftp_service("220 (vsFTPd 3.0.3)");
        assert_eq!(name, Some("vsftpd".to_string()));
    }

    #[test]
    fn test_extract_version() {
        let version = Fingerprinter::extract_version("Apache/2.4.41 (Ubuntu)", "Apache/");
        assert_eq!(version, Some("2.4.41".to_string()));

        let version = Fingerprinter::extract_version("nginx/1.18.0", "nginx/");
        assert_eq!(version, Some("1.18.0".to_string()));
    }
}
