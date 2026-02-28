//! Device fingerprinting engine.
//!
//! This module implements advanced device fingerprinting including:
//! - MAC address OUI (Organizationally Unique Identifier) vendor lookup
//! - TTL-based operating system detection
//! - Service version extraction from banners
//! - Device name and capability inference

use netgap_core::{Device, OsType};
use std::collections::HashMap;

/// Fingerprinter for device OS and vendor identification.
pub struct Fingerprinter {
    oui_database: HashMap<String, String>,
}

impl Fingerprinter {
    /// Create a new fingerprinter with built-in OUI database.
    pub fn new() -> Self {
        Fingerprinter {
            oui_database: Self::build_oui_db(),
        }
    }

    /// Build a basic OUI database (real implementation would load from file).
    fn build_oui_db() -> HashMap<String, String> {
        let mut db = HashMap::new();

        // Common vendors - MAC OUI prefixes (first 24 bits)
        db.insert("00:00:00".to_string(), "Xerox".to_string());
        db.insert("00:00:0C".to_string(), "Cisco".to_string());
        db.insert("00:00:5E".to_string(), "IANA".to_string());
        db.insert("00:05:00".to_string(), "Apple".to_string());
        db.insert("00:0F:00".to_string(), "Apple".to_string());
        db.insert("00:1E:33".to_string(), "Netgear".to_string());
        db.insert("00:22:B0".to_string(), "Cisco".to_string());
        db.insert("00:30:48".to_string(), "Supermicro".to_string());
        db.insert("00:50:F2".to_string(), "Microsoft".to_string());
        db.insert("08:00:27".to_string(), "Oracle".to_string()); // VirtualBox
        db.insert("40:C2:BA".to_string(), "Realtek".to_string());
        db.insert("52:54:00".to_string(), "QEMU".to_string());
        db.insert("94:BB:43".to_string(), "Qualcomm".to_string());
        db.insert("9E:FE:56".to_string(), "Docker".to_string());
        db.insert("AC:DE:48".to_string(), "Google".to_string()); // Nest
        db.insert("B4:2E:99".to_string(), "TP-Link".to_string());
        db.insert("DC:A6:32".to_string(), "Tp-Link".to_string());
        db.insert("D0:17:C2".to_string(), "D-Link".to_string());
        db.insert("E0:91:F5".to_string(), "ASUS".to_string());
        db.insert("F4:6D:04".to_string(), "AVM".to_string()); // Fritzbox

        db
    }

    /// Look up vendor name from MAC address.
    pub fn lookup_vendor(&self, mac: &str) -> Option<String> {
        // MAC format: XX:XX:XX:XX:XX:XX, OUI is first 3 octets
        let parts: Vec<&str> = mac.split(':').collect();
        if parts.len() < 3 {
            return None;
        }

        let oui = format!("{}:{}:{}", parts[0], parts[1], parts[2]).to_uppercase();
        self.oui_database.get(&oui).cloned()
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

        // For now, TTL detection would require ICMP echo, which we'll implement in a follow-up
        // Here we just set it to Unknown with low confidence
        device.os = OsType::Unknown;
        device.os_confidence = 0.0;
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
        let has_https = open_ports.contains(&443);
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

        // Test Cisco OUI
        let vendor = fp.lookup_vendor("00:00:0C:AA:BB:CC");
        assert_eq!(vendor, Some("Cisco".to_string()));

        // Test unknown OUI
        let vendor = fp.lookup_vendor("FF:FF:FF:AA:BB:CC");
        assert_eq!(vendor, None);
    }

    #[test]
    fn test_oui_case_insensitive() {
        let fp = Fingerprinter::new();

        // Should work with lowercase
        let vendor = fp.lookup_vendor("00:00:0c:aa:bb:cc");
        assert_eq!(vendor, Some("Cisco".to_string()));
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
    fn test_fingerprint_device() {
        let fp = Fingerprinter::new();
        let mut device = Device::new("192.168.1.1".parse().unwrap());
        device.mac = Some("00:00:0C:AA:BB:CC".to_string());

        fp.fingerprint_device(&mut device);

        assert_eq!(device.vendor, Some("Cisco".to_string()));
    }
}
