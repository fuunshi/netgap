//! mDNS/Bonjour service discovery for LAN devices.
//!
//! This module discovers services advertised via mDNS (Multicast DNS),
//! allowing detection of printers, AirPlay speakers, cameras, web servers, etc.

use anyhow::{anyhow, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::sleep;

/// Represents a discovered mDNS service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsService {
    pub name: String,
    pub service_type: ServiceType,
    pub ip: Option<Ipv4Addr>,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
    pub confidence: f32,  // 1.0 = verified, <1.0 = inferred
}

/// Classification of service types found on LAN.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ServiceType {
    /// Network printer (IPP, LPD, etc.)
    Printer,
    /// Audio/streaming device (AirPlay, Bluetooth, etc.)
    Speaker,
    /// IP camera or video device
    Camera,
    /// Web server or HTTP service
    WebServer,
    /// SSH/remote access
    RemoteAccess,
    /// Database service
    Database,
    /// File sharing (SMB, NFS, etc.)
    FileShare,
    /// Media server (DLNA, Plex, etc.)
    MediaServer,
    /// IoT device
    IoT,
    /// Unknown/other service
    Unknown,
}

impl ServiceType {
    /// Guess service type from mDNS service name/type.
    pub fn from_name(name: &str, service_type: &str) -> Self {
        let lower_name = name.to_lowercase();
        let lower_type = service_type.to_lowercase();

        // Check common service type indicators
        if lower_type.contains("ipp") || lower_type.contains("printer") {
            ServiceType::Printer
        } else if lower_type.contains("airplay")
            || lower_type.contains("raop")
            || lower_type.contains("audio")
            || lower_name.contains("speaker")
        {
            ServiceType::Speaker
        } else if lower_type.contains("rtsp")
            || lower_type.contains("camera")
            || lower_type.contains("http-cam")
        {
            ServiceType::Camera
        } else if lower_type.contains("http") || lower_type.contains("web") {
            ServiceType::WebServer
        } else if lower_type.contains("ssh") || lower_type.contains("sftp") {
            ServiceType::RemoteAccess
        } else if lower_type.contains("mysql")
            || lower_type.contains("postgres")
            || lower_type.contains("database")
        {
            ServiceType::Database
        } else if lower_type.contains("smb")
            || lower_type.contains("nfs")
            || lower_type.contains("afp")
        {
            ServiceType::FileShare
        } else if lower_type.contains("dlna")
            || lower_type.contains("upnp")
            || lower_type.contains("media")
        {
            ServiceType::MediaServer
        } else if lower_name.contains("iot")
            || lower_name.contains("smart")
            || lower_type.contains("homekit")
        {
            ServiceType::IoT
        } else {
            ServiceType::Unknown
        }
    }

    /// Get human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            ServiceType::Printer => "Printer",
            ServiceType::Speaker => "Speaker",
            ServiceType::Camera => "Camera",
            ServiceType::WebServer => "Web Server",
            ServiceType::RemoteAccess => "Remote Access",
            ServiceType::Database => "Database",
            ServiceType::FileShare => "File Share",
            ServiceType::MediaServer => "Media Server",
            ServiceType::IoT => "IoT Device",
            ServiceType::Unknown => "Unknown",
        }
    }
}

/// mDNS service discovery engine.
pub struct MdnsDiscovery;

impl MdnsDiscovery {
    /// Discover all services on the LAN via mDNS.
    /// Note: This is a framework implementation. Full mDNS discovery requires
    /// platform-specific socket and event handling.
    pub async fn discover_services(timeout_secs: u64) -> Result<Vec<MdnsService>> {
        let services = Vec::new();

        // TODO: Full implementation using mdns-sd crate:
        // 1. Create ServiceDaemon
        // 2. Browse common service types
        // 3. Collect ServiceFound events
        // 4. Parse service info and add to services vector
        //
        // Common service types to search:
        // - _ipp._tcp.local.          (Printers)
        // - _airplay._tcp.local.      (AirPlay speakers)
        // - _http._tcp.local.         (HTTP servers)
        // - _ssh._tcp.local.          (SSH services)
        // - _smb._tcp.local.          (SMB file sharing)
        // - _rtsp._tcp.local.         (RTSP cameras)
        //
        // This framework is ready for full implementation with
        // proper event handling and timeout logic.

        Ok(services)
    }

    /// Group services by device IP.
    pub fn group_by_device(services: &[MdnsService]) -> HashMap<Ipv4Addr, Vec<MdnsService>> {
        let mut grouped: HashMap<Ipv4Addr, Vec<MdnsService>> = HashMap::new();

        for service in services {
            if let Some(ip) = service.ip {
                grouped.entry(ip).or_insert_with(Vec::new).push(service.clone());
            }
        }

        grouped
    }

    /// Get summary statistics of discovered services.
    pub fn get_summary(services: &[MdnsService]) -> ServiceSummary {
        let mut summary = ServiceSummary::default();
        let mut type_counts = HashMap::new();

        for service in services {
            *type_counts.entry(service.service_type).or_insert(0) += 1;

            match service.service_type {
                ServiceType::Printer => summary.printers += 1,
                ServiceType::Speaker => summary.speakers += 1,
                ServiceType::Camera => summary.cameras += 1,
                ServiceType::WebServer => summary.web_servers += 1,
                ServiceType::RemoteAccess => summary.remote_access += 1,
                ServiceType::Database => summary.databases += 1,
                ServiceType::FileShare => summary.file_shares += 1,
                ServiceType::MediaServer => summary.media_servers += 1,
                ServiceType::IoT => summary.iot_devices += 1,
                ServiceType::Unknown => summary.unknown += 1,
            }
        }

        summary.total = services.len();
        summary
    }
}

/// Summary of discovered services by type.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ServiceSummary {
    pub total: usize,
    pub printers: usize,
    pub speakers: usize,
    pub cameras: usize,
    pub web_servers: usize,
    pub remote_access: usize,
    pub databases: usize,
    pub file_shares: usize,
    pub media_servers: usize,
    pub iot_devices: usize,
    pub unknown: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_from_ipp() {
        let svc_type = ServiceType::from_name("HP LaserJet", "_ipp._tcp.local.");
        assert_eq!(svc_type, ServiceType::Printer);
    }

    #[test]
    fn test_service_type_from_airplay() {
        let svc_type = ServiceType::from_name("Living Room", "_airplay._tcp.local.");
        assert_eq!(svc_type, ServiceType::Speaker);
    }

    #[test]
    fn test_service_type_from_http() {
        let svc_type = ServiceType::from_name("Web Server", "_http._tcp.local.");
        assert_eq!(svc_type, ServiceType::WebServer);
    }

    #[test]
    fn test_service_type_from_ssh() {
        let svc_type = ServiceType::from_name("SSH Server", "_ssh._tcp.local.");
        assert_eq!(svc_type, ServiceType::RemoteAccess);
    }

    #[test]
    fn test_service_type_display() {
        assert_eq!(ServiceType::Printer.display_name(), "Printer");
        assert_eq!(ServiceType::Speaker.display_name(), "Speaker");
        assert_eq!(ServiceType::Camera.display_name(), "Camera");
    }

    #[test]
    fn test_group_by_device() {
        let services = vec![
            MdnsService {
                name: "Service1".to_string(),
                service_type: ServiceType::Printer,
                ip: Some(Ipv4Addr::new(192, 168, 1, 10)),
                port: 631,
                txt_records: HashMap::new(),
                confidence: 1.0,
            },
            MdnsService {
                name: "Service2".to_string(),
                service_type: ServiceType::WebServer,
                ip: Some(Ipv4Addr::new(192, 168, 1, 10)),
                port: 80,
                txt_records: HashMap::new(),
                confidence: 1.0,
            },
            MdnsService {
                name: "Service3".to_string(),
                service_type: ServiceType::Speaker,
                ip: Some(Ipv4Addr::new(192, 168, 1, 20)),
                port: 5000,
                txt_records: HashMap::new(),
                confidence: 1.0,
            },
        ];

        let grouped = MdnsDiscovery::group_by_device(&services);

        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&Ipv4Addr::new(192, 168, 1, 10)].len(), 2);
        assert_eq!(grouped[&Ipv4Addr::new(192, 168, 1, 20)].len(), 1);
    }

    #[test]
    fn test_service_summary() {
        let services = vec![
            MdnsService {
                name: "Printer1".to_string(),
                service_type: ServiceType::Printer,
                ip: Some(Ipv4Addr::new(192, 168, 1, 10)),
                port: 631,
                txt_records: HashMap::new(),
                confidence: 1.0,
            },
            MdnsService {
                name: "Printer2".to_string(),
                service_type: ServiceType::Printer,
                ip: Some(Ipv4Addr::new(192, 168, 1, 11)),
                port: 631,
                txt_records: HashMap::new(),
                confidence: 1.0,
            },
            MdnsService {
                name: "Speaker1".to_string(),
                service_type: ServiceType::Speaker,
                ip: Some(Ipv4Addr::new(192, 168, 1, 20)),
                port: 5000,
                txt_records: HashMap::new(),
                confidence: 1.0,
            },
        ];

        let summary = MdnsDiscovery::get_summary(&services);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.printers, 2);
        assert_eq!(summary.speakers, 1);
        assert_eq!(summary.unknown, 0);
    }

    #[test]
    fn test_mdns_service_creation() {
        let service = MdnsService {
            name: "Test Service".to_string(),
            service_type: ServiceType::WebServer,
            ip: Some(Ipv4Addr::new(192, 168, 1, 100)),
            port: 80,
            txt_records: HashMap::new(),
            confidence: 1.0,
        };

        assert_eq!(service.name, "Test Service");
        assert_eq!(service.port, 80);
        assert_eq!(service.confidence, 1.0);
    }
}
