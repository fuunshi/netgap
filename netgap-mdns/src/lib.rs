//! mDNS/Bonjour service discovery for LAN devices.
//!
//! Devices that advertise over mDNS name *themselves* — "HP LaserJet MFP",
//! "Living Room TV", "Sonos Play:5" — which is information no amount of packet
//! analysis can recover. It is also the only way to describe the many phones
//! and tablets that randomize their MAC address and so carry no vendor data.
//!
//! Discovery browses a set of common service types ([`DEFAULT_SERVICE_TYPES`])
//! and resolves what answers, within a caller-supplied time budget.

use anyhow::{bail, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Service types browsed by default.
///
/// Chosen to cover what is actually found on home and small-office networks:
/// printers, speakers and streaming sticks, cameras, file sharing, remote
/// access and smart-home devices.
pub const DEFAULT_SERVICE_TYPES: &[&str] = &[
    "_ipp._tcp.local.",             // IPP printers
    "_printer._tcp.local.",         // LPD printers
    "_pdl-datastream._tcp.local.",  // raw printing
    "_airplay._tcp.local.",         // AirPlay video and audio
    "_raop._tcp.local.",            // AirPlay audio
    "_googlecast._tcp.local.",      // Chromecast and Google TVs
    "_sonos._tcp.local.",           // Sonos speakers
    "_spotify-connect._tcp.local.", // Spotify Connect
    "_http._tcp.local.",            // web interfaces
    "_https._tcp.local.",
    "_ssh._tcp.local.", // remote access
    "_sftp-ssh._tcp.local.",
    "_smb._tcp.local.", // file sharing
    "_afpovertcp._tcp.local.",
    "_nfs._tcp.local.",
    "_rtsp._tcp.local.",           // IP cameras
    "_hap._tcp.local.",            // HomeKit
    "_matter._tcp.local.",         // Matter smart home
    "_workstation._tcp.local.",    // workstations and file servers
    "_device-info._tcp.local.",    // device metadata
    "_companion-link._tcp.local.", // Apple devices
];

/// Represents a discovered mDNS service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsService {
    /// Instance name as advertised, e.g. "HP LaserJet MFP". This is the name
    /// the owner gave the device, so it is the friendliest thing to display.
    pub name: String,
    /// The mDNS hostname, e.g. "hp-laserjet.local."
    #[serde(default)]
    pub hostname: Option<String>,
    pub service_type: ServiceType,
    pub ip: Option<Ipv4Addr>,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
    pub confidence: f32, // 1.0 = verified, <1.0 = inferred
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
        if lower_type.contains("ipp")
            || lower_type.contains("printer")
            || lower_type.contains("pdl-datastream")
        {
            ServiceType::Printer
        } else if lower_type.contains("airplay")
            || lower_type.contains("raop")
            || lower_type.contains("audio")
            || lower_type.contains("sonos")
            || lower_type.contains("spotify")
            || lower_name.contains("speaker")
        {
            ServiceType::Speaker
        } else if lower_type.contains("rtsp")
            || lower_type.contains("camera")
            || lower_type.contains("http-cam")
        {
            ServiceType::Camera
        } else if lower_type.contains("googlecast") || lower_type.contains("dlna") {
            ServiceType::MediaServer
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
        } else if lower_type.contains("upnp") || lower_type.contains("media") {
            ServiceType::MediaServer
        } else if lower_name.contains("iot")
            || lower_name.contains("smart")
            || lower_type.contains("homekit")
            || lower_type.contains("hap")
            || lower_type.contains("matter")
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

    /// A device-type label for a host offering this service.
    ///
    /// Distinct from [`Self::display_name`] because it describes the *device*,
    /// which is what the discovery report shows.
    pub fn device_label(&self) -> &'static str {
        match self {
            ServiceType::Printer => "Printer",
            ServiceType::Speaker => "Speaker",
            ServiceType::Camera => "IP camera",
            ServiceType::WebServer => "Web device",
            ServiceType::RemoteAccess => "Server",
            ServiceType::Database => "Server",
            ServiceType::FileShare => "NAS / file server",
            ServiceType::MediaServer => "Media device",
            ServiceType::IoT => "IoT device",
            ServiceType::Unknown => "Unknown device",
        }
    }
}

/// mDNS service discovery engine.
pub struct MdnsDiscovery;

impl MdnsDiscovery {
    /// Whether mDNS discovery is actually implemented.
    ///
    /// Kept so callers written against the earlier stub still compile; it is
    /// now always true.
    pub const IMPLEMENTED: bool = true;

    /// Discover all services on the LAN via mDNS.
    ///
    /// Blocks for up to `timeout_secs` while answers arrive, then returns what
    /// was found. An empty result is a normal outcome on networks where
    /// multicast is blocked or nothing advertises.
    pub async fn discover_services(timeout_secs: u64) -> Result<Vec<MdnsService>> {
        Self::discover_with_types(timeout_secs, DEFAULT_SERVICE_TYPES).await
    }

    /// Discover a specific set of service types.
    pub async fn discover_with_types(
        timeout_secs: u64,
        service_types: &[&str],
    ) -> Result<Vec<MdnsService>> {
        let service_types: Vec<String> = service_types.iter().map(|s| s.to_string()).collect();
        let timeout = Duration::from_secs(timeout_secs.max(1));

        // mdns-sd owns its own threads and hands back a blocking channel, so
        // the browse runs off the async runtime.
        tokio::task::spawn_blocking(move || browse(&service_types, timeout))
            .await
            .context("mDNS discovery task panicked")?
    }

    /// Group services by device IP.
    pub fn group_by_device(services: &[MdnsService]) -> HashMap<Ipv4Addr, Vec<MdnsService>> {
        let mut grouped: HashMap<Ipv4Addr, Vec<MdnsService>> = HashMap::new();

        for service in services {
            if let Some(ip) = service.ip {
                grouped.entry(ip).or_default().push(service.clone());
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

/// What merging mDNS results into a device list changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MergeOutcome {
    /// Devices that gained a name.
    pub named: usize,
    /// Devices whose type was refined by what they advertise.
    pub classified: usize,
    /// Hosts that mDNS revealed and other discovery had missed.
    pub added: usize,
}

impl MergeOutcome {
    /// Whether anything changed.
    pub fn is_empty(&self) -> bool {
        self.named == 0 && self.classified == 0 && self.added == 0
    }
}

/// Fold mDNS results into the devices found by ARP or TCP discovery.
///
/// Fills in names, refines device types, and adds hosts that only advertise
/// themselves over mDNS (common when the unprivileged TCP sweep is in use).
/// Existing names and types are never overwritten — mDNS fills gaps rather than
/// replacing what is already known.
pub fn merge_into_devices(
    devices: &mut Vec<netgap_core::Device>,
    services: &[MdnsService],
) -> MergeOutcome {
    use std::net::{IpAddr, Ipv4Addr};

    let mut outcome = MergeOutcome::default();
    let grouped = MdnsDiscovery::group_by_device(services);

    for (ip, device) in devices.iter_mut().enumerate() {
        let _ = ip;
        let IpAddr::V4(ipv4) = device.ip else {
            continue;
        };
        let Some(found) = grouped.get(&ipv4) else {
            continue;
        };

        // The friendliest name wins: a user-assigned instance name over a
        // machine hostname.
        if device.hostname.is_none() {
            if let Some(name) = found
                .iter()
                .map(|service| &service.name)
                .find(|name| !name.is_empty())
            {
                device.hostname = Some(name.clone());
                outcome.named += 1;
            }
        }

        let unclassified = device
            .device_type
            .as_deref()
            .map(|label| label == "Unknown device")
            .unwrap_or(true);

        if unclassified {
            // Prefer the most specific service the host advertises.
            let label = found
                .iter()
                .map(|service| service.service_type)
                .filter(|service_type| *service_type != ServiceType::Unknown)
                .map(|service_type| service_type.device_label())
                .next();

            if let Some(label) = label {
                device.device_type = Some(label.to_string());
                outcome.classified += 1;
            }
        }
    }

    // Hosts that only mDNS knows about.
    let known: std::collections::HashSet<Ipv4Addr> = devices
        .iter()
        .filter_map(|device| match device.ip {
            IpAddr::V4(ipv4) => Some(ipv4),
            IpAddr::V6(_) => None,
        })
        .collect();

    for (ip, found) in grouped {
        if known.contains(&ip) {
            continue;
        }

        let mut device = netgap_core::Device::new(IpAddr::V4(ip));
        device.hostname = found
            .iter()
            .map(|service| service.name.clone())
            .find(|name| !name.is_empty());
        device.device_type = found
            .iter()
            .map(|service| service.service_type)
            .filter(|service_type| *service_type != ServiceType::Unknown)
            .map(|service_type| service_type.device_label())
            .next()
            .map(str::to_string);

        devices.push(device);
        outcome.added += 1;
    }

    outcome
}

/// Browse for services until the budget expires.
fn browse(service_types: &[String], timeout: Duration) -> Result<Vec<MdnsService>> {
    let daemon = ServiceDaemon::new().context("starting the mDNS daemon")?;

    let mut receivers = Vec::new();
    for service_type in service_types {
        match daemon.browse(service_type) {
            Ok(receiver) => receivers.push((service_type.clone(), receiver)),
            Err(error) => eprintln!("⚠️  mDNS: cannot browse {service_type}: {error}"),
        }
    }

    if receivers.is_empty() {
        let _ = daemon.shutdown();
        bail!("mDNS daemon accepted none of the requested service types");
    }

    // Keyed by full name so a service answering on several interfaces, or
    // re-announcing itself, is only reported once.
    let mut found: HashMap<String, MdnsService> = HashMap::new();
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        for (_, receiver) in &receivers {
            while let Ok(event) = receiver.try_recv() {
                if let ServiceEvent::ServiceResolved(info) = event {
                    if let Some(service) = service_from_info(&info) {
                        found.insert(info.get_fullname().to_string(), service);
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    for (service_type, _) in &receivers {
        let _ = daemon.stop_browse(service_type);
    }
    let _ = daemon.shutdown();

    let mut services: Vec<MdnsService> = found.into_values().collect();
    services.sort_by(|a, b| {
        a.service_type
            .display_name()
            .cmp(b.service_type.display_name())
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(services)
}

/// Convert a resolved mDNS record into our own type.
fn service_from_info(info: &ServiceInfo) -> Option<MdnsService> {
    let service_type = info.get_type();
    let name = instance_name(info.get_fullname(), service_type);

    if name.is_empty() {
        return None;
    }

    let ip = info.get_addresses_v4().into_iter().next().copied();

    let txt_records = info
        .get_properties()
        .iter()
        .map(|property| (property.key().to_string(), property.val_str().to_string()))
        .collect();

    let hostname = {
        let hostname = info.get_hostname().trim_end_matches('.').to_string();
        (!hostname.is_empty()).then_some(hostname)
    };

    Some(MdnsService {
        name,
        hostname,
        service_type: ServiceType::from_name(info.get_fullname(), service_type),
        ip,
        port: info.get_port(),
        txt_records,
        confidence: 1.0,
    })
}

/// Extract the instance name from a full service name.
///
/// mDNS full names look like `HP LaserJet MFP._ipp._tcp.local.`; the part the
/// owner chose is everything before the service type.
fn instance_name(fullname: &str, service_type: &str) -> String {
    let fullname = fullname.trim_end_matches('.');
    let service_type = service_type.trim_end_matches('.');

    // The service type may itself be a suffix of the full name.
    if let Some(stripped) = fullname.strip_suffix(service_type) {
        return stripped.trim_end_matches('.').trim().to_string();
    }

    // Fall back to the first label, which is the instance name in practice
    // (mDNS escapes embedded dots).
    fullname
        .split('.')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
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
    use netgap_core::Device;
    use std::net::IpAddr;

    fn service(name: &str, service_type: ServiceType, ip: &str, port: u16) -> MdnsService {
        MdnsService {
            name: name.to_string(),
            hostname: None,
            service_type,
            ip: Some(ip.parse().expect("valid ip")),
            port,
            txt_records: HashMap::new(),
            confidence: 1.0,
        }
    }

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
    fn test_service_types_beyond_the_original_stub() {
        assert_eq!(
            ServiceType::from_name("Office", "_pdl-datastream._tcp.local."),
            ServiceType::Printer
        );
        assert_eq!(
            ServiceType::from_name("Living Room", "_googlecast._tcp.local."),
            ServiceType::MediaServer
        );
        assert_eq!(
            ServiceType::from_name("Kitchen", "_sonos._tcp.local."),
            ServiceType::Speaker
        );
        assert_eq!(
            ServiceType::from_name("Front Door", "_hap._tcp.local."),
            ServiceType::IoT
        );
        assert_eq!(
            ServiceType::from_name("Office", "_smb._tcp.local."),
            ServiceType::FileShare
        );
        assert_eq!(
            ServiceType::from_name("Cam", "_rtsp._tcp.local."),
            ServiceType::Camera
        );
    }

    #[test]
    fn test_group_by_device() {
        let services = vec![
            service("Service1", ServiceType::Printer, "192.168.1.10", 631),
            service("Service2", ServiceType::WebServer, "192.168.1.10", 80),
            service("Service3", ServiceType::Speaker, "192.168.1.20", 5000),
        ];

        let grouped = MdnsDiscovery::group_by_device(&services);

        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[&Ipv4Addr::new(192, 168, 1, 10)].len(), 2);
        assert_eq!(grouped[&Ipv4Addr::new(192, 168, 1, 20)].len(), 1);
    }

    #[test]
    fn test_service_summary() {
        let services = vec![
            service("Printer1", ServiceType::Printer, "192.168.1.10", 631),
            service("Printer2", ServiceType::Printer, "192.168.1.11", 631),
            service("Speaker1", ServiceType::Speaker, "192.168.1.20", 5000),
        ];

        let summary = MdnsDiscovery::get_summary(&services);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.printers, 2);
        assert_eq!(summary.speakers, 1);
        assert_eq!(summary.unknown, 0);
    }

    #[test]
    fn test_mdns_service_creation() {
        let service = service("Test Service", ServiceType::WebServer, "192.168.1.100", 80);

        assert_eq!(service.name, "Test Service");
        assert_eq!(service.port, 80);
        assert_eq!(service.confidence, 1.0);
    }

    #[test]
    fn test_instance_name_extraction() {
        assert_eq!(
            instance_name("HP LaserJet MFP._ipp._tcp.local.", "_ipp._tcp.local."),
            "HP LaserJet MFP"
        );
        // Trailing dot variants and a name containing dots.
        assert_eq!(
            instance_name(
                "J. Smith's iPad._airplay._tcp.local.",
                "_airplay._tcp.local."
            ),
            "J. Smith's iPad"
        );
        assert_eq!(
            instance_name("Living Room._airplay._tcp.local.", "_airplay._tcp.local"),
            "Living Room"
        );
    }

    #[test]
    fn test_service_from_info_maps_fields() {
        let info = ServiceInfo::new(
            "_ipp._tcp.local.",
            "HP LaserJet MFP",
            "hp-laserjet.local.",
            "192.168.1.50",
            631,
            &[("ty", "HP LaserJet MFP")][..],
        )
        .expect("valid service info");

        let service = service_from_info(&info).expect("should convert");

        assert_eq!(service.name, "HP LaserJet MFP");
        assert_eq!(service.service_type, ServiceType::Printer);
        assert_eq!(service.ip, Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(service.port, 631);
        assert_eq!(service.hostname.as_deref(), Some("hp-laserjet.local"));
        assert_eq!(
            service.txt_records.get("ty").map(String::as_str),
            Some("HP LaserJet MFP")
        );
        assert_eq!(service.confidence, 1.0);
    }

    #[test]
    fn test_merge_names_and_classifies_devices() {
        let mut devices = vec![Device::new("192.168.1.50".parse::<IpAddr>().unwrap())];
        devices[0].device_type = Some("Unknown device".to_string());

        let services = vec![service(
            "HP LaserJet MFP",
            ServiceType::Printer,
            "192.168.1.50",
            631,
        )];
        let outcome = merge_into_devices(&mut devices, &services);

        assert_eq!(outcome.named, 1);
        assert_eq!(outcome.classified, 1);
        assert_eq!(outcome.added, 0);
        assert_eq!(devices[0].hostname.as_deref(), Some("HP LaserJet MFP"));
        assert_eq!(devices[0].device_type.as_deref(), Some("Printer"));
    }

    #[test]
    fn test_merge_does_not_overwrite_what_is_known() {
        let mut devices = vec![Device::new("192.168.1.50".parse::<IpAddr>().unwrap())];
        devices[0].hostname = Some("nas.local".to_string());
        devices[0].device_type = Some("Windows File Server".to_string());

        let services = vec![service(
            "Some Printer",
            ServiceType::Printer,
            "192.168.1.50",
            631,
        )];
        let outcome = merge_into_devices(&mut devices, &services);

        assert_eq!(outcome, MergeOutcome::default());
        assert_eq!(devices[0].hostname.as_deref(), Some("nas.local"));
        assert_eq!(
            devices[0].device_type.as_deref(),
            Some("Windows File Server")
        );
    }

    #[test]
    fn test_merge_adds_hosts_only_mdns_knows() {
        let mut devices = vec![Device::new("192.168.1.50".parse::<IpAddr>().unwrap())];

        let services = vec![
            service(
                "Living Room TV",
                ServiceType::MediaServer,
                "192.168.1.60",
                8009,
            ),
            service("Unknown Thing", ServiceType::Unknown, "192.168.1.61", 1234),
        ];
        let outcome = merge_into_devices(&mut devices, &services);

        assert_eq!(outcome.added, 2);
        assert_eq!(devices.len(), 3);

        let tv = devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.1.60")
            .unwrap();
        assert_eq!(tv.hostname.as_deref(), Some("Living Room TV"));
        assert_eq!(tv.device_type.as_deref(), Some("Media device"));

        // A service we cannot classify still contributes its name.
        let unknown = devices
            .iter()
            .find(|d| d.ip.to_string() == "192.168.1.61")
            .unwrap();
        assert_eq!(unknown.hostname.as_deref(), Some("Unknown Thing"));
        assert!(unknown.device_type.is_none());
    }

    #[test]
    fn test_merge_ignores_services_without_an_address() {
        let mut devices = vec![Device::new("192.168.1.50".parse::<IpAddr>().unwrap())];
        let mut orphan = service("No Address", ServiceType::Printer, "192.168.1.70", 631);
        orphan.ip = None;

        let outcome = merge_into_devices(&mut devices, &[orphan]);

        assert!(outcome.is_empty());
        assert_eq!(devices.len(), 1);
    }

    /// Exercises a real daemon end to end: announce a service, browse for it,
    /// and convert what comes back.
    ///
    /// Ignored by default, and worth understanding before enabling. It
    /// announces and browses from the same host, so passing requires the
    /// machine to deliver multicast back to its own sockets. Plenty of
    /// environments do not — Wi-Fi drivers in power save, and containers —
    /// and there the test fails for reasons that have nothing to do with this
    /// code. Check with a bare socket pair first; on such a host the browse
    /// path can only be exercised against devices on another machine.
    #[test]
    #[ignore = "needs working multicast loopback; verify with a raw socket test first"]
    fn test_live_browse_finds_a_registered_service() {
        // Announce on the interface that carries traffic, not loopback: a
        // loopback registration is only published on lo, so a browse on the
        // real interface would never see it.
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("udp socket");
        probe.connect("1.1.1.1:80").expect("route lookup");
        let local_ip = probe.local_addr().expect("local addr").ip().to_string();

        let daemon = ServiceDaemon::new().expect("daemon");
        let info = ServiceInfo::new(
            "_netgap-test._tcp.local.",
            "netgap test service",
            "netgap-test.local.",
            local_ip.as_str(),
            9999,
            &[("test", "1")][..],
        )
        .expect("service info");
        daemon.register(info).expect("register");

        let services = browse(
            &["_netgap-test._tcp.local.".to_string()],
            Duration::from_secs(5),
        )
        .expect("browse");

        let _ = daemon.shutdown();

        assert!(
            services.iter().any(|s| s.name == "netgap test service"),
            "expected the registered service to be discovered, got {services:?}"
        );
    }
}
