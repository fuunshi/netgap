//! UPnP Internet Gateway Device discovery, and the port mappings it holds.
//!
//! UPnP lets any device on a network ask the router to publish a port to the
//! internet, with no authentication and no approval from the owner. The
//! mappings that result are invisible in the router's web interface on many
//! models, which is what makes them worth reading: `netgap upnp` asks the
//! gateway what it has actually published.
//!
//! Three protocols, in order:
//!
//! 1. **SSDP** (UDP 1900) — a multicast `M-SEARCH` asking for
//!    `InternetGatewayDevice`. The reply carries a `LOCATION` URL.
//! 2. **HTTP** — fetch that URL: an XML description of the device that names
//!    the control URL for the WAN connection service.
//! 3. **SOAP** — `GetGenericPortMappingEntry` for index 0, 1, 2… until the
//!    device answers 713 ("no such entry").
//!
//! All three are read-only. Nothing here adds, edits or removes a mapping: the
//! check answers "what is published", and changes the router only when the
//! owner does.
//!
//! Discovery uses SSDP because it is the only way to find the control URL
//! without already knowing the router's model. Some routers filter multicast
//! between clients (the same AP policy that breaks mDNS), so `discover_on` can
//! ask a known address directly — the gateway's own address usually works even
//! when the multicast does not.

use anyhow::{anyhow, bail, Context, Result};
use quick_xml::escape::unescape;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

/// Where an SSDP search is sent when nobody says otherwise.
const SSDP_MULTICAST: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);

/// The device types worth asking for. Version 2 is what most current routers
/// claim; version 1 is still common on older firmware.
const SEARCH_TARGETS: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
];

/// How many port mappings to read before assuming something is wrong.
///
/// A home router holds single digits. A device that claims more than this is
/// either unusual or answering in a loop, and either way the rest is not worth
/// waiting for.
const MAX_MAPPINGS: usize = 64;

/// How long to wait for one HTTP or SOAP exchange.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// One inbound port the router has published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub external_port: u16,
    pub protocol: String,
    pub internal_client: String,
    pub internal_port: u16,
    pub enabled: bool,
    pub description: String,
    pub lease_seconds: u32,
}

/// A router that answered, and what it has published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Igd {
    /// The description URL the SSDP reply named.
    pub location: String,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    /// The service the mappings were read through, e.g.
    /// `urn:schemas-upnp-org:service:WANIPConnection:1`.
    pub service_type: String,
    pub control_url: String,
    pub mappings: Vec<PortMapping>,
}

impl Igd {
    /// The mappings that are actually open, sorted by external port.
    pub fn enabled_mappings(&self) -> Vec<&PortMapping> {
        let mut open: Vec<&PortMapping> = self
            .mappings
            .iter()
            .filter(|mapping| mapping.enabled)
            .collect();
        open.sort_by_key(|mapping| mapping.external_port);
        open
    }

    /// A name for the router, falling back through what it published.
    pub fn name(&self) -> Option<&str> {
        self.friendly_name
            .as_deref()
            .or(self.model.as_deref())
            .or(self.manufacturer.as_deref())
    }
}

// ------------------------------------------------------------- discovery ---

/// Ask the multicast group who is an internet gateway.
pub async fn discover(timeout: Duration) -> Result<Vec<String>> {
    search(&[SSDP_MULTICAST], timeout).await
}

/// Ask one host directly, for when multicast does not reach the router.
pub async fn discover_on(host: IpAddr, timeout: Duration) -> Result<Vec<String>> {
    search(&[SocketAddr::new(host, 1900)], timeout).await
}

/// Send the searches and collect the distinct `LOCATION` URLs that answer.
async fn search(targets: &[SocketAddr], window: Duration) -> Result<Vec<String>> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("opening a UDP socket for UPnP discovery")?;

    for target in targets {
        for service in SEARCH_TARGETS {
            let message = format!(
                "M-SEARCH * HTTP/1.1\r\n\
                 HOST: 239.255.255.250:1900\r\n\
                 MAN: \"ssdp:discover\"\r\n\
                 MX: 2\r\n\
                 ST: {service}\r\n\r\n"
            );
            // A refused send (no route) is not fatal: the other target may work.
            let _ = socket.send_to(message.as_bytes(), target).await;
        }
    }

    let deadline = Instant::now() + window;
    let mut buffer = [0u8; 2048];
    let mut locations: Vec<String> = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(Ok((read, _from))) => {
                let text = String::from_utf8_lossy(&buffer[..read]);
                if let Some(location) = location_header(&text) {
                    if !locations.contains(&location) {
                        locations.push(location);
                    }
                }
            }
            // Timed out, or the socket failed: either way there is nothing
            // more to read.
            _ => break,
        }
    }

    Ok(locations)
}

/// The `LOCATION` header of an SSDP response.
///
/// Header names are case-insensitive, and the response is not XML — it is a
/// block of HTTP-like headers, which is why this is a line scan rather than a
/// parser.
pub fn location_header(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("location") {
            return None;
        }
        let value = value.trim();
        if value.starts_with("http://") || value.starts_with("https://") {
            Some(value.to_string())
        } else {
            None
        }
    })
}

// --------------------------------------------------------------- querying ---

/// Ask one router what it has published.
pub async fn query(location: &str) -> Result<Igd> {
    let description = http_request(location, "GET", &[], None)
        .await
        .with_context(|| format!("reading the gateway description at {location}"))?;

    let parts = parse_description(&description).ok_or_else(|| {
        anyhow!("{location} did not describe an internet gateway with a WAN connection service")
    })?;

    let control_url = resolve_url(location, &parts.control_url);
    let mut mappings = Vec::new();

    for index in 0..MAX_MAPPINGS {
        let body = port_mapping_request(&parts.service_type, index);
        let action = format!("\"{}#GetGenericPortMappingEntry\"", parts.service_type);
        let headers = [
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPAction", action.as_str()),
        ];

        let response = match http_request(&control_url, "POST", &headers, Some(&body)).await {
            Ok(response) => response,
            Err(error) => {
                if index == 0 {
                    return Err(error).context("asking the gateway for its port mappings");
                }
                // A device that answers some indices and then fails has told
                // us what it can.
                break;
            }
        };

        match parse_port_mapping(&response) {
            Some(mapping) => mappings.push(mapping),
            None => {
                // 713 is the spec's "no such entry": the end of the list.
                let code = soap_error_code(&response);
                if index == 0 && code.is_some() && code != Some(713) {
                    bail!(
                        "the gateway refused to list its port mappings (UPnP error {})",
                        code.unwrap_or_default()
                    );
                }
                break;
            }
        }
    }

    Ok(Igd {
        location: location.to_string(),
        friendly_name: parts.friendly_name,
        manufacturer: parts.manufacturer,
        model: parts.model,
        service_type: parts.service_type,
        control_url,
        mappings,
    })
}

/// Discover and read in one step.
///
/// The multicast and the fallback address are asked at the same time rather
/// than one after the other: the wait is the expensive part of this check, and
/// asking twice over the same window costs a scan nothing extra.
pub async fn inspect(fallback: Option<IpAddr>, window: Duration) -> Result<Option<Igd>> {
    let mut targets = vec![SSDP_MULTICAST];
    if let Some(host) = fallback {
        targets.push(SocketAddr::new(host, 1900));
    }

    for location in search(&targets, window).await? {
        // A device that answers SSDP but not HTTP is not worth failing over:
        // the next one might be the router.
        if let Ok(igd) = query(&location).await {
            return Ok(Some(igd));
        }
    }

    Ok(None)
}

/// A GET or POST, returning the response body.
///
/// HTTP/1.0 with `Connection: close`, which is what UPnP devices expect and
/// what makes the end of the body unambiguous.
async fn http_request(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Result<String> {
    let (authority, path) = split_url(url)?;

    let mut request = format!(
        "{method} {path} HTTP/1.0\r\nHost: {authority}\r\nUser-Agent: netgap\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    if let Some(body) = body {
        request.push_str(body);
    }

    let connect = tokio::time::timeout(REQUEST_TIMEOUT, TcpStream::connect(authority.as_str()));
    let mut stream = connect
        .await
        .map_err(|_| anyhow!("connecting to {authority} timed out"))?
        .with_context(|| format!("connecting to {authority}"))?;

    tokio::time::timeout(REQUEST_TIMEOUT, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| anyhow!("sending the request to {authority} timed out"))??;

    let response = crate::read_until_close(&mut stream, 64 * 1024).await;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or((response.as_str(), ""));
    if !head.starts_with("HTTP/") {
        bail!("{authority} did not answer with HTTP");
    }

    Ok(body.to_string())
}

/// The authority and path of an `http://` URL.
fn split_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("{url} is not an http:// URL"))?;
    match rest.split_once('/') {
        Some((authority, path)) => Ok((authority.to_string(), format!("/{path}"))),
        None => Ok((rest.to_string(), "/".to_string())),
    }
}

/// Resolve the control URL, which UPnP devices commonly give relative to the
/// description document rather than in full.
fn resolve_url(base: &str, control: &str) -> String {
    if control.starts_with("http://") || control.starts_with("https://") {
        return control.to_string();
    }

    let Ok((authority, base_path)) = split_url(base) else {
        return control.to_string();
    };

    if let Some(absolute) = control.strip_prefix('/') {
        return format!("http://{authority}/{absolute}");
    }

    // Relative to the document's directory.
    let directory = match base_path.rfind('/') {
        Some(index) => &base_path[..=index],
        None => "/",
    };
    format!("http://{authority}{directory}{control}")
}

// ------------------------------------------------------------- parsing ---

/// The description document, reduced to what the query needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Description {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub service_type: String,
    pub control_url: String,
}

/// Whether a service type is the one that carries WAN port mappings.
fn is_wan_service(service_type: &str) -> bool {
    service_type.contains("WANIPConnection") || service_type.contains("WANPPPConnection")
}

/// Read the gateway description.
///
/// A flat pass over the element texts is enough: the fields of interest have
/// unique names in the document, and the one ordering that matters — a
/// `controlURL` belonging to the service whose type was just read — is handled
/// by clearing it when a new service block starts.
pub fn parse_description(xml: &str) -> Option<Description> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut description = Description::default();
    let mut current: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                current = Some(local_name(&event));
            }
            Ok(Event::End(_)) => {
                current = None;
            }
            Ok(Event::Text(text)) => {
                let Some(tag) = current.as_deref() else {
                    continue;
                };
                let Ok(value) = text.decode() else {
                    continue;
                };
                let value = unescape(&value)
                    .map(|value| value.trim().to_string())
                    .unwrap_or_default();
                if value.is_empty() {
                    continue;
                }

                match tag {
                    "friendlyName" => description.friendly_name.get_or_insert(value),
                    "manufacturer" => description.manufacturer.get_or_insert(value),
                    "modelName" => description.model.get_or_insert(value),
                    "serviceType" if is_wan_service(&value) => {
                        description.service_type = value;
                        // A new service means the control URL after it belongs
                        // to that service, not the previous one.
                        description.control_url.clear();
                        continue;
                    }
                    "controlURL" if !description.service_type.is_empty() => {
                        description.control_url = value;
                        continue;
                    }
                    _ => continue,
                };
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    (!description.control_url.is_empty()).then_some(description)
}

/// The SOAP request that asks for mapping `index`.
fn port_mapping_request(service_type: &str, index: usize) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body>\
         <u:GetGenericPortMappingEntry xmlns:u=\"{service_type}\">\
         <NewPortMappingIndex>{index}</NewPortMappingIndex>\
         </u:GetGenericPortMappingEntry>\
         </s:Body>\
         </s:Envelope>"
    )
}

/// One SOAP reply, as a mapping.
pub fn parse_port_mapping(xml: &str) -> Option<PortMapping> {
    let fields = element_texts(xml);

    let external_port = fields.get("NewExternalPort")?.parse().ok()?;
    let internal_port = fields
        .get("NewInternalPort")
        .and_then(|port| port.parse().ok())
        .unwrap_or(0);
    let internal_client = fields.get("NewInternalClient").cloned().unwrap_or_default();

    Some(PortMapping {
        external_port,
        protocol: fields
            .get("NewProtocol")
            .cloned()
            .unwrap_or_else(|| "TCP".to_string()),
        internal_client,
        internal_port,
        // A device that omits the flag has still published the mapping.
        enabled: fields
            .get("NewEnabled")
            .map(|flag| flag != "0")
            .unwrap_or(true),
        description: fields
            .get("NewPortMappingDescription")
            .cloned()
            .unwrap_or_default(),
        lease_seconds: fields
            .get("NewLeaseDuration")
            .and_then(|lease| lease.parse().ok())
            .unwrap_or(0),
    })
}

/// The UPnP error number in a SOAP fault, if the reply is one.
pub fn soap_error_code(xml: &str) -> Option<u16> {
    if !xml.contains("errorCode") {
        return None;
    }
    element_texts(xml).get("errorCode")?.parse().ok()
}

/// Every element's text in a small document, keyed by local name.
///
/// SOAP replies and description documents are shallow, and the names of
/// interest do not repeat within one, so the last value wins.
fn element_texts(xml: &str) -> HashMap<String, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut fields = HashMap::new();
    let mut current: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(event)) => {
                current = Some(local_name(&event));
            }
            Ok(Event::End(_)) => {
                current = None;
            }
            Ok(Event::Text(text)) => {
                let Some(tag) = current.as_deref() else {
                    continue;
                };
                let Ok(value) = text.decode() else {
                    continue;
                };
                let value = unescape(&value)
                    .map(|value| value.trim().to_string())
                    .unwrap_or_default();
                if !value.is_empty() {
                    fields.insert(tag.to_string(), value);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    fields
}

/// An element's name without its namespace prefix.
fn local_name(event: &quick_xml::events::BytesStart<'_>) -> String {
    String::from_utf8_lossy(event.local_name().as_ref()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ssdp_reply_yields_its_location() {
        let reply = "HTTP/1.1 200 OK\r\n\
                     CACHE-CONTROL: max-age=120\r\n\
                     Location: http://192.168.1.1:5000/rootDesc.xml\r\n\
                     ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
        assert_eq!(
            location_header(reply).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
    }

    #[test]
    fn a_reply_without_a_usable_location_is_ignored() {
        assert_eq!(
            location_header("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n"),
            None
        );
        assert_eq!(
            location_header("HTTP/1.1 200 OK\r\nLOCATION: not-a-url\r\n\r\n"),
            None
        );
    }

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>TP-Link Archer AX10</friendlyName>
    <manufacturer>TP-Link</manufacturer>
    <modelName>Archer AX10</modelName>
    <deviceList>
      <device>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
            <controlURL>/ctl/L3F</controlURL>
          </service>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <controlURL>/ctl/IPConn</controlURL>
          </service>
        </serviceList>
      </device>
    </deviceList>
  </device>
</root>"#;

    #[test]
    fn the_description_yields_the_wan_control_url() {
        let parts = parse_description(DESCRIPTION).expect("parse");
        assert_eq!(parts.friendly_name.as_deref(), Some("TP-Link Archer AX10"));
        assert_eq!(parts.manufacturer.as_deref(), Some("TP-Link"));
        assert_eq!(parts.model.as_deref(), Some("Archer AX10"));
        assert_eq!(
            parts.service_type,
            "urn:schemas-upnp-org:service:WANIPConnection:1"
        );
        assert_eq!(parts.control_url, "/ctl/IPConn");
    }

    #[test]
    fn a_description_without_a_wan_service_is_not_a_gateway() {
        let xml = DESCRIPTION.replace("WANIPConnection", "Layer3Forwarding");
        assert!(parse_description(&xml).is_none());
    }

    #[test]
    fn control_urls_resolve_against_the_description() {
        let base = "http://192.168.1.1:5000/rootDesc.xml";
        assert_eq!(
            resolve_url(base, "/ctl/IPConn"),
            "http://192.168.1.1:5000/ctl/IPConn"
        );
        assert_eq!(
            resolve_url(base, "ctl/IPConn"),
            "http://192.168.1.1:5000/ctl/IPConn"
        );
        assert_eq!(
            resolve_url(base, "http://192.168.1.1:2869/upnp/control"),
            "http://192.168.1.1:2869/upnp/control"
        );
        // A port that is not written out is HTTP's own.
        assert_eq!(
            resolve_url("http://192.168.1.1/rootDesc.xml", "/ctl"),
            "http://192.168.1.1/ctl"
        );
    }

    #[test]
    fn a_port_mapping_reply_is_parsed() {
        let reply = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
 <s:Body>
  <u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
   <NewRemoteHost></NewRemoteHost>
   <NewExternalPort>8080</NewExternalPort>
   <NewProtocol>TCP</NewProtocol>
   <NewInternalPort>80</NewInternalPort>
   <NewInternalClient>192.168.1.50</NewInternalClient>
   <NewEnabled>1</NewEnabled>
   <NewPortMappingDescription>camera web</NewPortMappingDescription>
   <NewLeaseDuration>0</NewLeaseDuration>
  </u:GetGenericPortMappingEntryResponse>
 </s:Body>
</s:Envelope>"#;

        let mapping = parse_port_mapping(reply).expect("parse");
        assert_eq!(mapping.external_port, 8080);
        assert_eq!(mapping.protocol, "TCP");
        assert_eq!(mapping.internal_client, "192.168.1.50");
        assert_eq!(mapping.internal_port, 80);
        assert!(mapping.enabled);
        assert_eq!(mapping.description, "camera web");
        assert_eq!(mapping.lease_seconds, 0);
        assert_eq!(soap_error_code(reply), None);
    }

    #[test]
    fn an_empty_index_is_the_end_of_the_list() {
        let fault = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
 <s:Body>
  <s:Fault>
   <faultcode>s:Client</faultcode>
   <faultstring>UPnPError</faultstring>
   <detail>
    <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
     <errorCode>713</errorCode>
     <errorDescription>SpecifiedArrayIndexInvalid</errorDescription>
    </UPnPError>
   </detail>
  </s:Fault>
 </s:Body>
</s:Envelope>"#;

        assert!(parse_port_mapping(fault).is_none());
        assert_eq!(soap_error_code(fault), Some(713));
    }

    #[test]
    fn a_disabled_mapping_is_read_but_not_enabled() {
        let reply = r#"<NewExternalPort>9000</NewExternalPort>
<NewProtocol>UDP</NewProtocol>
<NewInternalPort>9000</NewInternalPort>
<NewInternalClient>192.168.1.60</NewInternalClient>
<NewEnabled>0</NewEnabled>
<NewPortMappingDescription></NewPortMappingDescription>
<NewLeaseDuration>600</NewLeaseDuration>"#;

        let mapping = parse_port_mapping(reply).expect("parse");
        assert!(!mapping.enabled);
        assert_eq!(mapping.protocol, "UDP");
        assert_eq!(mapping.lease_seconds, 600);
    }

    #[test]
    fn enabled_mappings_are_sorted_by_external_port() {
        let mapping = |port: u16, enabled: bool| PortMapping {
            external_port: port,
            protocol: "TCP".into(),
            internal_client: "192.168.1.2".into(),
            internal_port: 80,
            enabled,
            description: String::new(),
            lease_seconds: 0,
        };
        let igd = Igd {
            location: "http://192.168.1.1/rootDesc.xml".into(),
            friendly_name: Some("router".into()),
            manufacturer: None,
            model: None,
            service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
            control_url: "http://192.168.1.1/ctl".into(),
            mappings: vec![mapping(9000, true), mapping(8080, true), mapping(22, false)],
        };

        let open: Vec<u16> = igd
            .enabled_mappings()
            .iter()
            .map(|mapping| mapping.external_port)
            .collect();
        assert_eq!(open, vec![8080, 9000]);
        assert_eq!(igd.name(), Some("router"));
    }

    #[test]
    fn a_non_http_url_is_refused_rather_than_guessed() {
        assert!(split_url("https://192.168.1.1/rootDesc.xml").is_err());
        assert_eq!(
            split_url("http://192.168.1.1:5000/rootDesc.xml").unwrap(),
            ("192.168.1.1:5000".to_string(), "/rootDesc.xml".to_string())
        );
    }

    // --- a gateway over a real socket ------------------------------------

    fn mapping_reply(external_port: u16) -> String {
        format!(
            "<?xml version=\"1.0\"?>\n\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>\
             <u:GetGenericPortMappingEntryResponse>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>\
             <NewInternalPort>80</NewInternalPort>\
             <NewInternalClient>192.168.1.50</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>test mapping</NewPortMappingDescription>\
             <NewLeaseDuration>0</NewLeaseDuration>\
             </u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"
        )
    }

    fn end_of_list_reply() -> String {
        "<?xml version=\"1.0\"?>\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault>\
         <detail><UPnPError><errorCode>713</errorCode></UPnPError></detail>\
         </s:Fault></s:Body></s:Envelope>"
            .to_string()
    }

    #[tokio::test]
    async fn a_gateway_over_http_is_described_and_counted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");

        tokio::spawn(async move {
            while let Ok((mut stream, _peer)) = listener.accept().await {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                // One loopback read usually has the whole request, but the
                // reader is allowed to split it.
                let request = loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        break String::new();
                    };
                    if read == 0 {
                        break String::from_utf8_lossy(&buffer).to_string();
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&buffer).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        if body.contains("</s:Envelope>") || !head.starts_with("POST") {
                            break text;
                        }
                    }
                };

                let body = if request.starts_with("GET ") {
                    DESCRIPTION.to_string()
                } else {
                    let index = request
                        .split_once("<NewPortMappingIndex>")
                        .and_then(|(_, rest)| rest.split_once("</NewPortMappingIndex>"))
                        .and_then(|(digits, _)| digits.trim().parse::<usize>().ok())
                        .unwrap_or(usize::MAX);
                    match index {
                        0 => mapping_reply(8080),
                        1 => mapping_reply(9000),
                        _ => end_of_list_reply(),
                    }
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let location = format!("http://{address}/rootDesc.xml");
        let igd = query(&location).await.expect("query");

        assert_eq!(igd.location, location);
        assert_eq!(igd.friendly_name.as_deref(), Some("TP-Link Archer AX10"));
        assert_eq!(igd.name(), Some("TP-Link Archer AX10"));
        assert_eq!(igd.control_url, format!("http://{address}/ctl/IPConn"));
        assert_eq!(
            igd.mappings
                .iter()
                .map(|mapping| mapping.external_port)
                .collect::<Vec<_>>(),
            vec![8080, 9000]
        );
        assert_eq!(igd.enabled_mappings().len(), 2);
    }
}
