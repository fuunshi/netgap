use anyhow::{Context, Result};
use pnet::datalink::NetworkInterface;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{
    tcp_packet_iter, transport_channel, TransportChannelType::Layer4, TransportProtocol,
};
use rand::{thread_rng, Rng};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::discovery;
use crate::model::{DiscoveredHost, HostReport, PortFinding, ScanMode};

pub fn scan_host(
    interface: &NetworkInterface,
    host: DiscoveredHost,
    mode: ScanMode,
) -> Result<HostReport> {
    let target_ip: Ipv4Addr = host
        .ip
        .parse()
        .with_context(|| format!("invalid IPv4 address {}", host.ip))?;
    let source_ip = discovery::primary_ipv4(interface)?;
    let ports = ports_for_mode(mode);
    let open_ports = raw_syn_scan(source_ip, target_ip, &ports)
        .unwrap_or_else(|_| connect_scan(target_ip, &ports));

    let mut open_ports = open_ports
        .into_iter()
        .map(|port| fingerprint_port(target_ip, port))
        .collect::<Result<Vec<_>>>()?;

    open_ports.sort_by_key(|port| port.port);

    Ok(HostReport {
        ip: host.ip,
        hostname: host.hostname,
        mac: host.mac,
        open_ports,
        gaps: Vec::new(),
    })
}

fn ports_for_mode(mode: ScanMode) -> Vec<u16> {
    match mode {
        ScanMode::Quick => quick_ports().into_iter().take(100).collect(),
        ScanMode::Full => (1..=1000).collect(),
    }
}

fn quick_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 512, 513, 514,
        587, 593, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432,
        5900, 5985, 5986, 6379, 7001, 7002, 8000, 8080, 8081, 8088, 8443, 9000, 9200, 10000, 11211,
        27017, 28017, 5000, 5060, 5222, 5431, 5601, 5672, 5901, 6000, 6378, 6667, 7000, 7070, 7474,
        7547, 7681, 8008, 8089, 8090, 8200, 8333, 8500, 8600, 8761, 8888, 9001, 9042, 9090, 9092,
        9100, 9201, 9300, 9418, 9443, 9999, 10050, 11211, 27018, 50070, 50075, 60020, 61616, 6379,
        7001, 7002, 7473, 7687, 7777, 8009, 8069, 8222, 8300, 8444, 8501, 8787, 8880, 8889, 9002,
        9043, 9091, 9202, 9301, 9444, 9800, 9981, 10080, 10443, 11212, 18080, 20000, 27019, 31337,
    ]
}

fn raw_syn_scan(source_ip: Ipv4Addr, target_ip: Ipv4Addr, ports: &[u16]) -> Result<Vec<u16>> {
    let (mut tx, mut rx) = transport_channel(
        4096,
        Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )?;
    let mut iter = tcp_packet_iter(&mut rx);
    let mut rng = thread_rng();
    let source_port: u16 = rng.gen_range(40000..60000);
    let mut open = Vec::new();

    for port in ports {
        let mut buffer = [0u8; 20];
        let mut packet = MutableTcpPacket::new(&mut buffer).unwrap();
        packet.set_source(source_port);
        packet.set_destination(*port);
        packet.set_sequence(rng.gen());
        packet.set_acknowledgement(0);
        packet.set_data_offset(5);
        packet.set_reserved(0);
        packet.set_flags(TcpFlags::SYN);
        packet.set_window(64240);
        packet.set_urgent_ptr(0);
        packet.set_checksum(0);
        let checksum = ipv4_checksum(&packet.to_immutable(), &source_ip, &target_ip);
        packet.set_checksum(checksum);

        tx.send_to(packet, IpAddr::V4(target_ip))?;

        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(180) {
            match iter.next_with_timeout(Duration::from_millis(50))? {
                Some((response, addr)) => {
                    if addr != IpAddr::V4(target_ip) {
                        continue;
                    }

                    if response.get_destination() != source_port || response.get_source() != *port {
                        continue;
                    }

                    let flags = response.get_flags();
                    if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                        open.push(*port);
                    }

                    break;
                }
                None => break,
            }
        }
    }

    Ok(open)
}

fn connect_scan(target_ip: Ipv4Addr, ports: &[u16]) -> Vec<u16> {
    ports
        .iter()
        .copied()
        .filter(|port| {
            let socket = SocketAddr::new(IpAddr::V4(target_ip), *port);
            TcpStream::connect_timeout(&socket, Duration::from_millis(300)).is_ok()
        })
        .collect()
}

fn fingerprint_port(target_ip: Ipv4Addr, port: u16) -> Result<PortFinding> {
    let service = service_hint(port);
    let banner = banner_grab(target_ip, port);

    Ok(PortFinding {
        port,
        protocol: "tcp".into(),
        service,
        banner,
    })
}

fn banner_grab(target_ip: Ipv4Addr, port: u16) -> Option<String> {
    let socket = SocketAddr::new(IpAddr::V4(target_ip), port);
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_millis(300)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));

    if matches!(
        port,
        80 | 8080 | 8081 | 8000 | 8008 | 8443 | 8888 | 9000 | 9001 | 9443
    ) {
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: netgap\r\nConnection: close\r\n\r\n");
    }

    let mut buffer = [0u8; 512];
    match stream.read(&mut buffer) {
        Ok(0) | Err(_) => None,
        Ok(bytes) => Some(String::from_utf8_lossy(&buffer[..bytes]).trim().to_string()),
    }
}

fn service_hint(port: u16) -> Option<String> {
    let service = match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 | 8080 | 8081 | 8000 | 8008 | 8888 | 9000 | 9001 | 9443 => "http",
        110 => "pop3",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        2375 | 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 | 5901 => "vnc",
        5985 | 5986 => "winrm",
        6379 => "redis",
        8088 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 | 27018 | 27019 => "mongodb",
        _ => return None,
    };

    Some(service.into())
}
