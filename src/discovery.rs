use anyhow::{anyhow, Context, Result};
use pnet::datalink::{self, NetworkInterface};
use std::net::{IpAddr, Ipv4Addr};

use crate::model::{InterfaceInfo, ScanMode};

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
	let interfaces = datalink::interfaces();

	Ok(interfaces
		.into_iter()
		.map(|interface| InterfaceInfo {
			is_up: interface.is_up(),
			is_loopback: interface.is_loopback(),
			name: interface.name,
			ips: interface.ips.iter().map(|ip| ip.ip().to_string()).collect(),
			mac: interface.mac.map(|mac| mac.to_string()),
		})
		.collect())
}

pub fn select_interface(name: Option<&str>) -> Result<NetworkInterface> {
	let interfaces = datalink::interfaces();

	if let Some(name) = name {
		interfaces
			.into_iter()
			.find(|interface| interface.name == name)
			.ok_or_else(|| anyhow!("interface '{name}' was not found"))
	} else {
		interfaces
			.into_iter()
			.find(|interface| interface.is_up() && !interface.is_loopback())
			.context("no usable interface found; pass --interface to choose one")
	}
}

pub fn discover_hosts(interface: &NetworkInterface, mode: ScanMode) -> Result<Vec<Ipv4Addr>> {
	let mut hosts = Vec::new();

	for ip_network in &interface.ips {
		if let IpAddr::V4(addr) = ip_network.ip() {
			let prefix = ip_network.prefix();
			let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
			let network = u32::from(addr) & mask;
			let broadcast = network | !mask;

			let start = network.saturating_add(1);
			let end = broadcast.saturating_sub(1);
			let host_limit = match mode {
				ScanMode::Quick => 64,
				ScanMode::Full => 256,
			};

			for value in start..=end {
				if hosts.len() >= host_limit {
					break;
				}

				let candidate = Ipv4Addr::from(value);
				if candidate != addr {
					hosts.push(candidate);
				}
			}
		}
	}

	if hosts.is_empty() {
		Err(anyhow!("no IPv4 targets could be derived from interface {}", interface.name))
	} else {
		Ok(hosts)
	}
}
