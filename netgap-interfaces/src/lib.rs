//! Network interface enumeration and selection.
//!
//! This module provides functionality to enumerate available network interfaces
//! and allow the user to select one for scanning. It also handles persistence
//! of the selected interface.

use anyhow::{anyhow, Result};
use pnet::datalink;
use std::path::PathBuf;
use std::io::{self, Write};

/// Represents an enumerated network interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub mac: Option<String>,
    pub is_up: bool,
}

/// Get all available network interfaces on the system.
pub fn get_interfaces() -> Result<Vec<InterfaceInfo>> {
    let interfaces = datalink::interfaces();
    let mut result = Vec::new();

    for iface in interfaces {
        let ipv4 = iface
            .ips
            .iter()
            .find_map(|ip| match ip {
                pnet::ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip().to_string()),
                _ => None,
            });

        let ipv6 = iface
            .ips
            .iter()
            .find_map(|ip| match ip {
                pnet::ipnetwork::IpNetwork::V6(ipv6) => Some(ipv6.ip().to_string()),
                _ => None,
            });

        let mac = iface.mac.map(|m| m.to_string());

        result.push(InterfaceInfo {
            name: iface.name.clone(),
            ipv4,
            ipv6,
            mac,
            is_up: iface.is_up(),
        });
    }

    Ok(result)
}

/// Get a specific interface by name.
pub fn get_interface(name: &str) -> Result<InterfaceInfo> {
    let interfaces = get_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or_else(|| anyhow!("Interface '{}' not found", name))
}

/// List all interface names in human-readable format.
pub fn list_interfaces_formatted() -> Result<Vec<String>> {
    let interfaces = get_interfaces()?;
    let formatted: Vec<String> = interfaces
        .iter()
        .map(|iface| {
            let status = if iface.is_up { "UP" } else { "DOWN" };
            let ip = iface
                .ipv4
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("No IPv4");
            format!("{:<15} {} ({})", iface.name, ip, status)
        })
        .collect();
    Ok(formatted)
}

/// Get the IPv4 CIDR notation for an interface.
/// Example: "192.168.1.0/24"
pub fn get_interface_cidr(iface_name: &str) -> Result<String> {
    let iface = get_interface(iface_name)?;
    let ipv4 = iface
        .ipv4
        .ok_or_else(|| anyhow!("No IPv4 address found on interface '{}'", iface_name))?;

    // For a simple implementation, assume /24 for typical LANs
    // In a real scanner, you'd derive this from the netmask
    Ok(format!("{}/24", ipv4.split('.').take(3).collect::<Vec<_>>().join(".")))
}

/// Store selected interface in config file.
pub fn save_interface_preference(interface_name: &str) -> Result<()> {
    // Create config directory if it doesn't exist
    let config_dir = get_config_dir()?;
    std::fs::create_dir_all(&config_dir)?;

    // Write interface name to preference file
    let pref_file = config_dir.join("interface_preference");
    std::fs::write(pref_file, interface_name)?;

    Ok(())
}

/// Load saved interface preference.
pub fn load_interface_preference() -> Result<Option<String>> {
    let config_dir = get_config_dir()?;
    let pref_file = config_dir.join("interface_preference");

    if pref_file.exists() {
        let content = std::fs::read_to_string(pref_file)?;
        Ok(Some(content.trim().to_string()))
    } else {
        Ok(None)
    }
}

/// Get the config directory for netgap.
fn get_config_dir() -> Result<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        Ok(PathBuf::from(home).join(".config/netgap"))
    } else if let Ok(home) = std::env::var("USERPROFILE") {
        // Windows
        Ok(PathBuf::from(home).join(".config/netgap"))
    } else {
        Err(anyhow!("Could not determine home directory"))
    }
}

/// Interactive TUI-style interface selector (terminal-based menu).
/// Shows a numbered list and prompts the user to select.
pub fn select_interface_interactive() -> Result<String> {
    let interfaces = get_interfaces()?;
    
    if interfaces.is_empty() {
        return Err(anyhow!("No network interfaces found"));
    }

    println!("\n📡 Select Network Interface:\n");
    
    // Display interface options
    for (idx, iface) in interfaces.iter().enumerate() {
        let status = if iface.is_up { "✓" } else { "✗" };
        let ip_str = iface.ipv4.as_ref().map(|s| s.as_str()).unwrap_or("No IPv4");
        println!("  {}. {} {} [{}]", idx + 1, iface.name, ip_str, status);
    }

    // Get user input
    loop {
        print!("\nSelect interface (1-{}): ", interfaces.len());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if let Ok(choice) = input.trim().parse::<usize>() {
            if choice > 0 && choice <= interfaces.len() {
                let selected = interfaces[choice - 1].name.clone();
                save_interface_preference(&selected)?;
                println!("✓ Selected: {}\n", selected);
                return Ok(selected);
            }
        }
        
        println!("❌ Invalid selection. Please try again.");
    }
}

/// Get interface with fallback to saved preference or first available.
pub fn get_interface_auto() -> Result<String> {
    // Try saved preference first
    if let Ok(Some(saved)) = load_interface_preference() {
        if let Ok(_) = get_interface(&saved) {
            return Ok(saved);
        }
    }

    // Fallback to first up interface
    let interfaces = get_interfaces()?;
    let up_interfaces: Vec<_> = interfaces
        .iter()
        .filter(|iface| iface.is_up && iface.ipv4.is_some())
        .collect();

    if !up_interfaces.is_empty() {
        return Ok(up_interfaces[0].name.clone());
    }

    // Last resort: any interface
    if !interfaces.is_empty() {
        return Ok(interfaces[0].name.clone());
    }

    Err(anyhow!("No network interfaces available"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_interfaces_not_empty() {
        let interfaces = get_interfaces().expect("Should get interfaces");
        assert!(!interfaces.is_empty(), "System should have at least one interface");
    }

    #[test]
    fn test_list_interfaces_formatted() {
        let formatted = list_interfaces_formatted().expect("Should format interfaces");
        assert!(!formatted.is_empty());
        // Each line should have interface name and status
        for line in formatted {
            assert!(line.contains("UP") || line.contains("DOWN"));
        }
    }

    #[test]
    fn test_interface_names_not_empty() {
        let interfaces = get_interfaces().expect("Should get interfaces");
        for iface in interfaces {
            assert!(!iface.name.is_empty());
        }
    }

    #[test]
    fn test_get_interface_auto() {
        let iface = get_interface_auto().expect("Should get an interface");
        assert!(!iface.is_empty());
    }

    #[test]
    fn test_save_load_interface_preference() {
        let interfaces = get_interfaces().expect("Should get interfaces");
        if !interfaces.is_empty() {
            let test_iface = &interfaces[0].name;
            save_interface_preference(test_iface).expect("Should save preference");
            
            let loaded = load_interface_preference()
                .expect("Should load preference")
                .expect("Should have preference");
            
            assert_eq!(&loaded, test_iface);
        }
    }
}
