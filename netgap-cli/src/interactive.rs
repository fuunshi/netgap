use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{self, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use netgap_core::Device;
use netgap_discover::{ArpDiscovery, DiscoveryConfig};
use netgap_interfaces::{get_interface_auto, get_interface_cidr};
use netgap_scan::{PortScanEvent, ScanConfig as PortScanConfig, PortScanner, TOP_DANGEROUS_PORTS};
use std::io::{stdout, Write};
use std::time::Duration;
use tokio::sync::mpsc;

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        let mut out = stdout();
        execute!(out, EnterAlternateScreen, cursor::Hide)?;
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let mut out = stdout();
        let _ = execute!(out, cursor::Show, LeaveAlternateScreen);
    }
}

#[derive(Clone)]
struct HostState {
    device: Device,
    completed_ports: usize,
    total_ports: usize,
    open_ports: Vec<u16>,
    last_port: Option<u16>,
    finished: bool,
}

impl HostState {
    fn new(device: Device, total_ports: usize) -> Self {
        Self {
            device,
            completed_ports: 0,
            total_ports,
            open_ports: Vec::new(),
            last_port: None,
            finished: false,
        }
    }
}

pub async fn run(
    interface_name: Option<String>,
    target_cidr: Option<String>,
    quick: bool,
) -> Result<Vec<Device>> {
    let iface_name = interface_name.unwrap_or_else(|| {
        get_interface_auto().unwrap_or_else(|_| "eth0".to_string())
    });
    let resolved_target = target_cidr.unwrap_or_else(|| {
        get_interface_cidr(&iface_name).unwrap_or_else(|_| "192.168.1.0/24".to_string())
    });

    let discovery_config = DiscoveryConfig {
        interface_name: iface_name.clone(),
        target_cidr: resolved_target.clone(),
        timeout_ms: 1000,
    };

    let discovery = ArpDiscovery::new(discovery_config);
    let devices = discovery.scan().await?;

    if devices.is_empty() {
        println!("\n✗ No devices discovered on target network");
        return Ok(devices);
    }

    println!("✓ Discovered {} device(s)", devices.len());

    if quick {
        println!("ℹ️  Quick mode enabled: skipping live port dashboard");
        return Ok(devices);
    }

    let port_config = PortScanConfig {
        ports: TOP_DANGEROUS_PORTS.to_vec(),
        timeout_ms: 2000,
        concurrency: 32,
    };
    let total_ports = port_config.ports.len();

    println!("\nInteractive host dashboard");
    println!("Use number keys to switch between hosts while scans are running.");

    let _guard = TerminalGuard::enter()?;

    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel::<PortScanEvent>();
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<KeyEvent>();

    std::thread::spawn(move || {
        loop {
            match event::read() {
                Ok(Event::Key(key_event)) => {
                    if key_tx.send(key_event).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    let mut handles = Vec::new();
    let host_states: Vec<HostState> = devices
        .iter()
        .cloned()
        .map(|device| HostState::new(device, total_ports))
        .collect();

    for device in devices.into_iter() {
        let progress = progress_tx.clone();
        let scan_config = port_config.clone();
        handles.push(tokio::spawn(async move {
            let scanner = PortScanner::new(scan_config);
            let mut single = vec![device];
            scanner
                .scan_devices_with_progress(&mut single, Some(progress))
                .await?;
            Ok::<Device, anyhow::Error>(single.remove(0))
        }));
    }
    drop(progress_tx);

    let mut states = host_states;
    let mut selected = 0usize;
    let mut dirty = true;
    let mut redraw_tick = tokio::time::interval(Duration::from_millis(120));

    loop {
        tokio::select! {
            maybe_progress = progress_rx.recv() => {
                if let Some(progress) = maybe_progress {
                    if let Some(state) = states.iter_mut().find(|state| state.device.ip == progress.device_ip) {
                        state.completed_ports = progress.completed_ports;
                        state.total_ports = progress.total_ports;
                        if let Some(port) = progress.open_port {
                            if !state.open_ports.contains(&port) {
                                state.open_ports.push(port);
                                state.open_ports.sort();
                            }
                            state.last_port = Some(port);
                        }
                        if progress.finished {
                            state.finished = true;
                        }
                    }
                    dirty = true;
                }
            }
            maybe_key = key_rx.recv() => {
                if let Some(key) = maybe_key {
                    match key.code {
                        KeyCode::Char(ch) if ch.is_ascii_digit() => {
                            if let Some(index) = ch.to_digit(10).map(|value| value as usize) {
                                if index > 0 && index <= states.len() {
                                    selected = index - 1;
                                    dirty = true;
                                }
                            }
                        }
                        KeyCode::Left | KeyCode::Up => {
                            if selected > 0 {
                                selected -= 1;
                                dirty = true;
                            }
                        }
                        KeyCode::Right | KeyCode::Down => {
                            if selected + 1 < states.len() {
                                selected += 1;
                                dirty = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ = redraw_tick.tick() => {
                dirty = true;
            }
        }

        if dirty {
            render_dashboard(&states, selected, &iface_name, &resolved_target)?;
            dirty = false;
        }

        if states.iter().all(|state| state.finished) {
            break;
        }
    }

    let mut final_devices = Vec::new();
    for handle in handles {
        final_devices.push(handle.await??);
    }

    Ok(final_devices)
}

fn render_dashboard(
    states: &[HostState],
    selected: usize,
    iface_name: &str,
    target: &str,
) -> Result<()> {
    let mut out = stdout();
    execute!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All))?;

    println!("netgap interactive scan");
    println!("Interface: {}", iface_name);
    println!("Target: {}", target);
    println!("Hosts detected: {}", states.len());
    println!("Controls: 1-9 switch host, left/right arrows also work");
    println!();

    for (index, state) in states.iter().enumerate() {
        let marker = if index == selected { ">" } else { " " };
        let status = if state.finished { "done" } else { "running" };
        println!(
            "{} [{}] {}  {}/{} ports  open:{}  {}",
            marker,
            index + 1,
            state.device.ip,
            state.completed_ports,
            state.total_ports,
            state.open_ports.len(),
            status,
        );
    }

    if let Some(state) = states.get(selected) {
        println!();
        println!("Active host: {}", state.device.ip);
        if let Some(hostname) = &state.device.hostname {
            println!("Hostname: {}", hostname);
        }
        if let Some(mac) = &state.device.mac {
            println!("MAC: {}", mac);
        }
        println!("Progress: {}/{} ports", state.completed_ports, state.total_ports);
        println!("Open ports: {}", if state.open_ports.is_empty() {
            "none yet".to_string()
        } else {
            state
                .open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        });
        if let Some(port) = state.last_port {
            println!("Last detected open port: {}", port);
        }
    }

    out.flush()?;
    Ok(())
}
