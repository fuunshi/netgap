//! Full-screen interactive view.
//!
//! The subcommands are the tool; this is the same tool with a face on it. One
//! screen lists the interfaces, one lists what a scan found, and one lists the
//! scans already recorded. Every action is a key printed at the bottom, and
//! the work behind them is the same code the subcommands call — so choosing an
//! interface here is choosing it for `netgap scan`, not a second scanner.
//!
//! It is deliberately plain: no mouse, no panels to drag, no colours that
//! carry meaning on their own. A tool that needs a manual is worse than the
//! command line it replaces.

mod view;

use crate::discovery::{self, DiscoveryMethod, DiscoveryPlan};
use anyhow::{anyhow, Result};
use crossterm::cursor;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use netgap_core::{Device, FindingSummary, ScanConfig, ScanResult};
use netgap_interfaces::InterfaceInfo;
use netgap_scan::{PortScanner, ScanConfig as PortScanConfig, TOP_DANGEROUS_PORTS};
use netgap_storage::{ScanMetadata, ScanStore};
use std::io::{stdout, IsTerminal};
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::task::JoinHandle;

/// Restores the terminal however this function is left.
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

/// Which screen the user is looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Interfaces,
    Options,
    Scanning,
    Devices,
    Scans,
}

/// How hosts will be found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodChoice {
    Auto,
    Arp,
    Tcp,
}

impl MethodChoice {
    fn next(self) -> Self {
        match self {
            MethodChoice::Auto => MethodChoice::Arp,
            MethodChoice::Arp => MethodChoice::Tcp,
            MethodChoice::Tcp => MethodChoice::Auto,
        }
    }

    fn previous(self) -> Self {
        match self {
            MethodChoice::Auto => MethodChoice::Tcp,
            MethodChoice::Tcp => MethodChoice::Arp,
            MethodChoice::Arp => MethodChoice::Auto,
        }
    }
}

/// How much work a scan does once the devices are found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Discover,
    Ports,
}

impl ScanMode {
    fn toggle(self) -> Self {
        match self {
            ScanMode::Discover => ScanMode::Ports,
            ScanMode::Ports => ScanMode::Discover,
        }
    }

    fn label(self) -> &'static str {
        match self {
            ScanMode::Discover => "Discover devices",
            ScanMode::Ports => "Ports & findings",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            ScanMode::Discover => {
                "Finds who is on the network. Fast, and sends almost nothing to each device."
            }
            ScanMode::Ports => {
                "Also checks the common service ports and records what it finds wrong."
            }
        }
    }
}

/// Everything the UI receives on one channel, so the event loop has one thing
/// to wait on.
enum UiEvent {
    Key(KeyEvent),
    Resize,
    Scan(ScanUpdate),
}

/// Progress from a scan running in the background.
enum ScanUpdate {
    Stage { generation: u64, message: String },
    Done { generation: u64, result: ScanResult },
    Failed { generation: u64, message: String },
}

/// The whole state of the view.
struct App {
    interfaces: Vec<InterfaceInfo>,
    selected: usize,
    show_all: bool,
    method: MethodChoice,
    mode: ScanMode,
    screen: Screen,
    devices: Vec<Device>,
    device_selected: usize,
    /// Where Esc goes from the devices screen: the interface list for a live
    /// scan, the saved-scan list for one opened from history.
    devices_back: Screen,
    saved_scan: Option<ScanMetadata>,
    scans: Vec<ScanMetadata>,
    scan_selected: usize,
    status: String,
    stage: String,
    spinner: usize,
    generation: u64,
    scan_handle: Option<JoinHandle<()>>,
    help: bool,
    quit: bool,
    dirty: bool,
}

impl App {
    fn new() -> Result<Self> {
        let mut app = App {
            interfaces: Vec::new(),
            selected: 0,
            show_all: false,
            method: MethodChoice::Auto,
            mode: ScanMode::Discover,
            screen: Screen::Interfaces,
            devices: Vec::new(),
            device_selected: 0,
            devices_back: Screen::Interfaces,
            saved_scan: None,
            scans: Vec::new(),
            scan_selected: 0,
            status: String::new(),
            stage: String::new(),
            spinner: 0,
            generation: 0,
            scan_handle: None,
            help: false,
            quit: false,
            dirty: true,
        };
        app.reload_interfaces()?;
        Ok(app)
    }

    /// Enumerate interfaces and start on the one the CLI would have picked.
    fn reload_interfaces(&mut self) -> Result<()> {
        self.interfaces = netgap_interfaces::get_interfaces()?;

        if self.interfaces.is_empty() {
            self.selected = 0;
            self.status = "No network interfaces were found.".to_string();
            return Ok(());
        }

        let saved = netgap_interfaces::load_validated_preference()
            .ok()
            .flatten()
            .and_then(|iface| {
                self.interfaces
                    .iter()
                    .position(|candidate| candidate.name == iface.name)
            });

        let route = self
            .interfaces
            .iter()
            .find(|iface| iface.is_default_route)
            .map(|iface| iface.name.clone());
        let best =
            netgap_interfaces::select_best(&self.interfaces, route.as_deref()).and_then(|iface| {
                self.interfaces
                    .iter()
                    .position(|candidate| candidate.name == iface.name)
            });

        self.selected = saved.or(best).unwrap_or(0);
        self.status.clear();
        Ok(())
    }

    /// Indices of the interfaces the current filter shows.
    ///
    /// The default filter drops virtual bridges and tunnels as well as
    /// loopback: `is_scannable` answers "could this be scanned", which a
    /// docker bridge can, but the question the screen asks is "which of these
    /// is the network". The full list is one keypress away.
    fn visible_interfaces(&self) -> Vec<usize> {
        self.interfaces
            .iter()
            .enumerate()
            .filter(|(_, iface)| self.show_all || (iface.is_scannable() && !iface.is_virtual()))
            .map(|(index, _)| index)
            .collect()
    }

    fn selected_interface(&self) -> Option<&InterfaceInfo> {
        self.interfaces.get(self.selected)
    }

    /// What `Auto` actually does right now, named so the user is not
    /// surprised by a TCP sweep after expecting ARP.
    fn discovery_label(&self) -> String {
        match self.method {
            MethodChoice::Auto => {
                if netgap_discover::privilege::has_cap_net_raw() {
                    "Auto — ARP (raw sockets available)".to_string()
                } else {
                    "Auto — TCP (needs root/CAP_NET_RAW for ARP)".to_string()
                }
            }
            MethodChoice::Arp => "ARP (raw socket)".to_string(),
            MethodChoice::Tcp => "TCP connect (unprivileged)".to_string(),
        }
    }

    /// The plan for the currently selected interface and options.
    fn build_plan(&self) -> Result<DiscoveryPlan> {
        let interface = self
            .selected_interface()
            .cloned()
            .ok_or_else(|| anyhow!("no interface selected"))?;

        if !interface.is_up {
            return Err(anyhow!("{} is down", interface.name));
        }

        let target = interface
            .cidr
            .clone()
            .ok_or_else(|| anyhow!("{} has no IPv4 network to scan", interface.name))?;

        let requested = match self.method {
            MethodChoice::Auto => None,
            MethodChoice::Arp => Some(DiscoveryMethod::Arp),
            MethodChoice::Tcp => Some(DiscoveryMethod::Tcp),
        };
        let method = requested.unwrap_or(if netgap_discover::privilege::has_cap_net_raw() {
            DiscoveryMethod::Arp
        } else {
            DiscoveryMethod::Tcp
        });

        Ok(DiscoveryPlan {
            method,
            interface,
            target,
            max_hosts: netgap_discover::DEFAULT_MAX_HOSTS,
            // An explicit TCP choice is not a fallback candidate; an explicit
            // ARP choice is, because failing back to TCP still finds hosts.
            allow_fallback: requested != Some(DiscoveryMethod::Tcp),
            mdns: false,
            quiet: true,
        })
    }

    fn move_interface(&mut self, delta: isize) {
        let visible = self.visible_interfaces();
        if visible.is_empty() {
            return;
        }
        let position = visible
            .iter()
            .position(|&index| index == self.selected)
            .unwrap_or(0);
        let next = (position as isize + delta).clamp(0, visible.len() as isize - 1) as usize;
        self.selected = visible[next];
    }

    fn toggle_filter(&mut self) {
        self.show_all = !self.show_all;
        let visible = self.visible_interfaces();
        if !visible.contains(&self.selected) {
            if let Some(first) = visible.first() {
                self.selected = *first;
            }
        }
    }

    fn move_device(&mut self, delta: isize) {
        if self.devices.is_empty() {
            return;
        }
        let next = (self.device_selected as isize + delta).clamp(0, self.devices.len() as isize - 1)
            as usize;
        self.device_selected = next;
    }

    fn move_scan(&mut self, delta: isize) {
        if self.scans.is_empty() {
            return;
        }
        let next =
            (self.scan_selected as isize + delta).clamp(0, self.scans.len() as isize - 1) as usize;
        self.scan_selected = next;
    }

    fn open_options(&mut self) {
        let Some(interface) = self.selected_interface() else {
            self.status = "No interface selected.".to_string();
            return;
        };
        if !interface.is_up {
            self.status = format!("{} is down.", interface.name);
            return;
        }
        if interface.cidr.is_none() {
            self.status = format!("{} has no IPv4 network to scan.", interface.name);
            return;
        }
        self.status.clear();
        self.screen = Screen::Options;
    }

    fn start_scan(&mut self, events: &UnboundedSender<UiEvent>) {
        let plan = match self.build_plan() {
            Ok(plan) => plan,
            Err(error) => {
                self.status = error.to_string();
                return;
            }
        };

        if self.scan_handle.is_some() {
            return;
        }

        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        let full = self.mode == ScanMode::Ports;
        let started_at = chrono::Local::now().to_rfc3339();
        let config = ScanConfig {
            interface: plan.interface.name.clone(),
            target: plan.target.clone(),
            timeout_ms: if full { 2000 } else { 1000 },
            concurrency: 32,
            discovery_only: !full,
        };

        self.screen = Screen::Scanning;
        self.stage = "Finding devices…".to_string();
        self.status.clear();

        let events = events.clone();
        self.scan_handle = Some(tokio::spawn(async move {
            let event = match scan_job(plan, full, generation, &events).await {
                Ok(devices) => {
                    let mut summary = FindingSummary::new();
                    for device in &devices {
                        for finding in &device.findings {
                            summary.add_finding(finding.severity);
                        }
                    }
                    UiEvent::Scan(ScanUpdate::Done {
                        generation,
                        result: ScanResult {
                            started_at,
                            config,
                            devices,
                            summary,
                        },
                    })
                }
                Err(error) => UiEvent::Scan(ScanUpdate::Failed {
                    generation,
                    message: error.to_string(),
                }),
            };
            let _ = events.send(event);
        }));
    }

    fn cancel_scan(&mut self) {
        if let Some(handle) = self.scan_handle.take() {
            handle.abort();
        }
        // A message already in flight belongs to the abandoned run.
        self.generation = self.generation.wrapping_add(1);
        self.stage.clear();
        self.screen = Screen::Options;
        self.status = "Scan stopped.".to_string();
    }

    fn handle_scan(&mut self, update: ScanUpdate) {
        match update {
            ScanUpdate::Stage {
                generation,
                message,
            } if generation == self.generation => {
                self.stage = message;
            }
            ScanUpdate::Done { generation, result } if generation == self.generation => {
                self.scan_handle = None;
                let count = result.devices.len();
                let saved = if result.devices.is_empty() {
                    None
                } else {
                    Some(save_result(&result))
                };
                self.devices = result.devices;
                self.device_selected = 0;
                self.saved_scan = None;
                self.devices_back = Screen::Interfaces;
                self.screen = Screen::Devices;
                self.stage.clear();
                self.status = match saved {
                    None => {
                        "No devices answered. Esc goes back, 'a' shows every interface.".to_string()
                    }
                    Some(Ok(id)) => format!("Found {count} device(s). Saved as '{id}'."),
                    Some(Err(error)) => {
                        format!("Found {count} device(s). Could not save the scan: {error}")
                    }
                };
            }
            ScanUpdate::Failed {
                generation,
                message,
            } if generation == self.generation => {
                self.scan_handle = None;
                self.stage.clear();
                self.screen = Screen::Options;
                self.status = format!("Scan failed: {message}");
            }
            _ => {}
        }
    }

    fn open_scans(&mut self) {
        match ScanStore::open_default().and_then(|store| store.list_scans()) {
            Ok(scans) => {
                self.scans = scans;
                self.scan_selected = 0;
                self.screen = Screen::Scans;
                self.status.clear();
            }
            Err(error) => self.status = format!("Could not read saved scans: {error}"),
        }
    }

    fn open_selected_scan(&mut self) {
        let Some(metadata) = self.scans.get(self.scan_selected).cloned() else {
            return;
        };
        match ScanStore::open_default().and_then(|store| store.load_scan(&metadata.id)) {
            Ok(result) => {
                self.devices = result.devices;
                self.device_selected = 0;
                self.saved_scan = Some(metadata);
                self.devices_back = Screen::Scans;
                self.screen = Screen::Devices;
                self.status.clear();
            }
            Err(error) => self.status = format!("Could not open {}: {error}", metadata.id),
        }
    }

    fn handle_key(&mut self, key: KeyEvent, events: &UnboundedSender<UiEvent>) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        self.dirty = true;

        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.quit = true;
            return;
        }

        if self.help {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter
            ) {
                self.help = false;
            }
            return;
        }

        if key.code == KeyCode::Char('?') {
            self.help = true;
            return;
        }

        match self.screen {
            Screen::Interfaces => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.move_interface(-1),
                KeyCode::Down | KeyCode::Char('j') => self.move_interface(1),
                KeyCode::Char('a') => self.toggle_filter(),
                KeyCode::Char('r') => {
                    if let Err(error) = self.reload_interfaces() {
                        self.status = format!("Could not read interfaces: {error}");
                    }
                }
                KeyCode::Char('d') | KeyCode::Char('s') => self.open_scans(),
                KeyCode::Enter => self.open_options(),
                KeyCode::Char('q') => self.quit = true,
                _ => {}
            },
            Screen::Options => match key.code {
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j') => {
                    self.mode = self.mode.toggle();
                }
                KeyCode::Left | KeyCode::Char('h') => self.method = self.method.previous(),
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('m') => {
                    self.method = self.method.next();
                }
                KeyCode::Enter => self.start_scan(events),
                KeyCode::Esc => self.screen = Screen::Interfaces,
                KeyCode::Char('q') => self.quit = true,
                _ => {}
            },
            Screen::Scanning => match key.code {
                KeyCode::Esc => self.cancel_scan(),
                KeyCode::Char('q') => self.quit = true,
                _ => {}
            },
            Screen::Devices => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.move_device(-1),
                KeyCode::Down | KeyCode::Char('j') => self.move_device(1),
                KeyCode::Char('s') | KeyCode::Char('d') => self.open_scans(),
                KeyCode::Char('i') => self.screen = Screen::Interfaces,
                KeyCode::Esc => self.screen = self.devices_back,
                KeyCode::Char('q') => self.quit = true,
                _ => {}
            },
            Screen::Scans => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.move_scan(-1),
                KeyCode::Down | KeyCode::Char('j') => self.move_scan(1),
                KeyCode::Enter => self.open_selected_scan(),
                KeyCode::Char('r') => self.open_scans(),
                KeyCode::Char('i') | KeyCode::Esc => self.screen = Screen::Interfaces,
                KeyCode::Char('q') => self.quit = true,
                _ => {}
            },
        }
    }
}

/// Run discovery and, if asked, the port scan — quietly, because the UI draws
/// its own progress.
async fn scan_job(
    plan: DiscoveryPlan,
    full: bool,
    generation: u64,
    events: &UnboundedSender<UiEvent>,
) -> Result<Vec<Device>> {
    let stage = |message: String| {
        let _ = events.send(UiEvent::Scan(ScanUpdate::Stage {
            generation,
            message,
        }));
    };

    stage("Finding devices…".to_string());
    let mut devices = discovery::run(&plan).await?;

    // IPv6 neighbours annotate devices and can add ones IPv4 missed.
    crate::run_ipv6(&mut devices, &plan);

    if devices.is_empty() {
        return Ok(devices);
    }

    stage(format!(
        "Found {}. Looking up names and vendors…",
        count_devices(devices.len())
    ));
    crate::enrich_devices(&plan, &mut devices, false).await;

    if full {
        stage(format!(
            "Scanning {} for open ports…",
            count_devices(devices.len())
        ));
        let scanner = PortScanner::new(PortScanConfig {
            ports: TOP_DANGEROUS_PORTS.to_vec(),
            timeout_ms: 2000,
            concurrency: 32,
        })
        .quiet(true);
        scanner.scan_devices(&mut devices).await?;
    }

    Ok(devices)
}

fn save_result(result: &ScanResult) -> Result<String> {
    let mut store = ScanStore::open_default()?;
    store.save_scan(result)
}

fn count_devices(count: usize) -> String {
    if count == 1 {
        "1 device".to_string()
    } else {
        format!("{count} devices")
    }
}

fn spawn_input(events: UnboundedSender<UiEvent>) {
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(Event::Key(key)) => {
                if events.send(UiEvent::Key(key)).is_err() {
                    break;
                }
            }
            Ok(Event::Resize(_, _)) => {
                if events.send(UiEvent::Resize).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    });
}

/// Open the interactive view and run it until the user quits.
pub async fn run() -> Result<()> {
    if !stdout().is_terminal() {
        return Err(anyhow!(
            "'netgap ui' needs a terminal; run it directly from a shell"
        ));
    }

    let mut app = App::new()?;
    let guard = TerminalGuard::enter()?;

    let (events, mut receiver) = mpsc::unbounded_channel::<UiEvent>();
    spawn_input(events.clone());

    let mut ticker = tokio::time::interval(Duration::from_millis(150));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while !app.quit {
        tokio::select! {
            message = receiver.recv() => {
                match message {
                    Some(UiEvent::Key(key)) => app.handle_key(key, &events),
                    Some(UiEvent::Resize) => app.dirty = true,
                    Some(UiEvent::Scan(update)) => {
                        app.handle_scan(update);
                        app.dirty = true;
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                // The spinner is the only thing that changes on its own.
                if app.screen == Screen::Scanning {
                    app.spinner = app.spinner.wrapping_add(1);
                    app.dirty = true;
                }
            }
        }

        if app.dirty && !app.quit {
            view::render(&app)?;
            app.dirty = false;
        }
    }

    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn interface(name: &str, ipv4: &str, prefix: u8, up: bool) -> InterfaceInfo {
        InterfaceInfo {
            name: name.to_string(),
            ipv4: Some(ipv4.to_string()),
            ipv6: None,
            mac: None,
            is_up: up,
            is_lower_up: up,
            is_loopback: name == "lo",
            is_default_route: false,
            prefix: Some(prefix),
            cidr: Some(format!("{ipv4}/{prefix}")),
        }
    }

    fn app_with(interfaces: Vec<InterfaceInfo>) -> App {
        App {
            interfaces,
            selected: 0,
            show_all: false,
            method: MethodChoice::Auto,
            mode: ScanMode::Discover,
            screen: Screen::Interfaces,
            devices: Vec::new(),
            device_selected: 0,
            devices_back: Screen::Interfaces,
            saved_scan: None,
            scans: Vec::new(),
            scan_selected: 0,
            status: String::new(),
            stage: String::new(),
            spinner: 0,
            generation: 0,
            scan_handle: None,
            help: false,
            quit: false,
            dirty: false,
        }
    }

    #[test]
    fn test_filter_hides_loopback_virtual_and_down_interfaces() {
        let app = app_with(vec![
            interface("eth0", "192.168.1.10", 24, true),
            interface("lo", "127.0.0.1", 8, true),
            interface("eth1", "10.0.0.5", 24, false),
            interface("docker0", "172.17.0.1", 16, true),
        ]);

        assert_eq!(app.visible_interfaces(), vec![0]);

        let mut app = app;
        app.toggle_filter();
        assert_eq!(app.visible_interfaces(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_toggling_the_filter_moves_off_a_hidden_interface() {
        let mut app = app_with(vec![
            interface("eth0", "192.168.1.10", 24, true),
            interface("lo", "127.0.0.1", 8, true),
        ]);
        app.selected = 1;
        app.toggle_filter(); // loopback is now visible and stays selected
        assert_eq!(app.selected, 1);
        app.toggle_filter(); // scannable only; selection must move
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_moving_selection_stays_inside_the_filter() {
        let mut app = app_with(vec![
            interface("eth0", "192.168.1.10", 24, true),
            interface("lo", "127.0.0.1", 8, true),
            interface("eth1", "10.0.0.5", 24, true),
        ]);
        app.move_interface(1);
        assert_eq!(app.selected, 2, "loopback is skipped");
        app.move_interface(1);
        assert_eq!(app.selected, 2, "the end of the list is the end");
        app.move_interface(-2);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_plan_uses_the_interface_network() {
        let app = app_with(vec![interface("eth0", "192.168.1.10", 24, true)]);
        let plan = app.build_plan().expect("plan");
        assert_eq!(plan.target, "192.168.1.10/24");
        assert_eq!(plan.interface.name, "eth0");
        assert!(plan.quiet);
    }

    #[test]
    fn test_plan_refuses_an_interface_without_an_address() {
        let mut interface = interface("eth0", "192.168.1.10", 24, true);
        interface.cidr = None;
        let app = app_with(vec![interface]);
        let error = app.build_plan().expect_err("should refuse");
        assert!(error.to_string().contains("no IPv4 network"));
    }

    #[test]
    fn test_count_devices_agrees_with_itself() {
        assert_eq!(count_devices(1), "1 device");
        assert_eq!(count_devices(0), "0 devices");
        assert_eq!(count_devices(12), "12 devices");
    }

    #[test]
    fn test_interface_keeps_a_usable_address() {
        let iface = interface("eth0", "192.168.1.10", 24, true);
        assert_eq!(
            iface.ipv4_network().map(|network| network.ip()),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
    }
}
