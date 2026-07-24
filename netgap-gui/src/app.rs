//! Window state and the shell around the views.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, Stroke, Vec2};
use netgap_core::{ScanResult, Severity};
use netgap_engine::discovery::{self, DiscoveryMethod};
use netgap_interfaces::InterfaceInfo;
use netgap_storage::{ScanMetadata, ScanStore};

use crate::theme::{self, Palette, Theme};
use crate::views;
use crate::widgets;
use crate::worker::{self, WorkerEvent};

/// The four places the window can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Scan,
    Devices,
    History,
}

impl Tab {
    fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Scan => "Scan network",
            Tab::Devices => "Devices",
            Tab::History => "History",
        }
    }

    /// The screen named on the command line, so `netgap-gui history` opens
    /// straight onto the history.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "dashboard" | "overview" => Some(Tab::Dashboard),
            "scan" => Some(Tab::Scan),
            "devices" => Some(Tab::Devices),
            "history" => Some(Tab::History),
            _ => None,
        }
    }
}

/// How hosts will be found, in the terms the scan screen offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodChoice {
    Auto,
    Arp,
    Tcp,
}

impl MethodChoice {
    fn to_requested(self) -> Option<DiscoveryMethod> {
        match self {
            MethodChoice::Auto => None,
            MethodChoice::Arp => Some(DiscoveryMethod::Arp),
            MethodChoice::Tcp => Some(DiscoveryMethod::Tcp),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MethodChoice::Auto => "Automatic",
            MethodChoice::Arp => "ARP (most complete)",
            MethodChoice::Tcp => "TCP connect (no privileges)",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            MethodChoice::Auto => {
                "Uses ARP when netgap has permission, and the TCP sweep otherwise."
            }
            MethodChoice::Arp => "Needs root or CAP_NET_RAW. Finds every device on the link.",
            MethodChoice::Tcp => "Works without privileges. Finds fewer devices.",
        }
    }
}

/// A scan loaded from the database, or one that just finished.
#[derive(Debug, Clone)]
pub struct LoadedScan {
    pub id: Option<String>,
    pub result: ScanResult,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub created: Instant,
}

impl Toast {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            created: Instant::now(),
        }
    }

    pub fn visible(&self) -> bool {
        self.created.elapsed().as_secs_f32() < 4.5
    }
}

pub struct NetgapApp {
    pub tab: Tab,
    pub theme: Theme,
    pub palette: Palette,
    theme_dirty: bool,

    pub store: Option<ScanStore>,
    pub store_error: Option<String>,
    pub scans: Vec<ScanMetadata>,
    pub seen_devices: usize,

    /// The newest recorded scan, which the dashboard describes.
    pub latest: Option<LoadedScan>,
    /// The scan the device view is showing. Starts as the newest.
    pub selected_scan: Option<LoadedScan>,

    pub interfaces: Vec<InterfaceInfo>,
    pub interfaces_error: Option<String>,
    pub selected_interface: Option<usize>,
    pub show_all_interfaces: bool,
    pub target: String,
    pub method: MethodChoice,
    pub privileged: bool,
    pub full_scan: bool,

    pub scanning: bool,
    pub scan_started: Option<Instant>,
    pub scan_log: Vec<String>,
    pub scan_stage: String,
    pub scan_error: Option<String>,
    events: Option<Receiver<WorkerEvent>>,

    pub device_search: String,
    pub severity_filter: Option<Severity>,
    pub selected_device: Option<usize>,

    pub toast: Option<Toast>,
}

impl NetgapApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial_tab: Tab, theme: Theme) -> Self {
        theme::apply(&cc.egui_ctx, theme);

        let (interfaces, interfaces_error) = match netgap_interfaces::get_interfaces() {
            Ok(interfaces) => (interfaces, None),
            Err(error) => (
                Vec::new(),
                Some(format!("Could not list network interfaces: {error}")),
            ),
        };

        let selected_interface = default_interface_index(&interfaces);
        let target = selected_interface
            .and_then(|index| interfaces.get(index))
            .map(default_target)
            .unwrap_or_default();

        let (store, store_error) = match ScanStore::open_default() {
            Ok(store) => (Some(store), None),
            Err(error) => (None, Some(format!("Scan history is unavailable: {error}"))),
        };

        let mut app = Self {
            tab: initial_tab,
            theme,
            palette: Palette::for_theme(theme),
            theme_dirty: false,
            store,
            store_error,
            scans: Vec::new(),
            seen_devices: 0,
            latest: None,
            selected_scan: None,
            interfaces,
            interfaces_error,
            selected_interface,
            show_all_interfaces: false,
            target,
            method: MethodChoice::Auto,
            privileged: discovery::has_cap_net_raw(),
            full_scan: true,
            scanning: false,
            scan_started: None,
            scan_log: Vec::new(),
            scan_stage: String::new(),
            scan_error: None,
            events: None,
            device_search: String::new(),
            severity_filter: None,
            selected_device: None,
            toast: None,
        };

        app.reload_history();
        app.load_latest();
        app
    }

    /// Read the scan list and the count of devices ever seen. Cheap enough to
    /// do after every scan and when the history screen is opened.
    pub fn reload_history(&mut self) {
        let Some(store) = &self.store else {
            return;
        };

        match store.list_scans() {
            Ok(scans) => self.scans = scans,
            Err(error) => {
                self.store_error = Some(format!("Could not read scan history: {error}"));
            }
        }

        if let Ok(seen) = store.device_history() {
            self.seen_devices = seen.len();
        }
    }

    fn load_latest(&mut self) {
        let Some(metadata) = self.scans.first().cloned() else {
            return;
        };
        let Some(store) = &self.store else {
            return;
        };

        match store.load_scan(&metadata.id) {
            Ok(result) => {
                let loaded = LoadedScan {
                    id: Some(metadata.id.clone()),
                    result,
                };
                // The device view picks the worst device in the list; keep
                // the selection empty so that happens when it is opened.
                self.selected_device = None;
                self.latest = Some(loaded.clone());
                self.selected_scan = Some(loaded);
            }
            Err(error) => {
                self.store_error = Some(format!("Could not read the latest scan: {error}"));
            }
        }
    }

    /// Load one stored scan for the device view and the history detail.
    pub fn open_scan(&mut self, id: &str) {
        let Some(store) = &self.store else {
            self.toast = Some(Toast::new("Scan history is not available."));
            return;
        };

        match store.load_scan(id) {
            Ok(result) => {
                // The device view picks the worst device in the list; keep
                // the selection empty so that happens when it is opened.
                self.selected_device = None;
                self.selected_scan = Some(LoadedScan {
                    id: Some(id.to_string()),
                    result,
                });
                self.device_search.clear();
                self.severity_filter = None;
            }
            Err(error) => {
                self.toast = Some(Toast::new(format!("Could not open that scan: {error}")));
            }
        }
    }

    /// The scan the Devices screen is about.
    pub fn current(&self) -> Option<&LoadedScan> {
        self.selected_scan.as_ref().or(self.latest.as_ref())
    }

    pub fn current_devices(&self) -> usize {
        self.current().map_or(0, |scan| scan.result.devices.len())
    }

    /// Indices into `interfaces` that the scan screen should list.
    pub fn visible_interfaces(&self) -> Vec<usize> {
        self.interfaces
            .iter()
            .enumerate()
            .filter(|(_, interface)| {
                self.show_all_interfaces || (interface.is_scannable() && !interface.is_virtual())
            })
            .map(|(index, _)| index)
            .collect()
    }

    pub fn selected_interface(&self) -> Option<&InterfaceInfo> {
        self.selected_interface
            .and_then(|index| self.interfaces.get(index))
    }

    /// Keep the selection on a row the current filter shows.
    pub fn ensure_selection(&mut self) {
        let visible = self.visible_interfaces();
        if visible.is_empty() {
            self.selected_interface = None;
            return;
        }

        let still_visible = self
            .selected_interface
            .map(|selected| visible.contains(&selected))
            .unwrap_or(false);
        if !still_visible {
            self.selected_interface = visible.first().copied();
        }
    }

    pub fn choose_interface(&mut self, index: usize) {
        self.selected_interface = Some(index);
        if let Some(interface) = self.interfaces.get(index) {
            self.target = default_target(interface);
        }
    }

    pub fn rescan_interfaces(&mut self) {
        match netgap_interfaces::get_interfaces() {
            Ok(interfaces) => {
                self.interfaces = interfaces;
                self.interfaces_error = None;
                self.ensure_selection();
                if self.target.trim().is_empty() {
                    if let Some(interface) = self.selected_interface() {
                        self.target = default_target(interface);
                    }
                }
            }
            Err(error) => {
                self.interfaces_error = Some(format!("Could not list network interfaces: {error}"));
            }
        }
    }

    pub fn start_scan(&mut self) {
        if self.scanning {
            return;
        }

        let Some(interface) = self.selected_interface().cloned() else {
            self.scan_error = Some("Choose a network interface first.".to_string());
            return;
        };

        let target = self.target.trim().to_string();
        if target.is_empty() {
            self.scan_error = Some("Enter the network to scan, for example 192.168.1.0/24.".into());
            return;
        }

        let plan = match discovery::build_plan(
            interface,
            target,
            self.method.to_requested(),
            discovery::DEFAULT_MAX_HOSTS,
            false,
            true,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                self.scan_error = Some(format!("{error:#}"));
                return;
            }
        };

        let request = netgap_engine::scan::ScanRequest {
            plan,
            ports: self.full_scan,
        };

        match worker::start(request) {
            Ok(receiver) => {
                self.events = Some(receiver);
                self.scanning = true;
                self.scan_started = Some(Instant::now());
                self.scan_log.clear();
                self.scan_stage = "Starting…".to_string();
                self.scan_error = None;
                self.toast = None;
            }
            Err(error) => {
                self.scan_error = Some(error);
            }
        }
    }

    fn poll_events(&mut self) {
        let events: Vec<WorkerEvent> = self
            .events
            .as_ref()
            .map(|receiver| receiver.try_iter().collect())
            .unwrap_or_default();

        for event in events {
            match event {
                WorkerEvent::Progress(progress) => {
                    self.scan_stage = progress.message.clone();
                    self.scan_log.push(progress.message);
                    if self.scan_log.len() > 30 {
                        self.scan_log.remove(0);
                    }
                }
                WorkerEvent::Done {
                    result,
                    scan_id,
                    warning,
                } => {
                    self.scanning = false;
                    self.scan_started = None;
                    self.events = None;
                    self.scan_stage = "Finished".to_string();
                    self.selected_device = None;
                    self.device_search.clear();
                    self.severity_filter = None;

                    let loaded = LoadedScan {
                        id: scan_id,
                        result,
                    };
                    self.latest = Some(loaded.clone());
                    self.selected_scan = Some(loaded);
                    self.reload_history();
                    self.tab = Tab::Devices;

                    self.toast = Some(Toast::new(match warning {
                        Some(warning) => warning,
                        None => format!(
                            "Scan finished: {}.",
                            crate::format::devices(self.current_devices())
                        ),
                    }));
                }
                WorkerEvent::Failed(message) => {
                    self.scanning = false;
                    self.scan_started = None;
                    self.events = None;
                    self.scan_stage = "Stopped".to_string();
                    self.scan_error = Some(message);
                }
            }
        }

        if self.scanning {
            let disconnected = self
                .events
                .as_ref()
                .map(|receiver| matches!(receiver.try_recv(), Err(TryRecvError::Disconnected)))
                .unwrap_or(true);
            if disconnected {
                self.scanning = false;
                self.scan_started = None;
                self.events = None;
                self.scan_error = Some("The scan stopped before it reported a result.".to_string());
            }
        }
    }

    pub fn toggle_theme(&mut self) {
        self.theme = self.theme.toggled();
        self.theme_dirty = true;
    }

    /// Write a report for the current scan and say where it went.
    pub fn export_report(&mut self, format: &str) {
        let Some(id) = self.current().and_then(|scan| scan.id.clone()) else {
            self.toast = Some(Toast::new(
                "This scan is not in the history, so it has no report to export.",
            ));
            return;
        };
        let Some(store) = &self.store else {
            self.toast = Some(Toast::new("Scan history is not available."));
            return;
        };

        let contents = match format {
            "csv" => store.export_csv(&id),
            _ => store.export_html(&id),
        };

        let contents = match contents {
            Ok(contents) => contents,
            Err(error) => {
                self.toast = Some(Toast::new(format!("Could not build the report: {error}")));
                return;
            }
        };

        let extension = if format == "csv" { "csv" } else { "html" };
        let path = home_directory().join(format!("netgap-{id}.{extension}"));
        match std::fs::write(&path, contents) {
            Ok(()) => {
                self.toast = Some(Toast::new(format!("Report saved to {}", path.display())));
            }
            Err(error) => {
                self.toast = Some(Toast::new(format!(
                    "Could not write {}: {error}",
                    path.display()
                )));
            }
        }
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        let p = self.palette;

        egui::SidePanel::left("sidebar")
            .exact_width(214.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(p.panel)
                    .inner_margin(egui::Margin::symmetric(14, 18)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(32.0), egui::Sense::hover());
                    let painter = ui.painter();
                    painter.circle_filled(rect.center(), 15.0, p.accent_soft);
                    painter.circle_stroke(rect.center(), 15.0, Stroke::new(1.5, p.accent));
                    painter.circle_filled(rect.center(), 4.5, p.accent);

                    ui.add_space(2.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("netgap").size(20.0).strong().color(p.text));
                        ui.label(RichText::new("network security").size(10.5).color(p.muted));
                    });
                });

                ui.add_space(28.0);

                for tab in [Tab::Dashboard, Tab::Scan, Tab::Devices, Tab::History] {
                    if widgets::nav_button(ui, &p, self.tab == tab, tab.label()) {
                        self.tab = tab;
                        if tab == Tab::History {
                            self.reload_history();
                        }
                    }
                    ui.add_space(2.0);
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new(format!("netgap {}", env!("CARGO_PKG_VERSION")))
                            .size(11.0)
                            .color(p.muted),
                    );
                    ui.add_space(6.0);

                    let label = if self.theme.is_dark() {
                        "Light mode"
                    } else {
                        "Dark mode"
                    };
                    if widgets::secondary_button(ui, &p, label) {
                        self.toggle_theme();
                    }

                    ui.add_space(10.0);
                    ui.label(
                        RichText::new("Same scanner as the command line.")
                            .size(11.0)
                            .color(p.muted),
                    );
                    ui.add_space(4.0);
                });
            });
    }

    fn toast(&mut self, ctx: &egui::Context) {
        let Some(toast) = &self.toast else {
            return;
        };
        if !toast.visible() {
            self.toast = None;
            return;
        }

        let p = self.palette;
        let text = toast.text.clone();
        ctx.request_repaint_after(Duration::from_millis(250));

        egui::Area::new(egui::Id::new("toast"))
            .anchor(egui::Align2::RIGHT_BOTTOM, Vec2::new(-24.0, -24.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(p.card)
                    .stroke(Stroke::new(1.0, p.accent))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(16, 11))
                    .show(ui, |ui| {
                        ui.set_max_width(430.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("●").size(12.0).color(p.accent));
                            ui.label(RichText::new(text).size(13.0).color(p.text));
                        });
                    });
            });
    }
}

impl eframe::App for NetgapApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.theme_dirty {
            theme::apply(ctx, self.theme);
            self.palette = Palette::for_theme(self.theme);
            self.theme_dirty = false;
        }

        self.poll_events();
        self.ensure_selection();

        if self.scanning || self.toast.as_ref().is_some_and(Toast::visible) {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        self.sidebar(ctx);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(self.palette.bg)
                    .inner_margin(egui::Margin::symmetric(26, 22)),
            )
            .show(ctx, |ui| match self.tab {
                // The device screen sizes itself to the remaining window and
                // scrolls its two panes separately. The others are documents
                // that are taller than a small window, so they scroll whole.
                Tab::Devices => views::devices::show(self, ui),
                tab => {
                    egui::ScrollArea::vertical()
                        .id_salt(("page", tab.label()))
                        .auto_shrink([false, false])
                        .show(ui, |ui| match tab {
                            Tab::Dashboard => views::dashboard::show(self, ui),
                            Tab::Scan => views::scan::show(self, ui),
                            Tab::History => views::history::show(self, ui),
                            Tab::Devices => unreachable!("handled above"),
                        });
                }
            });

        self.toast(ctx);
    }
}

fn default_interface_index(interfaces: &[InterfaceInfo]) -> Option<usize> {
    if let Ok(Some(preferred)) = netgap_interfaces::load_validated_preference() {
        if let Some(index) = interfaces
            .iter()
            .position(|interface| interface.name == preferred.name)
        {
            return Some(index);
        }
    }

    let default_route = interfaces
        .iter()
        .find(|interface| interface.is_default_route)
        .map(|interface| interface.name.as_str());
    let best = netgap_interfaces::select_best(interfaces, default_route)?;
    interfaces
        .iter()
        .position(|interface| interface.name == best.name)
}

fn default_target(interface: &InterfaceInfo) -> String {
    interface
        .cidr
        .clone()
        .or_else(|| netgap_interfaces::get_interface_cidr(&interface.name).ok())
        .unwrap_or_default()
}

fn home_directory() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
