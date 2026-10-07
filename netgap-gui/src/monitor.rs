//! Scheduled scans, and the difference one makes from the one before it.
//!
//! A window that only scans when someone presses a button is a scanner people
//! stop pressing. The schedule scans again on an interval with the settings
//! already on the scan screen, and says only what changed since the last
//! recorded scan.
//!
//! The clock and the scan live on a thread of their own, not in the window's
//! frame loop: a compositor is free to stop drawing a window it considers
//! hidden, minimised or covered, and egui then gets no frames at all. What
//! still works while the window is not drawing is the database, the tray
//! tooltip and desktop notifications, so those are what a scheduled scan
//! updates. The window picks the result up the next time it draws.
//!
//! The comparison is `netgap-trends`, the same `ChangeDetection` that
//! `netgap watch` prints and the command line's alerts are built from — a
//! second idea of what "changed" means would mean two answers to the same
//! question. What gets reported follows the command line's alert defaults:
//! a critical finding that was not there before, and a port that opened or
//! closed. A new device is not reported — a guest's phone and a randomising
//! address look exactly like one — and neither is a device going quiet, since
//! phones sleep.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use eframe::egui;
use netgap_core::{HealthScore, ScanResult, Severity};
use netgap_engine::scan::{self, ScanRequest};
use netgap_storage::ScanStore;
use netgap_trends::{ChangeDetection, NetworkChange, ScanHistory};

/// The intervals the scan screen offers, in minutes.
pub const INTERVALS: [u64; 5] = [5, 15, 30, 60, 180];

/// A health drop this large is worth a notification on its own; the same
/// figure `netgap watch` prints an alert for.
const HEALTH_DROP_WORTH_SAYING: i16 = 5;

/// What one scheduled scan found different from the one before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Briefing {
    /// Everything that changed, including the changes not worth reporting.
    pub changes: Vec<NetworkChange>,
    /// The subset worth interrupting someone for.
    pub reported: Vec<NetworkChange>,
    /// The health score of the newest scan.
    pub health: Option<u8>,
    /// How many points the score fell, when it fell.
    pub health_drop: Option<i16>,
}

impl Briefing {
    /// Whether this briefing is worth a desktop notification.
    ///
    /// A monitor that announces every scheduled scan is one people mute. The
    /// tooltip always carries the result; the notification is for what
    /// changed.
    pub fn worth_saying(&self) -> bool {
        !self.reported.is_empty()
            || self
                .health_drop
                .is_some_and(|drop| drop >= HEALTH_DROP_WORTH_SAYING)
    }

    /// The one line that goes in the tooltip and the notification title.
    pub fn headline(&self) -> String {
        if !self.reported.is_empty() {
            let critical = self
                .reported
                .iter()
                .filter(|change| matches!(change, NetworkChange::CriticalVulnDetected { .. }))
                .count();
            let ports = self.reported.len() - critical;

            let mut parts = Vec::new();
            if critical > 0 {
                parts.push(match critical {
                    1 => "1 critical finding".to_string(),
                    count => format!("{count} critical findings"),
                });
            }
            if ports > 0 {
                parts.push(match ports {
                    1 => "1 port change".to_string(),
                    count => format!("{count} port changes"),
                });
            }
            return parts.join(" · ");
        }

        if let Some(drop) = self
            .health_drop
            .filter(|drop| *drop >= HEALTH_DROP_WORTH_SAYING)
        {
            return format!("health score fell {drop} points");
        }

        // A scan with nothing to say is still worth saying something about:
        // an empty notification reads as one that failed.
        match self.changes.len() {
            0 => "nothing changed".to_string(),
            1 => "1 change, none of them serious".to_string(),
            count => format!("{count} changes, none of them serious"),
        }
    }

    /// The reported changes, one per line, for a notification body.
    /// Capped: a network that changed in fifty places is a sentence, not a
    /// scroll, and the window has the whole list.
    pub fn detail(&self) -> String {
        const SHOWN: usize = 6;

        let mut lines: Vec<String> = self
            .reported
            .iter()
            .take(SHOWN)
            .map(|change| change.to_string())
            .collect();

        if self.reported.len() > SHOWN {
            lines.push(format!(
                "and {} more",
                self.reported.len().saturating_sub(SHOWN)
            ));
        }

        lines.join("\n")
    }
}

/// Compare two scans the way `netgap watch` does.
///
/// Link-local IPv6 addresses are left out. They appear and disappear with the
/// interface, change nothing about the device, and read as noise beside
/// addresses a person recognises — the dashboard drops them for the same
/// reason.
pub fn briefing(previous: &ScanResult, current: &ScanResult) -> Briefing {
    let before = ScanHistory::from_scan_result("previous".to_string(), previous);
    let after = ScanHistory::from_scan_result("current".to_string(), current);

    let changes: Vec<NetworkChange> = ChangeDetection::detect_changes(&before, &after)
        .into_iter()
        .filter(is_about_a_named_device)
        .collect();
    let reported = changes
        .iter()
        .filter(|change| is_worth_reporting(change))
        .cloned()
        .collect();

    let before_score = HealthScore::from_result(previous).score;
    let score = HealthScore::from_result(current).score;

    Briefing {
        changes,
        reported,
        health: Some(score),
        health_drop: (before_score > score).then(|| i16::from(before_score - score)),
    }
}

fn is_about_a_named_device(change: &NetworkChange) -> bool {
    !ip_of(change).contains(':')
}

fn ip_of(change: &NetworkChange) -> &str {
    match change {
        NetworkChange::NewDevice { ip, .. }
        | NetworkChange::DeviceGone { ip }
        | NetworkChange::NewService { ip, .. }
        | NetworkChange::ServiceClosed { ip, .. }
        | NetworkChange::CriticalVulnDetected { ip, .. }
        | NetworkChange::VulnerabilityImproved { ip }
        | NetworkChange::VulnerabilityRegressed { ip } => ip,
    }
}

/// The changes the command line alerts on by default: a critical finding that
/// is new, and a port that opened or closed. Both are about what a device
/// offers; a device appearing or leaving is a fact about the network that is
/// usually a phone going to sleep.
fn is_worth_reporting(change: &NetworkChange) -> bool {
    matches!(
        change,
        NetworkChange::CriticalVulnDetected { .. }
            | NetworkChange::NewService { .. }
            | NetworkChange::ServiceClosed { .. }
    )
}

/// When the next scheduled scan is due.
///
/// Kept as plain state with an injected `now`, so the rules can be tested
/// without sleeping and the window can ask for a repaint at exactly the right
/// time.
#[derive(Debug, Clone)]
pub struct Schedule {
    pub enabled: bool,
    pub interval: Duration,
    next_due: Option<Instant>,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            enabled: false,
            interval: Duration::from_secs(15 * 60),
            next_due: None,
        }
    }
}

impl Schedule {
    /// A schedule that is already on, counting down from now — what
    /// `netgap-gui --monitor=15` asks for.
    pub fn starting(minutes: u64, now: Instant) -> Self {
        let interval = Duration::from_secs(minutes.clamp(1, 24 * 60) * 60);
        Self {
            enabled: true,
            interval,
            next_due: Some(now + interval),
        }
    }

    /// Turn the schedule on or off. Turning it on starts the countdown now
    /// rather than scanning immediately: the person is in the window, and the
    /// Start button is right there.
    pub fn set_enabled(&mut self, enabled: bool, now: Instant) {
        if enabled == self.enabled {
            return;
        }
        self.enabled = enabled;
        self.next_due = enabled.then(|| now + self.interval);
    }

    /// Change `interval` and restart the countdown, so choosing "every hour"
    /// does not mean waiting out the previous five-minute remainder.
    pub fn set_interval(&mut self, minutes: u64, now: Instant) {
        self.interval = Duration::from_secs(minutes.clamp(1, 24 * 60) * 60);
        if self.enabled {
            self.next_due = Some(now + self.interval);
        }
    }

    /// The next scan is due: take it, and move the next one back so that a
    /// scan which fails cannot become a retry loop.
    pub fn take_due(&mut self, now: Instant) -> bool {
        if !self.enabled {
            return false;
        }
        match self.next_due {
            Some(due) if now >= due => {
                self.next_due = Some(now + self.interval);
                true
            }
            _ => false,
        }
    }

    /// A scan finished. The next one is a full interval after it ended, not
    /// after it started, so a slow scan does not immediately overlap itself.
    pub fn ran(&mut self, now: Instant) {
        if self.enabled {
            self.next_due = Some(now + self.interval);
        }
    }

    /// How long until the next scan, for the countdown on the scan screen.
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        if !self.enabled {
            return None;
        }
        Some(self.next_due?.saturating_duration_since(now))
    }

    /// When a scheduled scan is due, for the alarm that wakes the window.
    pub fn due_at(&self) -> Option<Instant> {
        if self.enabled {
            self.next_due
        } else {
            None
        }
    }
}

/// A scheduled scan that has finished, waiting for the window to notice.
pub struct Finished {
    pub result: ScanResult,
    pub briefing: Option<Briefing>,
    pub scan_id: Option<String>,
    pub warning: Option<String>,
}

/// The schedule, on its own thread.
///
/// The clock cannot live in `update`. On Wayland a compositor stops sending
/// frame callbacks to a window it is not painting — hidden, minimised, or
/// resized — and winit then discards the redraw requests that ask for one, so
/// egui's update loop stalls outright. A timer armed inside it fires once and
/// then never again (found by leaving `--monitor=1` alone with the window
/// covered: one scan, then silence for the rest of the interval). The tray has
/// the same problem, which is why a window that hides itself cannot be brought
/// back by its own icon.
///
/// This thread owns the schedule instead. It sleeps, runs the scan, saves it
/// and only then asks the window to repaint. That request is best-effort by
/// design: when the window is not drawing, the result is already on disk and
/// in the tooltip, and the window picks it up the next time the compositor
/// lets it draw.
pub struct Runner {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

/// What a due time does. A seam, so the clock can be tested without a network.
type ScanFn = Box<dyn Fn(&ScanRequest) -> Result<Finished, String> + Send>;

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    context: egui::Context,
    tray: Option<Arc<crate::tray::Tray>>,
    /// Whether the window is in front. A scan that changes nothing does not
    /// interrupt someone already looking at the window.
    attention: AtomicBool,
}

struct State {
    schedule: Schedule,
    request: Option<ScanRequest>,
    stop: bool,
    running: bool,
    finished: Option<Finished>,
    error: Option<String>,
}

impl Runner {
    pub fn new(context: egui::Context, tray: Option<Arc<crate::tray::Tray>>) -> Self {
        Self::with_scan(context, tray, Box::new(run_scheduled))
    }

    fn with_scan(
        context: egui::Context,
        tray: Option<Arc<crate::tray::Tray>>,
        scan: ScanFn,
    ) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                schedule: Schedule::default(),
                request: None,
                stop: false,
                running: false,
                finished: None,
                error: None,
            }),
            changed: Condvar::new(),
            context,
            tray,
            attention: AtomicBool::new(false),
        });

        let thread = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("netgap-monitor".into())
                .spawn(move || run_loop(shared, scan))
                .ok()
        };

        Self { shared, thread }
    }

    /// `--monitor=MINUTES`: on from the start, counting down from now.
    pub fn start(&self, minutes: u64, now: Instant) {
        let mut state = self.lock();
        state.schedule = Schedule::starting(minutes, now);
        self.shared.changed.notify_all();
    }

    pub fn set_enabled(&self, enabled: bool, now: Instant) {
        self.lock().schedule.set_enabled(enabled, now);
        self.shared.changed.notify_all();
    }

    pub fn set_interval(&self, minutes: u64, now: Instant) {
        self.lock().schedule.set_interval(minutes, now);
        self.shared.changed.notify_all();
    }

    /// The scan a due time runs, pushed by the window whenever the choices on
    /// the scan screen change. `None` means there is nothing valid to scan.
    pub fn set_request(&self, request: Option<ScanRequest>) {
        self.lock().request = request;
        self.shared.changed.notify_all();
    }

    pub fn set_attention(&self, attention: bool) {
        self.shared.attention.store(attention, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.lock().schedule.enabled
    }

    pub fn interval_minutes(&self) -> u64 {
        self.lock().schedule.interval.as_secs() / 60
    }

    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.lock().schedule.remaining(now)
    }

    pub fn running(&self) -> bool {
        self.lock().running
    }

    /// The result of a scheduled scan, once. The window owns it from here.
    pub fn take_finished(&self) -> Option<Finished> {
        self.lock().finished.take()
    }

    pub fn take_error(&self) -> Option<String> {
        self.lock().error.take()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        let running = {
            let mut state = self.lock();
            state.stop = true;
            self.shared.changed.notify_all();
            state.running
        };

        // A scan can take half a minute; the window should not wait for it on
        // its way out. The thread sees the stop flag when the scan ends.
        if !running {
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

fn run_loop(shared: Arc<Shared>, scan: ScanFn) {
    loop {
        let request = {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());

            loop {
                if state.stop {
                    return;
                }

                let now = Instant::now();
                match (state.schedule.due_at(), state.request.clone()) {
                    (Some(due), _) if now < due => {
                        state = shared
                            .changed
                            .wait_timeout(state, due - now)
                            .unwrap_or_else(|error| error.into_inner())
                            .0;
                    }
                    (Some(_), Some(request)) => {
                        state.schedule.take_due(now);
                        state.running = true;
                        break request;
                    }
                    (Some(_), None) => {
                        // Nothing valid to scan: move the clock on rather than
                        // spinning on a due time that can never be taken.
                        state.schedule.take_due(now);
                    }
                    (None, _) => {
                        state = shared
                            .changed
                            .wait(state)
                            .unwrap_or_else(|error| error.into_inner());
                    }
                }
            }
        };

        let outcome = scan(&request);
        let ended = Instant::now();
        let attention = shared.attention.load(Ordering::Relaxed);
        let announcement: (Option<String>, Option<(String, String)>) = match &outcome {
            Ok(finished) => announce(finished, attention),
            Err(error) => (
                None,
                (!attention).then(|| ("Scheduled scan failed".to_string(), error.clone())),
            ),
        };

        {
            let mut state = shared
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.running = false;
            state.schedule.ran(ended);
            match outcome {
                Ok(finished) => state.finished = Some(finished),
                Err(error) => state.error = Some(error),
            }
            shared.changed.notify_all();
        }

        if let Some(tray) = &shared.tray {
            if let Some(tooltip) = announcement.0 {
                tray.set_tooltip(&tooltip);
            }
            if let Some((summary, body)) = announcement.1 {
                tray.notify(&summary, &body);
            }
        }

        shared.context.request_repaint();
    }
}

/// The tooltip every scan leaves behind, and the notification only a change
/// earns while the window is not in front.
fn announce(finished: &Finished, attention: bool) -> (Option<String>, Option<(String, String)>) {
    let critical = finished
        .result
        .devices
        .iter()
        .flat_map(|device| &device.findings)
        .filter(|finding| finding.severity == Severity::Critical)
        .count();
    let headline = match &finished.briefing {
        Some(briefing) => briefing.headline(),
        None if critical == 0 => "no critical findings".to_string(),
        None => format!("{critical} critical"),
    };
    let devices = crate::format::devices(finished.result.devices.len());
    let tooltip = format!("{devices} · {headline}");

    let notification = match (&finished.briefing, &finished.warning) {
        (Some(briefing), _) if briefing.worth_saying() && !attention => {
            let detail = briefing.detail();
            let body = if detail.is_empty() {
                tooltip.clone()
            } else {
                format!("{tooltip}\n{detail}")
            };
            Some(("Netgap: something changed".to_string(), body))
        }
        (_, Some(warning)) if !attention => Some((
            "Scheduled scan finished with a warning".to_string(),
            warning.clone(),
        )),
        _ => None,
    };

    (Some(tooltip), notification)
}

/// Run the scan a due time asked for, and record it the way the window's own
/// worker does: a scheduled scan is history like any other.
fn run_scheduled(request: &ScanRequest) -> Result<Finished, String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Could not start the scanner: {error}"))?;

    let result = runtime
        .block_on(scan::run(request, |_progress| {}))
        .map_err(|error| format!("{error:#}"))?;

    let mut store = ScanStore::open_default()
        .map_err(|error| format!("The scan finished, but its history is unavailable: {error}"))?;

    let (scan_id, warning) = if result.devices.is_empty() {
        (None, None)
    } else {
        match store.save_scan(&result) {
            Ok(id) => (Some(id), None),
            Err(error) => (
                None,
                Some(format!(
                    "The scan finished, but its history could not be saved: {error}"
                )),
            ),
        }
    };

    // The comparison is against the history on disk, not only against scans
    // this window happened to run — including a scan the command line made.
    let previous = store.list_scans().ok().and_then(|scans| {
        scans
            .iter()
            .find(|scan| Some(scan.id.as_str()) != scan_id.as_deref())
            .and_then(|scan| store.load_scan(&scan.id).ok())
    });
    let briefing = previous
        .as_ref()
        .map(|previous| briefing(previous, &result));

    Ok(Finished {
        result,
        briefing,
        scan_id,
        warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netgap_core::{Device, Finding, FindingSummary, ScanConfig, Severity};

    fn device(ip: &str, ports: &[u16]) -> Device {
        let mut device = Device::new(ip.parse().expect("a valid address"));
        for port in ports {
            device.add_open_port(*port);
        }
        device
    }

    fn critical_finding(ip: &str) -> Finding {
        Finding {
            id: "telnet_exposed".to_string(),
            title: "Telnet is open".to_string(),
            description: "Anyone on the link can read the session.".to_string(),
            severity: Severity::Critical,
            ip: ip.parse().expect("a valid address"),
            port: Some(23),
            service: Some("Telnet".to_string()),
            remediation: "Turn Telnet off.".to_string(),
            confidence: 1.0,
        }
    }

    fn result(devices: Vec<Device>) -> ScanResult {
        ScanResult {
            started_at: chrono::Utc::now().to_rfc3339(),
            config: ScanConfig {
                interface: "eth0".to_string(),
                target: "192.168.1.0/24".to_string(),
                timeout_ms: 1000,
                concurrency: 8,
                discovery_only: false,
            },
            devices,
            summary: FindingSummary::new(),
        }
    }

    #[test]
    fn test_a_port_that_opened_is_reported() {
        let before = result(vec![device("192.168.1.10", &[22])]);
        let after = result(vec![device("192.168.1.10", &[22, 3389])]);

        let briefing = briefing(&before, &after);
        assert!(briefing
            .reported
            .iter()
            .any(|change| matches!(change, NetworkChange::NewService { port: 3389, .. })));
        assert_eq!(briefing.headline(), "1 port change");
    }

    #[test]
    fn test_closing_a_port_is_a_report_too() {
        let before = result(vec![device("192.168.1.10", &[22, 23])]);
        let after = result(vec![device("192.168.1.10", &[22])]);

        let briefing = briefing(&before, &after);
        assert!(briefing
            .reported
            .iter()
            .any(|change| matches!(change, NetworkChange::ServiceClosed { port: 23, .. })));
    }

    #[test]
    fn test_a_new_device_is_a_change_but_not_a_report() {
        let before = result(vec![device("192.168.1.10", &[22])]);
        let after = result(vec![
            device("192.168.1.10", &[22]),
            device("192.168.1.44", &[]),
        ]);

        let briefing = briefing(&before, &after);
        assert!(
            !briefing.changes.is_empty(),
            "a new device is still a change"
        );
        assert!(
            briefing.reported.is_empty(),
            "guests and randomising addresses are not alerts"
        );
        assert!(briefing.headline().contains("none of them serious"));
    }

    #[test]
    fn test_a_new_critical_finding_is_reported() {
        let before = result(vec![device("192.168.1.10", &[23])]);
        let mut after_device = device("192.168.1.10", &[23]);
        after_device.add_finding(critical_finding("192.168.1.10"));
        let after = result(vec![after_device]);

        let briefing = briefing(&before, &after);
        assert!(briefing
            .reported
            .iter()
            .any(|change| matches!(change, NetworkChange::CriticalVulnDetected { .. })));
        assert_eq!(briefing.headline(), "1 critical finding");
    }

    #[test]
    fn test_link_local_addresses_are_not_changes() {
        let before = result(vec![device("192.168.1.10", &[22])]);
        let after = result(vec![
            device("192.168.1.10", &[22]),
            device("fe80::1c2b:3aff:fe4d:5067", &[]),
        ]);

        let briefing = briefing(&before, &after);
        assert!(briefing.changes.is_empty());
        assert_eq!(briefing.headline(), "nothing changed");
    }

    #[test]
    fn test_a_health_drop_is_counted_when_nothing_else_changed() {
        // Two critical findings are two of the problems the score is charged
        // for, so the drop is real and the changes list need not be empty for
        // it to be worth saying.
        let before = result(vec![device("192.168.1.10", &[23])]);
        let mut after_device = device("192.168.1.10", &[23]);
        after_device.add_finding(critical_finding("192.168.1.10"));
        let after = result(vec![after_device]);

        let briefing = briefing(&before, &after);
        let expected = HealthScore::from_result(&before).score as i16
            - HealthScore::from_result(&after).score as i16;
        assert_eq!(briefing.health_drop, (expected > 0).then_some(expected));
    }

    #[test]
    fn test_only_a_change_interrupts_someone() {
        let before = result(vec![device("192.168.1.10", &[22])]);
        let quiet = result(vec![
            device("192.168.1.10", &[22]),
            device("192.168.1.44", &[]),
        ]);
        assert!(!briefing(&before, &quiet).worth_saying());

        let changed = result(vec![device("192.168.1.10", &[22, 3389])]);
        assert!(briefing(&before, &changed).worth_saying());
    }

    #[test]
    fn test_detail_lists_reported_changes_and_caps_them() {
        let mut briefing = Briefing::default();
        for port in 1..=10 {
            briefing.reported.push(NetworkChange::NewService {
                ip: "192.168.1.10".to_string(),
                port,
            });
        }

        let detail = briefing.detail();
        assert_eq!(detail.lines().count(), 7, "six lines and a count");
        assert!(detail.ends_with("and 4 more"));
    }

    #[test]
    fn test_the_schedule_is_off_and_stays_quiet() {
        let mut schedule = Schedule::default();
        let now = Instant::now();

        assert!(!schedule.take_due(now + Duration::from_secs(3600)));
        assert_eq!(schedule.remaining(now), None);
    }

    #[test]
    fn test_the_schedule_fires_once_an_interval_has_passed() {
        let mut schedule = Schedule::default();
        let now = Instant::now();
        schedule.set_enabled(true, now);

        assert!(!schedule.take_due(now + Duration::from_secs(14 * 60)));
        assert!(schedule.take_due(now + Duration::from_secs(15 * 60)));
        // Taking it moves the next one back: a failing scan must not spin.
        assert!(!schedule.take_due(now + Duration::from_secs(15 * 60)));
        assert!(schedule.take_due(now + Duration::from_secs(30 * 60)));
    }

    #[test]
    fn test_a_finished_scan_restarts_the_countdown_from_its_end() {
        let mut schedule = Schedule::default();
        let now = Instant::now();
        schedule.set_enabled(true, now);
        let started = now + Duration::from_secs(15 * 60);
        assert!(schedule.take_due(started));

        // The scan took four minutes; the next is fifteen after it finished.
        let ended = started + Duration::from_secs(4 * 60);
        schedule.ran(ended);

        assert!(!schedule.take_due(started + Duration::from_secs(14 * 60)));
        assert!(schedule.take_due(ended + Duration::from_secs(15 * 60)));
    }

    #[test]
    fn test_choosing_a_new_interval_restarts_the_countdown() {
        let mut schedule = Schedule::default();
        let now = Instant::now();
        schedule.set_enabled(true, now);
        schedule.set_interval(60, now);

        assert_eq!(schedule.remaining(now), Some(Duration::from_secs(60 * 60)));
        assert!(!schedule.take_due(now + Duration::from_secs(59 * 60)));
        assert!(schedule.take_due(now + Duration::from_secs(60 * 60)));
    }

    #[test]
    fn test_turning_the_schedule_off_clears_the_countdown() {
        let mut schedule = Schedule::default();
        let now = Instant::now();
        schedule.set_enabled(true, now);
        schedule.set_enabled(false, now);

        assert_eq!(schedule.remaining(now), None);
        assert!(!schedule.take_due(now + Duration::from_secs(24 * 60 * 60)));
    }

    #[test]
    fn test_starting_from_the_command_line_counts_down_from_now() {
        let now = Instant::now();
        let schedule = Schedule::starting(5, now);

        assert!(schedule.enabled);
        assert_eq!(schedule.remaining(now), Some(Duration::from_secs(5 * 60)));
    }

    fn request() -> ScanRequest {
        use netgap_engine::discovery::{DiscoveryMethod, DiscoveryPlan};
        use netgap_interfaces::InterfaceInfo;

        ScanRequest {
            plan: DiscoveryPlan {
                method: DiscoveryMethod::Tcp,
                interface: InterfaceInfo {
                    name: "eth0".to_string(),
                    ipv4: Some("192.168.1.2".to_string()),
                    ipv6: None,
                    mac: None,
                    is_up: true,
                    is_lower_up: true,
                    is_loopback: false,
                    is_default_route: false,
                    prefix: Some(24),
                    cidr: Some("192.168.1.0/24".to_string()),
                },
                target: "192.168.1.0/24".to_string(),
                max_hosts: 256,
                allow_fallback: true,
                mdns: false,
                quiet: true,
            },
            ports: false,
        }
    }

    /// A runner whose scan only says it ran, so the clock can be tested
    /// without a network or a database.
    fn runner_with_signal() -> (Runner, std::sync::mpsc::Receiver<()>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        let runner = Runner::with_scan(
            egui::Context::default(),
            None,
            Box::new(move |_| {
                let _ = sender.send(());
                Ok(Finished {
                    result: result(Vec::new()),
                    briefing: None,
                    scan_id: None,
                    warning: None,
                })
            }),
        );
        (runner, receiver)
    }

    #[test]
    fn test_the_runner_scans_when_due() {
        let (runner, ran) = runner_with_signal();
        runner.set_request(Some(request()));
        // A deadline in the past is due now.
        runner.start(1, Instant::now() - Duration::from_secs(61));

        ran.recv_timeout(Duration::from_secs(2))
            .expect("the due scan ran");

        // The scan signals before it returns, so the result reaches the
        // window a moment later.
        let deadline = Instant::now() + Duration::from_secs(2);
        let finished = loop {
            if let Some(finished) = runner.take_finished() {
                break finished;
            }
            assert!(
                Instant::now() < deadline,
                "the result was kept for the window"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(finished.result.devices.is_empty());
    }

    #[test]
    fn test_the_runner_stays_quiet_while_off() {
        let (runner, ran) = runner_with_signal();
        runner.set_request(Some(request()));

        assert!(ran.recv_timeout(Duration::from_millis(200)).is_err());
        assert!(!runner.running());
        assert!(runner.take_finished().is_none());
    }

    #[test]
    fn test_a_due_time_with_nothing_to_scan_is_skipped() {
        let (runner, ran) = runner_with_signal();
        // No request: a schedule watching an empty interface list must not
        // spin on a due time it can never honour.
        runner.start(1, Instant::now() - Duration::from_secs(61));

        assert!(ran.recv_timeout(Duration::from_millis(200)).is_err());
        assert!(runner
            .remaining(Instant::now())
            .is_some_and(|remaining| remaining > Duration::ZERO));
    }
}
