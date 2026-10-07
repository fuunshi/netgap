//! A StatusNotifierItem over D-Bus, plus desktop notifications.
//!
//! Nothing here needs GTK: the icon, its menu and the "still running" message
//! are all just D-Bus objects and calls, served on a blocking zbus connection
//! from the GUI's own process. That matters because the alternative crate
//! (`tray-icon`) links GTK at build time, which would tie a Rust build to a
//! development package no CI image here has.
//!
//! The specification has two halves, and both are implemented below:
//!
//! * `org.kde.StatusNotifierItem` at `/StatusNotifierItem` — the icon, its
//!   tooltip, and the `Activate`/`SecondaryActivate` methods the desktop calls
//!   when the icon is clicked.
//! * `com.canonical.dbusmenu` at `/MenuBar` — the right-click menu, which is
//!   how the icon offers "Scan now" and, crucially, "Quit".
//!
//! The menus are data: `GetLayout` returns the tree every time it is asked,
//! because the menu is four static entries and caching it would only add a
//! staleness bug. Clicks come back through the same channel as the icon
//! clicks, so the window has one place to handle them.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use zbus::blocking::{connection, Connection};
use zbus::zvariant::{Array, Dict, ObjectPath, OwnedObjectPath, StructureBuilder, Type, Value};

/// The object path the icon lives at, as the specification names it.
const ITEM_PATH: &str = "/StatusNotifierItem";
const ITEM_INTERFACE: &str = "org.kde.StatusNotifierItem";

/// The object path of the menu.
const MENU_PATH: &str = "/MenuBar";

/// The well-known name this process asks for; registering a stable name means
/// a second instance is detected by the bus rather than by both fighting over
/// one icon.
const WELL_KNOWN_NAME: &str = "org.kde.netgap";

/// The icon is 22×22, the size trays ask for when they ask for nothing.
const ICON_SIZE: i32 = 22;

/// The shape the desktop takes for a tray image: width, height, ARGB bytes.
type Pixmaps = Vec<(i32, i32, Vec<u8>)>;

/// What the menu or the icon asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The icon was clicked: bring the window back.
    Show,
    /// The menu asked for a scan.
    ScanNow,
    /// The menu asked to exit. Only the menu can do this once the window can
    /// be hidden.
    Quit,
}

/// The tooltip layout: icon, pixmaps, title, body.
type Tooltip = (String, Pixmaps, String, String);

/// State the icon shows and the window updates.
#[derive(Default)]
struct State {
    tooltip: String,
}

struct ItemIface {
    state: Arc<Mutex<State>>,
    events: Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl ItemIface {
    fn emit(&self, event: Event) {
        // A closed channel means the window is going away; the click is moot.
        let _ = self.events.send(event);
        (self.wake)();
    }
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl ItemIface {
    #[zbus(property)]
    fn id(&self) -> String {
        "netgap".to_string()
    }

    #[zbus(property)]
    fn category(&self) -> String {
        "ApplicationStatus".to_string()
    }

    #[zbus(property)]
    fn status(&self) -> String {
        "Active".to_string()
    }

    #[zbus(property)]
    fn title(&self) -> String {
        "Netgap".to_string()
    }

    /// Empty: the icon travels as a pixmap, so no icon theme has to know us.
    #[zbus(property)]
    fn icon_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Pixmaps {
        vec![(ICON_SIZE, ICON_SIZE, icon_pixels())]
    }

    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        ObjectPath::try_from(MENU_PATH)
            .expect("a constant object path")
            .into()
    }

    /// Left click shows the menu instead of activating the window. Both are
    /// useful, but the menu is the only way back to "Quit" once the window is
    /// hidden, so it gets the primary button.
    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        true
    }

    // The spec spells this one "ToolTip", not the "Tooltip" zbus would derive
    // from the method name. A host reads the spec spelling, so without this
    // the tooltip exists on the bus and is never shown.
    #[zbus(property, name = "ToolTip")]
    fn tooltip(&self) -> Tooltip {
        let body = self
            .state
            .lock()
            .map(|state| state.tooltip.clone())
            .unwrap_or_default();
        (
            "netgap".to_string(),
            vec![(ICON_SIZE, ICON_SIZE, icon_pixels())],
            "Netgap".to_string(),
            body,
        )
    }

    #[zbus(name = "Activate")]
    fn activate(&self, _x: i32, _y: i32) {
        self.emit(Event::Show);
    }

    #[zbus(name = "SecondaryActivate")]
    fn secondary_activate(&self, _x: i32, _y: i32) {
        self.emit(Event::ScanNow);
    }

    #[zbus(name = "ContextMenu")]
    fn context_menu(&self, _x: i32, _y: i32) {
        // The host opens the menu itself, from the same /MenuBar object.
    }

    #[zbus(name = "Scroll")]
    fn scroll(&self, _delta: i32, _orientation: String) {}
}

struct MenuIface {
    events: Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl MenuIface {
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
        (self.wake)();
    }
}

/// One menu entry as dbusmenu sends it: `(id, properties, children)`.
#[derive(Serialize, Type)]
struct LayoutItem {
    id: i32,
    properties: HashMap<String, Value<'static>>,
    children: Vec<Value<'static>>,
}

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl MenuIface {
    #[zbus(name = "GetLayout")]
    fn get_layout(
        &self,
        _parent_id: i32,
        _recursion_depth: i32,
        _property_names: Vec<String>,
    ) -> (u32, LayoutItem) {
        // Revision 1: the menu never changes, so hosts may cache it for as
        // long as they like.
        (1, layout())
    }

    #[zbus(name = "GetGroupProperties")]
    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        _property_names: Vec<String>,
    ) -> Vec<(i32, HashMap<String, Value<'static>>)> {
        entries()
            .into_iter()
            .filter(|(id, _)| ids.is_empty() || ids.contains(id))
            .collect()
    }

    #[zbus(name = "GetProperty")]
    fn get_property(&self, id: i32, name: String) -> zbus::fdo::Result<Value<'static>> {
        entries()
            .into_iter()
            .find(|(entry_id, _)| *entry_id == id)
            .and_then(|(_, properties)| properties.get(&name).cloned())
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("no menu item {id} named {name}")))
    }

    #[zbus(name = "Event")]
    fn event(&self, id: i32, event_id: String, _data: Value<'_>, _timestamp: u32) {
        // "clicked" is what hosts send for a normal activation; "activated" is
        // used when the item has no menu of its own.
        if event_id != "clicked" && event_id != "activated" {
            return;
        }

        match id {
            1 => self.emit(Event::Show),
            2 => self.emit(Event::ScanNow),
            4 => self.emit(Event::Quit),
            _ => {}
        }
    }

    #[zbus(name = "AboutToShow")]
    fn about_to_show(&self, _id: i32) -> bool {
        true
    }

    #[zbus(name = "AboutToShowGroup")]
    fn about_to_show_group(&self, _ids: Vec<i32>) -> Vec<i32> {
        Vec::new()
    }
}

/// The handle the window keeps. Dropping it removes the icon, because the
/// connection carrying it closes.
pub struct Tray {
    connection: Connection,
    state: Arc<Mutex<State>>,
}

impl Tray {
    /// Replace the tooltip body, which is where the last scan's result goes.
    pub fn set_tooltip(&self, text: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.tooltip = text.to_string();
        }

        let tooltip = self.tooltip();
        let _ = self.connection.emit_signal(
            None::<&str>,
            ITEM_PATH,
            ITEM_INTERFACE,
            "NewToolTip",
            &tooltip,
        );
    }

    /// Show a desktop notification. Used when the window hides itself, and
    /// later for scans that finish while it is hidden.
    ///
    /// A missing notification daemon is not an error worth reporting: the
    /// tooltip still carries the same words.
    pub fn notify(&self, summary: &str, body: &str) {
        let hints: HashMap<String, Value<'static>> = HashMap::new();
        let _ = self.connection.call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "Netgap",
                0u32,
                "",
                summary,
                body,
                Vec::<&str>::new(),
                hints,
                4000i32,
            ),
        );
    }

    fn tooltip(&self) -> Tooltip {
        let body = self
            .state
            .lock()
            .map(|state| state.tooltip.clone())
            .unwrap_or_default();
        (
            "netgap".to_string(),
            vec![(ICON_SIZE, ICON_SIZE, icon_pixels())],
            "Netgap".to_string(),
            body,
        )
    }
}

/// Start the icon. The returned receiver carries menu clicks; `wake` is called
/// after each one so the window's event loop, which may be idle while hidden,
/// repaints and drains the channel.
pub fn start(wake: impl Fn() + Send + Sync + 'static) -> Result<(Tray, Receiver<Event>), String> {
    start_on(None, wake)
}

/// The same, against a specific bus address — the seam the tests use to talk
/// to a private `dbus-daemon` rather than the developer's session.
fn start_on(
    bus_address: Option<&str>,
    wake: impl Fn() + Send + Sync + 'static,
) -> Result<(Tray, Receiver<Event>), String> {
    let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(wake);
    let (sender, receiver) = mpsc::channel();
    let state = Arc::new(Mutex::new(State::default()));

    let builder = match bus_address {
        Some(address) => connection::Builder::address(address),
        None => connection::Builder::session(),
    }
    .map_err(|error| format!("no D-Bus session to put an icon on: {error}"))?;

    let connection = builder
        .serve_at(
            ITEM_PATH,
            ItemIface {
                state: Arc::clone(&state),
                events: sender.clone(),
                wake: Arc::clone(&wake),
            },
        )
        .map_err(|error| format!("could not publish the tray icon: {error}"))?
        .serve_at(
            MENU_PATH,
            MenuIface {
                events: sender,
                wake,
            },
        )
        .map_err(|error| format!("could not publish the tray menu: {error}"))?
        .name(WELL_KNOWN_NAME)
        .map_err(|error| format!("could not claim {WELL_KNOWN_NAME}: {error}"))?
        .build()
        .map_err(|error| format!("could not connect to D-Bus: {error}"))?;

    // The watcher is the service every status-notifier host owns. No watcher
    // means no tray: saying so lets the window keep its close button working
    // instead of vanishing into an icon nobody displays.
    connection
        .call_method(
            Some("org.kde.StatusNotifierWatcher"),
            "/StatusNotifierWatcher",
            Some("org.kde.StatusNotifierWatcher"),
            "RegisterStatusNotifierItem",
            &(WELL_KNOWN_NAME,),
        )
        .map_err(|error| {
            format!("no status-notifier host answered ({error}); the window will not hide")
        })?;

    Ok((Tray { connection, state }, receiver))
}

/// The menu, as one tree. Ids are stable because a click comes back as an id.
fn layout() -> LayoutItem {
    let entries = entries();
    let child = |id: i32| {
        let (_, properties) = entries
            .iter()
            .find(|(entry_id, _)| *entry_id == id)
            .expect("the menu defines this id");
        item_value(id, properties.clone(), Vec::new())
    };

    LayoutItem {
        id: 0,
        properties: HashMap::new(),
        children: vec![child(1), child(2), child(3), child(4)],
    }
}

/// Every entry's properties, in menu order.
fn entries() -> Vec<(i32, HashMap<String, Value<'static>>)> {
    vec![
        (1, entry("Open Netgap")),
        (2, entry("Scan now")),
        (3, separator()),
        (4, entry("Quit")),
    ]
}

fn entry(label: &str) -> HashMap<String, Value<'static>> {
    let mut properties = HashMap::new();
    properties.insert("label".to_string(), Value::from(label.to_owned()));
    properties.insert("enabled".to_string(), Value::from(true));
    properties.insert("visible".to_string(), Value::from(true));
    properties
}

fn separator() -> HashMap<String, Value<'static>> {
    let mut properties = HashMap::new();
    properties.insert("type".to_string(), Value::from("separator"));
    properties
}

fn item_value(
    id: i32,
    properties: HashMap<String, Value<'static>>,
    children: Vec<Value<'static>>,
) -> Value<'static> {
    let structure = StructureBuilder::new()
        .append_field(Value::from(id))
        .append_field(Value::Dict(Dict::from(properties)))
        .append_field(Value::Array(Array::from(children)))
        .build()
        .expect("a menu item always has three fields");
    Value::Structure(structure)
}

/// The icon, drawn rather than shipped as a file: 22×22, a teal disc with a
/// white "N" on it. ARGB, most significant byte first, as the specification
/// requires.
fn icon_pixels() -> Vec<u8> {
    // A five-by-seven "N", three pixels per cell.
    const GLYPH: [&str; 7] = [
        "#...#", "##..#", "##..#", "#.#.#", "#..##", "#..##", "#...#",
    ];
    const SCALE: i32 = 3;

    let mut pixels = vec![0u8; (ICON_SIZE * ICON_SIZE * 4) as usize];
    let (teal_r, teal_g, teal_b) = (46u8, 139u8, 122u8);
    let centre = (ICON_SIZE as f32 - 1.0) / 2.0;
    let radius = centre;

    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            let dx = x as f32 - centre;
            let dy = y as f32 - centre;
            let inside = (dx * dx + dy * dy).sqrt() <= radius;

            let glyph_x = (x - (ICON_SIZE - 5 * SCALE) / 2) / SCALE;
            let glyph_y = (y - (ICON_SIZE - 7 * SCALE) / 2) / SCALE;
            let on_glyph = (0..5).contains(&glyph_x)
                && (0..7).contains(&glyph_y)
                && GLYPH[glyph_y as usize].as_bytes()[glyph_x as usize] == b'#';

            let offset = ((y * ICON_SIZE + x) * 4) as usize;
            if on_glyph {
                pixels[offset + 1] = 255;
                pixels[offset + 2] = 255;
                pixels[offset + 3] = 255;
            } else if inside {
                pixels[offset + 1] = teal_r;
                pixels[offset + 2] = teal_g;
                pixels[offset + 3] = teal_b;
            }

            // The alpha byte stays zero outside the disc, so the icon is
            // round on whatever background the tray draws.
            if inside {
                pixels[offset] = 255;
            }
        }
    }

    pixels
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::OwnedValue;

    /// Named here because only the tests call the menu through D-Bus by
    /// interface rather than through the Rust methods.
    const MENU_INTERFACE: &str = "com.canonical.dbusmenu";

    /// GetLayout's reply: a revision and `(id, properties, children)`. Named
    /// because the nested tuple is not something to read inline.
    type LayoutReply = (u32, (i32, HashMap<String, OwnedValue>, Vec<OwnedValue>));

    #[test]
    fn test_the_icon_is_a_square_argb_image() {
        let pixels = icon_pixels();
        assert_eq!(pixels.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);

        // The corners are outside the disc: transparent.
        assert_eq!(pixels[0], 0, "top-left alpha");
        let last = pixels.len() - 4;
        assert_eq!(pixels[last], 0, "bottom-right alpha");

        // The middle is inside the disc and on the glyph.
        let centre = ((ICON_SIZE / 2) * ICON_SIZE + ICON_SIZE / 2) * 4;
        assert_eq!(pixels[centre as usize], 255, "centre is opaque");
    }

    #[test]
    fn test_the_menu_offers_the_three_actions_that_matter() {
        let names: Vec<String> = entries()
            .into_iter()
            .filter_map(|(_, mut properties)| {
                properties
                    .remove("label")
                    .and_then(|value| value.downcast::<String>().ok())
                    .map(|label| label.to_string())
            })
            .collect();

        assert_eq!(names, vec!["Open Netgap", "Scan now", "Quit"]);
    }

    #[test]
    fn test_the_layout_has_a_root_and_the_entries_as_children() {
        let layout = layout();
        assert_eq!(layout.id, 0);
        assert_eq!(layout.children.len(), 4);
    }

    #[test]
    fn test_clicking_an_entry_produces_its_event() {
        let (sender, receiver) = mpsc::channel();
        let menu = MenuIface {
            events: sender,
            wake: Arc::new(|| {}),
        };

        menu.event(2, "clicked".to_string(), Value::from(0), 0);
        assert_eq!(receiver.try_recv(), Ok(Event::ScanNow));

        menu.event(4, "clicked".to_string(), Value::from(0), 0);
        assert_eq!(receiver.try_recv(), Ok(Event::Quit));

        // A hovert or a command event is not a click.
        menu.event(1, "hovered".to_string(), Value::from(0), 0);
        assert!(receiver.try_recv().is_err());
    }

    /// Register against a private bus and drive both interfaces the way a
    /// desktop would. Skipped when dbus-daemon is not installed.
    #[test]
    fn test_the_icon_registers_and_answers_on_a_real_bus() {
        let Some(session) = PrivateBus::start() else {
            eprintln!("skipping: dbus-daemon is not installed");
            return;
        };

        let (sender, _events) = mpsc::channel();
        let watcher = session.serve_watcher(sender);

        let (tray, events) = start_on(Some(&session.address), || {}).expect("the tray starts");
        assert!(
            watcher.registered(),
            "the icon must announce itself to the host"
        );

        let connection = connection::Builder::address(session.address.as_str())
            .expect("a bus address")
            .build()
            .expect("a second connection");

        // Activate is what a left click sends.
        connection
            .call_method(
                Some(WELL_KNOWN_NAME),
                ITEM_PATH,
                Some(ITEM_INTERFACE),
                "Activate",
                &(0i32, 0i32),
            )
            .expect("Activate");
        assert_eq!(
            events.recv_timeout(std::time::Duration::from_secs(2)),
            Ok(Event::Show)
        );

        // The menu answers GetLayout with the entries above.
        let reply = connection
            .call_method(
                Some(WELL_KNOWN_NAME),
                MENU_PATH,
                Some(MENU_INTERFACE),
                "GetLayout",
                &(0i32, -1i32, Vec::<&str>::new()),
            )
            .expect("GetLayout");
        let (_, (id, _properties, children)): LayoutReply = reply
            .body()
            .deserialize()
            .expect("GetLayout returns a layout");
        assert_eq!(id, 0);
        assert_eq!(children.len(), 4);

        // And the tooltip is readable as a property.
        let reply = connection
            .call_method(
                Some(WELL_KNOWN_NAME),
                ITEM_PATH,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(ITEM_INTERFACE, "Title"),
            )
            .expect("Get Title");
        let title: OwnedValue = reply.body().deserialize().expect("a variant");
        match &*title {
            Value::Str(text) => assert_eq!(text.as_str(), "Netgap"),
            other => panic!("Title came back as {other:?}"),
        }

        // StatusNotifierItem spells this property "ToolTip"; a host reads the
        // spec spelling, so the derived "Tooltip" would leave the tooltip
        // exported and never shown.
        tray.set_tooltip("12 devices · 2 critical");
        let reply = connection
            .call_method(
                Some(WELL_KNOWN_NAME),
                ITEM_PATH,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &(ITEM_INTERFACE, "ToolTip"),
            )
            .expect("Get ToolTip");
        // Properties.Get returns the property inside a variant, so read it as
        // one and only then as the tuple.
        let value: OwnedValue = reply.body().deserialize().expect("a variant");
        let tooltip: Tooltip = value.try_into().expect("a tooltip");
        assert_eq!(tooltip.3, "12 devices · 2 critical");

        // Notifications go to the session's notification daemon, and a failed
        // call is deliberately ignored, so only a daemon that answers proves
        // the words and the signature are right.
        let notifier = session.serve_notifier();
        tray.notify("Netgap: something changed", "12 devices · 2 critical");
        assert_eq!(
            notifier.wait_for(),
            (
                "Netgap: something changed".to_string(),
                "12 devices · 2 critical".to_string()
            )
        );

        drop(tray);
    }

    /// A `dbus-daemon` of our own, so the test does not depend on, or disturb,
    /// whatever is running the developer's desktop.
    struct PrivateBus {
        address: String,
        child: std::process::Child,
    }

    impl PrivateBus {
        fn start() -> Option<Self> {
            let child = std::process::Command::new("dbus-daemon")
                .args(["--session", "--print-address=1", "--nofork", "--nopidfile"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok()?;

            let mut child = child;
            let stdout = child.stdout.take()?;
            let mut line = String::new();
            use std::io::BufRead;
            std::io::BufReader::new(stdout).read_line(&mut line).ok()?;
            let address = line.trim().to_string();
            if address.is_empty() {
                let _ = child.kill();
                return None;
            }

            Some(Self { address, child })
        }

        /// A stand-in for the desktop's watcher: it records the registration
        /// and says nothing else.
        fn serve_watcher(&self, _sender: Sender<Event>) -> Watcher {
            let connection = connection::Builder::address(self.address.as_str())
                .expect("a bus address")
                .name("org.kde.StatusNotifierWatcher")
                .expect("the watcher name")
                .serve_at("/StatusNotifierWatcher", WatcherIface::default())
                .expect("the watcher object")
                .build()
                .expect("a watcher connection");

            Watcher { connection }
        }

        /// Stand in for the notification daemon the tray addresses. The test
        /// bus has none, and `notify` ignores a call that fails.
        fn serve_notifier(&self) -> Notifier {
            let received = Arc::new(Mutex::new(None));
            let connection = connection::Builder::address(self.address.as_str())
                .expect("a bus address")
                .name("org.freedesktop.Notifications")
                .expect("the daemon name")
                .serve_at(
                    NOTIFICATIONS_PATH,
                    FakeNotifier {
                        received: Arc::clone(&received),
                    },
                )
                .expect("the notifications object")
                .build()
                .expect("a notifier connection");

            Notifier {
                _connection: connection,
                received,
            }
        }
    }

    /// The tray addresses the daemon by its well-known name and path, so the
    /// stand-in is exported under both, spelled as the spec spells them.
    const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";

    struct Notifier {
        _connection: Connection,
        received: Arc<Mutex<Option<(String, String)>>>,
    }

    impl Notifier {
        /// Poll rather than block: the call returns once the bus has the
        /// message, which can be a moment before the daemon handles it.
        fn wait_for(&self) -> (String, String) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                if let Ok(mut seen) = self.received.lock() {
                    if let Some(call) = seen.take() {
                        return call;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            panic!("the notification daemon was never called");
        }
    }

    struct FakeNotifier {
        received: Arc<Mutex<Option<(String, String)>>>,
    }

    #[zbus::interface(name = "org.freedesktop.Notifications")]
    impl FakeNotifier {
        #[allow(clippy::too_many_arguments)]
        fn notify(
            &self,
            _app_name: String,
            _replaces_id: u32,
            _app_icon: String,
            summary: String,
            body: String,
            _actions: Vec<String>,
            _hints: HashMap<String, OwnedValue>,
            _expire_timeout: i32,
        ) -> u32 {
            if let Ok(mut seen) = self.received.lock() {
                *seen = Some((summary, body));
            }
            // Any id will do; the tray does not read the reply.
            1
        }
    }

    impl Drop for PrivateBus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct Watcher {
        connection: Connection,
    }

    impl Watcher {
        fn registered(&self) -> bool {
            self.connection
                .object_server()
                .interface::<_, WatcherIface>("/StatusNotifierWatcher")
                .map(|iface| iface.get().registered.lock().map(|r| *r).unwrap_or(false))
                .unwrap_or(false)
        }
    }

    #[derive(Default)]
    struct WatcherIface {
        registered: Mutex<bool>,
    }

    #[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
    impl WatcherIface {
        #[zbus(name = "RegisterStatusNotifierItem")]
        fn register(&self, _service: String) {
            if let Ok(mut registered) = self.registered.lock() {
                *registered = true;
            }
        }

        #[zbus(property)]
        fn is_status_notifier_host_registered(&self) -> bool {
            true
        }

        #[zbus(property)]
        fn protocol_version(&self) -> i32 {
            0
        }
    }
}
