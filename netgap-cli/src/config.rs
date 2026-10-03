//! `config.toml`: what a scan should do when nobody says otherwise.
//!
//! Every switch is a flag, and a realistic scan is a sentence of them:
//! `--deep --threat-intel --threat-intel-update --mdns`. That is fine to type
//! once and unreasonable to type every time, and it is not something to ask a
//! non-technical user to remember at all.
//!
//! Two layers make it one word:
//!
//! * **A config file** at `config.toml` beside `scans.db`, holding the
//!   settings that are the same every time and any profiles the user defines.
//! * **Built-in profiles** — `quick`, `home` and `audit` — which are named
//!   sets of the flags that already exist, not new behaviour.
//!
//! Precedence is explicit flag, then profile, then the file's defaults, then
//! the built-in default. Anything else produces "why did it do that" reports.
//! `netgap config` shows the result of all four layers and where each value
//! came from, which is the only way to answer that question without reading
//! the source.

use anyhow::{anyhow, Context, Result};
use netgap_core::paths;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The profiles that exist without a config file.
pub const BUILT_IN_PROFILES: &[&str] = &["quick", "home", "audit"];

/// The scan formats the caller can render.
const FORMATS: &[&str] = &["table", "json", "summary"];

/// Where the settings file lives.
pub fn path() -> Option<PathBuf> {
    paths::config_dir().map(|dir| dir.join("config.toml"))
}

/// One layer of scan settings: only the fields someone actually set.
///
/// Everything is optional because a layer says what it wants, not what the
/// result is; `resolve` combines the layers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub interface: Option<String>,
    pub target: Option<String>,
    pub discovery: Option<String>,
    pub max_hosts: Option<usize>,
    pub mdns: Option<bool>,
    pub quick: Option<bool>,
    pub deep: Option<bool>,
    pub fingerprint: Option<bool>,
    pub assess: Option<bool>,
    pub interactive: Option<bool>,
    pub threat_intel: Option<bool>,
    pub threat_intel_update: Option<bool>,
    pub no_save: Option<bool>,
    pub format: Option<String>,
    pub no_alert: Option<bool>,
}

impl Settings {
    /// Copy every field `other` sets over this one.
    ///
    /// A profile in the file with a built-in's name refines that profile
    /// rather than replacing it, so `[profiles.home]` with one line does not
    /// have to restate the rest.
    pub fn overlay(&mut self, other: &Settings) {
        macro_rules! take {
            ($($field:ident),* $(,)?) => {
                $(
                    if other.$field.is_some() {
                        self.$field = other.$field.clone();
                    }
                )*
            };
        }

        take!(
            interface,
            target,
            discovery,
            max_hosts,
            mdns,
            quick,
            deep,
            fingerprint,
            assess,
            interactive,
            threat_intel,
            threat_intel_update,
            no_save,
            format,
            no_alert,
        );
    }
}

/// The parsed `config.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// The profile to use when `--profile` is not given.
    pub profile: Option<String>,
    /// Applied to every scan, before the profile.
    #[serde(default)]
    pub defaults: Settings,
    /// Profiles defined here, or adjustments to the built-in ones.
    #[serde(default)]
    pub profiles: BTreeMap<String, Settings>,
}

impl File {
    /// Every profile a scan may name, built-in first.
    pub fn profile_names(&self) -> Vec<String> {
        let mut names: Vec<String> = BUILT_IN_PROFILES.iter().map(|n| n.to_string()).collect();
        for name in self.profiles.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }
}

/// Load `config.toml`, or `None` when there is no file.
pub fn load() -> Result<Option<(PathBuf, File)>> {
    let Some(path) = path() else {
        return Ok(None);
    };

    Ok(load_from(&path)?.map(|file| (path, file)))
}

/// Load a specific file, or `None` when it does not exist.
///
/// A file that exists but does not parse is an error, not a silence: someone
/// who wrote settings expects them to apply, and a scan that quietly ignored
/// them would be doing something the user did not ask for.
pub fn load_from(path: &Path) -> Result<Option<File>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let file = toml::from_str(&text)
                .with_context(|| format!("{} is not a valid config file", path.display()))?;
            Ok(Some(file))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("could not read {}", path.display())),
    }
}

/// What a profile means before the file gets a chance to adjust it.
fn built_in(name: &str) -> Option<Settings> {
    let settings = match name {
        // Discovery only: the fastest answer to "what is on my network".
        "quick" => Settings {
            quick: Some(true),
            ..Settings::default()
        },
        // The scan a home user wants: who is here, what are they, and the
        // checks that need no credentials.
        "home" => Settings {
            mdns: Some(true),
            assess: Some(true),
            ..Settings::default()
        },
        // Everything, including version matching against the NVD cache.
        "audit" => Settings {
            mdns: Some(true),
            deep: Some(true),
            fingerprint: Some(true),
            assess: Some(true),
            threat_intel: Some(true),
            ..Settings::default()
        },
        _ => return None,
    };

    Some(settings)
}

/// Which layer supplied a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    Profile,
    File,
    Default,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Flag => "flag",
            Source::Profile => "profile",
            Source::File => "config.toml",
            Source::Default => "default",
        }
    }
}

/// The profile that was applied, and where its name came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileChoice {
    pub name: String,
    pub source: Source,
}

/// Settings with every field decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSettings {
    pub interface: Option<String>,
    pub target: Option<String>,
    pub discovery: String,
    pub max_hosts: usize,
    pub mdns: bool,
    pub quick: bool,
    pub deep: bool,
    pub fingerprint: bool,
    pub assess: bool,
    pub interactive: bool,
    pub threat_intel: bool,
    pub threat_intel_update: bool,
    pub no_save: bool,
    pub format: String,
    pub no_alert: bool,
}

/// The decided settings, and where each one came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub settings: ScanSettings,
    /// One entry per field, in the order `netgap config` prints them.
    pub sources: Vec<(&'static str, Source)>,
    pub profile: Option<ProfileChoice>,
}

/// Combine the layers into the settings a scan will use.
///
/// `requested` is the `--profile` value; `flags` is everything given on the
/// command line, with `None` for anything not typed.
pub fn resolve(requested: Option<&str>, file: Option<&File>, flags: &Settings) -> Result<Resolved> {
    let (profile_name, profile_source) = match requested {
        Some(name) => (Some(name.to_string()), Source::Flag),
        None => (file.and_then(|file| file.profile.clone()), Source::File),
    };

    // A named profile is the built-in of that name, refined by the file's
    // entry of the same name; a name the file invented starts from nothing.
    let profile_layer = match &profile_name {
        Some(name) => {
            let mut layer = built_in(name).unwrap_or_default();
            match file.and_then(|file| file.profiles.get(name)) {
                Some(overlay) => layer.overlay(overlay),
                None if built_in(name).is_none() => {
                    let available = match file {
                        Some(file) => file.profile_names(),
                        None => BUILT_IN_PROFILES.iter().map(|n| n.to_string()).collect(),
                    };
                    return Err(anyhow!(
                        "no profile called '{name}'. Available: {}",
                        available.join(", ")
                    ));
                }
                None => {}
            }
            layer
        }
        None => Settings::default(),
    };

    let file_layer = file.map(|file| &file.defaults).cloned().unwrap_or_default();

    let mut sources = Vec::with_capacity(15);

    // Optional fields keep `Option` in the result, so they pick the layer
    // rather than the value inside it.
    macro_rules! pick_opt {
        ($field:ident) => {{
            if flags.$field.is_some() {
                sources.push((stringify!($field), Source::Flag));
                flags.$field.clone()
            } else if profile_layer.$field.is_some() {
                sources.push((stringify!($field), Source::Profile));
                profile_layer.$field.clone()
            } else if file_layer.$field.is_some() {
                sources.push((stringify!($field), Source::File));
                file_layer.$field.clone()
            } else {
                sources.push((stringify!($field), Source::Default));
                None
            }
        }};
    }

    macro_rules! pick {
        ($field:ident, $default:expr) => {{
            let value = if let Some(value) = flags.$field.clone() {
                sources.push((stringify!($field), Source::Flag));
                value
            } else if let Some(value) = profile_layer.$field.clone() {
                sources.push((stringify!($field), Source::Profile));
                value
            } else if let Some(value) = file_layer.$field.clone() {
                sources.push((stringify!($field), Source::File));
                value
            } else {
                sources.push((stringify!($field), Source::Default));
                $default
            };
            value
        }};
    }

    let mut settings = ScanSettings {
        interface: pick_opt!(interface),
        target: pick_opt!(target),
        discovery: pick!(discovery, "auto".to_string()),
        max_hosts: pick!(max_hosts, netgap_discover::DEFAULT_MAX_HOSTS),
        mdns: pick!(mdns, false),
        quick: pick!(quick, false),
        deep: pick!(deep, false),
        fingerprint: pick!(fingerprint, false),
        assess: pick!(assess, false),
        interactive: pick!(interactive, false),
        threat_intel: pick!(threat_intel, false),
        threat_intel_update: pick!(threat_intel_update, false),
        no_save: pick!(no_save, false),
        format: pick!(format, "table".to_string()),
        no_alert: pick!(no_alert, false),
    };

    // --deep is a shorthand for the other two. Expanding it here rather than in
    // the scan keeps `netgap config` honest: it shows what will run. A switch
    // typed on the command line still wins, so `--deep --fingerprint=false`
    // means exactly that.
    if settings.deep {
        let deep_source = sources
            .iter()
            .find(|(name, _)| *name == "deep")
            .map(|(_, source)| *source)
            .unwrap_or(Source::Default);
        for (name, source) in sources.iter_mut() {
            if (*name == "fingerprint" || *name == "assess") && *source != Source::Flag {
                *source = deep_source;
                if *name == "fingerprint" {
                    settings.fingerprint = true;
                } else {
                    settings.assess = true;
                }
            }
        }
    }

    validate(&settings)?;

    Ok(Resolved {
        settings,
        sources,
        profile: profile_name.map(|name| ProfileChoice {
            name,
            source: profile_source,
        }),
    })
}

/// Reject values a later stage would only silently reinterpret.
fn validate(settings: &ScanSettings) -> Result<()> {
    if !FORMATS.contains(&settings.format.as_str()) {
        return Err(anyhow!(
            "format '{}' is not one of: {}",
            settings.format,
            FORMATS.join(", ")
        ));
    }

    if settings.max_hosts == 0 {
        return Err(anyhow!("max_hosts must be at least 1"));
    }

    if !matches!(settings.discovery.as_str(), "auto" | "arp" | "tcp") {
        return Err(anyhow!(
            "discovery '{}' is not one of: auto, arp, tcp",
            settings.discovery
        ));
    }

    Ok(())
}

/// `netgap config`: show the file and what a scan would actually use.
pub fn show(requested: Option<&str>, path_only: bool) -> Result<()> {
    let Some(path) = path() else {
        return Err(anyhow!(
            "no config directory (set HOME or NETGAP_CONFIG_DIR)"
        ));
    };

    if path_only {
        println!("{}", path.display());
        return Ok(());
    }

    let file = load_from(&path)?;
    let resolved = resolve(requested, file.as_ref(), &Settings::default())?;

    println!("📍 Config file: {}", path.display());
    if file.is_none() {
        println!("   (not found — defaults and built-in profiles only)");
    }
    match &resolved.profile {
        Some(choice) => println!(
            "🎚️  Profile: {} (chosen by {})",
            choice.name,
            choice.source.label()
        ),
        None => println!("🎚️  Profile: none (pass --profile quick|home|audit)"),
    }
    println!();

    println!("Effective scan settings:");
    let width = resolved
        .sources
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(0);
    for (name, source) in &resolved.sources {
        println!(
            "  {:<width$}  {:<24}  {}",
            name,
            describe(name, &resolved.settings),
            source.label(),
            width = width
        );
    }

    if let Some(file) = &file {
        println!();
        println!("Profiles available: {}", file.profile_names().join(", "));
    }

    Ok(())
}

/// A settings value as a person reads it in `netgap config`.
fn describe(field: &str, settings: &ScanSettings) -> String {
    match field {
        "interface" => settings
            .interface
            .clone()
            .unwrap_or_else(|| "any".to_string()),
        "target" => settings
            .target
            .clone()
            .unwrap_or_else(|| "from interface".to_string()),
        "discovery" => settings.discovery.clone(),
        "max_hosts" => settings.max_hosts.to_string(),
        "format" => settings.format.clone(),
        "mdns" => settings.mdns.to_string(),
        "quick" => settings.quick.to_string(),
        "deep" => settings.deep.to_string(),
        "fingerprint" => settings.fingerprint.to_string(),
        "assess" => settings.assess.to_string(),
        "interactive" => settings.interactive.to_string(),
        "threat_intel" => settings.threat_intel.to_string(),
        "threat_intel_update" => settings.threat_intel_update.to_string(),
        "no_save" => settings.no_save.to_string(),
        "no_alert" => settings.no_alert.to_string(),
        other => format!("<unknown field {other}>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
profile = "home"

[defaults]
format = "summary"

[profiles.audit]
no_save = true
"#;

    fn parse(text: &str) -> File {
        toml::from_str(text).expect("a valid file")
    }

    fn flag_layer() -> Settings {
        Settings::default()
    }

    #[test]
    fn test_a_profile_supplies_settings_no_flags_did() {
        let file = parse(FILE);
        let resolved = resolve(None, Some(&file), &flag_layer()).expect("resolve");

        assert_eq!(resolved.profile.as_ref().unwrap().name, "home");
        assert!(resolved.settings.assess, "home runs the config checks");
        assert!(resolved.settings.mdns, "home asks devices for names");
        assert!(!resolved.settings.quick);
        assert_eq!(
            resolved.settings.format, "summary",
            "the file's defaults apply beneath the profile"
        );
    }

    #[test]
    fn test_a_flag_beats_the_profile() {
        let file = parse(FILE);
        let flags = Settings {
            assess: Some(false),
            ..Settings::default()
        };

        let resolved = resolve(None, Some(&file), &flags).expect("resolve");

        assert!(!resolved.settings.assess, "--assess=false must win");
        assert_eq!(
            resolved
                .sources
                .iter()
                .find(|(name, _)| *name == "assess")
                .map(|(_, source)| *source),
            Some(Source::Flag)
        );
    }

    #[test]
    fn test_the_file_beats_the_built_in_default() {
        let file = parse(FILE);
        let resolved = resolve(None, Some(&file), &flag_layer()).expect("resolve");

        assert_eq!(resolved.settings.format, "summary");
        assert_eq!(
            resolved
                .sources
                .iter()
                .find(|(name, _)| *name == "format")
                .map(|(_, source)| *source),
            Some(Source::File),
            "home does not set format, so the file must supply it"
        );
    }

    #[test]
    fn test_a_file_profile_refines_the_built_in_of_that_name() {
        let file = parse(FILE);
        let resolved = resolve(Some("audit"), Some(&file), &flag_layer()).expect("resolve");

        // From the built-in audit profile...
        assert!(resolved.settings.deep);
        assert!(resolved.settings.threat_intel);
        // ...and from the file's adjustment.
        assert!(resolved.settings.no_save);
        assert!(resolved.settings.assess);
    }

    #[test]
    fn test_an_unknown_profile_lists_what_exists() {
        let error = resolve(Some("paranoid"), None, &flag_layer()).expect_err("must fail");
        let message = error.to_string();
        for name in BUILT_IN_PROFILES {
            assert!(message.contains(name), "{message} should name {name}");
        }
    }

    #[test]
    fn test_quick_is_discovery_only() {
        let resolved = resolve(Some("quick"), None, &flag_layer()).expect("resolve");
        assert!(resolved.settings.quick);
        assert!(!resolved.settings.assess);
        assert!(!resolved.settings.fingerprint);
    }

    #[test]
    fn test_deep_expands_to_the_switches_it_stands_for() {
        let file = parse("[defaults]\ndeep = true\n");
        let resolved = resolve(None, Some(&file), &flag_layer()).expect("resolve");

        assert!(resolved.settings.fingerprint);
        assert!(resolved.settings.assess);
        let source = resolved
            .sources
            .iter()
            .find(|(name, _)| *name == "assess")
            .map(|(_, source)| *source);
        assert_eq!(
            source,
            Some(Source::File),
            "netgap config must credit the layer that asked for the deep scan"
        );
    }

    #[test]
    fn test_an_explicit_false_survives_deep() {
        let flags = Settings {
            deep: Some(true),
            fingerprint: Some(false),
            ..Settings::default()
        };

        let resolved = resolve(None, None, &flags).expect("resolve");

        assert!(
            resolved.settings.assess,
            "deep still implies the assessment"
        );
        assert!(
            !resolved.settings.fingerprint,
            "a switch typed on the command line wins over the shorthand"
        );
    }

    #[test]
    fn test_a_typo_in_the_file_is_an_error_not_a_silent_default() {
        let error = toml::from_str::<File>("[defaults]\nases = true\n")
            .expect_err("an unknown field must not parse");
        assert!(error.to_string().contains("ases"));
    }

    #[test]
    fn test_values_a_later_stage_would_misread_are_rejected() {
        let file = parse("[defaults]\nformat = \"summery\"\n");
        let error = resolve(None, Some(&file), &flag_layer()).expect_err("bad format");
        assert!(error.to_string().contains("summery"));

        let file = parse("[defaults]\ndiscovery = \"magic\"\n");
        let error = resolve(None, Some(&file), &flag_layer()).expect_err("bad method");
        assert!(error.to_string().contains("magic"));

        let file = parse("[defaults]\nmax_hosts = 0\n");
        let error = resolve(None, Some(&file), &flag_layer()).expect_err("no hosts");
        assert!(error.to_string().contains("max_hosts"));
    }

    #[test]
    fn test_the_profile_name_can_come_from_the_file() {
        let file = parse("profile = \"quick\"\n");
        let resolved = resolve(None, Some(&file), &flag_layer()).expect("resolve");
        assert_eq!(resolved.profile.as_ref().unwrap().name, "quick");
        assert_eq!(resolved.profile.as_ref().unwrap().source, Source::File);
        assert!(resolved.settings.quick);
    }

    #[test]
    fn test_a_missing_file_loads_as_none() {
        let path =
            std::env::temp_dir().join(format!("netgap-config-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(load_from(&path).expect("load").is_none());
    }

    #[test]
    fn test_a_file_is_read_from_disk() {
        let path = std::env::temp_dir().join(format!("netgap-config-{}", std::process::id()));
        std::fs::write(&path, FILE).expect("write");
        let file = load_from(&path).expect("load").expect("a file");
        assert_eq!(file.profile.as_deref(), Some("home"));
        let _ = std::fs::remove_file(&path);
    }
}
