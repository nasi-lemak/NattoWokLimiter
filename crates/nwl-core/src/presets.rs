//! Ready-made rule sets for common situations.
//!
//! A preset adds ordinary rules, named "<preset>: <what>", so they can be
//! edited or deleted one by one afterwards, and removing a preset removes the
//! rules with its name. App patterns are program names with a trailing `*`,
//! so they match on Linux (`steam`), on Windows (`steam.exe`) and helper
//! programs (`steamwebhelper`).

use crate::rules::Rule;
use serde_json::{json, Value};

pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// `(label, app pattern)` the preset's rules apply to.
    apps: &'static [(&'static str, &'static str)],
    /// Builds the rule for one app pattern.
    rule: fn(&str) -> Value,
}

const LAUNCHERS: &[(&str, &str)] = &[
    ("Steam", "steam*"),
    ("Epic Games", "epicgameslauncher*"),
    ("Battle.net", "battle.net*"),
    ("EA app", "eadesktop*"),
    ("Ubisoft Connect", "upc*"),
];

const SYNC: &[(&str, &str)] = &[
    ("Dropbox", "dropbox*"),
    ("OneDrive", "onedrive*"),
    ("Google Drive", "googledrivefs*"),
    ("MEGA", "megasync*"),
    ("Nextcloud", "nextcloud*"),
    ("Syncthing", "syncthing*"),
    ("rclone", "rclone*"),
];

const UPDATERS: &[(&str, &str)] = &[
    ("Steam", "steam*"),
    ("Epic Games", "epicgameslauncher*"),
    ("Battle.net", "battle.net*"),
    ("PackageKit updates", "packagekitd"),
    ("GNOME Software", "gnome-software"),
    ("Snap updates", "snapd"),
    ("Flatpak updates", "flatpak*"),
    ("APT downloads", "/usr/lib/apt/methods/*"),
];

const DISTRACTIONS: &[(&str, &str)] = &[
    ("Steam", "steam*"),
    ("Epic Games", "epicgameslauncher*"),
    ("Battle.net", "battle.net*"),
    ("Discord", "discord*"),
];

fn hotspot_rule(app: &str) -> Value {
    json!({"match": {"app": app}, "action": {"type": "block"}, "network": {"metered": true}})
}

fn calm_rule(app: &str) -> Value {
    json!({"match": {"app": app}, "action": {"type": "limit", "download": "1MB/s"}})
}

fn focus_rule(app: &str) -> Value {
    json!({
        "match": {"app": app},
        "action": {"type": "block"},
        "schedule": {"days": ["mon", "tue", "wed", "thu", "fri"], "from": "09:00", "until": "17:00"}
    })
}

/// A static list, so presets need no allocation to show.
static HOTSPOT_APPS: [(&str, &str); 12] = [
    LAUNCHERS[0],
    LAUNCHERS[1],
    LAUNCHERS[2],
    LAUNCHERS[3],
    LAUNCHERS[4],
    SYNC[0],
    SYNC[1],
    SYNC[2],
    SYNC[3],
    SYNC[4],
    SYNC[5],
    SYNC[6],
];

pub static PRESETS: [Preset; 3] = [
    Preset {
        id: "hotspot-saver",
        name: "Hotspot saver",
        description: "On metered networks (a phone hotspot, mobile data), block game launchers and cloud \
                      sync, which can use gigabytes in minutes. At home nothing changes.",
        apps: &HOTSPOT_APPS,
        rule: hotspot_rule,
    },
    Preset {
        id: "calm-downloads",
        name: "Calm background downloads",
        description: "Limit game launchers and system updaters to 1 MB/s each, so updates don't slow \
                      down everything else.",
        apps: UPDATERS,
        rule: calm_rule,
    },
    Preset {
        id: "focus-hours",
        name: "Focus hours",
        description: "Block games and Discord on weekdays from 9:00 to 17:00.",
        apps: DISTRACTIONS,
        rule: focus_rule,
    },
];

impl Preset {
    /// Finds a preset by id or name (any case).
    pub fn find(name: &str) -> Option<&'static Preset> {
        PRESETS.iter().find(|p| p.id.eq_ignore_ascii_case(name) || p.name.eq_ignore_ascii_case(name))
    }

    /// The prefix of the names of this preset's rules.
    pub fn prefix(&self) -> String {
        format!("{}: ", self.name)
    }

    /// Whether a rule was added by this preset.
    pub fn owns(&self, rule: &Rule) -> bool {
        rule.name.starts_with(&self.prefix())
    }

    /// The rules this preset adds.
    pub fn rules(&self) -> Vec<Rule> {
        self.apps
            .iter()
            .map(|(label, pattern)| {
                let mut rule = (self.rule)(pattern);
                rule["name"] = json!(format!("{}{label}", self.prefix()));
                serde_json::from_value(rule).expect("preset rules are valid")
            })
            .collect()
    }

    /// The apps it covers, for showing what it does.
    pub fn app_labels(&self) -> Vec<&'static str> {
        self.apps.iter().map(|(label, _)| *label).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AppId;
    use crate::rules::{Day, RuleSet};

    #[test]
    fn presets_are_valid_and_match_real_programs() {
        for p in &PRESETS {
            let rules = p.rules();
            assert!(!rules.is_empty());
            RuleSet::new(rules.clone()).unwrap_or_else(|e| panic!("{}: {e}", p.id));
            assert!(rules.iter().all(|r| p.owns(r)), "{}", p.id);
            assert_eq!(Preset::find(p.id).map(|f| f.id), Some(p.id));
        }
        let hotspot = Preset::find("Hotspot Saver").unwrap().rules();
        let steam = hotspot.iter().find(|r| r.name == "Hotspot saver: Steam").unwrap();
        let app = steam.matcher.app.as_ref().unwrap();
        for exe in
            ["/usr/bin/steam", "C:\\Program Files (x86)\\Steam\\steam.exe", "/opt/steam/steamwebhelper"]
        {
            assert!(app.matches_app(&AppId(exe.into())), "{exe}");
        }
        assert!(steam.network.as_ref().is_some_and(|n| n.metered == Some(true)));
        let apt = Preset::find("calm-downloads").unwrap().rules();
        let apt = apt.iter().find(|r| r.name.ends_with("APT downloads")).unwrap();
        assert!(apt.matcher.app.as_ref().unwrap().matches_app(&AppId("/usr/lib/apt/methods/http".into())));
        let focus = Preset::find("focus-hours").unwrap().rules();
        assert!(focus[0].schedule.as_ref().is_some_and(|s| s.days.len() == 5 && !s.days.contains(&Day::Sat)));
    }
}
