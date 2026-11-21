//! Which network the machine is on, and rules that only apply on some.
//!
//! The point is mobile data: on a phone hotspot or a metered connection,
//! rules such as "block Steam" or "cap Dropbox at 500 MB" can apply that
//! would be pointless at home. The operating system says whether the primary
//! connection is metered (NetworkManager marks Android hotspots metered by
//! itself; Windows has a per-network "metered connection" switch), and the
//! user can override that per network.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// What the platform detected about the primary connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detected {
    /// The connection's name (for Wi-Fi usually the network's SSID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether it is metered; `None` when the platform can't tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered: Option<bool>,
}

/// The network rules are evaluated against: detection plus the user's override.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub metered: bool,
}

/// The user's "treat as metered" choices, per network name. The key `""`
/// stands for a network without a name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overrides {
    #[serde(default)]
    pub metered: BTreeMap<String, bool>,
}

impl Overrides {
    fn key(name: Option<&str>) -> String {
        name.unwrap_or_default().to_string()
    }

    /// The override for a network, if the user set one.
    pub fn get(&self, name: Option<&str>) -> Option<bool> {
        self.metered.get(&Self::key(name)).copied()
    }

    /// Sets (`Some`) or clears (`None`, back to detection) the override.
    pub fn set(&mut self, name: Option<&str>, metered: Option<bool>) {
        match metered {
            Some(m) => self.metered.insert(Self::key(name), m),
            None => self.metered.remove(&Self::key(name)),
        };
    }

    /// The network as rules see it. Unknown counts as not metered.
    pub fn resolve(&self, detected: &Detected) -> Network {
        let metered = self.get(detected.name.as_deref()).or(detected.metered).unwrap_or(false);
        Network { name: detected.name.clone(), metered }
    }
}

/// A rule's network condition: it applies only on networks that are (or
/// aren't) metered, and/or have one of these names. Both, when both are set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered: Option<bool>,
    /// Network names, compared without regard to case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

impl NetworkCondition {
    pub fn is_empty(&self) -> bool {
        self.metered.is_none() && self.names.iter().all(|n| n.trim().is_empty())
    }

    pub fn active(&self, network: &Network) -> bool {
        let metered = self.metered.map_or(true, |m| m == network.metered);
        let named = self.names.is_empty()
            || network
                .name
                .as_deref()
                .is_some_and(|name| self.names.iter().any(|n| n.trim().eq_ignore_ascii_case(name.trim())));
        metered && named
    }
}

impl fmt::Display for NetworkCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.metered {
            Some(true) => "metered ",
            Some(false) => "unmetered ",
            None => "",
        };
        if self.names.is_empty() {
            write!(f, "on {kind}networks")
        } else {
            write!(f, "on {kind}{}", self.names.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(name: Option<&str>, metered: bool) -> Network {
        Network { name: name.map(String::from), metered }
    }

    #[test]
    fn conditions() {
        let metered = NetworkCondition { metered: Some(true), names: vec![] };
        assert!(metered.active(&net(Some("Pixel"), true)));
        assert!(!metered.active(&net(Some("Home"), false)));
        assert_eq!(metered.to_string(), "on metered networks");

        let named = NetworkCondition { metered: None, names: vec!["pixel 8".into(), "Office".into()] };
        assert!(named.active(&net(Some("Pixel 8"), false)), "names ignore case");
        assert!(!named.active(&net(Some("Home"), true)));
        assert!(!named.active(&net(None, true)), "a name never matches an unnamed network");
        assert_eq!(named.to_string(), "on pixel 8, Office");

        let both = NetworkCondition { metered: Some(false), names: vec!["Home".into()] };
        assert!(both.active(&net(Some("home"), false)));
        assert!(!both.active(&net(Some("home"), true)));
        assert_eq!(both.to_string(), "on unmetered Home");
        assert!(NetworkCondition { metered: None, names: vec![" ".into()] }.is_empty());
    }

    #[test]
    fn overrides_win_over_detection() {
        let mut o = Overrides::default();
        let hotspot = Detected { name: Some("Pixel".into()), metered: Some(true) };
        let unknown = Detected { name: Some("Cafe".into()), metered: None };
        assert!(o.resolve(&hotspot).metered);
        assert!(!o.resolve(&unknown).metered, "unknown counts as unmetered");
        o.set(Some("Cafe"), Some(true));
        o.set(Some("Pixel"), Some(false));
        assert!(o.resolve(&unknown).metered);
        assert!(!o.resolve(&hotspot).metered);
        o.set(Some("Pixel"), None);
        assert!(o.resolve(&hotspot).metered, "cleared: back to detection");
        o.set(None, Some(true));
        assert!(o.resolve(&Detected::default()).metered, "unnamed networks have their own override");
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(serde_json::from_str::<Overrides>(&json).unwrap(), o);
    }
}
