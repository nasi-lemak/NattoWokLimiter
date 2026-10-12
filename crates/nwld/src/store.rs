//! Persistent state under the state directory, written atomically as JSON.

use nwl_core::model::AppId;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::PathBuf;

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    #[cfg(test)]
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    /// Loads `name`, returning `None` if it does not exist.
    pub fn load<T: DeserializeOwned>(&self, name: &str) -> anyhow::Result<Option<T>> {
        match fs::read(self.path(name)) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .map_err(|e| anyhow::anyhow!("{} is corrupt: {e}", self.path(name).display()))?,
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> anyhow::Result<()> {
        let tmp = self.path(&format!("{name}.tmp"));
        fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
        fs::rename(&tmp, self.path(name))?;
        Ok(())
    }
}

/// Default state directory for this platform and privilege level.
pub fn default_state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(base).join("NattoWokLimiter")
    }
    #[cfg(not(windows))]
    {
        // SAFETY: geteuid has no preconditions.
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root {
            return PathBuf::from("/var/lib/nattowok");
        }
        if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(state).join("nattowok");
        }
        let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
        PathBuf::from(home).join(".local/state/nattowok")
    }
}

/// Bytes per application per local calendar day: the long-term history
/// behind the usage view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageDb {
    /// `YYYY-MM-DD` -> app -> `[up, down]`.
    pub days: BTreeMap<String, BTreeMap<AppId, [u64; 2]>>,
}

impl UsageDb {
    pub const RETAIN_DAYS: usize = 400;

    pub fn record(&mut self, day: &str, app: &AppId, up: u64, down: u64) {
        let entry = self.days.entry(day.to_string()).or_default().entry(app.clone()).or_default();
        entry[0] += up;
        entry[1] += down;
        while self.days.len() > Self::RETAIN_DAYS {
            self.days.pop_first();
        }
    }

    pub fn last_days(&self, n: usize) -> impl Iterator<Item = (&String, &BTreeMap<AppId, [u64; 2]>)> {
        let skip = self.days.len().saturating_sub(n);
        self.days.iter().skip(skip)
    }
}

/// Applications seen at least once, to raise "new application" events.
pub type KnownApps = BTreeSet<AppId>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_missing() {
        let dir = std::env::temp_dir().join(format!("nwl-store-test-{}", std::process::id()));
        let store = Store::open(dir.clone()).unwrap();
        assert!(store.load::<UsageDb>("usage.json").unwrap().is_none());
        let mut db = UsageDb::default();
        db.record("2026-10-12", &AppId("/usr/bin/curl".into()), 1, 2);
        db.record("2026-10-12", &AppId("/usr/bin/curl".into()), 3, 4);
        store.save("usage.json", &db).unwrap();
        let back: UsageDb = store.load("usage.json").unwrap().unwrap();
        assert_eq!(back.days["2026-10-12"][&AppId("/usr/bin/curl".into())], [4, 6]);
        fs::write(dir.join("bad.json"), "{").unwrap();
        assert!(store.load::<UsageDb>("bad.json").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn usage_retention() {
        let mut db = UsageDb::default();
        for d in 0..(UsageDb::RETAIN_DAYS + 5) {
            db.record(&format!("day{d:05}"), &AppId("a".into()), 1, 1);
        }
        assert_eq!(db.days.len(), UsageDb::RETAIN_DAYS);
        assert_eq!(db.last_days(2).count(), 2);
    }
}
