//! The primary connection and whether it is metered, from NetworkManager
//! over the system D-Bus.

use nwl_core::network::Detected;
use zbus::blocking::{proxy::Builder, Connection, Proxy};
use zbus::proxy::CacheProperties;

const SERVICE: &str = "org.freedesktop.NetworkManager";

pub struct NetworkManager {
    bus: Connection,
}

impl NetworkManager {
    /// Connects to the system bus and checks NetworkManager is running.
    pub fn connect() -> zbus::Result<Self> {
        let nm = Self { bus: Connection::system()? };
        nm.proxy("/org/freedesktop/NetworkManager", SERVICE)?.get_property::<String>("Version")?;
        Ok(nm)
    }

    fn proxy<'a>(&'a self, path: &'a str, interface: &'a str) -> zbus::Result<Proxy<'a>> {
        // Read properties fresh each time instead of caching and following
        // change signals: polling every few seconds is all that's needed.
        Builder::new(&self.bus)
            .destination(SERVICE)?
            .path(path)?
            .interface(interface)?
            .cache_properties(CacheProperties::No)
            .build()
    }

    fn query(&self) -> zbus::Result<Detected> {
        let nm = self.proxy("/org/freedesktop/NetworkManager", SERVICE)?;
        let metered = metered(nm.get_property::<u32>("Metered")?);
        let primary: zbus::zvariant::OwnedObjectPath = nm.get_property("PrimaryConnection")?;
        let name = if primary.as_str() == "/" {
            None
        } else {
            let active = self.proxy(primary.as_str(), "org.freedesktop.NetworkManager.Connection.Active")?;
            Some(active.get_property::<String>("Id")?)
        };
        Ok(Detected { name, metered: if_connected(metered, primary.as_str()) })
    }
}

/// `NMMetered`: 1 yes, 2 no, 3 guessed yes (e.g. an Android hotspot or a
/// mobile broadband modem), 4 guessed no; 0 unknown.
fn metered(value: u32) -> Option<bool> {
    match value {
        1 | 3 => Some(true),
        2 | 4 => Some(false),
        _ => None,
    }
}

/// Without a primary connection there is nothing to be metered.
fn if_connected(metered: Option<bool>, primary: &str) -> Option<bool> {
    if primary == "/" {
        None
    } else {
        metered
    }
}

impl crate::network::NetworkProbe for NetworkManager {
    fn name(&self) -> &'static str {
        "NetworkManager"
    }

    fn detect(&mut self) -> Detected {
        self.query().unwrap_or_else(|e| {
            tracing::debug!("NetworkManager query failed: {e}");
            Detected::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metered_values() {
        assert_eq!(metered(1), Some(true));
        assert_eq!(metered(3), Some(true), "NetworkManager guesses hotspots metered");
        assert_eq!(metered(2), Some(false));
        assert_eq!(metered(4), Some(false));
        assert_eq!(metered(0), None);
        assert_eq!(if_connected(Some(true), "/"), None);
        assert_eq!(
            if_connected(Some(true), "/org/freedesktop/NetworkManager/ActiveConnection/3"),
            Some(true)
        );
    }
}
