//! Which network the machine is on, and whether it is metered (see
//! [`nwl_core::network`]).
//!
//! | Platform | Source |
//! |----------|--------|
//! | Linux    | NetworkManager over D-Bus: primary connection and its `Metered` state (Android hotspots are detected as metered) |
//! | Windows  | `NetworkInformation::GetInternetConnectionProfile`: profile name and connection cost |
//! | other, or without NetworkManager | unknown; the user can still mark a network as metered |

use nwl_core::network::Detected;

/// Reports the primary network connection. May block briefly (D-Bus, WinRT
/// calls), so the daemon polls it on its own thread.
pub trait NetworkProbe: Send {
    fn name(&self) -> &'static str;
    fn detect(&mut self) -> Detected;
}

/// A network that never changes: the demo's, or "unknown".
pub struct FixedNetwork {
    name: &'static str,
    network: Detected,
}

impl FixedNetwork {
    /// The demo's network: an unmetered Wi-Fi the user can mark as metered.
    pub fn demo() -> Self {
        Self { name: "the demo", network: Detected { name: Some("Demo Wi-Fi".into()), metered: Some(false) } }
    }

    /// No way to detect anything.
    pub fn unknown() -> Self {
        Self { name: "none", network: Detected::default() }
    }
}

impl NetworkProbe for FixedNetwork {
    fn name(&self) -> &'static str {
        self.name
    }

    fn detect(&mut self) -> Detected {
        self.network.clone()
    }
}

/// The platform's network detection, or [`FixedNetwork::unknown`] if there
/// is none (e.g. Linux without NetworkManager).
pub fn native_network_probe() -> Box<dyn NetworkProbe> {
    #[cfg(target_os = "linux")]
    {
        match crate::linux::netman::NetworkManager::connect() {
            Ok(nm) => return Box::new(nm),
            Err(e) => tracing::info!("network detection unavailable (NetworkManager: {e})"),
        }
    }
    #[cfg(windows)]
    {
        return Box::new(crate::windows::netcost::ConnectionProfile);
    }
    #[allow(unreachable_code)]
    Box::new(FixedNetwork::unknown())
}
