//! The Internet connection profile and its cost (metered or not), from the
//! Windows Runtime `NetworkInformation` API. "Set as metered connection" in
//! Windows settings, and mobile broadband, make a profile metered.

use ::windows::Networking::Connectivity::{NetworkCostType, NetworkInformation};
use nwl_core::network::Detected;

pub struct ConnectionProfile;

impl ConnectionProfile {
    fn query() -> ::windows::core::Result<Detected> {
        let Ok(profile) = NetworkInformation::GetInternetConnectionProfile() else {
            // No Internet connection.
            return Ok(Detected::default());
        };
        let name = profile.ProfileName()?.to_string_lossy();
        let cost = profile.GetConnectionCost()?.NetworkCostType()?;
        let metered = if cost == NetworkCostType::Unrestricted {
            Some(false)
        } else if cost == NetworkCostType::Fixed || cost == NetworkCostType::Variable {
            Some(true)
        } else {
            None
        };
        Ok(Detected { name: Some(name).filter(|n| !n.is_empty()), metered })
    }
}

impl crate::network::NetworkProbe for ConnectionProfile {
    fn name(&self) -> &'static str {
        "Windows connection profile"
    }

    fn detect(&mut self) -> Detected {
        Self::query().unwrap_or_else(|e| {
            tracing::debug!("connection profile query failed: {e}");
            Detected::default()
        })
    }
}
