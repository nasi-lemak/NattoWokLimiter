//! Platform-independent core of NattoWokLimiter.
//!
//! * [`model`]: processes, sockets and snapshots as reported by a backend.
//! * [`rules`]: the allow / block / limit / quota rule engine.
//! * [`accounting`]: per-application rates, totals and history.
//! * [`quota`]: per-period data caps.
//! * [`rate`]: parsing and formatting of sizes and rates.
//! * [`remotes`]: bytes per remote address per application.
//! * [`history`]: long-term traffic history per minute and hour.
//! * [`spikes`]: traffic spike detection per application.
//! * [`api`]: request and response types of the daemon's HTTP API.

pub mod accounting;
pub mod api;
pub mod history;
pub mod model;
pub mod quota;
pub mod rate;
pub mod remotes;
pub mod rules;
pub mod spikes;

macro_rules! notice {
    () => {
        "Copyright (C) 2026 The NattoWokLimiter contributors.
License GPL-3.0-or-later <https://www.gnu.org/licenses/gpl-3.0.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law."
    };
}

/// The copyright and license notice every program shows (`--version`, the
/// app's About window), as the GPL asks of interactive programs.
pub const NOTICE: &str = notice!();

/// Where the source code is.
pub const SOURCE: &str = env!("CARGO_PKG_REPOSITORY");

/// `--version` text: the version, then [`NOTICE`] and [`SOURCE`].
pub const LONG_VERSION: &str =
    concat!(env!("CARGO_PKG_VERSION"), "\n", notice!(), "\nSource: ", env!("CARGO_PKG_REPOSITORY"));
