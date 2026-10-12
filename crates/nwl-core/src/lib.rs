//! Platform-independent core of NattoWokLimiter.
//!
//! * [`model`]: processes, sockets and snapshots as reported by a backend.
//! * [`rules`]: the allow / block / limit / quota rule engine.
//! * [`accounting`]: per-application rates, totals and history.
//! * [`quota`]: per-period data caps.
//! * [`rate`]: parsing and formatting of sizes and rates.
//! * [`api`]: request and response types of the daemon's HTTP API.

pub mod accounting;
pub mod api;
pub mod model;
pub mod quota;
pub mod rate;
pub mod rules;
