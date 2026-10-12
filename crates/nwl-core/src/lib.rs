//! Platform-independent core of NattoWokLimiter.
//!
//! * [`model`]: processes, sockets and snapshots as reported by a backend.
//! * [`rules`]: the allow / block / limit / quota rule engine.
//! * [`accounting`]: per-application rates, totals and history.
//! * [`quota`]: per-period data caps.
//! * [`rate`]: parsing and formatting of sizes and rates.

pub mod accounting;
pub mod model;
pub mod quota;
pub mod rate;
pub mod rules;
