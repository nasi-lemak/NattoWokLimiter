//! Data model shared by every platform backend, the daemon and the clients.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Transport protocol of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        })
    }
}

/// Traffic direction relative to the local machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Download / ingress.
    In,
    /// Upload / egress.
    Out,
    #[default]
    Both,
}

impl Direction {
    pub fn includes_in(self) -> bool {
        matches!(self, Direction::In | Direction::Both)
    }
    pub fn includes_out(self) -> bool {
        matches!(self, Direction::Out | Direction::Both)
    }
}

/// TCP connection state, normalised across platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Unknown,
}

impl TcpState {
    /// Maps the Linux kernel `TCP_*` state numbering (also used by `/proc/net/tcp`).
    pub fn from_linux(code: u8) -> Self {
        match code {
            1 => Self::Established,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::FinWait1,
            5 => Self::FinWait2,
            6 => Self::TimeWait,
            7 => Self::Close,
            8 => Self::CloseWait,
            9 => Self::LastAck,
            10 => Self::Listen,
            11 => Self::Closing,
            _ => Self::Unknown,
        }
    }
}

/// A running process that owns at least one socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Short name (`comm` on Linux, image name on Windows).
    pub name: String,
    /// Full path to the executable when it can be resolved.
    pub exe: Option<PathBuf>,
    /// Numeric user id (Unix) of the process owner, if known.
    pub uid: Option<u32>,
}

impl ProcessInfo {
    /// The identity used to group processes into an "application".
    ///
    /// Several processes of the same executable (browser helpers, worker pools)
    /// collapse into one application, which is what users think in terms of.
    pub fn app_id(&self) -> AppId {
        match &self.exe {
            Some(path) => AppId(path.to_string_lossy().into_owned()),
            None => AppId(self.name.clone()),
        }
    }
}

/// Stable identifier of an application: its executable path, or its process
/// name when the path is unavailable (kernel threads, permission denied).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppId(pub String);

impl AppId {
    /// File name component, e.g. `firefox` for `/usr/lib/firefox/firefox`.
    pub fn display_name(&self) -> &str {
        self.0.rsplit(['/', '\\']).next().unwrap_or(&self.0)
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Uniquely identifies a socket for the lifetime of the socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConnKey {
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    /// Platform socket identity (inode on Linux) to disambiguate reuse of a tuple.
    pub cookie: u64,
}

/// One socket observed by a backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub key: ConnKey,
    pub state: Option<TcpState>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    /// Cumulative bytes sent by the socket, when the platform exposes it.
    pub bytes_sent: Option<u64>,
    /// Cumulative bytes received by the socket, when the platform exposes it.
    pub bytes_recv: Option<u64>,
    /// Smoothed round-trip time in microseconds (TCP only).
    pub rtt_us: Option<u32>,
    /// The socket is already gone; it is reported once more so the bytes it
    /// moved since the last sample are still counted. Not shown as open.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub closed: bool,
}

impl Connection {
    /// Traffic that never leaves the machine (localhost on either end).
    pub fn is_loopback(&self) -> bool {
        let lo = |ip: std::net::IpAddr| match ip {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(v6.is_loopback(), |v4| v4.is_loopback()),
            v4 => v4.is_loopback(),
        };
        lo(self.key.local.ip()) || self.key.remote.is_some_and(|r| lo(r.ip()))
    }

    pub fn is_listening(&self) -> bool {
        match self.key.protocol {
            Protocol::Tcp => self.state == Some(TcpState::Listen),
            Protocol::Udp => self.key.remote.is_none(),
        }
    }
}

/// Byte counters of a network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceCounters {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Everything a backend observed at one instant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// Monotonic timestamp in milliseconds; only differences are meaningful.
    pub mono_ms: u64,
    pub processes: HashMap<u32, ProcessInfo>,
    pub connections: Vec<Connection>,
    pub interfaces: Vec<InterfaceCounters>,
}

impl Snapshot {
    pub fn process_of(&self, conn: &Connection) -> Option<&ProcessInfo> {
        conn.pid.and_then(|pid| self.processes.get(&pid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        let conn = |local: &str, remote: Option<&str>| Connection {
            key: ConnKey {
                protocol: Protocol::Tcp,
                local: local.parse().unwrap(),
                remote: remote.map(|r| r.parse().unwrap()),
                cookie: 0,
            },
            state: None,
            pid: None,
            uid: None,
            bytes_sent: None,
            bytes_recv: None,
            rtt_us: None,
            closed: false,
        };
        assert!(conn("127.0.0.1:1", Some("127.0.0.1:2")).is_loopback());
        assert!(conn("[::1]:1", None).is_loopback());
        assert!(conn("[::ffff:127.0.0.1]:1", Some("[::ffff:127.0.0.1]:2")).is_loopback());
        assert!(!conn("10.0.0.1:1", Some("1.1.1.1:443")).is_loopback());
        assert!(!conn("0.0.0.0:80", None).is_loopback());
    }

    #[test]
    fn app_id_prefers_exe() {
        let p = ProcessInfo {
            pid: 1,
            name: "Web Content".into(),
            exe: Some("/usr/lib/firefox/firefox".into()),
            uid: None,
        };
        assert_eq!(p.app_id().0, "/usr/lib/firefox/firefox");
        assert_eq!(p.app_id().display_name(), "firefox");
        let w = AppId(r"C:\Program Files\Steam\steam.exe".into());
        assert_eq!(w.display_name(), "steam.exe");
    }
}
