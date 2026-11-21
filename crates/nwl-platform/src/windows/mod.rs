//! Windows backend.
//!
//! * Monitoring: `GetExtendedTcpTable` / `GetExtendedUdpTable` for sockets and
//!   owning pids, TCP extended statistics (`GetPerTcpConnectionEStats`) for
//!   per-connection bytes (requires Administrator), `GetIfTable2` for totals.
//! * Enforcement: Windows Firewall rules and QoS policies, see
//!   [`crate::winplan`].

pub mod appinfo;
pub mod netcost;

use crate::{winplan, EnforceReport, Enforcer, Error, Monitor, Policy, Result};
use nwl_core::model::{
    AppId, ConnKey, Connection, InterfaceCounters, ProcessInfo, Protocol, Snapshot, TcpState,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::c_void;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Calls a size-probing IP Helper function until the buffer is large enough.
fn query_table(mut call: impl FnMut(*mut c_void, &mut u32) -> u32) -> Result<Vec<u64>> {
    let mut size = 0u32;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..8 {
        let ret = call(buf.as_mut_ptr().cast(), &mut size);
        if ret == NO_ERROR {
            return Ok(buf);
        }
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return Err(Error::io("IP Helper table query", std::io::Error::from_raw_os_error(ret as i32)));
        }
        // u64 elements keep the buffer 8-byte aligned for the row structs.
        buf = vec![0u64; (size as usize).div_ceil(8) + 1];
        size = (buf.len() * 8) as u32;
    }
    Err(Error::Other("socket table kept growing".into()))
}

/// Rows of a `{ dwNumEntries, table[] }` IP Helper table.
///
/// # Safety
/// `buf` must hold a table whose rows are of type `T`, as filled by Windows.
unsafe fn rows<T>(buf: &[u64]) -> &[T] {
    if buf.is_empty() {
        return &[];
    }
    let base = buf.as_ptr() as *const u8;
    let n = *(base as *const u32) as usize;
    // The row array starts at the first offset aligned for T after the count.
    let offset = std::mem::size_of::<u32>().next_multiple_of(std::mem::align_of::<T>());
    std::slice::from_raw_parts(base.add(offset) as *const T, n)
}

fn port(raw: u32) -> u16 {
    u16::from_be((raw & 0xffff) as u16)
}

fn v4(raw: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
}

fn tcp_state(code: u32) -> TcpState {
    match code {
        1 => TcpState::Close,
        2 => TcpState::Listen,
        3 => TcpState::SynSent,
        4 => TcpState::SynRecv,
        5 => TcpState::Established,
        6 => TcpState::FinWait1,
        7 => TcpState::FinWait2,
        8 => TcpState::CloseWait,
        9 => TcpState::Closing,
        10 => TcpState::LastAck,
        11 => TcpState::TimeWait,
        _ => TcpState::Unknown,
    }
}

fn remote_opt(addr: SocketAddr) -> Option<SocketAddr> {
    (!addr.ip().is_unspecified() || addr.port() != 0).then_some(addr)
}

pub struct WindowsMonitor {
    start: Instant,
    /// Connections for which EStats collection was enabled.
    estats_enabled: HashSet<ConnKey>,
    names: HashMap<u32, ProcessInfo>,
}

impl WindowsMonitor {
    pub fn new() -> Result<Self> {
        Ok(Self { start: Instant::now(), estats_enabled: HashSet::new(), names: HashMap::new() })
    }

    fn process(&mut self, pid: u32) -> ProcessInfo {
        if let Some(p) = self.names.get(&pid) {
            return p.clone();
        }
        let info = match pid {
            0 => ProcessInfo { pid, name: "System Idle Process".into(), exe: None, uid: None },
            4 => ProcessInfo { pid, name: "System".into(), exe: None, uid: None },
            _ => {
                let exe = image_path(pid);
                let name = exe
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| format!("pid {pid}"));
                ProcessInfo { pid, name, exe, uid: None }
            }
        };
        self.names.insert(pid, info.clone());
        info
    }

    /// Per-connection byte counters via TCP EStats. Collection must be
    /// enabled per connection (Administrator only) and counts from then on.
    fn estats_v4(&mut self, key: &ConnKey, row: &MIB_TCPROW_OWNER_PID) -> Option<(u64, u64)> {
        let lh = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { dwState: row.dwState },
            dwLocalAddr: row.dwLocalAddr,
            dwLocalPort: row.dwLocalPort,
            dwRemoteAddr: row.dwRemoteAddr,
            dwRemotePort: row.dwRemotePort,
        };
        if !self.estats_enabled.contains(key) {
            let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: 1 };
            // SAFETY: pointers reference live, correctly typed locals.
            let ret = unsafe {
                SetPerTcpConnectionEStats(
                    &lh,
                    TcpConnectionEstatsData,
                    (&rw as *const TCP_ESTATS_DATA_RW_v0).cast(),
                    0,
                    std::mem::size_of_val(&rw) as u32,
                    0,
                )
            };
            if ret != NO_ERROR {
                return None;
            }
            self.estats_enabled.insert(key.clone());
        }
        // SAFETY: zeroed is a valid value for this plain-data struct.
        let mut rod: TCP_ESTATS_DATA_ROD_v0 = unsafe { std::mem::zeroed() };
        // SAFETY: rod is a live, correctly sized out-parameter.
        let ret = unsafe {
            GetPerTcpConnectionEStats(
                &lh,
                TcpConnectionEstatsData,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                0,
                (&mut rod as *mut TCP_ESTATS_DATA_ROD_v0).cast(),
                0,
                std::mem::size_of_val(&rod) as u32,
            )
        };
        (ret == NO_ERROR).then_some((rod.DataBytesOut, rod.DataBytesIn))
    }

    fn estats_v6(&mut self, key: &ConnKey, row: &MIB_TCP6ROW_OWNER_PID) -> Option<(u64, u64)> {
        let r6 = MIB_TCP6ROW {
            State: row.dwState as i32,
            LocalAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: row.ucLocalAddr } },
            dwLocalScopeId: row.dwLocalScopeId,
            dwLocalPort: row.dwLocalPort,
            RemoteAddr: IN6_ADDR { u: IN6_ADDR_0 { Byte: row.ucRemoteAddr } },
            dwRemoteScopeId: row.dwRemoteScopeId,
            dwRemotePort: row.dwRemotePort,
        };
        if !self.estats_enabled.contains(key) {
            let rw = TCP_ESTATS_DATA_RW_v0 { EnableCollection: 1 };
            // SAFETY: pointers reference live, correctly typed locals.
            let ret = unsafe {
                SetPerTcp6ConnectionEStats(
                    &r6,
                    TcpConnectionEstatsData,
                    (&rw as *const TCP_ESTATS_DATA_RW_v0).cast(),
                    0,
                    std::mem::size_of_val(&rw) as u32,
                    0,
                )
            };
            if ret != NO_ERROR {
                return None;
            }
            self.estats_enabled.insert(key.clone());
        }
        // SAFETY: zeroed is a valid value for this plain-data struct.
        let mut rod: TCP_ESTATS_DATA_ROD_v0 = unsafe { std::mem::zeroed() };
        // SAFETY: rod is a live, correctly sized out-parameter.
        let ret = unsafe {
            GetPerTcp6ConnectionEStats(
                &r6,
                TcpConnectionEstatsData,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                0,
                (&mut rod as *mut TCP_ESTATS_DATA_ROD_v0).cast(),
                0,
                std::mem::size_of_val(&rod) as u32,
            )
        };
        (ret == NO_ERROR).then_some((rod.DataBytesOut, rod.DataBytesIn))
    }
}

fn image_path(pid: u32) -> Option<PathBuf> {
    // SAFETY: plain Win32 calls; the handle is closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }
}

fn interfaces() -> Vec<InterfaceCounters> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: GetIfTable2 allocates the table, freed with FreeMibTable.
    unsafe {
        if GetIfTable2(&mut table) != NO_ERROR || table.is_null() {
            return vec![];
        }
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        let out = rows
            .iter()
            .filter(|r| {
                let flags = r.InterfaceAndOperStatusFlags._bitfield;
                let hardware = flags & 0x1 != 0;
                let filter = flags & 0x2 != 0;
                hardware && !filter && r.Type != IF_TYPE_SOFTWARE_LOOPBACK && r.OperStatus == IfOperStatusUp
            })
            .map(|r| {
                let end = r.Alias.iter().position(|&c| c == 0).unwrap_or(r.Alias.len());
                InterfaceCounters {
                    name: String::from_utf16_lossy(&r.Alias[..end]),
                    rx_bytes: r.InOctets,
                    tx_bytes: r.OutOctets,
                }
            })
            .collect();
        FreeMibTable(table as *const c_void);
        out
    }
}

impl Monitor for WindowsMonitor {
    fn name(&self) -> &'static str {
        "windows (IP Helper + TCP EStats)"
    }

    /// Resets a TCP connection (`SetTcpEntry` with `DELETE_TCB`). Windows
    /// offers this for IPv4 TCP only; it needs Administrator.
    fn close(&mut self, key: &ConnKey) -> Result<()> {
        let (SocketAddr::V4(local), Some(SocketAddr::V4(remote))) = (key.local, key.remote) else {
            return Err(Error::Unsupported("Windows can only close IPv4 TCP connections".into()));
        };
        if key.protocol != Protocol::Tcp {
            return Err(Error::Unsupported("Windows can only close TCP connections".into()));
        }
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_DELETE_TCB },
            dwLocalAddr: u32::from_ne_bytes(local.ip().octets()),
            dwLocalPort: local.port().to_be() as u32,
            dwRemoteAddr: u32::from_ne_bytes(remote.ip().octets()),
            dwRemotePort: remote.port().to_be() as u32,
        };
        // SAFETY: `row` is a valid, initialized MIB_TCPROW for the call.
        match unsafe { SetTcpEntry(&row) } {
            NO_ERROR => Ok(()),
            5 => Err(Error::Other("closing connections needs Administrator".into())), // ERROR_ACCESS_DENIED
            code => Err(Error::Other(format!("closing the connection failed (error {code})"))),
        }
    }

    fn snapshot(&mut self) -> Result<Snapshot> {
        let mut snap = Snapshot { mono_ms: self.start.elapsed().as_millis() as u64, ..Default::default() };
        let mut live = HashSet::new();
        self.names.clear(); // pids are reused quickly on Windows

        let tcp4 = query_table(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        // SAFETY: the buffer was filled with MIB_TCPTABLE_OWNER_PID.
        for row in unsafe { rows::<MIB_TCPROW_OWNER_PID>(&tcp4) } {
            let state = tcp_state(row.dwState);
            if state == TcpState::TimeWait {
                continue;
            }
            let key = ConnKey {
                protocol: Protocol::Tcp,
                local: SocketAddr::new(v4(row.dwLocalAddr), port(row.dwLocalPort)),
                remote: remote_opt(SocketAddr::new(v4(row.dwRemoteAddr), port(row.dwRemotePort))),
                cookie: row.dwOwningPid as u64,
            };
            let bytes = (state == TcpState::Established).then(|| self.estats_v4(&key, row)).flatten();
            self.push(&mut snap, key, Some(state), row.dwOwningPid, bytes, &mut live);
        }

        let tcp6 = query_table(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        // SAFETY: the buffer was filled with MIB_TCP6TABLE_OWNER_PID.
        for row in unsafe { rows::<MIB_TCP6ROW_OWNER_PID>(&tcp6) } {
            let state = tcp_state(row.dwState);
            if state == TcpState::TimeWait {
                continue;
            }
            let key = ConnKey {
                protocol: Protocol::Tcp,
                local: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)), port(row.dwLocalPort)),
                remote: remote_opt(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                    port(row.dwRemotePort),
                )),
                cookie: row.dwOwningPid as u64,
            };
            let bytes = (state == TcpState::Established).then(|| self.estats_v6(&key, row)).flatten();
            self.push(&mut snap, key, Some(state), row.dwOwningPid, bytes, &mut live);
        }

        let udp4 = query_table(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        // SAFETY: the buffer was filled with MIB_UDPTABLE_OWNER_PID.
        for row in unsafe { rows::<MIB_UDPROW_OWNER_PID>(&udp4) } {
            let key = ConnKey {
                protocol: Protocol::Udp,
                local: SocketAddr::new(v4(row.dwLocalAddr), port(row.dwLocalPort)),
                remote: None,
                cookie: row.dwOwningPid as u64,
            };
            self.push(&mut snap, key, None, row.dwOwningPid, None, &mut live);
        }

        let udp6 = query_table(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        // SAFETY: the buffer was filled with MIB_UDP6TABLE_OWNER_PID.
        for row in unsafe { rows::<MIB_UDP6ROW_OWNER_PID>(&udp6) } {
            let key = ConnKey {
                protocol: Protocol::Udp,
                local: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)), port(row.dwLocalPort)),
                remote: None,
                cookie: row.dwOwningPid as u64,
            };
            self.push(&mut snap, key, None, row.dwOwningPid, None, &mut live);
        }

        self.estats_enabled.retain(|k| live.contains(k));
        snap.interfaces = interfaces();
        Ok(snap)
    }
}

impl WindowsMonitor {
    fn push(
        &mut self,
        snap: &mut Snapshot,
        key: ConnKey,
        state: Option<TcpState>,
        pid: u32,
        bytes: Option<(u64, u64)>,
        live: &mut HashSet<ConnKey>,
    ) {
        snap.processes.entry(pid).or_insert_with(|| self.process(pid));
        live.insert(key.clone());
        snap.connections.push(Connection {
            key,
            state,
            pid: Some(pid),
            uid: None,
            bytes_sent: bytes.map(|b| b.0),
            bytes_recv: bytes.map(|b| b.1),
            rtt_us: None,
            closed: false,
        });
    }
}

pub struct WindowsEnforcer {
    /// Every executable seen so far, so app rules keep applying to programs
    /// that are not running right now (firewall rules are by path).
    known_apps: BTreeSet<AppId>,
    last_script: Option<String>,
}

impl WindowsEnforcer {
    pub fn new() -> Result<Self> {
        Ok(Self { known_apps: BTreeSet::new(), last_script: None })
    }
}

fn run_powershell(script: &str) -> Result<()> {
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::io("spawn powershell.exe", e))?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(script.as_bytes())
        .map_err(|e| Error::io("write PowerShell script", e))?;
    let out = child.wait_with_output().map_err(|e| Error::io("wait for powershell.exe", e))?;
    if !out.status.success() || !out.stderr.is_empty() {
        return Err(Error::Other(format!(
            "PowerShell failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

impl Enforcer for WindowsEnforcer {
    fn name(&self) -> &'static str {
        "windows (Windows Firewall + QoS policies)"
    }

    fn apply(&mut self, policy: &Policy<'_>) -> Result<EnforceReport> {
        self.known_apps
            .extend(policy.snapshot.processes.values().filter(|p| p.exe.is_some()).map(|p| p.app_id()));
        let plan = winplan::plan(policy.rules, policy.exhausted_quotas, &self.known_apps);
        let script = winplan::script(&plan);
        let mut report = EnforceReport { changed: false, warnings: plan.warnings };
        if self.last_script.as_deref() != Some(script.as_str()) {
            run_powershell(&script)?;
            self.last_script = Some(script);
            report.changed = true;
        }
        Ok(report)
    }

    fn clear(&mut self) -> Result<()> {
        self.last_script = None;
        run_powershell(&winplan::clear_script())
    }
}
