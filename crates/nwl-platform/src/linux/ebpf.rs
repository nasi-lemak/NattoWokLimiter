//! Exact per-socket traffic counters for every protocol, from eBPF.
//!
//! `tcp_info` only covers TCP and only sockets that are still open when we
//! sample. Three tiny programs attached to the root cgroup close both gaps:
//!
//! * `cgroup/sock_create` records, for every new socket, the process that
//!   created it and its protocol, keyed by the socket cookie (the id
//!   `sock_diag` also reports);
//! * `cgroup_skb` ingress and egress add every packet's length to that
//!   socket's counters.
//!
//! So UDP (QUIC/HTTP3, games, voice) is counted, and bytes of sockets that
//! open and close between two samples are still attributed to their process.
//!
//! The programs are a few dozen instructions, so they are assembled right
//! here and loaded with the raw `bpf()` syscall: no eBPF toolchain, no BTF,
//! no extra dependencies. They always return "allow", so they only observe.
//! They are attached with BPF links, which the kernel removes when the
//! daemon exits, even if it crashes.
//!
//! Counted bytes are IP packet lengths (payload plus IP/TCP/UDP headers,
//! including retransmissions): what crosses the wire and what an ISP meters.
//! Packets on the loopback interface are skipped unless asked for: they never
//! leave the machine.

use crate::{Error, Result};
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

// bpf() commands.
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_PROG_LOAD: u32 = 5;
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_MAP_LOOKUP_BATCH: u32 = 24;
const BPF_LINK_CREATE: u32 = 28;

const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_CGROUP_INET_INGRESS: u32 = 0;
const BPF_CGROUP_INET_EGRESS: u32 = 1;
const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;
const BPF_F_ALLOW_MULTI: u32 = 2;
const BPF_ANY: i32 = 0;
const BPF_NOEXIST: i32 = 1;

// Helper function ids.
const HELPER_MAP_LOOKUP_ELEM: i32 = 1;
const HELPER_MAP_UPDATE_ELEM: i32 = 2;
const HELPER_GET_CURRENT_PID_TGID: i32 = 14;
const HELPER_GET_CURRENT_COMM: i32 = 16;
const HELPER_GET_SOCKET_COOKIE: i32 = 46;

/// `struct __sk_buff` and `struct bpf_sock` field offsets (stable UAPI).
const SKB_LEN: i16 = 0;
const SKB_IFINDEX: i16 = 40;
const SOCK_PROTOCOL: i16 = 12;
/// The loopback device is always ifindex 1 in its network namespace.
const LOOPBACK_IFINDEX: i32 = 1;

/// Sockets tracked at once; least recently used entries are evicted first.
const MAX_SOCKETS: u32 = 65_536;

/// Map value layout, see [`Counter`].
const VALUE_SIZE: usize = 40;
const OFF_RX: i16 = 0;
const OFF_TX: i16 = 8;
const OFF_TGID: i16 = 16;
const OFF_PROTO: i16 = 20;
const OFF_COMM: i16 = 24;
const COMM_LEN: i32 = 16;
/// The map value lives on the program stack at `fp + VALUE_FP`, the key at `fp - 8`.
const VALUE_FP: i16 = -8 - VALUE_SIZE as i16;

/// What the kernel counted for one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counter {
    pub rx: u64,
    pub tx: u64,
    /// Process (thread group) that created the socket; 0 if the socket
    /// existed before the counters were attached.
    pub tgid: u32,
    /// IP protocol number (6 TCP, 17 UDP); 0 if unknown.
    pub protocol: u32,
    /// Short name (`comm`) of the creating process, NUL padded.
    pub comm: [u8; 16],
}

impl Counter {
    /// The creating process's short name, if recorded.
    pub fn comm(&self) -> Option<String> {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(self.comm.len());
        (end > 0).then(|| String::from_utf8_lossy(&self.comm[..end]).into_owned())
    }
}

impl Counter {
    fn from_bytes(v: &[u8]) -> Self {
        let u64_at = |o: i16| u64::from_ne_bytes(v[o as usize..o as usize + 8].try_into().unwrap());
        let u32_at = |o: i16| u32::from_ne_bytes(v[o as usize..o as usize + 4].try_into().unwrap());
        let comm = v[OFF_COMM as usize..OFF_COMM as usize + 16].try_into().unwrap();
        Counter {
            rx: u64_at(OFF_RX),
            tx: u64_at(OFF_TX),
            tgid: u32_at(OFF_TGID),
            protocol: u32_at(OFF_PROTO),
            comm,
        }
    }
}

/// The `union bpf_attr` passed to `bpf()`; unused bytes must stay zero.
struct Attr([u8; 128]);

impl Attr {
    fn new() -> Self {
        Attr([0; 128])
    }
    fn u32(mut self, off: usize, v: u32) -> Self {
        self.0[off..off + 4].copy_from_slice(&v.to_ne_bytes());
        self
    }
    fn u64(mut self, off: usize, v: u64) -> Self {
        self.0[off..off + 8].copy_from_slice(&v.to_ne_bytes());
        self
    }
    fn name(mut self, off: usize, name: &str) -> Self {
        let n = name.len().min(15);
        self.0[off..off + n].copy_from_slice(&name.as_bytes()[..n]);
        self
    }
    fn get_u32(&self, off: usize) -> u32 {
        u32::from_ne_bytes(self.0[off..off + 4].try_into().unwrap())
    }
}

fn bpf(cmd: u32, attr: &mut Attr) -> io::Result<i64> {
    // SAFETY: attr is a valid, fully initialised buffer of the given size;
    // pointers stored in it are kept alive by the callers for the call.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.0.as_mut_ptr(), attr.0.len()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn bpf_fd(cmd: u32, attr: &mut Attr) -> io::Result<OwnedFd> {
    let fd = bpf(cmd, attr)? as RawFd;
    // SAFETY: the kernel just returned this new descriptor to us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A minimal eBPF assembler with labels: just what the counters need.
mod asm {
    pub type Insn = [u8; 8];

    pub const R0: u8 = 0;
    pub const R1: u8 = 1;
    pub const R2: u8 = 2;
    pub const R3: u8 = 3;
    pub const R4: u8 = 4;
    pub const R6: u8 = 6;
    pub const R7: u8 = 7;
    pub const R10: u8 = 10;

    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
        let o = off.to_le_bytes();
        let i = imm.to_le_bytes();
        [code, (src << 4) | (dst & 0xf), o[0], o[1], i[0], i[1], i[2], i[3]]
    }

    #[derive(Default)]
    pub struct Program {
        insns: Vec<Insn>,
        labels: Vec<(&'static str, usize)>,
        fixups: Vec<(usize, &'static str)>,
    }

    impl Program {
        fn push(&mut self, i: Insn) -> &mut Self {
            self.insns.push(i);
            self
        }
        pub fn label(&mut self, name: &'static str) -> &mut Self {
            self.labels.push((name, self.insns.len()));
            self
        }
        fn jump(&mut self, code: u8, dst: u8, imm: i32, to: &'static str) -> &mut Self {
            self.fixups.push((self.insns.len(), to));
            self.push(insn(code, dst, 0, 0, imm))
        }
        pub fn mov_reg(&mut self, dst: u8, src: u8) -> &mut Self {
            self.push(insn(0xbf, dst, src, 0, 0))
        }
        pub fn mov_imm(&mut self, dst: u8, imm: i32) -> &mut Self {
            self.push(insn(0xb7, dst, 0, 0, imm))
        }
        pub fn add_imm(&mut self, dst: u8, imm: i32) -> &mut Self {
            self.push(insn(0x07, dst, 0, 0, imm))
        }
        pub fn rsh_imm(&mut self, dst: u8, imm: i32) -> &mut Self {
            self.push(insn(0x77, dst, 0, 0, imm))
        }
        /// `dst = *(u32 *)(src + off)`.
        pub fn load_u32(&mut self, dst: u8, src: u8, off: i16) -> &mut Self {
            self.push(insn(0x61, dst, src, off, 0))
        }
        /// `*(u64 *)(dst + off) = src`.
        pub fn store_u64(&mut self, dst: u8, off: i16, src: u8) -> &mut Self {
            self.push(insn(0x7b, dst, src, off, 0))
        }
        /// `*(u32 *)(dst + off) = src`.
        pub fn store_u32(&mut self, dst: u8, off: i16, src: u8) -> &mut Self {
            self.push(insn(0x63, dst, src, off, 0))
        }
        /// `*(u64 *)(dst + off) = imm`.
        pub fn store_imm_u64(&mut self, dst: u8, off: i16, imm: i32) -> &mut Self {
            self.push(insn(0x7a, dst, 0, off, imm))
        }
        /// Atomic `*(u64 *)(dst + off) += src`.
        pub fn atomic_add_u64(&mut self, dst: u8, off: i16, src: u8) -> &mut Self {
            self.push(insn(0xdb, dst, src, off, 0))
        }
        /// `dst = &map` (a two-slot instruction).
        pub fn load_map(&mut self, dst: u8, fd: i32) -> &mut Self {
            const BPF_PSEUDO_MAP_FD: u8 = 1;
            self.push(insn(0x18, dst, BPF_PSEUDO_MAP_FD, 0, fd)).push(insn(0, 0, 0, 0, 0))
        }
        /// Zeroes `len` bytes (a multiple of 8) of the stack at `fp + off`.
        pub fn zero_stack(&mut self, off: i16, len: usize) -> &mut Self {
            for i in (0..len).step_by(8) {
                self.store_imm_u64(R10, off + i as i16, 0);
            }
            self
        }
        /// `dst = fp + off`: a pointer into the stack frame.
        pub fn stack_ptr(&mut self, dst: u8, off: i32) -> &mut Self {
            self.mov_reg(dst, R10).add_imm(dst, off)
        }
        pub fn call(&mut self, helper: i32) -> &mut Self {
            self.push(insn(0x85, 0, 0, 0, helper))
        }
        pub fn jeq(&mut self, dst: u8, imm: i32, to: &'static str) -> &mut Self {
            self.jump(0x15, dst, imm, to)
        }
        pub fn jne(&mut self, dst: u8, imm: i32, to: &'static str) -> &mut Self {
            self.jump(0x55, dst, imm, to)
        }
        pub fn exit(&mut self) -> &mut Self {
            self.push(insn(0x95, 0, 0, 0, 0))
        }

        /// Resolves jumps to labels.
        pub fn finish(&mut self) -> Vec<Insn> {
            for (at, name) in std::mem::take(&mut self.fixups) {
                let target =
                    self.labels.iter().find(|(n, _)| *n == name).map(|(_, t)| *t).expect("label defined");
                let off = (target as i64 - at as i64 - 1) as i16;
                self.insns[at][2..4].copy_from_slice(&off.to_le_bytes());
            }
            std::mem::take(&mut self.insns)
        }
    }
}

/// `cgroup_skb` program adding packet lengths to the counter at byte
/// offset `slot` of the socket's map value.
fn counter_program(map_fd: RawFd, slot: i16, count_loopback: bool) -> Vec<asm::Insn> {
    use asm::*;
    let mut p = Program::default();
    p.mov_reg(R6, R1); // r6 = skb
    if !count_loopback {
        p.load_u32(R7, R6, SKB_IFINDEX).jeq(R7, LOOPBACK_IFINDEX, "out");
    }
    p.call(HELPER_GET_SOCKET_COOKIE) // r0 = cookie(skb), r1 = skb
        .jeq(R0, 0, "out")
        .store_u64(R10, -8, R0) // key on the stack at fp-8
        .load_u32(R7, R6, SKB_LEN) // r7 = packet length
        .load_map(R1, map_fd)
        .stack_ptr(R2, -8)
        .call(HELPER_MAP_LOOKUP_ELEM)
        .jne(R0, 0, "count")
        // Socket created before we attached: start its counters at zero.
        .zero_stack(VALUE_FP, VALUE_SIZE)
        .load_map(R1, map_fd)
        .stack_ptr(R2, -8)
        .stack_ptr(R3, VALUE_FP as i32)
        .mov_imm(R4, BPF_NOEXIST)
        .call(HELPER_MAP_UPDATE_ELEM)
        .load_map(R1, map_fd)
        .stack_ptr(R2, -8)
        .call(HELPER_MAP_LOOKUP_ELEM)
        .jeq(R0, 0, "out")
        .label("count")
        .atomic_add_u64(R0, slot, R7)
        .label("out")
        .mov_imm(R0, 1) // always let the packet through
        .exit();
    p.finish()
}

/// `cgroup/sock_create` program recording the creating process and the
/// protocol of every new socket.
fn sock_create_program(map_fd: RawFd, with_comm: bool) -> Vec<asm::Insn> {
    use asm::*;
    let mut p = Program::default();
    p.mov_reg(R6, R1) // r6 = struct bpf_sock *
        .call(HELPER_GET_SOCKET_COOKIE)
        .jeq(R0, 0, "out")
        .store_u64(R10, -8, R0)
        .zero_stack(VALUE_FP, VALUE_SIZE);
    if with_comm {
        p.stack_ptr(R1, (VALUE_FP + OFF_COMM) as i32).mov_imm(R2, COMM_LEN).call(HELPER_GET_CURRENT_COMM);
    }
    p.call(HELPER_GET_CURRENT_PID_TGID)
        .rsh_imm(R0, 32) // tgid
        .store_u32(R10, VALUE_FP + OFF_TGID, R0)
        .load_u32(R7, R6, SOCK_PROTOCOL)
        .store_u32(R10, VALUE_FP + OFF_PROTO, R7)
        .load_map(R1, map_fd)
        .stack_ptr(R2, -8)
        .stack_ptr(R3, VALUE_FP as i32)
        .mov_imm(R4, BPF_ANY) // a reused cookie never carries old counts
        .call(HELPER_MAP_UPDATE_ELEM)
        .label("out")
        .mov_imm(R0, 1) // allow the socket
        .exit();
    p.finish()
}

fn load_program(insns: &[asm::Insn], prog_type: u32, name: &str, attach_type: u32) -> Result<OwnedFd> {
    let license = CString::new("GPL").expect("no NUL");
    let flat: Vec<u8> = insns.concat();
    let attr = |log: Option<&mut [u8]>| {
        let mut a = Attr::new()
            .u32(0, prog_type)
            .u32(4, insns.len() as u32)
            .u64(8, flat.as_ptr() as u64)
            .u64(16, license.as_ptr() as u64)
            .name(48, name)
            .u32(68, attach_type);
        if let Some(buf) = log {
            a = a.u32(24, 1).u32(28, buf.len() as u32).u64(32, buf.as_mut_ptr() as u64);
        }
        a
    };
    match bpf_fd(BPF_PROG_LOAD, &mut attr(None)) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            // Retry with the verifier log to explain the failure.
            let mut log = vec![0u8; 64 * 1024];
            let _ = bpf_fd(BPF_PROG_LOAD, &mut attr(Some(&mut log)));
            let end = log.iter().position(|&b| b == 0).unwrap_or(0);
            let detail = String::from_utf8_lossy(&log[..end]).trim().to_string();
            let detail = if detail.is_empty() { String::new() } else { format!("\n{detail}") };
            Err(Error::Other(format!("loading eBPF program {name}: {e}{detail}")))
        }
    }
}

/// How a program is attached; detached when dropped.
enum Attachment {
    /// A BPF link (Linux 5.7+): the kernel detaches it when the fd closes.
    Link(#[allow(dead_code)] OwnedFd),
    /// Legacy attach: must be detached explicitly.
    Legacy { cgroup: RawFd, prog: RawFd, attach_type: u32 },
}

impl Drop for Attachment {
    fn drop(&mut self) {
        if let Attachment::Legacy { cgroup, prog, attach_type } = *self {
            let mut a = Attr::new().u32(0, cgroup as u32).u32(4, prog as u32).u32(8, attach_type);
            let _ = bpf(BPF_PROG_DETACH, &mut a);
        }
    }
}

fn attach(cgroup: &OwnedFd, prog: &OwnedFd, attach_type: u32) -> Result<Attachment> {
    let mut link =
        Attr::new().u32(0, prog.as_raw_fd() as u32).u32(4, cgroup.as_raw_fd() as u32).u32(8, attach_type);
    match bpf_fd(BPF_LINK_CREATE, &mut link) {
        Ok(fd) => Ok(Attachment::Link(fd)),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOSYS)) => {
            let mut a = Attr::new()
                .u32(0, cgroup.as_raw_fd() as u32)
                .u32(4, prog.as_raw_fd() as u32)
                .u32(8, attach_type)
                .u32(12, BPF_F_ALLOW_MULTI);
            bpf(BPF_PROG_ATTACH, &mut a).map_err(|e| Error::io("attaching eBPF program", e))?;
            Ok(Attachment::Legacy { cgroup: cgroup.as_raw_fd(), prog: prog.as_raw_fd(), attach_type })
        }
        Err(e) => Err(Error::io("attaching eBPF program", e)),
    }
}

fn open_dir(path: &Path) -> Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| Error::Other("path contains NUL".into()))?;
    // SAFETY: plain open(2) of a directory; the result is checked.
    let raw = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(Error::io(format!("opening {}", path.display()), io::Error::last_os_error()));
    }
    // SAFETY: open just returned this descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Loaded and attached counters. Dropping it detaches everything.
pub struct SocketCounters {
    // Field order is drop order: detach before closing programs and the map.
    _attachments: Vec<Attachment>,
    _programs: Vec<OwnedFd>,
    _cgroup: OwnedFd,
    map: OwnedFd,
    /// Whether socket creators are recorded (needs a newer kernel than the
    /// packet counters).
    tracks_creators: bool,
    batch_supported: bool,
}

impl SocketCounters {
    /// Loads the programs and attaches them to the cgroup2 hierarchy mounted
    /// at `cgroup_root`, which covers every process. Needs root
    /// (`CAP_BPF` + `CAP_NET_ADMIN`).
    pub fn attach(cgroup_root: &Path, count_loopback: bool) -> Result<Self> {
        let mut map_attr = Attr::new()
            .u32(0, BPF_MAP_TYPE_LRU_HASH)
            .u32(4, 8)
            .u32(8, VALUE_SIZE as u32)
            .u32(12, MAX_SOCKETS)
            .name(28, "nwl_sock_bytes");
        let map = bpf_fd(BPF_MAP_CREATE, &mut map_attr).map_err(|e| Error::io("creating eBPF map", e))?;
        let cgroup = open_dir(cgroup_root)?;
        let fd = map.as_raw_fd();

        let mut programs = Vec::new();
        let mut attachments = Vec::new();
        // Attach the owner tracker first so sockets opened from now on get
        // their owner recorded before their first packet. Older kernels
        // (before 5.10) cannot run it; packet counting still works then.
        // Recording the process name needs a newer kernel than the rest;
        // try with it first.
        let load_owner = |with_comm: bool| {
            load_program(
                &sock_create_program(fd, with_comm),
                BPF_PROG_TYPE_CGROUP_SOCK,
                "nwl_sock_owner",
                BPF_CGROUP_INET_SOCK_CREATE,
            )
        };
        let owner = load_owner(true)
            .or_else(|_| load_owner(false))
            .and_then(|prog| Ok((attach(&cgroup, &prog, BPF_CGROUP_INET_SOCK_CREATE)?, prog)));
        let tracks_creators = match owner {
            Ok((a, prog)) => {
                attachments.push(a);
                programs.push(prog);
                true
            }
            Err(e) => {
                tracing::info!("socket owner tracking unavailable: {e}");
                false
            }
        };
        for (name, attach_type, slot) in [
            ("nwl_count_in", BPF_CGROUP_INET_INGRESS, OFF_RX),
            ("nwl_count_out", BPF_CGROUP_INET_EGRESS, OFF_TX),
        ] {
            let insns = counter_program(fd, slot, count_loopback);
            let prog = load_program(&insns, BPF_PROG_TYPE_CGROUP_SKB, name, attach_type)?;
            attachments.push(attach(&cgroup, &prog, attach_type)?);
            programs.push(prog);
        }
        Ok(Self {
            _attachments: attachments,
            _programs: programs,
            _cgroup: cgroup,
            map,
            tracks_creators,
            batch_supported: true,
        })
    }

    pub fn tracks_creators(&self) -> bool {
        self.tracks_creators
    }

    /// The counters of one socket, if it has been seen.
    pub fn get(&self, cookie: u64) -> Option<Counter> {
        let key = cookie.to_ne_bytes();
        let mut value = [0u8; VALUE_SIZE];
        let mut a = Attr::new()
            .u32(0, self.map.as_raw_fd() as u32)
            .u64(8, key.as_ptr() as u64)
            .u64(16, value.as_mut_ptr() as u64);
        bpf(BPF_MAP_LOOKUP_ELEM, &mut a).ok()?;
        Some(Counter::from_bytes(&value))
    }

    /// Forgets a socket that is gone.
    pub fn remove(&self, cookie: u64) {
        let key = cookie.to_ne_bytes();
        let mut a = Attr::new().u32(0, self.map.as_raw_fd() as u32).u64(8, key.as_ptr() as u64);
        let _ = bpf(BPF_MAP_DELETE_ELEM, &mut a);
    }

    /// Every tracked socket, read in bulk.
    pub fn all(&mut self) -> HashMap<u64, Counter> {
        if self.batch_supported {
            match self.all_batched() {
                Ok(all) => return all,
                // Batch lookups need Linux 5.6; iterate key by key before that.
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) | Some(524)
                    ) =>
                {
                    self.batch_supported = false;
                }
                Err(_) => return HashMap::new(),
            }
        }
        self.all_iterated()
    }

    fn all_batched(&self) -> io::Result<HashMap<u64, Counter>> {
        const CHUNK: usize = 4096;
        let mut out = HashMap::new();
        let mut keys = vec![0u8; CHUNK * 8];
        let mut values = vec![0u8; CHUNK * VALUE_SIZE];
        let (mut in_batch, mut out_batch) = ([0u8; 8], [0u8; 8]);
        let mut first = true;
        loop {
            let mut a = Attr::new()
                .u64(0, if first { 0 } else { in_batch.as_ptr() as u64 })
                .u64(8, out_batch.as_mut_ptr() as u64)
                .u64(16, keys.as_mut_ptr() as u64)
                .u64(24, values.as_mut_ptr() as u64)
                .u32(32, CHUNK as u32)
                .u32(36, self.map.as_raw_fd() as u32);
            let result = bpf(BPF_MAP_LOOKUP_BATCH, &mut a);
            let count = (a.get_u32(32) as usize).min(CHUNK);
            for i in 0..count {
                let cookie = u64::from_ne_bytes(keys[i * 8..i * 8 + 8].try_into().unwrap());
                out.insert(cookie, Counter::from_bytes(&values[i * VALUE_SIZE..(i + 1) * VALUE_SIZE]));
            }
            match result {
                Ok(_) => {
                    in_batch = out_batch;
                    first = false;
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(out), // done
                Err(e) => return Err(e),
            }
        }
    }

    fn all_iterated(&self) -> HashMap<u64, Counter> {
        let mut out = HashMap::new();
        let mut key = [0u8; 8];
        let mut next = [0u8; 8];
        let mut first = true;
        loop {
            let mut a = Attr::new()
                .u32(0, self.map.as_raw_fd() as u32)
                .u64(8, if first { 0 } else { key.as_ptr() as u64 })
                .u64(16, next.as_mut_ptr() as u64);
            if bpf(BPF_MAP_GET_NEXT_KEY, &mut a).is_err() {
                return out;
            }
            first = false;
            key = next;
            let cookie = u64::from_ne_bytes(key);
            if let Some(c) = self.get(cookie) {
                out.insert(cookie, c);
            }
        }
    }
}

/// Tests that attach to the root cgroup's hooks take this, so they run one
/// at a time and attach counts stay meaningful.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static KERNEL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    KERNEL.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::sockdiag;
    use std::net::UdpSocket;

    fn assert_jumps_valid(p: &[asm::Insn]) {
        for (i, insn) in p.iter().enumerate() {
            let class = insn[0] & 0x07;
            if class == 0x05 && insn[0] != 0x85 && insn[0] != 0x95 {
                let off = i16::from_le_bytes([insn[2], insn[3]]) as i64;
                let target = i as i64 + 1 + off;
                assert!((0..p.len() as i64).contains(&target), "insn {i} jumps to {target}");
            }
        }
        assert_eq!(p.last().unwrap()[0], 0x95, "ends with exit");
    }

    #[test]
    fn programs_are_well_formed() {
        assert_jumps_valid(&counter_program(3, OFF_TX, false));
        assert_jumps_valid(&counter_program(3, OFF_RX, true));
        assert_jumps_valid(&sock_create_program(3, true));
        assert_jumps_valid(&sock_create_program(3, false));
    }

    fn cgroup2_mount() -> Option<String> {
        let m = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        crate::linux::cgroup::find_cgroup2_mount(&m).map(|p| p.display().to_string())
    }

    /// Programs attached to the root cgroup for one hook (others, e.g.
    /// systemd's, may be there too).
    fn attached(mount: &str, attach_type: u32) -> u32 {
        let fd = open_dir(Path::new(mount)).unwrap();
        const BPF_PROG_QUERY: u32 = 16;
        let mut a = Attr::new().u32(0, fd.as_raw_fd() as u32).u32(4, attach_type);
        bpf(BPF_PROG_QUERY, &mut a).unwrap();
        a.get_u32(24) // prog_cnt
    }

    /// Counts real traffic against the real kernel. Needs root; skipped
    /// otherwise. Uses loopback, so loopback counting is enabled.
    #[test]
    fn counts_udp_and_records_owners_even_after_close() {
        let _guard = test_lock();
        let Some(mount) = cgroup2_mount() else { return eprintln!("no cgroup2, skipping") };
        let hooks = [BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_INET_INGRESS, BPF_CGROUP_INET_EGRESS];
        let mut counters = match SocketCounters::attach(Path::new(&mount), true) {
            Ok(c) => c,
            Err(e) => return eprintln!("eBPF unavailable here, skipping: {e}"),
        };
        let during: Vec<u32> = hooks.iter().map(|&h| attached(&mount, h)).collect();
        assert!(counters.tracks_creators(), "kernel too old for owner tracking?");

        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        for _ in 0..50 {
            tx.send(&[9u8; 1000]).unwrap();
        }
        let mut buf = [0u8; 2000];
        for _ in 0..50 {
            rx.recv(&mut buf).unwrap();
        }
        // Each datagram is 1000 bytes of payload + 8 (UDP) + 20 (IPv4).
        let wire = 50 * (1000 + 8 + 20);
        let socks = sockdiag::dump_all().unwrap();
        let cookie_of = |addr| socks.iter().find(|s| s.key.local == addr).map(|s| s.key.cookie).unwrap();
        let (tx_cookie, rx_cookie) =
            (cookie_of(tx.local_addr().unwrap()), cookie_of(rx.local_addr().unwrap()));
        let me = std::process::id();
        let (tx_c, rx_c) = (counters.get(tx_cookie).unwrap(), counters.get(rx_cookie).unwrap());
        assert_eq!((tx_c.rx, tx_c.tx, tx_c.tgid, tx_c.protocol), (0, wire, me, 17));
        assert_eq!((rx_c.rx, rx_c.tx, rx_c.tgid, rx_c.protocol), (wire, 0, me, 17));
        // comm is the creating thread's name, as the kernel reports it.
        let thread = std::fs::read_to_string("/proc/thread-self/comm").unwrap();
        assert_eq!(tx_c.comm().as_deref(), Some(thread.trim_end()));

        // A socket that is already closed is still accounted to its creator.
        drop((rx, tx));
        let all = counters.all();
        assert_eq!(all.get(&tx_cookie).map(|c| (c.tx, c.tgid)), Some((wire, me)));
        counters.remove(tx_cookie);
        assert_eq!(counters.get(tx_cookie), None);

        drop(counters);
        let after: Vec<u32> = hooks.iter().map(|&h| attached(&mount, h)).collect();
        let expected: Vec<u32> = during.iter().map(|n| n - 1).collect();
        assert_eq!(after, expected, "dropping detaches every program");
    }

    #[test]
    fn loopback_is_skipped_unless_requested() {
        let _guard = test_lock();
        let Some(mount) = cgroup2_mount() else { return };
        let Ok(counters) = SocketCounters::attach(Path::new(&mount), false) else { return };
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        tx.send(&[1u8; 100]).unwrap();
        rx.recv(&mut [0u8; 200]).unwrap();
        let socks = sockdiag::dump_all().unwrap();
        let cookie = socks.iter().find(|s| s.key.local == tx.local_addr().unwrap()).unwrap().key.cookie;
        let c = counters.get(cookie).expect("owner recorded at creation");
        assert_eq!((c.rx, c.tx), (0, 0), "loopback packets are not counted");
    }
}
