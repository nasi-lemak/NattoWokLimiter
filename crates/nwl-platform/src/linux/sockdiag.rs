//! Socket enumeration through the `NETLINK_SOCK_DIAG` interface (what `ss`
//! uses). Compared to parsing `/proc/net/tcp`, it also returns `tcp_info`,
//! giving exact per-socket byte counters and RTT without eBPF.

use nwl_core::model::{ConnKey, Protocol, TcpState};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_MSG_LEN: usize = 72;

/// TCP states worth reporting. TIME_WAIT/CLOSE sockets have no owner and move
/// no data; NEW_SYN_RECV are half-open request sockets.
const TCP_STATES: u32 = (1 << 1) // ESTABLISHED
    | (1 << 2) // SYN_SENT
    | (1 << 3) // SYN_RECV
    | (1 << 4) // FIN_WAIT1
    | (1 << 5) // FIN_WAIT2
    | (1 << 8) // CLOSE_WAIT
    | (1 << 9) // LAST_ACK
    | (1 << 10) // LISTEN
    | (1 << 11); // CLOSING

/// One socket as reported by the kernel.
#[derive(Debug, Clone)]
pub struct DiagSocket {
    pub key: ConnKey,
    pub state: Option<TcpState>,
    pub uid: u32,
    pub inode: u32,
    pub bytes_sent: Option<u64>,
    pub bytes_recv: Option<u64>,
    pub rtt_us: Option<u32>,
}

struct Netlink(libc::c_int);

impl Netlink {
    fn open() -> io::Result<Self> {
        // SAFETY: plain syscall; the result is checked.
        let fd = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_SOCK_DIAG)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Netlink(fd))
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        // SAFETY: we own the descriptor.
        unsafe { libc::close(self.0) };
    }
}

/// Dumps all TCP and UDP sockets, IPv4 and IPv6.
pub fn dump_all() -> io::Result<Vec<DiagSocket>> {
    let nl = Netlink::open()?;
    let mut out = Vec::new();
    let mut seq = 0;
    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        for (proto, states) in [(Protocol::Tcp, TCP_STATES), (Protocol::Udp, u32::MAX)] {
            seq += 1;
            dump(&nl, seq, family, proto, states, &mut out)?;
        }
    }
    Ok(out)
}

fn dump(
    nl: &Netlink,
    seq: u32,
    family: u8,
    proto: Protocol,
    states: u32,
    out: &mut Vec<DiagSocket>,
) -> io::Result<()> {
    let ipproto = match proto {
        Protocol::Tcp => libc::IPPROTO_TCP,
        Protocol::Udp => libc::IPPROTO_UDP,
    } as u8;

    // nlmsghdr (16) + inet_diag_req_v2 (8 + 48-byte inet_diag_sockid).
    let mut req = [0u8; NLMSG_HDRLEN + 56];
    let len = req.len() as u32;
    req[0..4].copy_from_slice(&len.to_ne_bytes());
    req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
    req[6..8].copy_from_slice(&flags.to_ne_bytes());
    req[8..12].copy_from_slice(&seq.to_ne_bytes());
    req[16] = family;
    req[17] = ipproto;
    req[18] = 1 << (INET_DIAG_INFO - 1); // request tcp_info
    req[20..24].copy_from_slice(&states.to_ne_bytes());

    // SAFETY: sockaddr_nl is plain data; zeroed is a valid value.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: buffers and lengths are valid for the duration of the call.
    let sent = unsafe {
        libc::sendto(
            nl.0,
            req.as_ptr().cast(),
            req.len(),
            0,
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf = vec![0u8; 1 << 16];
    loop {
        // SAFETY: buf is valid for writes of buf.len() bytes.
        let n = unsafe { libc::recv(nl.0, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let mut data = &buf[..n as usize];
        while data.len() >= NLMSG_HDRLEN {
            let msg_len = u32::from_ne_bytes(data[0..4].try_into().unwrap()) as usize;
            let msg_type = u16::from_ne_bytes(data[4..6].try_into().unwrap());
            if msg_len < NLMSG_HDRLEN || msg_len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated netlink message"));
            }
            let payload = &data[NLMSG_HDRLEN..msg_len];
            match msg_type {
                NLMSG_DONE => return Ok(()),
                NLMSG_ERROR => {
                    let errno =
                        payload.get(0..4).map(|b| i32::from_ne_bytes(b.try_into().unwrap())).unwrap_or(0);
                    if errno == 0 {
                        return Ok(()); // ACK
                    }
                    // Protocols without a diag module (e.g. udp_diag not
                    // loaded) report ENOENT; treat as "no sockets".
                    if -errno == libc::ENOENT {
                        return Ok(());
                    }
                    return Err(io::Error::from_raw_os_error(-errno));
                }
                SOCK_DIAG_BY_FAMILY => {
                    if let Some(sock) = parse_diag_msg(payload, proto) {
                        out.push(sock);
                    }
                }
                _ => {}
            }
            let aligned = (msg_len + 3) & !3;
            data = &data[aligned.min(data.len())..];
        }
    }
}

fn parse_addr(family: u8, bytes: &[u8], port: u16) -> SocketAddr {
    let ip = if family == libc::AF_INET as u8 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        let octets: [u8; 16] = bytes[..16].try_into().unwrap();
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    SocketAddr::new(ip, port)
}

/// Parses an `inet_diag_msg` and its attributes.
fn parse_diag_msg(p: &[u8], proto: Protocol) -> Option<DiagSocket> {
    if p.len() < INET_DIAG_MSG_LEN {
        return None;
    }
    let family = p[0];
    let state = p[1];
    // inet_diag_sockid starts at offset 4.
    let id = &p[4..52];
    let sport = u16::from_be_bytes([id[0], id[1]]);
    let dport = u16::from_be_bytes([id[2], id[3]]);
    let local = parse_addr(family, &id[4..20], sport);
    let remote = parse_addr(family, &id[20..36], dport);
    let cookie_lo = u32::from_ne_bytes(id[40..44].try_into().unwrap()) as u64;
    let cookie_hi = u32::from_ne_bytes(id[44..48].try_into().unwrap()) as u64;
    let uid = u32::from_ne_bytes(p[64..68].try_into().unwrap());
    let inode = u32::from_ne_bytes(p[68..72].try_into().unwrap());

    let remote = (!remote.ip().is_unspecified() || remote.port() != 0).then_some(remote);
    let mut sock = DiagSocket {
        key: ConnKey { protocol: proto, local, remote, cookie: cookie_lo | (cookie_hi << 32) },
        state: (proto == Protocol::Tcp).then(|| TcpState::from_linux(state)),
        uid,
        inode,
        bytes_sent: None,
        bytes_recv: None,
        rtt_us: None,
    };

    let mut attrs = &p[INET_DIAG_MSG_LEN..];
    while attrs.len() >= 4 {
        let len = u16::from_ne_bytes([attrs[0], attrs[1]]) as usize;
        let ty = u16::from_ne_bytes([attrs[2], attrs[3]]);
        if len < 4 || len > attrs.len() {
            break;
        }
        if ty == INET_DIAG_INFO {
            parse_tcp_info(&attrs[4..len], &mut sock);
        }
        attrs = &attrs[((len + 3) & !3).min(attrs.len())..];
    }
    Some(sock)
}

/// Extracts fields from `struct tcp_info` (see `include/uapi/linux/tcp.h`).
/// The struct only ever grows, so fields are read when the kernel's copy is
/// long enough to contain them.
fn parse_tcp_info(info: &[u8], sock: &mut DiagSocket) {
    let u32_at = |off: usize| info.get(off..off + 4).map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
    let u64_at = |off: usize| info.get(off..off + 8).map(|b| u64::from_ne_bytes(b.try_into().unwrap()));
    sock.rtt_us = u32_at(68); // tcpi_rtt
                              // tcpi_bytes_sent (Linux 4.19+) is payload put on the wire, including
                              // retransmissions, i.e. what an ISP meters. Older kernels only have
                              // tcpi_bytes_acked (4.1+), which on the connecting side also counts the
                              // SYN as one byte; close enough for a fallback.
    sock.bytes_sent = u64_at(200).or_else(|| u64_at(120));
    sock.bytes_recv = u64_at(128); // tcpi_bytes_received (Linux 4.1+)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn reports_bytes_of_a_local_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(server_addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let payload = vec![7u8; 100_000];
        client.write_all(&payload).unwrap();
        let mut received = vec![0u8; payload.len()];
        server.read_exact(&mut received).unwrap();
        server.write_all(&payload[..1234]).unwrap();
        let mut back = vec![0u8; 1234];
        client.read_exact(&mut back).unwrap();

        let socks = match dump_all() {
            Ok(s) => s,
            Err(e) => return crate::linux::skip_unless_required(&format!("sock_diag: {e}")),
        };
        let client_local = client.local_addr().unwrap();
        let c = socks
            .iter()
            .find(|s| s.key.local == client_local && s.key.remote == Some(server_addr))
            .expect("client socket listed");
        let server_local = server.local_addr().unwrap();
        let s = socks
            .iter()
            .find(|s| s.key.local == server_local && s.key.remote == Some(client_local))
            .expect("accepted socket listed");
        assert_eq!((s.bytes_sent, s.bytes_recv), (Some(1234), Some(100_000)));
        assert_eq!(c.state, Some(TcpState::Established));
        assert_eq!(c.bytes_sent, Some(100_000));
        assert_eq!(c.bytes_recv, Some(1234));
        assert!(c.inode != 0);
        assert!(c.key.cookie != 0);

        let listening = socks
            .iter()
            .find(|s| s.key.local == server_addr && s.state == Some(TcpState::Listen))
            .expect("listener listed");
        assert_eq!(listening.key.remote, None);
    }
}
