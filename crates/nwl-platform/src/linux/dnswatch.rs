//! Watches DNS answers on every interface, to name remote addresses.
//!
//! A packet socket receives copies of IP packets; a classic BPF filter in
//! the kernel passes only UDP packets from port 53 (DNS responses, IPv4 and
//! IPv6), so the daemon never sees other traffic. Answers to apps through a
//! local stub resolver (systemd-resolved on 127.0.0.53) are seen on the
//! loopback interface. Needs root (`CAP_NET_RAW`).

use nwl_core::dns::{parse_response, Answer};
use std::io;

/// Classic BPF: accept UDP from source port 53, IPv4 or IPv6. Offsets are
/// from the network header (the socket is `SOCK_DGRAM`).
const FILTER: [(u16, u8, u8, u32); 17] = [
    (0x30, 0, 0, 0),      // 0: ldb [0]
    (0x54, 0, 0, 0xf0),   // 1: and #0xf0
    (0x15, 0, 7, 0x40),   // 2: IPv4? else 10
    (0x30, 0, 0, 9),      // 3: ldb [9] (protocol)
    (0x15, 0, 11, 17),    // 4: UDP? else drop
    (0x28, 0, 0, 6),      // 5: ldh [6] (fragment offset)
    (0x45, 9, 0, 0x1fff), // 6: a later fragment? drop
    (0xb1, 0, 0, 0),      // 7: ldxb 4*([0]&0xf) (header length)
    (0x48, 0, 0, 0),      // 8: ldh [x+0] (source port)
    (0x15, 5, 6, 53),     // 9: 53? accept : drop
    (0x15, 0, 5, 0x60),   // 10: IPv6? else drop
    (0x30, 0, 0, 6),      // 11: ldb [6] (next header)
    (0x15, 0, 3, 17),     // 12: UDP? else drop
    (0x28, 0, 0, 40),     // 13: ldh [40] (source port)
    (0x15, 0, 1, 53),     // 14: 53? accept : drop
    (0x06, 0, 0, 0xffff), // 15: accept
    (0x06, 0, 0, 0),      // 16: drop
];

pub struct DnsWatcher {
    fd: libc::c_int,
}

impl DnsWatcher {
    pub fn open() -> io::Result<Self> {
        let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
        // SAFETY: plain syscall; the result is checked.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let watcher = DnsWatcher { fd };
        let mut code: Vec<libc::sock_filter> =
            FILTER.iter().map(|&(code, jt, jf, k)| libc::sock_filter { code, jt, jf, k }).collect();
        let prog = libc::sock_fprog { len: code.len() as u16, filter: code.as_mut_ptr() };
        // SAFETY: `prog` points to `code`, valid for the duration of the call.
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&prog as *const libc::sock_fprog).cast(),
                std::mem::size_of::<libc::sock_fprog>() as u32,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(watcher)
    }

    /// Receives DNS answers forever (until the socket fails), calling
    /// `sink` with each response's address answers.
    pub fn run(self, mut sink: impl FnMut(Vec<Answer>)) -> io::Error {
        let mut buf = vec![0u8; 1 << 16];
        loop {
            // SAFETY: buf is valid for writes of buf.len() bytes.
            let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return err;
            }
            if let Some(answers) = udp_payload(&buf[..n as usize]).and_then(parse_response) {
                if !answers.is_empty() {
                    sink(answers);
                }
            }
        }
    }
}

impl Drop for DnsWatcher {
    fn drop(&mut self) {
        // SAFETY: we own the descriptor.
        unsafe { libc::close(self.fd) };
    }
}

/// The UDP payload of an IPv4 or IPv6 packet (the filter passed only UDP).
fn udp_payload(packet: &[u8]) -> Option<&[u8]> {
    let header = match packet.first()? >> 4 {
        4 => (*packet.first()? & 0x0f) as usize * 4,
        6 => 40,
        _ => return None,
    };
    packet.get(header + 8..)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, UdpSocket};
    use std::sync::mpsc;
    use std::time::Duration;

    /// A response to `test.nattowok.invalid` with one A record.
    fn response(id: [u8; 2], last: u8) -> Vec<u8> {
        let mut m = vec![id[0], id[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in ["test", "nattowok", "invalid"] {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, last]);
        m
    }

    #[test]
    fn sees_dns_answers() {
        let watcher = match DnsWatcher::open() {
            Ok(w) => w,
            Err(e) => return crate::linux::skip_unless_required(&format!("packet socket: {e}")),
        };
        let server = match UdpSocket::bind("127.0.0.1:53") {
            Ok(s) => s,
            Err(e) => return crate::linux::skip_unless_required(&format!("binding port 53: {e}")),
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            watcher.run(|answers| {
                let _ = tx.send(answers);
            })
        });
        std::thread::sleep(Duration::from_millis(100));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(&[0xab, 0xcd, 1, 0], "127.0.0.1:53").unwrap(); // stands in for a query
        let mut buf = [0u8; 512];
        let (_, from) = server.recv_from(&mut buf).unwrap();
        server.send_to(&response([0xab, 0xcd], 77), from).unwrap();
        // Non-DNS traffic must not reach the watcher.
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other.send_to(&response([0, 0], 99), client.local_addr().unwrap()).unwrap();

        let answers = rx.recv_timeout(Duration::from_secs(5)).expect("the answer was seen");
        assert_eq!(answers[0].ip, "192.0.2.77".parse::<IpAddr>().unwrap());
        assert_eq!(answers[0].names, ["test.nattowok.invalid"]);
        // Loopback shows each packet twice (sent and received); fine. The
        // packet from another port must not show at all.
        let more: Vec<Answer> =
            rx.try_iter().chain(rx.recv_timeout(Duration::from_millis(300))).flatten().collect();
        assert!(more.iter().all(|a| a.ip == answers[0].ip), "only port-53 responses pass the filter");
    }
}
