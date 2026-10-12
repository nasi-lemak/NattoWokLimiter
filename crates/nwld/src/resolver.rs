//! Background reverse-DNS lookups for remote addresses, with a bounded cache.
//!
//! Lookups never block callers: an unknown address is queued and `None`
//! returned; the name shows up on a later request once resolved.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const POSITIVE_TTL: Duration = Duration::from_secs(3600);
const NEGATIVE_TTL: Duration = Duration::from_secs(600);
const MAX_ENTRIES: usize = 20_000;
const QUEUE: usize = 1024;

pub type LookupFn = fn(IpAddr) -> Option<String>;

enum Entry {
    Pending,
    Done { name: Option<String>, at: Instant },
}

#[derive(Clone)]
pub struct Resolver {
    cache: Arc<Mutex<HashMap<IpAddr, Entry>>>,
    queue: mpsc::SyncSender<IpAddr>,
}

/// Resolves with the system resolver (PTR records).
pub fn system_lookup(ip: IpAddr) -> Option<String> {
    dns_lookup::lookup_addr(&ip).ok().filter(|name| name.parse::<IpAddr>().is_err())
}

impl Resolver {
    pub fn new(workers: usize, lookup: LookupFn) -> Self {
        let cache: Arc<Mutex<HashMap<IpAddr, Entry>>> = Arc::default();
        let (queue, rx) = mpsc::sync_channel::<IpAddr>(QUEUE);
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..workers.max(1) {
            let (cache, rx) = (cache.clone(), rx.clone());
            let _ = std::thread::Builder::new().name(format!("resolver-{i}")).spawn(move || loop {
                let next = rx.lock().unwrap_or_else(|p| p.into_inner()).recv();
                let Ok(ip) = next else { return };
                let name = lookup(ip);
                cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(ip, Entry::Done { name, at: Instant::now() });
            });
        }
        Self { cache, queue }
    }

    /// The cached host name of `ip`, queueing a lookup if needed.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return None;
        }
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        match cache.get(&ip) {
            Some(Entry::Pending) => return None,
            Some(Entry::Done { name, at }) => {
                let ttl = if name.is_some() { POSITIVE_TTL } else { NEGATIVE_TTL };
                if at.elapsed() < ttl {
                    return name.clone();
                }
            }
            None => {}
        }
        if cache.len() >= MAX_ENTRIES {
            cache.retain(|_, e| matches!(e, Entry::Pending));
        }
        if self.queue.try_send(ip).is_ok() {
            // Keep serving a stale name while the refresh runs.
            let stale = match cache.insert(ip, Entry::Pending) {
                Some(Entry::Done { name, .. }) => name,
                _ => None,
            };
            if stale.is_some() {
                cache.insert(ip, Entry::Done { name: stale.clone(), at: Instant::now() - NEGATIVE_TTL });
                return stale;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(ip: IpAddr) -> Option<String> {
        (ip == IpAddr::from([1, 1, 1, 1])).then(|| "one.one.one.one".to_string())
    }

    #[test]
    fn resolves_in_background_and_caches() {
        let r = Resolver::new(1, fake);
        let ip = IpAddr::from([1, 1, 1, 1]);
        assert_eq!(r.lookup(ip), None, "first call only queues");
        let deadline = Instant::now() + Duration::from_secs(5);
        while r.lookup(ip).is_none() {
            assert!(Instant::now() < deadline, "lookup never completed");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(r.lookup(ip).as_deref(), Some("one.one.one.one"));
        // Mapped IPv6 resolves as IPv4; loopback is never looked up.
        assert_eq!(r.lookup("::ffff:1.1.1.1".parse().unwrap()).as_deref(), Some("one.one.one.one"));
        assert_eq!(r.lookup("127.0.0.1".parse().unwrap()), None);
        assert!(!r.cache.lock().unwrap().contains_key(&"127.0.0.1".parse::<IpAddr>().unwrap()));
    }
}
