//! Domain names for remote addresses, learned from DNS answers.
//!
//! The daemon watches DNS responses (where the platform allows) and keeps
//! which names resolved to which addresses, for as long as the answer is
//! valid. That names connections by the domain the app actually looked up
//! (`api.example.com`, not a CDN's reverse-DNS name), and lets rules match
//! domains: a rule for `example.com` applies to the addresses `example.com`
//! and its subdomains currently resolve to.
//!
//! Encrypted DNS (DNS over HTTPS or TLS, used by some browsers) can't be
//! seen; addresses only learned that way stay unnamed.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Answers are kept at least this long (seconds), so short TTLs still name
/// the connections they lead to...
const MIN_TTL: u32 = 300;
/// ...and at most this long.
const MAX_TTL: u32 = 6 * 3600;
const MAX_ENTRIES: usize = 50_000;

/// A domain in a rule: `example.com` matches it and every subdomain;
/// patterns with `*` are globs (`ads*.example.net`). Case is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DomainPattern(pub String);

impl DomainPattern {
    pub fn is_glob(&self) -> bool {
        self.0.contains('*')
    }

    pub fn matches(&self, name: &str) -> bool {
        let pattern = self.0.trim().trim_end_matches('.').to_ascii_lowercase();
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if self.is_glob() {
            glob(&pattern, &name)
        } else {
            name == pattern || name.ends_with(&format!(".{pattern}"))
        }
    }

    /// A plausible domain: letters, digits, `-`, `.`, `*`, `_`.
    pub fn is_valid(&self) -> bool {
        let p = self.0.trim();
        !p.is_empty()
            && p.len() <= 253
            && !p.starts_with('.')
            && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '*' | '_'))
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// An address a DNS answer gave for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub ip: IpAddr,
    /// The names it answers for: the name asked for, and the aliases
    /// (CNAMEs) on the way.
    pub names: Vec<String>,
    pub ttl: u32,
}

/// Names per address, expiring with their answers.
#[derive(Debug, Default)]
pub struct DnsCache {
    by_ip: HashMap<IpAddr, Vec<(String, i64)>>,
}

impl DnsCache {
    /// Records an answer seen at `now` (unix seconds).
    pub fn insert(&mut self, answer: &Answer, now: i64) {
        if self.by_ip.len() >= MAX_ENTRIES && !self.by_ip.contains_key(&answer.ip) {
            self.prune(now);
            if self.by_ip.len() >= MAX_ENTRIES {
                return;
            }
        }
        let expires = now + answer.ttl.clamp(MIN_TTL, MAX_TTL) as i64;
        let names = self.by_ip.entry(answer.ip).or_default();
        for name in &answer.names {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            match names.iter_mut().find(|(n, _)| *n == name) {
                Some(entry) => entry.1 = entry.1.max(expires),
                None => names.push((name, expires)),
            }
        }
    }

    /// Drops expired answers.
    pub fn prune(&mut self, now: i64) {
        self.by_ip.retain(|_, names| {
            names.retain(|(_, expires)| *expires > now);
            !names.is_empty()
        });
    }

    /// Names an address currently stands for, the name asked for first.
    pub fn names(&self, ip: IpAddr, now: i64) -> Vec<&str> {
        self.by_ip
            .get(&normalize(ip))
            .map(|v| v.iter().filter(|(_, e)| *e > now).map(|(n, _)| n.as_str()).collect())
            .unwrap_or_default()
    }

    /// Addresses currently known for names matching any of the patterns.
    pub fn addresses(&self, patterns: &[DomainPattern], now: i64) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .by_ip
            .iter()
            .filter(|(_, names)| names.iter().any(|(n, e)| *e > now && patterns.iter().any(|p| p.matches(n))))
            .map(|(ip, _)| *ip)
            .collect();
        out.sort();
        out
    }

    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

/// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) as IPv4.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// The address answers of a DNS response message (UDP payload).
pub fn parse_response(msg: &[u8]) -> Option<Vec<Answer>> {
    if msg.len() < 12 || msg[2] & 0x80 == 0 {
        return None; // not a response
    }
    let rcode = msg[3] & 0x0f;
    if rcode != 0 {
        return Some(Vec::new());
    }
    let count = |i: usize| u16::from_be_bytes([msg[i], msg[i + 1]]) as usize;
    let (questions, answers) = (count(4), count(6));
    let mut pos = 12;
    let mut asked = None;
    for _ in 0..questions {
        let (name, next) = read_name(msg, pos)?;
        asked.get_or_insert(name);
        pos = next + 4; // type, class
    }
    let asked = asked?;
    // Follow CNAMEs: every name on the chain stands for the final addresses.
    let mut chain = vec![asked];
    let mut records = Vec::new();
    for _ in 0..answers {
        let (name, next) = read_name(msg, pos)?;
        let header = msg.get(next..next + 10)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let len = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data_at = next + 10;
        let data = msg.get(data_at..data_at + len)?;
        match kind {
            1 if len == 4 => {
                records.push((name, IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])), ttl))
            }
            28 if len == 16 => {
                let octets: [u8; 16] = data.try_into().ok()?;
                records.push((name, IpAddr::V6(Ipv6Addr::from(octets)), ttl));
            }
            5 => {
                let (target, _) = read_name(msg, data_at)?;
                if chain.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                    chain.push(target);
                }
            }
            _ => {}
        }
        pos = data_at + len;
    }
    Some(
        records
            .into_iter()
            .filter(|(name, _, _)| chain.iter().any(|n| n.eq_ignore_ascii_case(name)))
            .map(|(_, ip, ttl)| Answer { ip, names: chain.clone(), ttl })
            .collect(),
    )
}

/// A possibly compressed name at `pos`; returns it and the position after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = target;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    None // a compression loop
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response for `www.example.com`: CNAME to `cdn.example.net`, which
    /// has an A and an AAAA record; names compressed after first use.
    fn response() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        let name = |m: &mut Vec<u8>, labels: &[&str]| {
            for l in labels {
                m.push(l.len() as u8);
                m.extend_from_slice(l.as_bytes());
            }
            m.push(0);
        };
        name(&mut m, &["www", "example", "com"]); // at 12
        m.extend_from_slice(&[0, 1, 0, 1]);
        // CNAME
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60]);
        let mut target = Vec::new();
        name(&mut target, &["cdn", "example", "net"]);
        m.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let cdn_at = m.len() as u8;
        m.extend_from_slice(&target);
        // A
        m.extend_from_slice(&[0xc0, cdn_at, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34]);
        // AAAA
        m.extend_from_slice(&[0xc0, cdn_at, 0, 28, 0, 1, 0, 0, 1, 0x2c, 0, 16]);
        m.extend_from_slice(&"2606:2800:220:1::248".parse::<Ipv6Addr>().unwrap().octets());
        m
    }

    #[test]
    fn parses_answers_through_cnames() {
        let answers = parse_response(&response()).unwrap();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(answers[0].names, ["www.example.com", "cdn.example.net"]);
        assert_eq!(answers[0].ttl, 300);
        assert!(answers[1].ip.is_ipv6());
        let mut query = response();
        query[2] = 0x01; // a query, not a response
        assert!(parse_response(&query).is_none());
        assert!(parse_response(&response()[..40]).is_none(), "truncated");
        let mut looped = response();
        looped[34] = 0xc0; // CNAME data pointing at itself
        looped[35] = 34;
        let _ = parse_response(&looped); // no hang, no panic
    }

    #[test]
    fn cache_and_patterns() {
        let mut cache = DnsCache::default();
        for a in parse_response(&response()).unwrap() {
            cache.insert(&a, 1000);
        }
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(cache.names(ip, 1000), ["www.example.com", "cdn.example.net"]);
        let mapped: IpAddr = "::ffff:93.184.216.34".parse().unwrap();
        assert_eq!(cache.names(mapped, 1000).len(), 2, "IPv4-mapped addresses");
        let p = |s: &str| DomainPattern(s.into());
        assert_eq!(cache.addresses(&[p("example.com")], 1000).len(), 2, "subdomains match");
        assert_eq!(cache.addresses(&[p("*.example.net")], 1000).len(), 2);
        assert!(cache.addresses(&[p("ample.com")], 1000).is_empty(), "whole labels only");
        assert!(cache.names(ip, 1000 + 301).is_empty(), "expires (minimum 5 minutes)");
        cache.prune(1000 + 301);
        assert!(cache.is_empty());
        assert!(p("Ads.Example.com").matches("ads.example.com."));
        assert!(p("doubleclick.net").matches("stats.g.doubleclick.net"));
        assert!(!p("doubleclick.net").matches("notdoubleclick.net"));
        assert!(p("ads*.example.net").matches("ads2.example.net"));
        assert!(p("example.com").is_valid() && !p("exa mple.com").is_valid() && !p("").is_valid());
    }
}
