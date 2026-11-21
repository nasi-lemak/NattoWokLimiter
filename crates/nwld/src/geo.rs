//! Country and network owner (ASN) of remote addresses, from MaxMind-format
//! databases the user installs: GeoLite2 (MaxMind) or DB-IP Lite (CC BY
//! 4.0), country and ASN editions. nwld looks in its state directory's
//! `geoip/` folder and the usual system folders, and uses what it finds.

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// File names (prefixes, so dated downloads like
/// `dbip-country-lite-2026-11.mmdb` match too), best first.
const COUNTRY: [&str; 5] =
    ["GeoLite2-Country", "dbip-country-lite", "dbip-country", "GeoLite2-City", "dbip-city-lite"];
const ASN: [&str; 3] = ["GeoLite2-ASN", "dbip-asn-lite", "dbip-asn"];

pub use nwl_core::api::Location;

pub struct GeoDb {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
    /// The files in use, for the status.
    pub sources: Vec<String>,
}

/// Where databases are looked for, in order.
pub fn search_dirs(state_dir: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![state_dir.join("geoip")];
    if cfg!(unix) {
        dirs.extend(["/var/lib/GeoIP", "/usr/share/GeoIP", "/usr/local/share/GeoIP"].map(PathBuf::from));
    }
    dirs
}

fn find(dirs: &[PathBuf], names: &[&str]) -> Option<PathBuf> {
    for name in names {
        for dir in dirs {
            let Ok(read) = std::fs::read_dir(dir) else { continue };
            let mut found: Vec<PathBuf> = read
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let file = p.file_name().and_then(|f| f.to_str()).unwrap_or("");
                    file.starts_with(name) && file.ends_with(".mmdb")
                })
                .collect();
            // The newest dated download.
            found.sort();
            if let Some(p) = found.pop() {
                return Some(p);
            }
        }
    }
    None
}

impl GeoDb {
    /// Opens the databases found in `dirs`; `None` if there are none.
    pub fn open(dirs: &[PathBuf]) -> Option<Self> {
        let open = |names: &[&str]| -> Option<(Reader<Vec<u8>>, String)> {
            let path = find(dirs, names)?;
            match Reader::open_readfile(&path) {
                Ok(r) => Some((r, path.display().to_string())),
                Err(e) => {
                    tracing::warn!("{}: {e}", path.display());
                    None
                }
            }
        };
        let country = open(&COUNTRY);
        let asn = open(&ASN);
        if country.is_none() && asn.is_none() {
            return None;
        }
        let sources = country.iter().chain(asn.iter()).map(|(_, s)| s.clone()).collect();
        Some(GeoDb { country: country.map(|c| c.0), asn: asn.map(|a| a.0), sources })
    }

    pub fn lookup(&self, ip: IpAddr) -> Location {
        if !is_public(ip) {
            return Location::default();
        }
        let mut loc = Location::default();
        if let Some(r) = &self.country {
            if let Ok(Some(c)) = r.lookup(ip).and_then(|l| l.decode::<geoip2::Country>()) {
                loc.country = c.country.iso_code.map(String::from);
                loc.country_name = c.country.names.english.map(String::from);
            }
        }
        if let Some(r) = &self.asn {
            if let Ok(Some(a)) = r.lookup(ip).and_then(|l| l.decode::<geoip2::Asn>()) {
                loc.asn = a.autonomous_system_number;
                loc.org = a.autonomous_system_organization.map(String::from);
            }
        }
        loc
    }
}

/// Addresses worth looking up: not private, loopback, link-local and such.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                let first = v6.segments()[0];
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (first & 0xfe00) == 0xfc00 // unique local
                    || (first & 0xffc0) == 0xfe80) // link local
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_databases_by_name() {
        let dir = std::env::temp_dir().join(format!("nwld-geo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for f in ["dbip-country-lite-2026-10.mmdb", "dbip-country-lite-2026-11.mmdb", "notes.txt"] {
            std::fs::write(dir.join(f), b"").unwrap();
        }
        let found = find(std::slice::from_ref(&dir), &COUNTRY).unwrap();
        assert!(found.ends_with("dbip-country-lite-2026-11.mmdb"), "the newest");
        assert!(find(std::slice::from_ref(&dir), &ASN).is_none());
        assert!(GeoDb::open(&[dir]).is_none(), "empty files aren't databases");
        assert!(!is_public("192.168.1.2".parse().unwrap()) && !is_public("fe80::1".parse().unwrap()));
        assert!(is_public("8.8.8.8".parse().unwrap()) && is_public("2001:4860::8888".parse().unwrap()));
    }

    /// With real databases (set NWL_GEOIP_DIR to a folder holding them).
    #[test]
    fn looks_up_with_real_databases() {
        let Some(dir) = std::env::var_os("NWL_GEOIP_DIR") else { return };
        let db = GeoDb::open(&[PathBuf::from(dir)]).expect("databases in NWL_GEOIP_DIR");
        let loc = db.lookup("8.8.8.8".parse().unwrap());
        assert_eq!(loc.country.as_deref(), Some("US"));
        assert_eq!(loc.asn, Some(15169));
        assert!(loc.org.unwrap().contains("Google"));
        assert_eq!(db.lookup("10.0.0.1".parse().unwrap()), Location::default());
    }
}
