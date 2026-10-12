//! `/proc` helpers: socket ownership, process identity, interface counters.

use nwl_core::model::{InterfaceCounters, ProcessInfo};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Maps socket inodes to the pid of a process holding them.
///
/// Only inodes in `wanted` are recorded, and the scan stops early once all of
/// them are found. When a socket is shared (after `fork`), the first pid found
/// wins; for accounting purposes they are the same application anyway.
pub fn socket_owners(proc_root: &Path, wanted: &HashSet<u32>) -> HashMap<u32, u32> {
    let mut owners = HashMap::with_capacity(wanted.len());
    if wanted.is_empty() {
        return owners;
    }
    let Ok(entries) = fs::read_dir(proc_root) else { return owners };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else { continue };
            if let Some(inode) = parse_socket_link(&target) {
                if wanted.contains(&inode) {
                    owners.entry(inode).or_insert(pid);
                }
            }
        }
        if owners.len() == wanted.len() {
            break;
        }
    }
    owners
}

/// Parses `socket:[12345]`.
fn parse_socket_link(target: &Path) -> Option<u32> {
    let s = target.to_str()?;
    s.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

pub fn process_info(proc_root: &Path, pid: u32) -> Option<ProcessInfo> {
    let dir = proc_root.join(pid.to_string());
    let meta = fs::metadata(&dir).ok()?;
    let name = fs::read_to_string(dir.join("comm"))
        .map(|s| s.trim_end().to_string())
        .unwrap_or_else(|_| pid.to_string());
    let exe = fs::read_link(dir.join("exe")).ok().map(clean_exe);
    Some(ProcessInfo { pid, name, exe, uid: Some(meta.uid()) })
}

/// The kernel appends " (deleted)" when the binary was replaced, as happens
/// during package upgrades; the app is still the same.
fn clean_exe(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_suffix(" (deleted)")) {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

/// Parses `/proc/net/dev`.
pub fn interface_counters(proc_root: &Path) -> Vec<InterfaceCounters> {
    fs::read_to_string(proc_root.join("net/dev")).map(|s| parse_net_dev(&s)).unwrap_or_default()
}

fn parse_net_dev(text: &str) -> Vec<InterfaceCounters> {
    text.lines()
        .skip(2)
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let fields: Vec<u64> = rest.split_whitespace().filter_map(|f| f.parse().ok()).collect();
            // rx: bytes packets errs drop fifo frame compressed multicast | tx: bytes ...
            Some(InterfaceCounters {
                name: name.trim().to_string(),
                rx_bytes: *fields.first()?,
                tx_bytes: *fields.get(8)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_net_dev() {
        let text = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
  eth0: 9876543   5000    0    0    0     0          0         0  1234567    4000    0    0    0     0       0          0
";
        let ifaces = parse_net_dev(text);
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[1].name, "eth0");
        assert_eq!((ifaces[1].rx_bytes, ifaces[1].tx_bytes), (9_876_543, 1_234_567));
    }

    #[test]
    fn socket_links() {
        assert_eq!(parse_socket_link(Path::new("socket:[4242]")), Some(4242));
        assert_eq!(parse_socket_link(Path::new("/dev/null")), None);
        assert_eq!(parse_socket_link(Path::new("anon_inode:[eventfd]")), None);
    }

    #[test]
    fn strips_deleted_suffix() {
        assert_eq!(clean_exe("/usr/bin/foo (deleted)".into()), PathBuf::from("/usr/bin/foo"));
    }

    #[test]
    fn finds_own_process() {
        let me = process_info(Path::new("/proc"), std::process::id()).unwrap();
        assert!(me.exe.is_some());
    }
}
