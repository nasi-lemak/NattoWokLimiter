//! Places processes of targeted applications into per-application cgroups so
//! nftables can match their sockets.
//!
//! Each managed cgroup is a child of the process's original cgroup, named
//! `nwl-<app>-<hash>`. Keeping it inside the original cgroup means systemd
//! units and desktop app scopes still own the process (stopping a unit still
//! kills it, resource limits still apply). Releasing moves processes back to
//! the parent and removes the child.

use super::nft::CgroupRef;
use super::procfs;
use crate::{app_scoped_rules, Error, Result};
use nwl_core::model::AppId;
use nwl_core::rules::{RuleId, RuleSet};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const PREFIX: &str = "nwl-";

pub struct CgroupManager {
    /// Where the cgroup2 hierarchy is mounted.
    mount: PathBuf,
    /// nftables resolves cgroup paths relative to `/sys/fs/cgroup`; on hybrid
    /// hierarchies cgroup2 lives at `/sys/fs/cgroup/unified`.
    nft_prefix: String,
    proc_root: PathBuf,
    /// cgroup paths (relative to the mount, starting with `/`) we created.
    managed: BTreeSet<String>,
}

impl CgroupManager {
    pub fn detect() -> Result<Self> {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| Error::io("read /proc/self/mountinfo", e))?;
        let mount = find_cgroup2_mount(&mountinfo)
            .ok_or_else(|| Error::Unsupported("cgroup v2 is not mounted; enforcement needs it".into()))?;
        Self::with_mount(mount, PathBuf::from("/proc"))
    }

    pub fn with_mount(mount: PathBuf, proc_root: PathBuf) -> Result<Self> {
        let nft_prefix = match mount.strip_prefix("/sys/fs/cgroup") {
            Ok(rel) if rel.as_os_str().is_empty() => String::new(),
            Ok(rel) => format!("{}/", rel.display()),
            Err(_) => {
                return Err(Error::Unsupported(format!(
                    "cgroup2 is mounted at {} but nftables only resolves paths under /sys/fs/cgroup",
                    mount.display()
                )))
            }
        };
        Ok(Self { mount, nft_prefix, proc_root, managed: BTreeSet::new() })
    }

    fn fs_path(&self, cg: &str) -> PathBuf {
        self.mount.join(cg.trim_start_matches('/'))
    }

    fn nft_ref(&self, cg: &str) -> CgroupRef {
        let rel = cg.trim_start_matches('/');
        CgroupRef {
            path: format!("{}{}", self.nft_prefix, rel),
            level: rel.split('/').filter(|c| !c.is_empty()).count(),
        }
    }

    fn move_pid(&self, pid: u32, cg: &str) -> io::Result<()> {
        fs::write(self.fs_path(cg).join("cgroup.procs"), pid.to_string())
    }

    /// Puts every process of every targeted app into its app cgroup, releases
    /// cgroups no longer needed, and returns the cgroups each rule applies to.
    pub fn sync(&mut self, rules: &RuleSet, warnings: &mut Vec<String>) -> BTreeMap<RuleId, Vec<CgroupRef>> {
        let scoped: Vec<_> = app_scoped_rules(rules).collect();
        if scoped.is_empty() && self.managed.is_empty() {
            return BTreeMap::new();
        }
        let mut used = BTreeSet::new();
        let mut per_rule: BTreeMap<RuleId, BTreeSet<String>> = BTreeMap::new();

        for pid in list_pids(&self.proc_root) {
            let Some(current) = read_cgroup(&self.proc_root, pid) else { continue };
            let (mut parent, in_ours) = split_managed(&current);
            // Without an exe it is a kernel thread or already gone.
            let process = if scoped.is_empty() {
                None
            } else {
                procfs::process_info(&self.proc_root, pid).filter(|p| p.exe.is_some())
            };
            let matched: Vec<RuleId> = process
                .as_ref()
                .map(|p| {
                    scoped
                        .iter()
                        .filter(|r| r.matcher.app.as_ref().is_some_and(|a| a.matches_process(p)))
                        .map(|r| r.id)
                        .collect()
                })
                .unwrap_or_default();
            let Some(app) = process.filter(|_| !matched.is_empty()).map(|p| p.app_id()) else {
                if in_ours {
                    let _ = self.move_pid(pid, &parent);
                }
                continue;
            };
            // cgroup paths end up inside the nftables script run as root, and
            // users can name cgroups in their delegated subtree freely, so
            // only well-formed paths are used; others fall back to the root.
            if !is_safe_cgroup_path(&parent) {
                parent = "/".to_string();
            }
            let desired = join_cg(&parent, &app_slug(&app));
            if current != desired {
                if let Err(e) =
                    fs::create_dir_all(self.fs_path(&desired)).and_then(|_| self.move_pid(pid, &desired))
                {
                    // ESRCH: exited meanwhile. Anything else is worth reporting.
                    if e.raw_os_error() != Some(libc::ESRCH) {
                        warnings.push(format!("cannot move pid {pid} ({app}) into {desired}: {e}"));
                    }
                    continue;
                }
            }
            self.managed.insert(desired.clone());
            used.insert(desired.clone());
            for id in matched {
                per_rule.entry(id).or_default().insert(desired.clone());
            }
        }

        let stale: Vec<String> = self.managed.difference(&used).cloned().collect();
        for cg in stale {
            self.release(&cg);
        }
        per_rule.into_iter().map(|(id, cgs)| (id, cgs.iter().map(|c| self.nft_ref(c)).collect())).collect()
    }

    /// Moves all processes of a managed cgroup back to its parent and removes it.
    fn release(&mut self, cg: &str) {
        let (parent, _) = split_managed(cg);
        if let Ok(procs) = fs::read_to_string(self.fs_path(cg).join("cgroup.procs")) {
            for pid in procs.lines().filter_map(|l| l.parse::<u32>().ok()) {
                let _ = self.move_pid(pid, &parent);
            }
        }
        if fs::remove_dir(self.fs_path(cg)).is_ok() || !self.fs_path(cg).exists() {
            self.managed.remove(cg);
        }
    }

    pub fn release_all(&mut self) {
        for cg in std::mem::take(&mut self.managed) {
            self.release(&cg);
        }
        self.release_stale();
    }

    /// Releases `nwl-*` cgroups left behind by a previous run.
    pub fn release_stale(&mut self) {
        let mut found = Vec::new();
        walk(&self.mount, "/", &mut found);
        for cg in found {
            self.release(&cg);
        }
    }
}

fn walk(mount: &Path, cg: &str, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(mount.join(cg.trim_start_matches('/'))) else { return };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let child = join_cg(cg, &name);
        if name.starts_with(PREFIX) {
            found.push(child);
        } else {
            walk(mount, &child, found);
        }
    }
}

/// Characters systemd and container runtimes use in cgroup names, minus
/// anything that could break out of an nftables string.
fn is_safe_cgroup_path(cg: &str) -> bool {
    cg.starts_with('/')
        && cg.len() < 512
        && cg.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-_.@:+".contains(&b))
}

fn join_cg(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Returns the parent of a managed cgroup, or the cgroup itself when it is
/// not one of ours, plus whether it was ours.
fn split_managed(cg: &str) -> (String, bool) {
    match cg.rsplit_once('/') {
        Some((parent, last)) if last.starts_with(PREFIX) => {
            (if parent.is_empty() { "/".to_string() } else { parent.to_string() }, true)
        }
        _ => (cg.to_string(), false),
    }
}

/// `nwl-<name>-<hash>`: readable in `systemd-cgls`, unique per executable.
pub fn app_slug(app: &AppId) -> String {
    let name: String = app
        .display_name()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(32)
        .collect();
    format!("{PREFIX}{name}-{:08x}", fnv1a(app.0.as_bytes()))
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ b as u32).wrapping_mul(0x0100_0193))
}

fn list_pids(proc_root: &Path) -> Vec<u32> {
    fs::read_dir(proc_root)
        .map(|it| it.flatten().filter_map(|e| e.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default()
}

/// The process's cgroup v2 path (the `0::` line of `/proc/<pid>/cgroup`).
fn read_cgroup(proc_root: &Path, pid: u32) -> Option<String> {
    let text = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    text.lines().find_map(|l| l.strip_prefix("0::")).map(|s| s.trim().to_string())
}

fn find_cgroup2_mount(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|line| {
        let (pre, post) = line.split_once(" - ")?;
        let fstype = post.split_whitespace().next()?;
        let mount_point = pre.split_whitespace().nth(4)?;
        (fstype == "cgroup2").then(|| PathBuf::from(mount_point))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_mounts() {
        let pure = "35 24 0:30 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2 cgroup2 rw\n";
        assert_eq!(find_cgroup2_mount(pure), Some(PathBuf::from("/sys/fs/cgroup")));
        let hybrid = "30 25 0:26 / /sys/fs/cgroup ro - tmpfs tmpfs ro\n\
                      31 30 0:27 / /sys/fs/cgroup/unified rw - cgroup2 cgroup2 rw\n";
        assert_eq!(find_cgroup2_mount(hybrid), Some(PathBuf::from("/sys/fs/cgroup/unified")));
        assert_eq!(find_cgroup2_mount("1 2 0:1 / / rw - ext4 /dev/sda rw\n"), None);
    }

    #[test]
    fn nft_refs() {
        let m = CgroupManager::with_mount("/sys/fs/cgroup".into(), "/proc".into()).unwrap();
        let r = m.nft_ref("/user.slice/app.scope/nwl-firefox-12345678");
        assert_eq!(r.path, "user.slice/app.scope/nwl-firefox-12345678");
        assert_eq!(r.level, 3);
        let h = CgroupManager::with_mount("/sys/fs/cgroup/unified".into(), "/proc".into()).unwrap();
        let r = h.nft_ref("/nwl-curl-1");
        assert_eq!((r.path.as_str(), r.level), ("unified/nwl-curl-1", 1));
        assert!(CgroupManager::with_mount("/cgroup2".into(), "/proc".into()).is_err());
    }

    #[test]
    fn managed_paths() {
        assert_eq!(split_managed("/a/b/nwl-x-1"), ("/a/b".to_string(), true));
        assert_eq!(split_managed("/nwl-x-1"), ("/".to_string(), true));
        assert_eq!(split_managed("/a/b"), ("/a/b".to_string(), false));
        assert_eq!(join_cg("/", "nwl-x"), "/nwl-x");
        assert_eq!(join_cg("/a", "nwl-x"), "/a/nwl-x");
    }

    #[test]
    fn rejects_unsafe_cgroup_paths() {
        assert!(is_safe_cgroup_path(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal-12.scope"
        ));
        assert!(is_safe_cgroup_path("/"));
        assert!(!is_safe_cgroup_path(r#"/user.slice/x" accept comment ""#));
        assert!(!is_safe_cgroup_path(r"/user.slice/app\x2dfoo.scope"));
        assert!(!is_safe_cgroup_path("/a b"));
        assert!(!is_safe_cgroup_path("relative"));
    }

    #[test]
    fn slugs_are_safe_and_distinct() {
        let a = app_slug(&AppId("/usr/bin/my app!".into()));
        assert!(a.starts_with("nwl-my_app_-"), "{a}");
        assert_ne!(a, app_slug(&AppId("/opt/my app!".into())));
    }
}
