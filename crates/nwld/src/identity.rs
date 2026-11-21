//! Program fingerprints: the SHA-256 of each app's executable, so a changed
//! program (an update, or a replaced binary) is noticed.
//!
//! Hashing a large executable takes a moment, so it happens on a worker
//! thread; the engine asks for checks and picks up results each tick. A file
//! is only hashed again when its size or modification time changed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Lowercase hex.
    pub sha256: String,
    pub size: u64,
    /// Modification time, unix seconds.
    pub modified: i64,
    /// When this fingerprint was first seen for the app, unix seconds.
    #[serde(default)]
    pub since: i64,
}

/// File size and modification time: what decides whether to hash again.
fn stat(path: &Path) -> Option<(u64, i64)> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some((meta.len(), modified))
}

pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Hashes executables on a worker thread.
pub struct Hasher {
    requests: Sender<PathBuf>,
    results: Receiver<(PathBuf, Fingerprint)>,
}

impl Hasher {
    /// `known` seeds the cache (fingerprints from the last run), so
    /// unchanged files aren't hashed again after a restart.
    pub fn new(known: HashMap<PathBuf, Fingerprint>) -> Self {
        let (requests, rx) = mpsc::channel::<PathBuf>();
        let (tx, results) = mpsc::channel();
        std::thread::Builder::new()
            .name("fingerprints".into())
            .spawn(move || {
                let mut cache = known;
                for path in rx {
                    let Some((size, modified)) = stat(&path) else { continue };
                    if let Some(fp) = cache.get(&path).filter(|f| (f.size, f.modified) == (size, modified)) {
                        let _ = tx.send((path, fp.clone()));
                        continue;
                    }
                    let Ok(sha256) = hash_file(&path) else { continue };
                    let fp = Fingerprint { sha256, size, modified, since: chrono::Utc::now().timestamp() };
                    cache.insert(path.clone(), fp.clone());
                    if tx.send((path, fp)).is_err() {
                        return;
                    }
                }
            })
            .expect("spawn fingerprint thread");
        Self { requests, results }
    }

    /// Asks for a (re)check of a file; the answer comes from [`Hasher::results`].
    pub fn check(&self, path: PathBuf) {
        let _ = self.requests.send(path);
    }

    pub fn results(&self) -> Vec<(PathBuf, Fingerprint)> {
        self.results.try_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn hashes_and_rehashes_on_change() {
        let dir = std::env::temp_dir().join(format!("nwld-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("prog");
        std::fs::write(&file, b"hello").unwrap();
        assert_eq!(
            hash_file(&file).unwrap(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );

        let hasher = Hasher::new(HashMap::new());
        let wait = || {
            for _ in 0..100 {
                let r = hasher.results();
                if !r.is_empty() {
                    return r;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("no result")
        };
        hasher.check(file.clone());
        let first = wait();
        assert_eq!(first[0].1.size, 5);
        std::fs::write(&file, b"hello, world").unwrap();
        hasher.check(file.clone());
        let second = wait();
        assert_ne!(second[0].1.sha256, first[0].1.sha256, "a changed file is hashed again");
        hasher.check(dir.join("missing"));
        std::thread::sleep(Duration::from_millis(50));
        assert!(hasher.results().is_empty(), "missing files are skipped");
    }
}
