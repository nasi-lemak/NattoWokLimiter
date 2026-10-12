//! End-to-end enforcement test against the real kernel.
//!
//! Needs root, nftables and cgroup v2, so it only runs with `NWL_E2E=1`:
//! `sudo -E NWL_E2E=1 cargo test -p nwl-platform --test linux_enforce`
//!
//! The test binary copies itself to a file named `nwl-e2e-client` and runs
//! that as the client, so rules can target the client application without
//! also matching the test process that runs the server.

use std::time::Duration;

const CLIENT_ENV: &str = "NWL_E2E_CLIENT";

fn main() {
    if let Ok(args) = std::env::var(CLIENT_ENV) {
        client(&args);
        return;
    }
    if std::env::var("NWL_E2E").as_deref() != Ok("1") {
        println!("linux_enforce: skipped (set NWL_E2E=1 and run as root)");
        return;
    }
    #[cfg(target_os = "linux")]
    e2e::run();
    #[cfg(not(target_os = "linux"))]
    println!("linux_enforce: skipped (not Linux)");
}

/// Client mode: `port,secs,warmup`. Waits so the enforcer can classify this
/// process, downloads for `warmup` seconds without counting (the kernel's
/// limiter starts with a full one-second bucket), then prints the bytes
/// received during the next `secs` seconds, or `error ...`.
fn client(args: &str) {
    use std::io::Read;
    use std::time::Instant;
    let parts: Vec<f64> = args.split(',').map(|p| p.parse().expect("numeric client arg")).collect();
    let (port, secs, warmup) = (parts[0] as u16, parts[1], parts[2]);
    std::thread::sleep(Duration::from_millis(700));
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let result = (|| -> std::io::Result<u64> {
        let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        s.set_read_timeout(Some(Duration::from_secs(2)))?;
        let start = Instant::now() + Duration::from_secs_f64(warmup);
        let end = start + Duration::from_secs_f64(secs);
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        while Instant::now() < end {
            let n = s.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if Instant::now() >= start {
                total += n as u64;
            }
        }
        Ok(total)
    })();
    match result {
        Ok(total) => println!("{total}"),
        Err(e) => println!("error {e}"),
    }
}

#[cfg(target_os = "linux")]
mod e2e {
    use super::*;

    const CLIENT_NAME: &str = "nwl-e2e-client";
    use nwl_core::model::Snapshot;
    use nwl_core::rules::{Rule, RuleSet};
    use nwl_platform::linux::LinuxEnforcer;
    use nwl_platform::{Enforcer, EnforcerOptions, Policy};
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;

    fn serve_forever() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let buf = vec![0u8; 64 * 1024];
                    while stream.write_all(&buf).is_ok() {}
                });
            }
        });
        port
    }

    fn client_binary() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nwl-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(CLIENT_NAME);
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        path
    }

    struct Harness {
        enforcer: LinuxEnforcer,
        client: PathBuf,
        port: u16,
    }

    impl Harness {
        fn run(&mut self, rules: &RuleSet, secs: f64, warmup: f64) -> String {
            let child = Command::new(&self.client)
                .env(CLIENT_ENV, format!("{},{secs},{warmup}", self.port))
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn client");
            thread::sleep(Duration::from_millis(200));
            let snap = Snapshot::default();
            let report =
                self.enforcer.apply(&Policy { rules, exhausted_quotas: &[], snapshot: &snap }).unwrap();
            assert!(report.warnings.is_empty(), "{:?}", report.warnings);
            let out = child.wait_with_output().unwrap();
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        }

        fn bytes(&mut self, rules: &RuleSet, secs: f64, warmup: f64) -> f64 {
            let out = self.run(rules, secs, warmup);
            out.parse().unwrap_or_else(|_| panic!("client failed: {out}"))
        }
    }

    fn rules(json: &str) -> RuleSet {
        RuleSet::new(vec![serde_json::from_str::<Rule>(json).unwrap()]).unwrap()
    }

    fn check(name: &str, ok: bool, detail: String) {
        println!("{} {name}: {detail}", if ok { "ok  " } else { "FAIL" });
        if !ok {
            std::process::exit(1);
        }
    }

    pub fn run() {
        let enforcer = LinuxEnforcer::new(EnforcerOptions { include_loopback: true })
            .expect("enforcer available (root, nft, cgroup v2)");
        let client = client_binary();
        let mut h = Harness { enforcer, client: client.clone(), port: serve_forever() };
        let none = RuleSet::default();
        let app =
            |action: &str| rules(&format!(r#"{{"match":{{"app":"{CLIENT_NAME}"}},"action":{action}}}"#));

        let free = h.bytes(&none, 1.0, 0.0);
        check("unthrottled", free > 20e6, format!("{free:.0} B in 1 s"));

        let secs = 3.0;
        let rate = h.bytes(&app(r#"{"type":"limit","download":"1MB/s"}"#), secs, 2.0) / secs;
        check("download limit 1 MB/s", (0.85e6..=1.15e6).contains(&rate), format!("{rate:.0} B/s"));

        let blocked = h.run(&app(r#"{"type":"block"}"#), 1.0, 0.0);
        check("block", blocked.starts_with("error"), blocked);

        h.enforcer.clear().unwrap();
        let after = h.bytes(&none, 1.0, 0.0);
        check("cleared", after > 20e6, format!("{after:.0} B in 1 s"));
        h.enforcer.clear().unwrap();

        let leftovers = nft_tables().contains("nattowok") || has_nwl_cgroups(Path::new("/sys/fs/cgroup"));
        check("no leftovers", !leftovers, "nft table and cgroups removed".into());
        let _ = std::fs::remove_dir_all(client.parent().unwrap());
    }

    fn nft_tables() -> String {
        let out = Command::new("nft").args(["list", "tables"]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn has_nwl_cgroups(dir: &Path) -> bool {
        std::fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            is_dir && (e.file_name().to_string_lossy().starts_with("nwl-") || has_nwl_cgroups(&e.path()))
        })
    }
}
