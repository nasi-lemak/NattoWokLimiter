//! End-to-end enforcement test against the real kernel.
//!
//! Needs root, nftables and cgroup v2, so it is ignored by default:
//! `sudo -E cargo test -p nwl-platform --test linux_enforce -- --ignored --test-threads=1`
#![cfg(target_os = "linux")]

use nwl_core::model::Snapshot;
use nwl_core::rules::{Rule, RuleSet};
use nwl_platform::linux::LinuxEnforcer;
use nwl_platform::{Enforcer, EnforcerOptions, Policy};
use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Python client: waits so the enforcer can classify it, downloads for
/// `warmup` seconds without counting (the kernel's limiter starts with a full
/// one-second bucket), then prints the bytes received in the next `secs`
/// seconds (or "error").
const CLIENT: &str = r#"
import socket, sys, time
port, secs, warmup = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
time.sleep(0.7)
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    s.settimeout(2)
    total, start = 0, time.time() + warmup
    end = start + secs
    while time.time() < end:
        chunk = s.recv(65536)
        if not chunk:
            break
        if time.time() >= start:
            total += len(chunk)
    print(total)
except Exception as e:
    print("error", e)
"#;

fn serve_forever() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut stream = stream;
                let buf = vec![0u8; 64 * 1024];
                while stream.write_all(&buf).is_ok() {}
            });
        }
    });
    port
}

fn run_client(enforcer: &mut LinuxEnforcer, rules: &RuleSet, port: u16, secs: f64, warmup: f64) -> String {
    let child = Command::new("python3")
        .args(["-c", CLIENT, &port.to_string(), &secs.to_string(), &warmup.to_string()])
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 available");
    thread::sleep(Duration::from_millis(200));
    let snap = Snapshot::default();
    let report = enforcer.apply(&Policy { rules, exhausted_quotas: &[], snapshot: &snap }).unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn rules(json: &str) -> RuleSet {
    RuleSet::new(vec![serde_json::from_str::<Rule>(json).unwrap()]).unwrap()
}

#[test]
#[ignore = "needs root, nftables and cgroup v2"]
fn limits_and_blocks_an_application() {
    let port = serve_forever();
    let mut enforcer =
        LinuxEnforcer::new(EnforcerOptions { include_loopback: true }).expect("enforcer available");

    let none = RuleSet::default();
    let free: f64 = run_client(&mut enforcer, &none, port, 1.0, 0.0).parse().unwrap();
    assert!(free > 20e6, "unthrottled loopback should be fast, got {free}");

    let limit = rules(r#"{"match":{"app":"python3*"},"action":{"type":"limit","download":"1MB/s"}}"#);
    let secs = 3.0;
    let limited: f64 = run_client(&mut enforcer, &limit, port, secs, 2.0).parse().unwrap();
    let rate = limited / secs;
    eprintln!("limited rate: {rate:.0} B/s");
    assert!((0.85e6..=1.15e6).contains(&rate), "expected ~1 MB/s, got {rate:.0} B/s");

    let block = rules(r#"{"match":{"app":"python3*"},"action":{"type":"block"}}"#);
    let blocked = run_client(&mut enforcer, &block, port, 1.0, 0.0);
    assert!(blocked.starts_with("error"), "expected connection failure, got {blocked}");

    enforcer.clear().unwrap();
    let after: f64 = run_client(&mut enforcer, &none, port, 1.0, 0.0).parse().unwrap();
    assert!(after > 20e6, "rules removed, got {after}");
    enforcer.clear().unwrap();
}
