# Contributing to NattoWokLimiter

Thanks for helping! Bug reports, testing on your system (especially Windows), and code are all
welcome.

## Reporting problems

Open an issue with what you did, what you expected and what happened. Include:

* your OS and version (and on Linux, the kernel: `uname -r`);
* `nwl status` output, and the daemon's log (`journalctl -u nwld` on Linux,
  `%ProgramData%\NattoWokLimiter\nwld.log` on Windows);
* whether `nwld --demo` shows the same thing.

Security problems: please don't open a public issue; use GitHub's private vulnerability reporting
("Report a vulnerability" on the Security tab) instead.

## Building

Rust 1.95 or newer (`rustup update`). Then:

```sh
cargo build                    # nwld (daemon), nwl (CLI), nattowok (desktop app)
cargo run -p nwld -- --demo    # simulated apps and traffic: no root, nothing installed
cargo run -p nwl-gui           # the desktop app, against the daemon above
```

The web dashboard is the desktop app compiled to WebAssembly:

```sh
rustup target add wasm32-unknown-unknown
cargo xtask web --dev          # then rebuild nwld to embed it
```

## Before sending a pull request

Run what CI runs:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo clippy -p nwl-gui --target wasm32-unknown-unknown -- -D warnings
cargo test
```

Changes to the Windows backend can be checked from Linux with
`rustup target add x86_64-pc-windows-msvc` and
`cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings`. CI then builds and tests
them on Windows, including installing the service.

Tests that need root and a real kernel (eBPF counters, nftables enforcement, socket destroy, DNS
watching) are skipped unless run as root with `NWL_E2E=1`:

```sh
cargo test -p nwl-platform --no-run   # then run the printed test binaries with sudo NWL_E2E=1
```

## How the code is organized

See "How it works" in the README. In short:

* `crates/nwl-core`: the platform-independent model and logic (rules, accounting, quotas, history,
  DNS, network conditions, presets, API types). No I/O; most tests live here.
* `crates/nwl-platform`: what talks to the OS (Linux: sock_diag, eBPF, cgroups, nftables, DNS
  watching, NetworkManager; Windows: IP Helper, Windows Firewall, QoS, connection profiles).
* `crates/nwld`: the daemon (engine, HTTP API, storage).
* `crates/nwl`: the CLI. `crates/nwl-gui`: the desktop app and web dashboard; `src/app/` has one module
  per tab.

## Style

* Keep changes focused; one topic per pull request.
* Code comments say why, not what. User-facing text is plain and specific: "Can't reach the NattoWok
  service", not "Error: connection failure".
* New behavior comes with a test, in `nwl-core` where possible.
* When a backend can't do exactly what a rule asks, it reports a warning; it never silently does
  something else.

## License

NattoWokLimiter is GPL-3.0-or-later. By contributing you agree that your contribution is licensed
under the same terms.
