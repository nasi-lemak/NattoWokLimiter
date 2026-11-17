# NattoWok Limiter

**See which apps use your network, then control them.** NattoWok Limiter is a per-application network
monitor, firewall, bandwidth limiter and data-cap manager in the spirit of NetLimiter, NetBalancer
and GlassWire. The goal is to beat all three: it's open, scriptable, cross-platform, and honest
about what the OS can and can't do. Everything, from the kernel backends to the desktop app, is
written in Rust.

![NattoWok Limiter desktop app](docs/screenshot.png)

```
$ nwl top
total  down 2.28 MB/s  up 138.40 kB/s  (session 227.10 MB down, 14.20 MB up)

APP            DOWN          UP    SESSION  CONNS  POLICY   PATH
steam     1.00 MB/s  27.60 kB/s  175.00 MB      2  limited  /home/me/.steam/steam/ubuntu12_32/steam
firefox 906.00 kB/s  40.30 kB/s   14.00 MB      3           /usr/lib/firefox/firefox
spotify 236.00 kB/s   2.86 kB/s    5.09 MB      1           /usr/share/spotify/spotify
dropbox           -           -   28.10 MB      1  blocked  /home/me/.dropbox-dist/dropbox

$ nwl limit steam --down 1MB/s
$ nwl block dropbox
$ nwl block steam --days weekdays --from 09:00 --until 17:00
$ nwl quota spotify 2GB --per month
```

There are three front ends over the same daemon:

* **`nattowok`**, the native desktop app (Rust, egui): live traffic graph, per-app sparklines,
  one-click block and limit, a connection inspector with host names and RTT, a rules editor with
  schedules, data usage history and an event log.
* **The web dashboard**, served by the daemon at <http://127.0.0.1:7657>, with the same views and no
  install.
* **`nwl`**, the CLI, for scripts and terminals.

## What it does today

| Feature | Linux | Windows |
|---|---|---|
| Live per-app download/upload rates, session totals | ✅ every protocol incl. UDP/QUIC, exact per socket (eBPF; TCP-only fallback without root) | ✅ TCP (EStats, run as Administrator) |
| Traffic of short-lived sockets and processes (a 30 ms `getent`) still credited | ✅ eBPF | ❌ |
| Connection list: owner, state, rates, RTT, which rule applies | ✅ | ✅ (no RTT yet) |
| Block an app / network / port (in, out or both) | ✅ nftables | ✅ Windows Firewall |
| Bandwidth limits per app or network, download **and** upload | ✅ nftables policing | ⚠️ upload only (QoS policy) |
| Data quotas per day/week/month, warning at 80%, auto-block when reached | ✅ | ✅ |
| Schedules: rules active on chosen days and times (overnight windows too) | ✅ | ✅ |
| Host names of remote addresses (reverse DNS, cached, in the background) | ✅ | ✅ |
| "Who is this app talking to?": remote hosts per app with bytes, ports, protocols | ✅ | ✅ |
| Usage history per app per day (400 days) | ✅ | ✅ |
| "New app used the network" events | ✅ | ✅ |
| Traffic spike detection ("Dropbox is uploading at 8 MB/s, usually 12 kB/s") | ✅ | ✅ |
| Desktop notifications for new apps, spikes, quotas and enforcement problems, each switchable | ✅ | ✅ |
| Desktop app, web dashboard, REST API, live stream, CLI | ✅ | ✅ |

Rules are evaluated predictably (see [rules](#rules)), and when a backend can't express a rule exactly
it **reports a warning in the UI** instead of silently doing something else.

Status: early (v0.1). The Linux backend is tested end-to-end against a real kernel (see
`crates/nwl-platform/tests/linux_enforce.rs`: a 1 MB/s limit measures 1.00 MB/s steady state, block
and cleanup verified). The Windows backend compiles and its rule translation is unit tested, but it
hasn't been run on a Windows machine yet.

## Quick start

Requirements: Rust 1.80+. On Linux, enforcement needs root, `nft` (nftables) and cgroup v2, which any
current distribution has. Monitoring works without them.

```sh
cargo build --release

# Try it without touching your system: simulated apps that obey your rules.
./target/release/nwld --demo
./target/release/nattowok        # desktop app, or open http://127.0.0.1:7657

# Real system (Linux): monitor + enforce
sudo ./target/release/nwld
# Monitor only, never installs anything
./target/release/nwld --monitor-only
```

On Windows, run `nwld.exe` from an elevated prompt. Without elevation it still monitors connections,
but per-connection byte counters and enforcement need Administrator.

Install as a service on Linux: copy the binaries to `/usr/local/bin` and use
[`packaging/nwld.service`](packaging/nwld.service); [`packaging/nattowok.desktop`](packaging/nattowok.desktop) adds the desktop app to the application menu.

### CLI

```
nwl status                       daemon and enforcement status
nwl top [-w]                     apps by current traffic (-w to watch)
nwl conns [--app PATH] [-a]      sockets with owner, rates, RTT, policy
nwl rules                        rules in evaluation order
nwl block APP [--direction in|out|both]          [WHEN]
nwl limit APP [--down RATE] [--up RATE]          [WHEN]
nwl quota APP SIZE [--per day|week|month] [--direction in|out|both] [WHEN]
      WHEN: --days mon,tue,…|weekdays|weekends  --from HH:MM --until HH:MM
nwl add '<rule json>'            any rule, see below
nwl rm ID | enable ID | disable ID
nwl usage [--days N]             data used per app
nwl remotes [--app PATH] [-n N]  remote hosts by traffic, per app or overall
nwl events
```

Use `--json` for machine-readable output. `APP` is an executable name (`firefox`), a full path, or a glob
(`*/steam/*`). Rates accept `500kB/s`, `2MB/s`, `1.5MiB/s`, `20Mbit`, `10Mbps`; sizes accept `500MB`,
`20GB`, `1TiB`.

## Rules

Rules live in `rules.json` in the state directory (`/var/lib/nattowok` as root,
`~/.local/state/nattowok` otherwise, `%ProgramData%\NattoWokLimiter` on Windows). They are normally
managed through the UI, CLI or API.

```json
{
  "name": "Throttle Steam downloads",
  "enabled": true,
  "match": {
    "app": "steam",
    "protocol": "tcp",
    "remote": ["203.0.113.0/24", "2001:db8::/32"],
    "remote_ports": [443, "27000-27100"],
    "local_ports": [],
    "uid": 1000
  },
  "action": { "type": "limit", "download": "5MB/s", "upload": "1MB/s" },
  "schedule": { "days": ["mon", "tue", "wed", "thu", "fri"], "from": "09:00", "until": "17:00" }
}
```

Every `match` field is optional, and an empty match covers all traffic. Actions:

* `{"type": "allow"}` and `{"type": "block", "direction": "in" | "out" | "both"}` are **access rules**.
  They're checked top to bottom and the first match wins. No match means allow.
* `{"type": "limit", "download": RATE, "upload": RATE}` limits **always apply**, whatever the order and
  whatever access rule matched. Each limit is one shared budget for everything it matches, so several
  limits can stack (per app plus a global cap).
* `{"type": "quota", "limit": SIZE, "period": "day" | "week" | "month", "direction": ...}` counts the
  traffic it matches in local calendar periods. Once the cap is reached, that traffic is blocked until
  the next period.

A `schedule` makes a rule apply only inside a weekly window, in local time. Without `days` it applies
every day; without `from`/`until` it applies all day. A window that ends before it starts runs
overnight (`22:00`–`06:00`), and `days` then names the day it starts on. Outside its window a rule
behaves as if disabled: a scheduled quota doesn't count traffic and doesn't block.

Localhost traffic is never counted or policed unless the daemon runs with `--include-loopback`. It
never reaches your ISP, and throttling it breaks local apps.

## How it works

```
             ┌───────────── nwld (daemon) ──────────────┐
  kernel ──▶ │ Monitor ─▶ Snapshot ─▶ Engine ─▶ Enforcer │ ──▶ kernel
             │            accounting, quotas, usage,     │
             │            events, rule store             │
             │                 │                         │
             │      REST + SSE API, web dashboard        │
             └─────────────────┬─────────────────────────┘
                               │ http://127.0.0.1:7657
         nattowok (desktop) ───┼─── browser ─── nwl (CLI)
```

* **`nwl-core`**: platform-independent data model, rule engine with schedules, accounting (rates,
  totals, history), quotas, size/rate parsing, and the API types shared by the daemon and every
  client. No I/O.
* **`nwl-platform`**: the OS backends, each a `Monitor` (observe) plus an `Enforcer` (apply rules):
  * **Linux**: sockets come from `NETLINK_SOCK_DIAG`, owners from `/proc/<pid>/fd`. Bytes come from
    three tiny eBPF programs on the root cgroup: one records which process (pid and name) created
    each socket, two add every packet's length to that socket's counters, keyed by the socket cookie
    `sock_diag` also reports. That counts UDP/QUIC too, and still credits sockets (and processes)
    that are gone before the next sample. The programs are assembled in Rust and loaded with the raw
    `bpf()` syscall, so there's no eBPF toolchain, BTF or extra dependency. They only observe
    (always "allow"), and are BPF links, which the kernel removes when the daemon exits, even on a
    crash. Without root, or with `--no-ebpf`, `tcp_info` gives TCP-only counters. To enforce,
    processes of targeted apps move into a child cgroup *inside their current cgroup*, so systemd
    units and desktop scopes still own them. One atomic nftables table then matches those sockets with
    `socket cgroupv2` and drops or polices their packets, using shared named `limit` objects.
  * **Windows**: sockets come from `GetExtendedTcpTable`/`GetExtendedUdpTable`, bytes from TCP
    extended statistics, and totals from `GetIfTable2`. Rules become Windows Firewall rules and QoS
    policies, installed by one PowerShell script and grouped under `NattoWokLimiter`.
  * **Simulated**: demo apps and traffic that obey the installed rules, for trying things out and
    developing the UI.
* **`nwld`**: the daemon. It runs the sampling loop, persists state, resolves host names in the
  background, and serves the API and dashboard. When it stops, it removes everything it installed.
* **`nwl-gui`** (binary `nattowok`): the desktop app. It polls the API on a background thread, so the
  UI never waits on the network, and table rows hold still while the pointer is over them so buttons
  don't move under the cursor.
* **`nwl`**: the CLI.

The API listens on loopback only. It rejects requests whose `Host` isn't a loopback name (to stop DNS
rebinding), and state-changing requests must carry an `X-NWL-Client` header (to stop CSRF from web
pages).

### API

| Method | Path | |
|---|---|---|
| GET | `/api/status` | version, backends, enforcement warnings/errors |
| GET | `/api/overview` | system rates, apps, quotas: what the stream sends each tick |
| GET | `/api/apps` | apps with history |
| GET | `/api/connections?app=PATH` | sockets with rates and policy decision |
| GET | `/api/system/history` | recent system-wide samples |
| GET/POST | `/api/rules` | list / create |
| PUT/DELETE | `/api/rules/{id}` | replace / delete |
| POST | `/api/rules/{id}/move` | `{"index": n}` reorder |
| GET | `/api/quotas` | quota usage in the current period |
| GET | `/api/usage?days=N` | per-app bytes per day |
| GET | `/api/remotes?app=PATH&limit=N` | remote hosts by traffic this session, for one app or all |
| GET | `/api/events?after=ID` | event log |
| GET | `/api/stream` | Server-Sent Events, one `overview` per tick |

## Known limitations

* **Linux**: per-app counts of every protocol need root (eBPF). Without it they cover TCP only, and
  the UI says so. With eBPF, counted bytes are IP packet sizes (payload plus headers, including
  retransmissions), which is what an ISP meters; the TCP-only fallback counts payload. A new process
  of a limited app is classified within one tick (1 s by default). Limits police (drop
  above the rate) instead of queueing. That works well for TCP, but the first second of a transfer can
  exceed the limit, because the kernel's bucket holds one second of rate.
* **Windows**: no download limits yet (they need a packet driver). Windows Firewall applies block
  rules before allow rules, so an `allow` can't carve an exception out of a later `block`. Both cases
  show as warnings. Byte counters cover TCP only.
* **macOS**: not supported yet (`--demo` works).

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md). The big ones: enforcement in eBPF (instant classification,
true shaping and priorities), a Windows packet driver for download limits and UDP counts,
ask-on-first-connection firewall prompts, domain rules from DNS answers, network profiles, and a tray
icon for the desktop app.

## Development

```sh
cargo test                       # unit + API tests, no privileges needed
sudo -E NWL_E2E=1 cargo test -p nwl-platform --test linux_enforce      # real-kernel enforcement test
cargo clippy --all-targets
cargo clippy --all-targets --target x86_64-pc-windows-msvc            # check the Windows backend from Linux
cargo run -p nwld -- --demo      # daemon with simulated traffic
cargo run -p nwl-gui             # desktop app
```

The desktop app needs no system libraries to build. At runtime on Linux it uses the usual desktop
libraries (OpenGL, `libxkbcommon`, X11 or Wayland), which every desktop distribution ships.
```
