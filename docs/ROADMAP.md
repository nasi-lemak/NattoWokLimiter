# Roadmap

What it takes to be the best tool in this space, roughly in priority order. Each item says *why*, so
trade-offs stay visible.

## Accuracy and control

- **eBPF backend (Linux).** `cgroup_skb` programs at the root cgroup, keyed by socket cookie, would give:
  exact per-process bytes for UDP/QUIC (today only TCP is per-app), classification at socket creation
  (no one-tick window for new processes), and no cgroup moves at all. Keep the nftables backend as the
  fallback for kernels without BTF.
- **True shaping instead of policing.** EDT pacing (`skb->tstamp` plus the `fq` qdisc) from eBPF, or
  HTB plus IFB as a non-eBPF path. Queueing is smoother than dropping, especially for UDP and for
  limits below about 1 Mbit/s.
- **Priorities (NetBalancer-style).** Low, normal, high, or "only use idle bandwidth" per app. Needs
  shaping, and an estimate of link capacity measured from interface counters.
- **Windows packet path.** WinDivert or a WFP callout driver for download limits, per-connection
  limits, UDP accounting and allow-exceptions. Today Windows Firewall applies block rules before allow
  rules.
- **macOS backend.** A Network Extension (content filter) for monitoring and blocking, and `pf` with
  `dummynet` for limits.

## Firewall experience

- **Ask mode.** Hold the first connection of an unknown app and prompt "allow once / always / block"
  (GlassWire and OpenSnitch style). On Linux that's NFQUEUE or eBPF.
- **Hostnames.** Snoop DNS answers so the UI shows `api.example.com`, not just an IP, and rules can
  match domains (`*.doubleclick.net`).
- **GeoIP and ASN** for connection details and rules ("block this app outside my country").
- **Schedules and profiles.** Rules active on weekdays 9–17, or a "metered connection" profile that
  switches automatically per network (SSID or gateway MAC).
- **Per-connection actions** from the connection list: kill, block remote, limit.

## Insight

- **Alerts.** Bandwidth spikes, quota at 80%/100%, an app first seen, a changed binary hash. Delivered
  as desktop notifications and webhooks.
- **Long-term graphs.** Hourly resolution, per app and per remote, with CSV/JSON export.
- **"Who is this app talking to?"** Top remotes per app with bytes, ASN and country.
- **Binary identity.** Hash and code-signature checks so a rule for `firefox` doesn't follow a
  replaced binary.

## Product

- **Native desktop app and tray icon** (Tauri) over the same API, plus a live speed meter in the tray.
- **Remote management** with authentication (token or mTLS), and several machines in one dashboard.
- **Packages**: deb/rpm/AUR, MSI with a service installer, Homebrew.
- **Config import** from NetLimiter and GlassWire rule exports, where feasible.
