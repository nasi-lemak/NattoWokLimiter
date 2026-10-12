# Roadmap

What it takes to be the best tool in this space, roughly in priority order. Each item says *why*, so
trade-offs stay visible.

## Accuracy and control

- **eBPF enforcement (Linux).** Counting is done in eBPF already (every protocol, per socket,
  including short-lived sockets). Next, enforce there too: the same `cgroup_skb` programs can drop
  and police by socket owner, with the verdict decided at socket creation. That removes the
  one-tick window for new processes and the cgroup moves, and makes per-connection rules possible.
  Keep nftables as the fallback for older kernels.
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
- **Domain names from DNS answers.** Reverse DNS is done (the UI shows PTR names), but PTR names are
  often CDN hosts. Snooping the app's own DNS answers would show the name it actually asked for
  (`api.example.com`), and would let rules match domains (`*.doubleclick.net`).
- **GeoIP and ASN** for connection details and rules ("block this app outside my country").
- **Profiles.** Schedules are done (rules active on chosen days and times). Next: rule sets that
  switch automatically per network, e.g. a "metered connection" profile keyed by SSID or gateway MAC.
- **Per-connection actions** from the connection list: kill, block remote, limit.

## Insight

- **Alerts.** Quota at 80% and 100% and "app first seen" are events today. Add bandwidth spikes and
  changed binary hashes, delivered as desktop notifications and webhooks.
- **Long-term graphs.** Hourly resolution, per app and per remote, with CSV/JSON export.
- **"Who is this app talking to?"** Top remotes per app with bytes, ASN and country.
- **Binary identity.** Hash and code-signature checks so a rule for `firefox` doesn't follow a
  replaced binary.

## Product

- **Tray icon** for the desktop app (done: `nattowok`, native Rust/egui), with a live speed meter and
  quick block/limit, plus desktop notifications for events.
- **Remote management** with authentication (token or mTLS), and several machines in one dashboard.
- **Packages**: deb/rpm/AUR, MSI with a service installer, Homebrew.
- **Config import** from NetLimiter and GlassWire rule exports, where feasible.
