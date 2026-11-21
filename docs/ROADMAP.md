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
- **Profiles.** Schedules and network conditions are done (rules for metered networks or named
  networks, with detection via NetworkManager and Windows connection cost). Next: detection without
  NetworkManager (systemd-networkd, gateway MAC), and a mobile-data budget across all apps.
- **Per-connection actions** from the connection list: kill, block remote, limit.

## Insight

- **More alerts.** Desktop notifications are done (new apps, traffic spikes, quota at 80% and 100%,
  enforcement problems). Next: changed binary hashes, per-app spike sensitivity, and webhooks.
- **Long-term graphs.** Traffic history is done (whole machine or per app, minute points for a day
  and hourly points for 90 days, CSV export). Next: history per remote host, and longer retention.
- **ASN and country for remote hosts.** "Who is this app talking to?" is done (hosts per app with
  bytes, ports and protocols). Next: ASN and country, and keeping it across restarts.
- **Binary identity.** Hash and code-signature checks so a rule for `firefox` doesn't follow a
  replaced binary.

## Product

- **Notification buttons on Windows and macOS.** Tray quick actions and notification buttons are done
  on Linux; Windows toasts and macOS notifications show without buttons for now.
- **Web dashboard extras.** The dashboard is the desktop app compiled to WebAssembly. Next: browser
  notifications, and a smaller download.
- **App identity on Windows and macOS.** Names and icons come from `.desktop` entries on Linux. Next:
  the executable's version info and icon on Windows, `Info.plist` on macOS, and grouping helper
  processes (browser and launcher helpers) under their app.
- **Remote management** with authentication (token or mTLS), and several machines in one dashboard.
- **Packages.** deb and rpm are done (built by CI, attached to releases). Next: AUR, an MSI with a
  service installer, Homebrew.
- **Config import** from NetLimiter and GlassWire rule exports, where feasible.
