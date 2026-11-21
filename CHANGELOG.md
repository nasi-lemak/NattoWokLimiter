# Changelog

## 0.1.0 (unreleased)

The first release. NattoWok Limiter shows which apps use the network and blocks, limits and caps them,
on Linux and Windows, from a desktop app, a web dashboard, a CLI or a REST API.

### Seeing traffic

- Live download and upload per app and per connection, with a two-minute graph and sparklines.
  Linux counts every protocol exactly per socket with eBPF (TCP-only without root); Windows counts
  TCP per connection.
- Apps shown with their own name and icon (Linux `.desktop` entries; Windows version info and icon),
  grouped per program, with a SHA-256 fingerprint of the program and an alert when it changes.
- Connections show the domain the app looked up (from DNS answers on Linux), reverse DNS, and, with a
  free GeoLite2 or DB-IP Lite database, the country and network owner.
- "Who does this app talk to": remote hosts per app with bytes, ports and protocols.
- History from the last hour to the last 90 days, per app or overall, with CSV export; usage per
  app per day for 400 days.
- Events and desktop notifications for new apps, traffic spikes, quotas at 80% and used up, changed
  programs, network changes and enforcement problems (with Block / Limit buttons on Linux).

### Controlling it

- Block, allow, limit (download and upload on Linux, upload on Windows) and data quotas per day, week
  or month, for apps, remote networks, domains, ports and protocols; first matching access rule wins,
  limits and quotas always apply.
- Rules that apply on a schedule, only on metered networks (phone hotspots, mobile data) or on named
  networks; mark any network metered.
- Ask before new apps use the network: held until you choose Allow, Allow this time or Block.
- Close a connection, or block its host or domain, from the connection list.
- Presets: Hotspot saver, Calm background downloads, Focus hours.
- Pause all rules; edit rules in place; undo deletes; backup and restore of rules.

### The app

- Desktop app (Linux and Windows) with tray icon and speed meter, tray quick actions, start with
  login, seven color themes (all contrast-checked) or the system's light/dark setting.
- The same app as a web dashboard in the browser, served by the daemon.
- `nwl` command line tool for everything, with JSON output.

### Installing

- Linux: .deb and .rpm packages with a systemd service.
- Windows: an installer that sets up the background service, Start menu entries and uninstall.
- Licensed GPL-3.0-or-later.

### Known limitations

- macOS: not supported yet (the demo runs).
- Windows: download limits need a kernel driver (not yet); per-app UDP traffic isn't counted;
  domain names come from direct lookups of rule domains only.
- New apps are noticed within a second, so their first packets can pass before "ask" holds them.
- Encrypted DNS (DNS over HTTPS) hides domain names.
