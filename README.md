# Citadel

Citadel is an outbound firewall for the Omarchy bar. Your apps sit inside the
walls. Whenever one tries to reach somewhere new, it waits **at the gate** for your verdict.
Everything you decide becomes a **policy** that Citadel enforces with nftables.

<p align="center">
  <img src="docs/screenshots/gate-card.png" width="440" alt="A connection waiting at the gate: python3.14 wants to reach 208.67.222.222 on port 443, with Block, Allow once and Always allow buttons">
</p>

## Install

### 1. Prerequisite for blocking: citadel-helper

Citadel watches and asks without any extra software. To actually **block**
traffic it needs **[citadel-helper](https://github.com/NeatOuk/citadel-helper)**,
a small root helper that turns your policies into nftables rules. **Citadel needs
citadel-helper 1.1.1 or newer** ([tag `v1.1.1`](https://github.com/NeatOuk/citadel-helper/releases/tag/v1.1.1)),
which only ever closes your own connections. Settings warns if an older helper
is installed. Build and install it once:

```bash
git clone https://github.com/NeatOuk/citadel-helper.git
cd citadel-helper && makepkg -si
```

An AUR package is coming later.

Its README explains what runs as root and why it is safe. You can install it
before or after the plugin; Citadel picks it up within a few seconds.

### 2. The plugin

```bash
omarchy plugin add https://github.com/NeatOuk/citadel.git --enable
```

Then open Citadel from the tower icon in the bar. Go to **Settings → Enforcement** and turn it on.

### Remove

```bash
omarchy plugin remove neat.citadel     # disables it (off the bar) and deletes the folder
sudo pacman -R citadel-helper          # if installed; switches enforcement off first
rm -rf ~/.local/share/citadel          # optional: your policies, history, feeds and GeoIP data
```

Citadel never edits your own configuration files. It only writes to `~/.local/share/citadel/`.

### Requirements

| Need | Package | Notes |
|---|---|---|
| Omarchy shell | Omarchy **4.x** | Settings warns on another major version |
| Watch process | `python` | standard library only |
| Connection list, cutting connections | `iproute2` | |
| Integrity check | `pacman` | Arch-based systems |
| Notifications, clipboard import/export | `libnotify`, `wl-clipboard` | part of Omarchy |
| Zone switching | `networkmanager` **or** `iwd` | wired links are detected either way; with neither, pick zones by hand |
| Countries | `python-maxminddb` | optional; the database downloads from Settings |
| Enforcement | [`citadel-helper`](https://github.com/NeatOuk/citadel-helper) (built with `makepkg`) → `nftables`, `polkit` | kernel with `nft_socket`, cgroup v2 and `INET_DIAG_DESTROY` (stock Arch has all three) |
| Password-free enforcement | membership in `wheel` | otherwise polkit asks for an admin password each time |

## At a glance

<img src="docs/screenshots/bar.png" height="32" alt="The Citadel tower in the Omarchy bar, with a badge for a waiting connection">

- **The tower** in the bar shows Citadel's state:
  - the gate door is closed while **Guarded**
  - the arch is empty while **Open**
  - portcullis bars are down in **Lockdown**
  - dim means *watching only*
  - a badge counts connections waiting at the gate
- **At the gate:** a card under the tower shows the app, its integrity, and where it wants to go (host, country, port).
  - Choose **Block**, **Allow once** or **Always allow**.
  - **Adjust** sets what the verdict covers: this port, this host or every host. It also sets how long it lasts: from now on, or until the app quits.
- **Modes:**
  - **Guarded** asks about new connections.
  - **Open** lets everything pass quietly, and logs it.
  - **Lockdown** blocks everything that isn't allowed.
  - Open and Lockdown can end on their own after 15 min or 1 h.
  - Right-click the tower for an hour of Open.

## The panel

<table>
  <tr>
    <td><img src="docs/screenshots/panel-gate.png" alt="Gate tab with one connection waiting for a verdict"></td>
    <td><img src="docs/screenshots/panel-traffic.png" alt="Traffic tab: live connections grouped by app with rates"></td>
  </tr>
  <tr>
    <td align="center"><b>Gate</b>: connections waiting for your verdict</td>
    <td align="center"><b>Traffic</b>: what is leaving right now, per app</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/panel-history.png" alt="History tab: last-hour traffic chart and top apps and hosts today"></td>
    <td><img src="docs/screenshots/panel-settings.png" alt="Settings tab: enforcement, Open and Lockdown timer, zones and gate behaviour"></td>
  </tr>
  <tr>
    <td align="center"><b>History</b>: the last hour, top apps, hosts and countries</td>
    <td align="center"><b>Settings</b>: enforcement, zones and how the gate behaves</td>
  </tr>
</table>

| Tab | What's there |
|---|---|
| **Gate** | Every connection waiting for a verdict. |
| **Traffic** | Live connections grouped by app: host, country, ports, bytes and rate in both directions, and why each one is allowed or blocked. Allow or Block an app, or a single destination. |
| **Policies** | Your policies. Each can cover an app, a host (domains include subdomains), an IP or CIDR, a port, or a combination. Scope them to a zone or to all zones. The most specific policy wins, and Block wins ties. Edit or remove them, or export and import through the clipboard. |
| | **Threat feeds:** IP feeds (FireHOL, Spamhaus DROP) go straight into the firewall. Domain feeds (StevenBlack, HaGeZi) block matching host names. LAN, loopback, Tailscale/CGNAT and multicast ranges are always removed from IP feeds. Feeds refresh daily. |
| **History** | Traffic over the last hour, top apps and hosts (today or 7 days), countries, and the log of verdicts. |
| **Settings** | Enforcement, the timer for Open and Lockdown, **zones** (link Wi-Fi or wired networks and Citadel switches as you move), what happens to an unanswered request, notifications, refresh rate, history retention, and the country database. |

**Who started it.** Tools like `curl`, `wget` or `git` are started by
something else, so Citadel shows the **launcher** too:
- `curl via omarchy-network-speedtest` for a script, or `claude in ghostty` when you started it in a terminal
- the command line, with passwords, tokens, `Authorization` headers and request bodies masked
- the full launch chain, under **Adjust**

At the gate, a verdict can cover the app **only when started by that
launcher**, so allowing curl for your speed test doesn't allow curl for everything.

**Short connections.** Many tool connections last less than a second, too short
to catch between two checks. With enforcement on and citadel-helper 1.2 or
newer, the helper logs each new connection from your apps to the kernel log
(rate-limited). Citadel reads it live and matches the connection to the process
that made it. Traffic shows these under **Just now**, each with a label saying
how sure the match is:
- **matched:** the command, or its launcher script, names that host
- **likely:** matched by timing
- **app unclear**

Only matched or likely connections are sent to the gate. The log lines are also
kept in your system journal like any kernel message. Turn this off under
**Settings → Catch short connections**.

**Integrity** stands in for code signing. Each program is checked against the sha256 that pacman recorded for its package. The levels are **verified**, **modified**, **not packaged** and **suspicious** (runs from `/tmp`, or deleted). If a program you allowed changes without a package update, it comes back to the gate.

## Enforcement

Watching and the gate work without root. To actually **drop** blocked traffic,
Citadel uses [citadel-helper](https://github.com/NeatOuk/citadel-helper). See
[Install](#install). Then switch **Settings → Enforcement** on. The helper provides:

- `/usr/lib/citadel/citadel-enforcer`: root-owned. It accepts only validated IPs, ports and cgroups inside your own user slice, and only touches `table inet citadel`.
- a polkit rule, so the active local `wheel` user can run exactly that helper without a password (anyone else is asked for an admin password)
- `citadel-restore.service`, which restores your policies at boot
- `citadel-off`, an emergency off switch for any terminal

Remove it with `sudo pacman -R citadel-helper`. That also switches enforcement off.

The helper's own [README](https://github.com/NeatOuk/citadel-helper#readme) covers its security model and commands.

Blocking is per app, not per address. nftables matches the app's own systemd scope (`socket cgroupv2`), so "block Chromium" stops Chromium while other apps can still reach the same server. Blocking a host also ends its live connections (`ss -K`).

What the firewall never touches:
- System services such as WARP, NetworkManager and DNS always pass.
- Established connections are only cut on purpose.

## Good to know

- **The first packet may leave.** Citadel sees a new connection within one refresh, and a moment before it answers the gate. Every later attempt follows your verdict.
- **Very short connections** are caught through the kernel log when *Catch short connections* is on (helper 1.2+). Without it they can slip between refreshes.
- **Command-line tools inside a terminal** share the terminal's scope, so their policies are enforced per destination within that scope. The policy is marked this way.
- **Blocking an interpreter** (e.g. `python3.14`) blocks every program running on it.
- **Host names come from reverse DNS.** CDNs may show their own names, and domain feeds only match names Citadel knows.

## Files

```
neat.citadel/
├── Panel.qml, CitadelIcon.qml   tower icon, gate card, panel + tabs
├── Service.qml                  state, policies, persistence, helper calls
├── Model.js                     matching, precedence, nft spec (tests/model.test.js)
├── views/                       Traffic, Policies, History, Settings, VerdictCard
├── docs/screenshots/            images used in this README
├── bin/citadel-monitor          python watch process (ss, /proc, rDNS, GeoIP, sqlite)
~/.local/share/citadel/          state.json, history.db, feeds, GeoIP, enforce spec
```

Run the logic tests with `node tests/model.test.js`.

## Third-party data

Citadel bundles no third-party data. It downloads these only when you ask:

| Data | Publisher | When |
|---|---|---|
| Country database | [DB-IP Lite](https://db-ip.com), CC BY 4.0 | Settings → Download |
| FireHOL Level 1 | [FireHOL](https://iplists.firehol.org/) | when you enable the feed |
| Spamhaus DROP | [Spamhaus](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | when you enable the feed |
| StevenBlack hosts | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | when you enable the feed |
| HaGeZi Light | [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) | when you enable the feed |

Each feed is published under its own license and terms of use; check them before relying on a feed.

## License

MIT, see [LICENSE](LICENSE).
