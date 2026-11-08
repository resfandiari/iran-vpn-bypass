# IranBypass — Iranian sites outside the VPN, from the macOS menu bar

A small menu bar app for macOS: while **any** IP-layer VPN is running (ExpressVPN, WireGuard,
OpenVPN/Tunnelblick, Proton, Mullvad, Nord, V2Ray/Clash/sing-box in TUN mode, …), traffic to
**Iranian sites is routed directly through your ISP** so local sites work normally — banking,
government portals, .ir services — while everything else keeps going through the tunnel.

Toggled with a single switch from the menu bar. After a one-time setup it never asks for your
password again.

IP ranges come from [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules)
(the `geoip:ir` category, ~2100 aggregated IPv4 ranges, auto-refreshed weekly).

## How it works

```
            ┌──────────────┐   default route (VPN tunnel)
 traffic ───┤              ├──────────────►  VPN  ──►  internet
            │  macOS kernel│
            │              │   2100 specific routes (longest-prefix match wins)
            └──────┬───────┴──────────────►  ISP  ──►  Iranian sites ✓
                   │ en0 / physical gateway
```

1. Downloads `geoip.dat` from the [Iran-v2ray-rules releases](https://github.com/Chocolate4U/Iran-v2ray-rules/releases)
   and extracts every Iranian IPv4 CIDR (parsed from the v2ray protobuf format — no external tools).
2. Detects your **local (non-VPN) gateway** from the routing table, skipping all tunnel
   interfaces (`utun*`, `tun*`, `tap*`, `wg*`, `zt*`, `ipsec*`, `ppp*`, …), with a
   `SystemConfiguration` fallback for clients that remove the physical default route.
3. Adds a static IPv4 route per Iranian range **via the local gateway**. Specific routes always
   beat the VPN's default route, so Iranian IPs exit through your ISP and everything else stays
   in the tunnel. Removing the bypass deletes exactly the routes it added.
4. Watches for network/VPN changes and **re-applies automatically** if your gateway changes or
   the VPN client flushes the routing table on reconnect.

This mechanism is VPN-agnostic — it never talks to the VPN client, it only relies on the
standard "default route through the tunnel" behavior.

## VPN compatibility

| VPN type | Works? |
|---|---|
| ExpressVPN, NordVPN, Surfshark, Proton, Mullvad, … | ✅ |
| WireGuard, OpenVPN / Tunnelblick, native L2TP/IPsec | ✅ |
| V2Ray / v2rayN / V2Box / Clash / sing-box / Streisand **in TUN mode** | ✅ |
| Tailscale, ZeroTier, similar mesh VPNs | ✅ |
| Proxy-only setups (ClashX *system proxy without TUN*, manual PAC/SOCKS in browser) | ➖ Not applicable — no IP-layer tunnel exists; use the proxy app's own `geosite:ir` rules instead |

**Kill switches block the bypass.** Any "block traffic outside the tunnel" feature must be
turned OFF: ExpressVPN **Network Lock**, Proton **Kill Switch**, Mullvad **Lockdown mode**,
WireGuard **Kill Switch**, etc. (DNS queries still go through the tunnel — that's fine: Iranian
domains resolve to Iranian IPs, which are then routed directly.)

## Requirements

- macOS 13 (Ventura) or newer, Apple Silicon or Intel
- Xcode Command Line Tools (`swiftc`) to build
- An admin account (for the one-time helper installation)

## Build & run

```bash
./build.sh
open dist/IranBypass.app
```

- Drag `dist/IranBypass.app` to `/Applications` (optional) and add it to
  **System Settings → General → Login Items** so it restores the bypass after reboot.
- Click the shield icon in the menu bar and flip the switch:
  - **On (first time only)**: macOS asks for your admin password **once** to install a tiny
    password-free helper — `/usr/local/libexec/iranbypass-helper` plus `/etc/sudoers.d/iranbypass`
    (a rule allowing `%admin` to run *only that helper* without a password).
  - **On / Off after that**: instant, no prompts (`sudo -n`).

The IP list is cached in `~/Library/Application Support/IranBypass/` and refreshes
automatically when older than 7 days (or via the *Update IP list* button).

## Security & privacy

- No telemetry, no analytics; the only network request is the `geoip.dat` download from GitHub.
- The privileged helper is a root-owned, fixed-function script: it can only add/delete the
  IPv4 routes listed in the routes file passed to it. It accepts no arbitrary commands and
  exposes nothing else. Remove it anytime:
  `sudo rm /usr/local/libexec/iranbypass-helper /etc/sudoers.d/iranbypass`
- Routes live in the kernel routing table only — nothing is installed system-wide besides the helper.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Iranian sites still fail with bypass ON | Turn off your VPN's kill switch (Network Lock / Kill Switch / Lockdown) |
| Bypass stopped working after VPN reconnect | Should self-heal within seconds; if not, toggle off & on |
| Switched Wi-Fi networks | Handled automatically; toggle off & on if not |
| After reboot | Routes are restored automatically when the app launches (add it to Login Items); otherwise just toggle on |
| Some Iranian sites still go through the VPN | They may be hosted on foreign CDNs (Cloudflare, …) — nothing to bypass |

Known limitations: IPv6 traffic is not routed (Iranian sites are effectively IPv4); DNS queries
keep using the VPN's DNS.

## CLI (for testing)

```bash
dist/IranBypass.app/Contents/MacOS/IranBypass --gateway       # print detected local gateway
dist/IranBypass.app/Contents/MacOS/IranBypass --update-list   # download + parse geoip:ir
dist/IranBypass.app/Contents/MacOS/IranBypass --categories    # list categories inside geoip.dat
```

## Uninstall

Toggle the bypass off, quit the app, delete it, then optionally:

```bash
sudo rm /usr/local/libexec/iranbypass-helper /etc/sudoers.d/iranbypass
rm -rf ~/Library/Application\ Support/IranBypass
```

## Credits & license

- Code: MIT — see [LICENSE](LICENSE)
- IP data: [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules) (GPL-3.0), downloaded at runtime from their releases
