# IranBypass — Iranian sites outside the VPN, from the macOS menu bar

A small menu bar app for macOS: while **any** IP-layer VPN is running (ExpressVPN, WireGuard,
OpenVPN/Tunnelblick, Proton, Mullvad, Nord, V2Ray/Clash/sing-box in TUN mode, …), traffic to
**Iranian sites is routed directly through your ISP** so local sites work normally — banking,
government portals, .ir services — while everything else keeps going through the tunnel.

Toggled with a single switch from the menu bar. After a one-time setup it never asks for your
password again.

Two data sources are combined:

1. **Iranian IP ranges** from [Chocolate4U/Iran-v2ray-rules](https://github.com/Chocolate4U/Iran-v2ray-rules)
   (the `geoip:ir` category, ~2100 aggregated IPv4 ranges, auto-refreshed weekly).
2. **Iranian websites** (the `geosite:category-ir` domain list, ~42 000 domains) that are
   resolved to IPv4 addresses and routed the same way. This catches Iranian sites hosted
   *outside* Iran (foreign CDNs, `.com`/`.net` domains, …) that the IP list alone misses.

You can also **add your own websites** in the menu bar window — type a domain, hit *Add*, and
it is resolved and bypassed immediately.

## How it works

```
            ┌──────────────┐   default route (VPN tunnel)
 traffic ───┤              ├──────────────►  VPN  ──►  internet
            │  macOS kernel│
            │              │   Iranian routes (longest-prefix match wins)
            └──────┬───────┴──────────────►  ISP  ──►  Iranian sites ✓
                   │ en0 / physical gateway
```

1. Downloads `geoip.dat` from the [Iran-v2ray-rules releases](https://github.com/Chocolate4U/Iran-v2ray-rules/releases)
   and extracts every Iranian IPv4 CIDR (parsed from the v2ray protobuf format — no external tools).
2. Downloads `geosite.dat` from the same release, extracts the `category-ir` domain list
   (the `geoip.dat` parser is reused for the protobuf format), and resolves each domain to its
   IPv4 addresses. IPs already covered by the Iranian ranges are dropped, so the extra routes
   are exactly the ones the IP list misses.
3. Detects your **local (non-VPN) gateway** from the routing table, skipping all tunnel
   interfaces (`utun*`, `tun*`, `tap*`, `wg*`, `zt*`, `ipsec*`, `ppp*`, …), with a
   `SystemConfiguration` fallback for clients that remove the physical default route.
4. Adds a static IPv4 route per range/website-IP **via the local gateway**. Specific routes always
   beat the VPN's default route, so Iranian IPs exit through your ISP and everything else stays
   in the tunnel. Removing the bypass deletes exactly the routes it added.
5. Watches for network/VPN changes and **re-applies automatically** if your gateway changes, your
   interface's IPv4 address changes (e.g. a new DHCP lease, which otherwise leaves the routes with
   a stale source address), or the VPN client flushes the routing table on reconnect. Re-applying
   deletes each route before re-adding it — `route add` alone does not refresh an existing entry.

The applied routes are recorded in `applied-routes.txt`, and the interface name + address they were
created with in `applied-meta.txt`, both under `~/Library/Application Support/IranBypass/`.

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
cp -R dist/IranBypass.app /Applications/   # optional — keeps it with your other apps
open /Applications/IranBypass.app          # or: open dist/IranBypass.app
```

- Add it to **System Settings → General → Login Items** so it restores the bypass after reboot.
- Click the shield icon in the menu bar and flip the switch:
  - **On (first time only)**: macOS asks for your admin password **once** to install a tiny
    password-free helper — `/usr/local/libexec/iranbypass-helper` plus `/etc/sudoers.d/iranbypass`
    (a rule allowing `%admin` to run *only that helper* without a password).
  - **On / Off after that**: instant, no prompts (`sudo -n`).
- **Bypass extra websites**: type a domain and press *Add* to route it outside the VPN even if it
  isn't in the automatic list. Added domains are listed right below the field (with a count) and
  each one has a trash button to remove it; removal re-applies the routes immediately.

The IP list and the website list are cached in `~/Library/Application Support/IranBypass/`
(`iran-ipv4.txt`, `iran-domains.txt`, `website-ipv4.txt`, plus `custom-domains.txt` for the sites
you add) and refresh automatically when older than 7 days (or via the *Update IP list* /
*Update websites* buttons). The first *Update websites* resolves ~42 000 domains and can take a
couple of minutes; it runs in the background and the bypass keeps working while it does.

## Security & privacy

- No telemetry, no analytics; the only network requests are the `geoip.dat`/`geosite.dat`
  downloads from GitHub and the DNS lookups used to resolve the website list.
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
| Iranian sites fail right after the router gives a new DHCP address | Handled automatically: the routes are re-created with the new source address; toggle off & on if not |
| After reboot | Routes are restored automatically when the app launches (add it to Login Items); otherwise just toggle on |
| Some Iranian sites still go through the VPN | Press *Update websites*; if it persists, add the domain under *Bypass extra websites* |
| Two shield icons in the menu bar | Two copies were running (each draws its own icon). Quit one — the app now detects and exits a second instance automatically |
| A non-Iranian site on the same CDN now bypasses the VPN | Expected — websites are bypassed by IP, and CDN IPs are shared. Remove it from your custom list or leave the website bypass off |

Known limitations: IPv6 traffic is not routed (Iranian sites are effectively IPv4); DNS queries
keep using the VPN's DNS; a resolved website IP is bypassed for *all* traffic to that IP, not just
the domain (unavoidable with IP routing — most relevant for shared CDN addresses).

## CLI (for testing)

```bash
dist/IranBypass.app/Contents/MacOS/IranBypass --gateway          # print detected local gateway
dist/IranBypass.app/Contents/MacOS/IranBypass --update-list      # download + parse geoip:ir
dist/IranBypass.app/Contents/MacOS/IranBypass --categories       # list categories inside geoip.dat
dist/IranBypass.app/Contents/MacOS/IranBypass --update-websites  # download + resolve the website list
dist/IranBypass.app/Contents/MacOS/IranBypass --dump-domains [category-ir]  # show parsed domains
dist/IranBypass.app/Contents/MacOS/IranBypass --resolve example.com         # resolve a domain
dist/IranBypass.app/Contents/MacOS/IranBypass --site-categories  # list categories inside geosite.dat
dist/IranBypass.app/Contents/MacOS/IranBypass --status           # applied record / validity / meta
dist/IranBypass.app/Contents/MacOS/IranBypass --custom-domains   # list manually added domains
dist/IranBypass.app/Contents/MacOS/IranBypass --remove-domain example.com  # remove a custom domain
dist/IranBypass.app/Contents/MacOS/IranBypass --apply            # apply routes from the cached lists
dist/IranBypass.app/Contents/MacOS/IranBypass --remove           # remove the routes recorded as applied
dist/IranBypass.app/Contents/MacOS/IranBypass --instances        # list running instances of the app
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
