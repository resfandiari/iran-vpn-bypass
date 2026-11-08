//
//  Iran VPN Bypass — macOS menu bar utility
//
//  While a VPN (e.g. ExpressVPN) is running, this tool adds IPv4 routes for
//  every Iranian IP range so traffic to Iranian sites exits through the
//  physical (ISP) gateway instead of the VPN tunnel. Longer-prefix routes
//  always beat the VPN's default route, so everything else stays in the tunnel.
//
//  IP ranges come from https://github.com/chocolate4u/Iran-v2ray-rules
//  (geoip.dat, category "ir"). Toggle it on/off from the menu bar.
//

import SwiftUI
import AppKit
import Network
import SystemConfiguration

// MARK: - Errors

enum BypassError: LocalizedError {
    case badHTTP(Int)
    case listEmpty
    case noGateway
    case cancelled
    case helperMissing
    case runtime(String)

    var errorDescription: String? {
        switch self {
        case .badHTTP(let code): return "Download failed (HTTP \(code))"
        case .listEmpty: return "Iranian IP list is empty — try “Update IP list”"
        case .noGateway: return "Could not detect the local (non-VPN) gateway. Check your internet connection and try again."
        case .cancelled: return "Cancelled — admin password was not entered"
        case .helperMissing: return "Password-free helper is not installed or authorized"
        case .runtime(let m): return m
        }
    }
}

enum ProtoError: Error { case truncated, malformed }

// MARK: - IPv4 helpers

enum IPv4 {
    static func parse(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return nil }
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    }

    static func string(_ v: UInt32) -> String {
        "\(v >> 24 & 255).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)"
    }

    static func mask(_ prefix: UInt8) -> UInt32 {
        prefix == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefix))
    }
}

struct CIDR: Hashable, Comparable, CustomStringConvertible {
    let network: UInt32
    let prefix: UInt8

    init?(string: String) {
        let p = string.split(separator: "/")
        guard p.count == 2,
              let ip = IPv4.parse(String(p[0])),
              let n = UInt8(p[1]), n <= 32 else { return nil }
        prefix = n
        network = ip & IPv4.mask(n)
    }

    init(network: UInt32, prefix: UInt8) {
        self.prefix = prefix
        self.network = network & IPv4.mask(prefix)
    }

    var description: String { "\(IPv4.string(network))/\(prefix)" }
    var networkString: String { IPv4.string(network) }
    var netmaskString: String { IPv4.string(IPv4.mask(prefix)) }
    var broadcast: UInt32 { network | ~IPv4.mask(prefix) }

    static func < (a: CIDR, b: CIDR) -> Bool {
        a.network != b.network ? a.network < b.network : a.prefix < b.prefix
    }
}

/// Merge contained / adjacent prefixes so the route table stays small.
func aggregate(_ input: [CIDR]) -> [CIDR] {
    let sorted = input.sorted()
    var out: [CIDR] = []
    for c in sorted {
        if let last = out.last {
            if c.network >= last.network && c.network <= last.broadcast { continue }
            if last.prefix >= 2, last.prefix == c.prefix {
                let blockSize = UInt32(1) << (32 - UInt32(c.prefix))
                if c.network == last.network + blockSize,
                   last.network & ~((blockSize << 1) - 1) == last.network {
                    out.removeLast()
                    out.append(CIDR(network: last.network, prefix: last.prefix - 1))
                    continue
                }
            }
        }
        out.append(c)
    }
    return out
}

// MARK: - Minimal protobuf reader for v2ray geoip.dat
//
//   GeoIPList { repeated GeoIP entry = 1; }
//   GeoIP { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3; }
//   CIDR { bytes ip_addr = 1; uint32 prefix_len = 2; }

enum Proto {
    private struct Cursor {
        let buf: [UInt8]
        var i = 0
        init(_ bytes: [UInt8]) { buf = bytes }

        mutating func varint() throws -> UInt64 {
            var v: UInt64 = 0
            var shift: UInt64 = 0
            while true {
                guard i < buf.count else { throw ProtoError.truncated }
                let b = buf[i]
                i += 1
                v |= UInt64(b & 0x7F) << shift
                if b & 0x80 == 0 { return v }
                shift += 7
                if shift > 63 { throw ProtoError.malformed }
            }
        }

        mutating func take(_ n: Int) throws -> ArraySlice<UInt8> {
            guard n >= 0, i + n <= buf.count else { throw ProtoError.truncated }
            let r = buf[i..<i + n]
            i += n
            return r
        }

        mutating func skip(_ wireType: UInt64) throws {
            switch wireType {
            case 0: _ = try varint()
            case 1: _ = try take(8)
            case 2: _ = try take(Int(try varint()))
            case 5: _ = try take(4)
            default: throw ProtoError.malformed
            }
        }
    }

    /// Parse a geoip.dat (GeoIPList) into country code → IPv4 CIDRs.
    static func parseGeoIPList(_ data: Data) throws -> [String: [CIDR]] {
        var c = Cursor([UInt8](data))
        var result: [String: [CIDR]] = [:]
        while c.i < c.buf.count {
            let tag = try c.varint()
            let field = tag >> 3, wt = tag & 7
            if field == 1, wt == 2 {
                let len = Int(try c.varint())
                let entry = try c.take(len)
                if let (code, cidrs) = try parseGeoIPEntry(Array(entry)) {
                    result[code, default: []].append(contentsOf: cidrs)
                }
            } else {
                try c.skip(wt)
            }
        }
        return result
    }

    private static func parseGeoIPEntry(_ bytes: [UInt8]) throws -> (String, [CIDR])? {
        var c = Cursor(bytes)
        var code = ""
        var pairs: [(UInt32, UInt8)] = []
        while c.i < c.buf.count {
            let tag = try c.varint()
            let field = tag >> 3, wt = tag & 7
            switch (field, wt) {
            case (1, 2):
                let raw = try c.take(Int(try c.varint()))
                code = String(bytes: raw, encoding: .utf8) ?? ""
            case (2, 2):
                var sub = Cursor(Array(try c.take(Int(try c.varint()))))
                var ip: [UInt8] = []
                var prefix: UInt8 = 0
                while sub.i < sub.buf.count {
                    let t2 = try sub.varint()
                    let f2 = t2 >> 3, w2 = t2 & 7
                    if f2 == 1, w2 == 2 {
                        ip = Array(try sub.take(Int(try sub.varint())))
                    } else if f2 == 2, w2 == 0 {
                        prefix = UInt8(clamping: try sub.varint())
                    } else {
                        try sub.skip(w2)
                    }
                }
                if ip.count == 4, prefix <= 32 {
                    let n = UInt32(ip[0]) << 24 | UInt32(ip[1]) << 16 | UInt32(ip[2]) << 8 | UInt32(ip[3])
                    pairs.append((n, prefix))
                }
            case (3, 0):
                _ = try c.varint() // reverse_match
            default:
                try c.skip(wt)
            }
        }
        return (code, pairs.map { CIDR(network: $0.0, prefix: $0.1) })
    }
}

// MARK: - Process helper

func runSync(_ path: String, _ args: [String]) throws -> (out: String, err: String, code: Int32) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let o = Pipe(), e = Pipe()
    p.standardOutput = o
    p.standardError = e
    try p.run()
    var outData = Data(), errData = Data()
    let group = DispatchGroup()
    group.enter()
    DispatchQueue.global().async { outData = o.fileHandleForReading.readDataToEndOfFile(); group.leave() }
    group.enter()
    DispatchQueue.global().async { errData = e.fileHandleForReading.readDataToEndOfFile(); group.leave() }
    group.wait()
    p.waitUntilExit()
    let out = String(data: outData, encoding: .utf8) ?? ""
    let err = String(data: errData, encoding: .utf8) ?? ""
    return (out, err, p.terminationStatus)
}

// MARK: - Iranian IP list (chocolate4u/Iran-v2ray-rules)

final class IPListStore {
    static let repoPageURL = URL(string: "https://github.com/chocolate4u/Iran-v2ray-rules")!
    static let geoipURL = URL(string: "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat")!
    static let maxAge: TimeInterval = 7 * 24 * 3600

    let dir: URL
    let cidrsURL: URL
    let stampURL: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dir = base.appendingPathComponent("IranBypass", isDirectory: true)
        cidrsURL = dir.appendingPathComponent("iran-ipv4.txt")
        stampURL = dir.appendingPathComponent("list-date.txt")
    }

    func loadCached() -> [CIDR] {
        guard let s = try? String(contentsOf: cidrsURL, encoding: .utf8) else { return [] }
        return s.split(separator: "\n").compactMap { CIDR(string: String($0)) }
    }

    func cachedDate() -> Date? {
        if let s = try? String(contentsOf: stampURL, encoding: .utf8),
           let t = TimeInterval(s.trimmingCharacters(in: .whitespacesAndNewlines)) {
            return Date(timeIntervalSince1970: t)
        }
        let attrs = try? FileManager.default.attributesOfItem(atPath: cidrsURL.path)
        return attrs?[.modificationDate] as? Date
    }

    func isFresh() -> Bool {
        guard let d = cachedDate() else { return false }
        return Date().timeIntervalSince(d) < Self.maxAge
    }

    func downloadGeoIPSync() throws -> Data {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 60
        cfg.timeoutIntervalForResource = 300
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        let sem = DispatchSemaphore(value: 0)
        var result: Result<Data, Error>!
        session.dataTask(with: Self.geoipURL) { d, r, e in
            if let e = e { result = .failure(e) }
            else if let d = d, let h = r as? HTTPURLResponse, (200..<300).contains(h.statusCode) { result = .success(d) }
            else { result = .failure(BypassError.badHTTP((r as? HTTPURLResponse)?.statusCode ?? -1)) }
            sem.signal()
        }.resume()
        sem.wait()
        return try result.get()
    }

    func updateSync(force: Bool) throws -> [CIDR] {
        if !force, isFresh(), !loadCached().isEmpty { return loadCached() }
        let data = try downloadGeoIPSync()
        let all = try Proto.parseGeoIPList(data)
        let ir = all["ir"] ?? all["IR"] ?? []
        guard !ir.isEmpty else { throw BypassError.listEmpty }
        let agg = aggregate(ir)
        guard !agg.isEmpty else { throw BypassError.listEmpty }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try agg.map(\.description).joined(separator: "\n").write(to: cidrsURL, atomically: true, encoding: .utf8)
        try "\(Int(Date().timeIntervalSince1970))".write(to: stampURL, atomically: true, encoding: .utf8)
        return agg
    }

    func update(force: Bool) async throws -> [CIDR] {
        try await Task.detached(priority: .userInitiated) { try self.updateSync(force: force) }.value
    }
}

// MARK: - Route engine

final class RouteEngine {
    let dir: URL
    var appliedURL: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dir = base.appendingPathComponent("IranBypass", isDirectory: true)
        appliedURL = dir.appendingPathComponent("applied-routes.txt")
    }

    func hasAppliedRecord() -> Bool {
        FileManager.default.fileExists(atPath: appliedURL.path)
    }

    /// Verify the routes we recorded are still in the routing table (they vanish on reboot).
    func appliedRoutesValid() -> Bool {
        guard let content = try? String(contentsOf: appliedURL, encoding: .utf8) else { return false }
        let lines = content.split(separator: "\n").map(String.init)
        guard lines.count >= 2 else { return false }
        let gw = lines[0]
        let net = lines[1].split(separator: " ").first.map(String.init) ?? ""
        guard IPv4.parse(gw) != nil, !net.isEmpty, let current = routeGetGateway(net) else { return false }
        return current == gw
    }

    /// True when the bypass needs to be re-applied: the local gateway changed
    /// (switched networks) or the routes were flushed (reboot, or a VPN client
    /// that flushes the routing table when its tunnel comes up).
    func needsReapply() -> Bool {
        guard let content = try? String(contentsOf: appliedURL, encoding: .utf8) else { return false }
        let lines = content.split(separator: "\n").map(String.init)
        guard lines.count >= 2, IPv4.parse(lines[0]) != nil else { return false }
        let recordedGw = lines[0]
        if let current = defaultGateway(), current.gw != recordedGw { return true }
        let net = lines[1].split(separator: " ").first.map(String.init) ?? ""
        guard !net.isEmpty else { return false }
        return routeGetGateway(net) != recordedGw
    }

    // MARK: gateway detection

    func defaultGateway() -> (gw: String, iface: String)? {
        if let g = gatewayFromNetstat() { return g }
        return gatewayFromDynamicStore()
    }

    private func isBlockedIface(_ name: String) -> Bool {
        // Tunnel/virtual interfaces used by VPN clients and VMs (utun* covers most
        // modern VPNs via Network Extensions; tun*/tap* cover OpenVPN/TAP kexts;
        // wg* WireGuard-go, zt* ZeroTier, tinc* Tinc, ppp* native L2TP/PPTP).
        let blocked = ["ut", "lo", "awdl", "llw", "gif", "stf", "ipsec", "ppp", "bridge",
                       "vlan", "feth", "vmen", "vmnet", "tap", "tun", "wg", "zt", "tinc", "pdp"]
        return blocked.contains { name.hasPrefix($0) }
    }

    private func gatewayFromNetstat() -> (String, String)? {
        guard let r = try? runSync("/usr/sbin/netstat", ["-rn", "-f", "inet"]) else { return nil }
        for rawLine in r.out.split(separator: "\n") {
            let t = rawLine.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard t.count >= 3, t[0] == "default" else { continue }
            let gw = t[1]
            guard IPv4.parse(gw) != nil else { continue }
            let iface = t.last ?? ""
            if !isBlockedIface(iface) { return (gw, iface) }
        }
        return nil
    }

    private func gatewayFromDynamicStore() -> (String, String)? {
        guard let store = SCDynamicStoreCreate(nil, "IranBypass" as CFString, nil, nil),
              let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/IPv4" as CFString) as? [String] else { return nil }
        for key in keys {
            guard let d = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  let router = d["Router"] as? String, IPv4.parse(router) != nil else { continue }
            let ifaceKey = key.replacingOccurrences(of: "/IPv4", with: "/Interface")
            guard let idict = SCDynamicStoreCopyValue(store, ifaceKey as CFString) as? [String: Any],
                  let device = idict["DeviceName"] as? String else { continue }
            if !isBlockedIface(device) { return (router, device) }
        }
        return nil
    }

    private func routeGetGateway(_ dest: String) -> String? {
        guard let r = try? runSync("/sbin/route", ["-n", "get", dest]), r.code == 0 else { return nil }
        for line in r.out.split(separator: "\n") {
            let t = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            if t.count >= 2, t[0] == "gateway:" { return String(t[1]) }
        }
        return nil
    }

    // MARK: apply / remove
    //
    // Uses a one-time-installed password-free helper:
    //   /usr/local/libexec/iranbypass-helper  (root-owned, fixed function)
    //   /etc/sudoers.d/iranbypass             (%admin NOPASSWD for the helper only)
    // The helper is installed on the first toggle (one password prompt), after
    // which every toggle runs `sudo -n` without any prompt.

    static let helperPath = "/usr/local/libexec/iranbypass-helper"

    func helperInstalled() -> Bool {
        guard let s = try? String(contentsOfFile: Self.helperPath, encoding: .utf8) else { return false }
        return s.contains("IRANBYPASS-HELPER v2")
    }

    private func writeRoutesFile(gateway: String, cidrs: [CIDR]) throws -> URL {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let f = dir.appendingPathComponent("pending-routes.txt")
        let lines = [gateway] + cidrs.map { "\($0.networkString) \($0.netmaskString)" }
        try lines.joined(separator: "\n").write(to: f, atomically: true, encoding: .utf8)
        return f
    }

    private func runHelper(_ mode: String, file: URL) throws -> String {
        let r = try runSync("/usr/bin/sudo", ["-n", Self.helperPath, mode, file.path])
        if r.code == 0 {
            return r.out.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let e = r.err.trimmingCharacters(in: .whitespacesAndNewlines)
        if e.contains("a password is required") || e.contains("command not found") || e.contains("not allowed") {
            throw BypassError.helperMissing
        }
        throw BypassError.runtime("Helper failed: \(e.isEmpty ? "(no output)" : e)")
    }

    func applySync(cidrs: [CIDR], gateway: String) throws -> String {
        let routesFile = try writeRoutesFile(gateway: gateway, cidrs: cidrs)
        if helperInstalled() {
            do {
                return try runHelper("apply", file: routesFile)
            } catch BypassError.helperMissing { /* helper deleted or unauthorized — reinstall */ }
        }
        try installHelper()
        let out = try runHelper("apply", file: routesFile)
        try ([gateway] + cidrs.map { "\($0.networkString) \($0.netmaskString)" })
            .joined(separator: "\n")
            .write(to: appliedURL, atomically: true, encoding: .utf8)
        return out
    }

    func removeSync() throws -> String {
        guard FileManager.default.fileExists(atPath: appliedURL.path),
              let content = try? String(contentsOf: appliedURL, encoding: .utf8), !content.isEmpty else {
            return "no routes recorded"
        }
        let lines = content.split(separator: "\n").map(String.init)
        guard lines.count >= 2, IPv4.parse(lines[0]) != nil else { return "no routes recorded" }
        defer { try? FileManager.default.removeItem(at: appliedURL) }
        if helperInstalled() {
            do {
                return try runHelper("remove", file: appliedURL)
            } catch BypassError.helperMissing { /* fall through to legacy prompt */ }
        }
        return try legacyRemove(content: content)
    }

    /// Fallback for when the helper was removed manually: one osascript prompt.
    private func legacyRemove(content: String) throws -> String {
        let routesFile = dir.appendingPathComponent("pending-routes.txt")
        try content.write(to: routesFile, atomically: true, encoding: .utf8)
        let script = """
        #!/bin/bash
        FILE='\(routesFile.path)'
        GW=$(head -n 1 "$FILE")
        TMP=$(mktemp); tail -n +2 "$FILE" > "$TMP"
        RES=$(mktemp); : > "$RES"
        i=0
        while read -r net mask || [ -n "$net" ]; do
          [ -z "$net" ] && continue
          ( { /sbin/route -n delete -net "$net" "$GW" "$mask" >/dev/null 2>&1 || /sbin/route -n delete -net "$net" "$GW" >/dev/null 2>&1; } && echo 1 >> "$RES" || echo 0 >> "$RES" ) &
          i=$((i+1)); [ $((i % 64)) -eq 0 ] && wait
        done < "$TMP"
        wait
        ok=$(grep -c '^1$' "$RES" || true); miss=$(grep -c '^0$' "$RES" || true)
        rm -f "$TMP" "$RES"
        echo "removed ${ok:-0} routes (not present: ${miss:-0})"
        """
        let f = dir.appendingPathComponent("remove-routes.sh")
        try script.write(to: f, atomically: true, encoding: .utf8)
        return try runAdmin("/bin/bash '\(f.path)'")
    }

    private func installHelper() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let f = dir.appendingPathComponent("install-helper.sh")
        try Self.installScript.write(to: f, atomically: true, encoding: .utf8)
        try runAdmin("/bin/bash '\(f.path)'")
    }

    // MARK: helper + installer sources

    static let helperSource = """
#!/bin/bash
# Fixed-function privileged helper for Iran VPN Bypass (IRANBYPASS-HELPER v2).
# Only adds/deletes the IPv4 routes listed in the file passed as argument 2.
# File format: first line = gateway IP, then one "network netmask" per line.
set -u
MODE="${1:-}"; FILE="${2:-}"
if [ "$MODE" != "apply" ] && [ "$MODE" != "remove" ]; then
  echo "usage: iranbypass-helper apply|remove <routes-file>" >&2; exit 2
fi
if [ ! -r "$FILE" ]; then echo "routes file not readable: $FILE" >&2; exit 2; fi
GW="$(head -n 1 "$FILE" | tr -d '[:space:]')"
case "$GW" in ''|*[!0-9.]*) echo "bad gateway line" >&2; exit 2 ;; esac
RES="$(mktemp)"; : > "$RES"
i=0
while read -r net mask || [ -n "$net" ]; do
  [ -z "$net" ] && continue
  case "$net" in *[!0-9.]*) continue ;; esac
  if [ "$MODE" = "apply" ]; then
    ( /sbin/route -n add -net "$net" "$GW" "$mask" >/dev/null 2>&1 && echo 1 >> "$RES" || echo 0 >> "$RES" ) &
  else
    ( { /sbin/route -n delete -net "$net" "$GW" "$mask" >/dev/null 2>&1 || /sbin/route -n delete -net "$net" "$GW" >/dev/null 2>&1; } && echo 1 >> "$RES" || echo 0 >> "$RES" ) &
  fi
  i=$((i+1)); [ $((i % 64)) -eq 0 ] && wait
done < <(tail -n +2 "$FILE")
wait
ok=$(/usr/bin/grep -c '^1$' "$RES" || true); bad=$(/usr/bin/grep -c '^0$' "$RES" || true)
rm -f "$RES"
if [ "$MODE" = "apply" ]; then
  echo "added ${ok:-0} routes (skipped/failed: ${bad:-0})"
else
  echo "removed ${ok:-0} routes (not present: ${bad:-0})"
fi
"""

    static var installScript: String {
        """
        #!/bin/bash
        set -e
        mkdir -p /usr/local/libexec
        cat > /usr/local/libexec/iranbypass-helper <<'IRANBYPASS_HELPER_EOF'
        \(helperSource)
        IRANBYPASS_HELPER_EOF
        chown root:wheel /usr/local/libexec/iranbypass-helper
        chmod 0755 /usr/local/libexec/iranbypass-helper
        if ! grep -Eq '^[@#]includedir[[:space:]]+/etc/sudoers.d[[:space:]]*$' /etc/sudoers; then
          cp /etc/sudoers /etc/sudoers.pre-iranbypass
          printf '@includedir /etc/sudoers.d\\n' >> /etc/sudoers
        fi
        printf '%s ALL=(root) NOPASSWD: /usr/local/libexec/iranbypass-helper\\n' '%admin' > /etc/sudoers.d/iranbypass
        chown root:wheel /etc/sudoers.d/iranbypass
        chmod 0440 /etc/sudoers.d/iranbypass
        visudo -cf /etc/sudoers.d/iranbypass >/dev/null || { rm -f /etc/sudoers.d/iranbypass; echo 'sudoers validation failed' >&2; exit 1; }
        echo 'password-free helper installed'
        """
    }

    func apply(cidrs: [CIDR], gateway: String) async throws -> String {
        try await Task.detached(priority: .userInitiated) { try self.applySync(cidrs: cidrs, gateway: gateway) }.value
    }

    func remove() async throws -> String {
        try await Task.detached(priority: .userInitiated) { try self.removeSync() }.value
    }

    @discardableResult
    private func runAdmin(_ shellCommand: String) throws -> String {
        let escaped = shellCommand
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript = "do shell script \"\(escaped)\" with administrator privileges"
        let r = try runSync("/usr/bin/osascript", ["-e", appleScript])
        guard r.code == 0 else {
            let e = r.err
            if e.contains("cancel") || e.contains("Cancel") { throw BypassError.cancelled }
            throw BypassError.runtime("Admin command failed: \(e.isEmpty ? "(no output)" : e)")
        }
        return r.out.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func expressVPNRunning() -> Bool {
        guard let r = try? runSync("/usr/bin/pgrep", ["-i", "-f", "expressvpn"]) else { return false }
        return r.code == 0 && !r.out.isEmpty
    }
}

// MARK: - View model

@MainActor
final class BypassViewModel: ObservableObject {
    @Published var busy = false
    @Published var enabled = false
    @Published var status = "Ready"
    @Published var info: [String] = []

    private let engine = RouteEngine()
    private let listStore = IPListStore()
    private let pathMonitor = NWPathMonitor()
    private var recheckTask: Task<Void, Never>?

    init() {
        if engine.hasAppliedRecord() {
            if engine.appliedRoutesValid() {
                enabled = true
                status = "Routes active (from a previous session)"
            } else if engine.helperInstalled() {
                // Routes were lost (reboot / VPN flush) — restore them automatically.
                enabled = true
                status = "Restoring routes…"
                Task {
                    try? await Task.sleep(nanoseconds: 4_000_000_000)
                    await reapplyIfNeeded()
                }
            } else {
                try? FileManager.default.removeItem(at: engine.appliedURL)
                status = "Previous routes are gone — turn bypass on again"
            }
        }
        refreshInfo()
        startMonitoring()
    }

    // MARK: network / VPN change watching
    //
    // Re-applies routes (password-free via the helper) when the local gateway
    // changes or a VPN client flushes the routing table.

    private func startMonitoring() {
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            guard let self else { return }
            Task { await MainActor.run { self.scheduleRecheck() } }
        }
        pathMonitor.start(queue: DispatchQueue(label: "local.iranbypass.path"))
    }

    private func scheduleRecheck() {
        recheckTask?.cancel()
        recheckTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard let self, !Task.isCancelled else { return }
            await self.reapplyIfNeeded()
        }
    }

    func reapplyIfNeeded() async {
        guard enabled, !busy, engine.hasAppliedRecord() else { return }
        guard engine.helperInstalled() else {
            status = "Routes need re-applying — toggle off & on to reinstall the helper"
            return
        }
        let eng = engine
        let needs = await Task.detached(priority: .utility) { eng.needsReapply() }.value
        guard needs else { return }
        let cidrs = listStore.loadCached()
        guard !cidrs.isEmpty else {
            status = "⚠️ Routes need re-applying but the IP list cache is empty"
            return
        }
        busy = true
        defer { busy = false }
        do {
            guard let g = engine.defaultGateway() else { throw BypassError.noGateway }
            status = "Network changed — re-applying \(cidrs.count) routes via \(g.gw)…"
            let out = try await engine.apply(cidrs: cidrs, gateway: g.gw)
            status = "Bypass ON — \(out)"
        } catch {
            status = "⚠️ Re-apply failed: \(error.localizedDescription)"
        }
        refreshInfo()
    }

    func refreshInfo() {
        var lines: [String] = []
        if let g = engine.defaultGateway() {
            lines.append("Local gateway: \(g.gw)  (\(g.iface))")
        } else {
            lines.append("Local gateway: not detected")
        }
        lines.append("Iranian IPv4 ranges cached: \(listStore.loadCached().count)")
        if let d = listStore.cachedDate() {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd HH:mm"
            lines.append("List updated: \(f.string(from: d))")
        }
        lines.append("ExpressVPN: \(engine.expressVPNRunning() ? "running" : "not detected")")
        lines.append("Password-free helper: \(engine.helperInstalled() ? "installed" : "not installed yet")")
        info = lines
    }

    func toggle() {
        guard !busy else { return }
        Task {
            busy = true
            defer { busy = false }
            do {
                if enabled { try await disable() } else { try await enable() }
            } catch {
                status = "⚠️ \(error.localizedDescription)"
            }
            refreshInfo()
        }
    }

    private func enable() async throws {
        var cidrs = listStore.loadCached()
        if cidrs.isEmpty || !listStore.isFresh() {
            status = "Downloading IP list (Iran-v2ray-rules)…"
            do {
                cidrs = try await listStore.update(force: false)
            } catch {
                if cidrs.isEmpty { throw error }
                status = "Using cached list (download failed)"
            }
        }
        guard !cidrs.isEmpty else { throw BypassError.listEmpty }
        status = "Detecting local gateway…"
        guard let g = engine.defaultGateway() else { throw BypassError.noGateway }
        let needsSetup = !engine.helperInstalled()
        status = needsSetup
            ? "First-time setup + adding \(cidrs.count) routes via \(g.gw)… (password asked once)"
            : "Adding \(cidrs.count) routes via \(g.gw)…"
        let out = try await engine.apply(cidrs: cidrs, gateway: g.gw)
        enabled = true
        status = "Bypass ON — \(out)"
    }

    private func disable() async throws {
        status = "Removing routes…"
        let out = try await engine.remove()
        enabled = false
        status = "Bypass OFF — \(out)"
    }

    func updateList() {
        guard !busy else { return }
        Task {
            busy = true
            defer { busy = false }
            do {
                let n = try await listStore.update(force: true)
                status = "List updated: \(n) ranges. Turn bypass off & on to apply changes."
            } catch {
                status = "⚠️ \(error.localizedDescription)"
            }
            refreshInfo()
        }
    }
}

// MARK: - UI

struct ContentView: View {
    @ObservedObject var vm: BypassViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Iran VPN Bypass").font(.headline)
                    Text("Route Iranian sites outside the VPN").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { vm.enabled },
                    set: { _ in vm.toggle() }
                ))
                .toggleStyle(.switch)
                .labelsHidden()
                .disabled(vm.busy)
            }

            HStack(spacing: 6) {
                if vm.busy { ProgressView().controlSize(.small) }
                Text(vm.status).font(.callout).lineLimit(4)
            }

            Divider()

            ForEach(vm.info, id: \.self) { line in
                Text(line).font(.caption).foregroundStyle(.secondary)
            }

            Text("If Iranian sites still fail, turn OFF ExpressVPN “Network Lock” (kill switch) — it blocks traffic outside the tunnel.")
                .font(.caption2)
                .foregroundStyle(.orange)

            Divider()

            HStack {
                Button("Update IP list") { vm.updateList() }
                    .disabled(vm.busy)
                Button("GitHub repo") { NSWorkspace.shared.open(IPListStore.repoPageURL) }
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(14)
        .frame(width: 340)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
    }
}

struct IranBypassApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var vm = BypassViewModel()

    var body: some Scene {
        // HIG for menu bar icons: template rendering, ~16–18 pt, matching the
        // system's own status items. The systemImage initializer lets macOS size
        // and render the SF Symbol exactly like its built-in status icons.
        MenuBarExtra("Iran VPN Bypass", systemImage: vm.enabled ? "shield.lefthalf.filled" : "shield") {
            ContentView(vm: vm)
        }
        .menuBarExtraStyle(.window)
    }
}

// MARK: - CLI helpers (for testing without the GUI)

let args = CommandLine.arguments
if args.contains("--dump-scripts") {
    print("=== HELPER ===")
    print(RouteEngine.helperSource)
    print("=== INSTALL ===")
    print(RouteEngine.installScript)
    exit(0)
}
if args.contains("--gateway") {
    if let g = RouteEngine().defaultGateway() {
        print("\(g.gw) \(g.iface)")
    } else {
        print("no gateway found")
    }
    exit(0)
}
if args.contains("--update-list") {
    do {
        let list = try IPListStore().updateSync(force: true)
        print("ranges: \(list.count)")
        for c in list.prefix(5) { print("  \(c)") }
    } catch {
        print("error: \(error.localizedDescription)")
        exit(1)
    }
    exit(0)
}
if args.contains("--categories") {
    do {
        let data = try IPListStore().downloadGeoIPSync()
        let all = try Proto.parseGeoIPList(data)
        for k in all.keys.sorted() { print("\(k): \(all[k]!.count) cidrs") }
    } catch {
        print("error: \(error.localizedDescription)")
        exit(1)
    }
    exit(0)
}

IranBypassApp.main()
