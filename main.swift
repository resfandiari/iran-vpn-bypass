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
import Darwin

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

    // MARK: geosite.dat (GeoIPList-style, but for domains)
    //
    //   GeoSiteList { repeated GeoSite entry = 1; }
    //   GeoSite { string country_code = 1; repeated Domain domain = 2; }
    //   Domain { Type type = 1; string value = 2; }   // 0 plain, 1 regex, 2 domain, 3 full

    /// Parse a geosite.dat (GeoSiteList) into country code → resolvable hostnames.
    /// Regex entries are skipped; only `domain` (suffix) and `full` entries are real
    /// hostnames we can hand to the resolver.
    static func parseGeoSiteList(_ data: Data) throws -> [String: [String]] {
        var c = Cursor([UInt8](data))
        var result: [String: [String]] = [:]
        while c.i < c.buf.count {
            let tag = try c.varint()
            let field = tag >> 3, wt = tag & 7
            if field == 1, wt == 2 {
                let len = Int(try c.varint())
                let entry = try c.take(len)
                if let (code, domains) = try parseGeoSiteEntry(Array(entry)) {
                    result[code, default: []].append(contentsOf: domains)
                }
            } else {
                try c.skip(wt)
            }
        }
        return result
    }

    private static func parseGeoSiteEntry(_ bytes: [UInt8]) throws -> (String, [String])? {
        var c = Cursor(bytes)
        var code = ""
        var domains: [String] = []
        while c.i < c.buf.count {
            let tag = try c.varint()
            let field = tag >> 3, wt = tag & 7
            switch (field, wt) {
            case (1, 2):
                let raw = try c.take(Int(try c.varint()))
                code = String(bytes: raw, encoding: .utf8) ?? ""
            case (2, 2):
                var sub = Cursor(Array(try c.take(Int(try c.varint()))))
                var type: UInt64 = 0
                var value = ""
                while sub.i < sub.buf.count {
                    let t2 = try sub.varint()
                    let f2 = t2 >> 3, w2 = t2 & 7
                    if f2 == 1, w2 == 0 {
                        type = try sub.varint()
                    } else if f2 == 2, w2 == 2 {
                        let raw = try sub.take(Int(try sub.varint()))
                        value = String(bytes: raw, encoding: .utf8) ?? ""
                    } else {
                        try sub.skip(w2)
                    }
                }
                // 0 = plain (substring, not a hostname), 1 = regex, 2 = domain, 3 = full
                if (type == 2 || type == 3), !value.isEmpty {
                    domains.append(value.lowercased())
                }
            default:
                try c.skip(wt)
            }
        }
        return (code, domains)
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

/// Blocking download of a URL (used from background tasks only).
func downloadSync(_ url: URL, resourceTimeout: TimeInterval = 300) throws -> Data {
    let cfg = URLSessionConfiguration.ephemeral
    cfg.timeoutIntervalForRequest = 60
    cfg.timeoutIntervalForResource = resourceTimeout
    let session = URLSession(configuration: cfg)
    defer { session.finishTasksAndInvalidate() }
    let sem = DispatchSemaphore(value: 0)
    var result: Result<Data, Error>!
    session.dataTask(with: url) { d, r, e in
        if let e = e { result = .failure(e) }
        else if let d = d, let h = r as? HTTPURLResponse, (200..<300).contains(h.statusCode) { result = .success(d) }
        else { result = .failure(BypassError.badHTTP((r as? HTTPURLResponse)?.statusCode ?? -1)) }
        sem.signal()
    }.resume()
    sem.wait()
    return try result.get()
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
        try downloadSync(Self.geoipURL)
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

// MARK: - DNS resolution (domains → IPv4)

enum DNS {
    /// Resolve a hostname to its IPv4 addresses, skipping non-routable results.
    static func resolveIPv4(_ host: String) -> [UInt32] {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil,
                             ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let head = res else { return [] }
        defer { freeaddrinfo(head) }
        var out = Set<UInt32>()
        var p: UnsafeMutablePointer<addrinfo>? = head
        while let cur = p {
            if let sa = cur.pointee.ai_addr, sa.pointee.sa_family == sa_family_t(AF_INET) {
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    let v = UInt32(bigEndian: sin.pointee.sin_addr.s_addr)
                    if isRoutable(v) { out.insert(v) }
                }
            }
            p = cur.pointee.ai_next
        }
        return Array(out)
    }

    /// Exclude loopback, link-local, private, CGNAT, multicast and reserved space.
    static func isRoutable(_ ip: UInt32) -> Bool {
        let b0 = (ip >> 24) & 255, b1 = (ip >> 16) & 255, b2 = (ip >> 8) & 255
        if b0 == 0 || b0 == 127 || b0 >= 224 { return false }        // 0/8, 127/8, 224/4, 240/4
        if b0 == 10 { return false }                                  // 10/8
        if b0 == 172, (16...31).contains(b1) { return false }         // 172.16/12
        if b0 == 192, b1 == 168 { return false }                      // 192.168/16
        if b0 == 169, b1 == 254 { return false }                      // 169.254/16
        if b0 == 100, (64...127).contains(b1) { return false }        // 100.64/10
        if b0 == 192, b1 == 0, b2 == 0 { return false }               // 192.0.0/24
        if b0 == 198, b1 == 18 || b1 == 19 { return false }           // 198.18/15
        return true
    }

    /// Resolve many hostnames concurrently (bounded in-flight, overall deadline).
    static func resolveAll(_ hosts: [String], concurrency: Int = 48, deadline: TimeInterval = 600,
                           progress: ((Int, Int) -> Void)? = nil) -> [String: [UInt32]] {
        let total = hosts.count
        let lock = NSLock()
        var out: [String: [UInt32]] = [:]
        var done = 0
        let start = Date()
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = concurrency
        queue.qualityOfService = .utility
        // Keep exactly `concurrency` lookups in flight. The producer blocks on the
        // semaphore, so the overall deadline is enforced without queueing the whole
        // list up front (and without per-chunk drain stalls).
        let slots = DispatchSemaphore(value: concurrency)
        for host in hosts {
            if Date().timeIntervalSince(start) > deadline { break }
            slots.wait()
            queue.addOperation {
                let ips = resolveIPv4(host)
                lock.lock()
                out[host] = ips
                done += 1
                let n = done
                lock.unlock()
                progress?(n, total)
                slots.signal()
            }
        }
        queue.waitUntilAllOperationsAreFinished()
        return out
    }
}

// MARK: - Iranian website list (geosite.dat, category "ir") + resolution cache

final class DomainListStore {
    static let geositeURL = URL(string: "https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat")!
    static let maxAge: TimeInterval = 7 * 24 * 3600

    let dir: URL
    let domainsURL: URL        // downloaded Iranian domains
    let customURL: URL         // user-added domains
    let resolvedURL: URL       // IPv4 /32 routes resolved from the downloaded list
    let customResolvedURL: URL // IPv4 /32 routes resolved from the custom list
    let stampURL: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dir = base.appendingPathComponent("IranBypass", isDirectory: true)
        domainsURL = dir.appendingPathComponent("iran-domains.txt")
        customURL = dir.appendingPathComponent("custom-domains.txt")
        resolvedURL = dir.appendingPathComponent("website-ipv4.txt")
        customResolvedURL = dir.appendingPathComponent("custom-website-ipv4.txt")
        stampURL = dir.appendingPathComponent("domains-date.txt")
    }

    private func readList(_ url: URL) -> [String] {
        guard let s = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return s.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private func write(_ lines: [String], to url: URL) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    func loadDomains() -> [String] { readList(domainsURL) }
    func loadCustom() -> [String] { readList(customURL) }

    /// All cached website routes: downloaded list + custom domains.
    func loadResolved() -> [CIDR] {
        (readList(resolvedURL) + readList(customResolvedURL)).compactMap { CIDR(string: $0) }
    }

    func cachedDate() -> Date? {
        if let s = try? String(contentsOf: stampURL, encoding: .utf8),
           let t = TimeInterval(s.trimmingCharacters(in: .whitespacesAndNewlines)) {
            return Date(timeIntervalSince1970: t)
        }
        return (try? FileManager.default.attributesOfItem(atPath: resolvedURL.path))?[.modificationDate] as? Date
    }

    func isFresh() -> Bool {
        guard let d = cachedDate() else { return false }
        return Date().timeIntervalSince(d) < Self.maxAge
    }

    func hasResolved() -> Bool { !loadResolved().isEmpty }

    // MARK: custom domains

    /// Accept "example.com", "https://example.com/path", "*.example.com", …
    static func normalizeDomain(_ raw: String) -> String? {
        var d = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let i = d.range(of: "://") { d = String(d[i.upperBound...]) }
        if let i = d.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) { d = String(d[..<i]) }
        if let at = d.firstIndex(of: "@") { d = String(d[d.index(after: at)...]) }
        if d.hasPrefix("*.") { d.removeFirst(2) }
        if let colon = d.firstIndex(of: ":"), !d.contains("]") { d = String(d[..<colon]) }
        if d.hasSuffix(".") { d.removeLast() }
        guard d.contains("."),
              d.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }) else { return nil }
        return d
    }

    func addCustom(_ raw: String) throws -> String {
        guard let d = Self.normalizeDomain(raw) else {
            throw BypassError.runtime("“\(raw)” doesn’t look like a domain")
        }
        var list = loadCustom()
        if !list.contains(d) {
            list.append(d)
            list.sort()
            try write(list, to: customURL)
        }
        return d
    }

    func removeCustom(_ d: String) throws {
        var list = loadCustom()
        list.removeAll { $0 == d }
        try write(list, to: customURL)
    }

    // MARK: download + resolve

    @discardableResult
    func downloadDomainsSync() throws -> [String] {
        let data = try downloadSync(Self.geositeURL, resourceTimeout: 300)
        let all = try Proto.parseGeoSiteList(data)
        // "category-ir" is the same list with inactive domains removed (checked daily).
        var domains = all["category-ir"] ?? all["CATEGORY-IR"] ?? all["ir"] ?? all["IR"] ?? []
        domains = domains.filter { $0.contains(".") }
        guard !domains.isEmpty else { throw BypassError.runtime("Website list came back empty — try again later") }
        domains = Array(Set(domains)).sorted()
        try write(domains, to: domainsURL)
        try "\(Int(Date().timeIntervalSince1970))".write(to: stampURL, atomically: true, encoding: .utf8)
        return domains
    }

    /// Binary search for `ip` inside a sorted, non-overlapping CIDR list.
    static func contains(_ ranges: [CIDR], _ ip: UInt32) -> Bool {
        var lo = 0, hi = ranges.count - 1, best = -1
        while lo <= hi {
            let mid = (lo + hi) / 2
            if ranges[mid].network <= ip { best = mid; lo = mid + 1 } else { hi = mid - 1 }
        }
        return best >= 0 && ranges[best].broadcast >= ip
    }

    private func resolveHosts(_ hosts: [String], exclude: [CIDR], progress: ((Int, Int) -> Void)?) -> [CIDR] {
        guard !hosts.isEmpty else { return [] }
        let throttled: ((Int, Int) -> Void)? = progress.map { report in
            { done, total in if done % 25 == 0 || done == total { report(done, total) } }
        }
        let map = DNS.resolveAll(hosts, progress: throttled)
        let sorted = exclude.sorted()
        var cidrs: [CIDR] = []
        for (_, ips) in map {
            for ip in ips {
                // Already reached directly through the Iranian IP ranges — skip.
                if !sorted.isEmpty, Self.contains(sorted, ip) { continue }
                cidrs.append(CIDR(network: ip, prefix: 32))
            }
        }
        return aggregate(cidrs)
    }

    /// Re-resolve the downloaded Iranian domains into cached /32 routes.
    @discardableResult
    func resolveDomainsSync(exclude: [CIDR] = [], progress: ((Int, Int) -> Void)? = nil) throws -> [CIDR] {
        let hosts = loadDomains()
        guard !hosts.isEmpty else { throw BypassError.runtime("Website list is empty — update it first") }
        let agg = resolveHosts(hosts, exclude: exclude, progress: progress)
        guard !agg.isEmpty else { throw BypassError.runtime("No website IPs resolved (check your connection)") }
        try write(agg.map(\.description), to: resolvedURL)
        return agg
    }

    /// Re-resolve only the user's custom domains (fast). Custom domains are kept
    /// even when their IP is inside an Iranian range, so they always show as bypassed.
    @discardableResult
    func resolveCustomSync() throws -> [CIDR] {
        let hosts = loadCustom()
        if hosts.isEmpty {
            try? FileManager.default.removeItem(at: customResolvedURL)
            return []
        }
        let agg = resolveHosts(hosts, exclude: [], progress: nil)
        try write(agg.map(\.description), to: customResolvedURL)
        return agg
    }

    /// Full refresh: download (when needed) + resolve downloaded and custom domains.
    @discardableResult
    func updateSync(force: Bool, exclude: [CIDR] = [], progress: ((Int, Int) -> Void)? = nil) throws -> [CIDR] {
        if force || !isFresh() || loadDomains().isEmpty {
            _ = try downloadDomainsSync()
        }
        let agg = try resolveDomainsSync(exclude: exclude, progress: progress)
        try resolveCustomSync()
        return agg
    }

    func update(force: Bool, exclude: [CIDR] = [], progress: ((Int, Int) -> Void)? = nil) async throws -> [CIDR] {
        try await Task.detached(priority: .utility) {
            try self.updateSync(force: force, exclude: exclude, progress: progress)
        }.value
    }
}

// MARK: - Route engine

final class RouteEngine {
    let dir: URL
    var appliedURL: URL
    /// Records the interface name and its IPv4 address at the time the routes
    /// were added (2 lines: interface, address). The kernel binds each route to
    /// the interface address that was current when it was created, so if the
    /// address later changes (DHCP lease change) the routes keep a stale source
    /// address and every connection through them fails with "Can't assign
    /// requested address". The routes must then be removed and re-added.
    var appliedMetaURL: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dir = base.appendingPathComponent("IranBypass", isDirectory: true)
        appliedURL = dir.appendingPathComponent("applied-routes.txt")
        appliedMetaURL = dir.appendingPathComponent("applied-meta.txt")
    }

    func hasAppliedRecord() -> Bool {
        FileManager.default.fileExists(atPath: appliedURL.path)
    }

    /// The IPv4 address currently assigned to an interface, if any.
    func interfaceIPv4(_ name: String) -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = ptr {
            let ifa = cur.pointee
            if let sa = ifa.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) {
                if String(cString: ifa.ifa_name) == name {
                    var addr = sa.pointee
                    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(&addr, socklen_t(sa.pointee.sa_len),
                                   &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                        return String(cString: host)
                    }
                }
            }
            ptr = ifa.ifa_next
        }
        return nil
    }

    private func writeAppliedMeta(iface: String) throws {
        let addr = interfaceIPv4(iface) ?? ""
        try "\(iface)\n\(addr)".write(to: appliedMetaURL, atomically: true, encoding: .utf8)
    }

    private func readAppliedMeta() -> (iface: String, addr: String)? {
        guard let content = try? String(contentsOf: appliedMetaURL, encoding: .utf8) else { return nil }
        let lines = content.split(separator: "\n").map(String.init)
        guard let iface = lines.first, !iface.isEmpty else { return nil }
        return (iface, lines.count >= 2 ? lines[1] : "")
    }

    /// Verify the routes we recorded are still in the routing table (they vanish
    /// on reboot) and were created with the interface address still in use.
    func appliedRoutesValid() -> Bool {
        guard let content = try? String(contentsOf: appliedURL, encoding: .utf8) else { return false }
        let lines = content.split(separator: "\n").map(String.init)
        guard lines.count >= 2 else { return false }
        let gw = lines[0]
        let net = lines[1].split(separator: " ").first.map(String.init) ?? ""
        guard IPv4.parse(gw) != nil, !net.isEmpty, let current = routeGetGateway(net) else { return false }
        guard current == gw else { return false }
        if let m = readAppliedMeta(), !m.addr.isEmpty, interfaceIPv4(m.iface) != m.addr { return false }
        return true
    }

    /// True when the bypass needs to be re-applied: the local gateway changed
    /// (switched networks), the interface address changed (DHCP lease renewal,
    /// which leaves the routes with a stale source address), or the routes were
    /// flushed (reboot, or a VPN client that flushes the routing table when its
    /// tunnel comes up).
    func needsReapply() -> Bool {
        guard let content = try? String(contentsOf: appliedURL, encoding: .utf8) else { return false }
        let lines = content.split(separator: "\n").map(String.init)
        guard lines.count >= 2, IPv4.parse(lines[0]) != nil else { return false }
        let recordedGw = lines[0]
        let current = defaultGateway()
        if let current, current.gw != recordedGw { return true }
        if let m = readAppliedMeta(), !m.addr.isEmpty,
           let current, current.iface == m.iface, interfaceIPv4(m.iface) != m.addr {
            return true
        }
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

    private func recordApplied(content: String, iface: String?) throws {
        try content.write(to: appliedURL, atomically: true, encoding: .utf8)
        if let iface, !iface.isEmpty {
            try writeAppliedMeta(iface: iface)
        } else {
            try? FileManager.default.removeItem(at: appliedMetaURL)
        }
    }

    func applySync(cidrs: [CIDR], gateway: String, iface: String? = nil) throws -> String {
        let routesFile = try writeRoutesFile(gateway: gateway, cidrs: cidrs)
        let content = ([gateway] + cidrs.map { "\($0.networkString) \($0.netmaskString)" })
            .joined(separator: "\n")
        if helperInstalled() {
            do {
                // Drop routes that were applied before but are no longer part of
                // the bypass (list shrank, custom domain removed, gateway changed).
                let previous = (try? String(contentsOf: appliedURL, encoding: .utf8)) ?? ""
                if !previous.isEmpty && previous != content {
                    _ = try? runHelper("remove", file: appliedURL)
                }
                // Remove the new set before adding it: `route add` on an existing
                // entry does not refresh it, so any route whose binding is stale
                // (older gateway, or an interface address that changed) would
                // otherwise keep pointing at the wrong source address.
                _ = try? runHelper("remove", file: routesFile)
                let out = try runHelper("apply", file: routesFile)
                try recordApplied(content: content, iface: iface)
                return out
            } catch BypassError.helperMissing { /* helper deleted or unauthorized — reinstall */ }
        }
        try installHelper()
        let out = try runHelper("apply", file: routesFile)
        try recordApplied(content: content, iface: iface)
        return out
    }

    func removeSync() throws -> String {
        guard FileManager.default.fileExists(atPath: appliedURL.path),
              let content = try? String(contentsOf: appliedURL, encoding: .utf8), !content.isEmpty else {
            return "no routes recorded"
        }
        let lines = content.split(separator: "\n").map(String.init)
        guard lines.count >= 2, IPv4.parse(lines[0]) != nil else { return "no routes recorded" }
        defer {
            try? FileManager.default.removeItem(at: appliedURL)
            try? FileManager.default.removeItem(at: appliedMetaURL)
        }
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

    func apply(cidrs: [CIDR], gateway: String, iface: String? = nil) async throws -> String {
        try await Task.detached(priority: .userInitiated) {
            try self.applySync(cidrs: cidrs, gateway: gateway, iface: iface)
        }.value
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
    @Published var customDomains: [String] = []
    @Published var newDomain = ""

    private let engine = RouteEngine()
    private let listStore = IPListStore()
    private let domainStore = DomainListStore()
    private let pathMonitor = NWPathMonitor()
    private var recheckTask: Task<Void, Never>?
    private var websiteTask: Task<Void, Never>?

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

    func reapplyIfNeeded(force: Bool = false) async {
        guard enabled, !busy, engine.hasAppliedRecord() else { return }
        guard engine.helperInstalled() else {
            status = "Routes need re-applying — toggle off & on to reinstall the helper"
            return
        }
        let eng = engine
        if !force {
            let needs = await Task.detached(priority: .utility) { eng.needsReapply() }.value
            guard needs else { return }
        }
        let cidrs = aggregate(listStore.loadCached() + domainStore.loadResolved())
        guard !cidrs.isEmpty else {
            status = "⚠️ Routes need re-applying but the list cache is empty"
            return
        }
        busy = true
        defer { busy = false }
        do {
            guard let g = engine.defaultGateway() else { throw BypassError.noGateway }
            status = "Network changed — re-applying \(cidrs.count) routes via \(g.gw)…"
            let out = try await engine.apply(cidrs: cidrs, gateway: g.gw, iface: g.iface)
            status = "Bypass ON — \(out)"
        } catch {
            status = "⚠️ Re-apply failed: \(error.localizedDescription)"
        }
        refreshInfo()
    }

    func refreshInfo() {
        var lines: [String] = []
        if let g = engine.defaultGateway() {
            let addr = engine.interfaceIPv4(g.iface).map { "  \($0)" } ?? ""
            lines.append("Local gateway: \(g.gw)  (\(g.iface)\(addr))")
        } else {
            lines.append("Local gateway: not detected")
        }
        lines.append("Iranian IPv4 ranges cached: \(listStore.loadCached().count)")
        if let d = listStore.cachedDate() {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd HH:mm"
            lines.append("List updated: \(f.string(from: d))")
        }
        lines.append("Iranian websites cached: \(domainStore.loadDomains().count) domains → \(domainStore.loadResolved().count) IPv4")
        if let d = domainStore.cachedDate() {
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd HH:mm"
            lines.append("Websites updated: \(f.string(from: d))")
        }
        lines.append("ExpressVPN: \(engine.expressVPNRunning() ? "running" : "not detected")")
        lines.append("Password-free helper: \(engine.helperInstalled() ? "installed" : "not installed yet")")
        info = lines
        customDomains = domainStore.loadCustom()
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
        var ipCidrs = listStore.loadCached()
        if ipCidrs.isEmpty || !listStore.isFresh() {
            status = "Downloading IP list (Iran-v2ray-rules)…"
            do {
                ipCidrs = try await listStore.update(force: false)
            } catch {
                if ipCidrs.isEmpty { throw error }
                status = "Using cached list (download failed)"
            }
        }
        guard !ipCidrs.isEmpty else { throw BypassError.listEmpty }

        let webCidrs = domainStore.loadResolved()
        let cidrs = aggregate(ipCidrs + webCidrs)
        status = "Detecting local gateway…"
        guard let g = engine.defaultGateway() else { throw BypassError.noGateway }
        let needsSetup = !engine.helperInstalled()
        let webNote = webCidrs.isEmpty ? "" : " + \(webCidrs.count) website IPs"
        status = needsSetup
            ? "First-time setup + adding \(cidrs.count) routes\(webNote) via \(g.gw)… (password asked once)"
            : "Adding \(cidrs.count) routes\(webNote) via \(g.gw)…"
        let out = try await engine.apply(cidrs: cidrs, gateway: g.gw, iface: g.iface)
        enabled = true
        status = "Bypass ON — \(out)"
        if webCidrs.isEmpty || !domainStore.isFresh() {
            refreshWebsites(force: false)
        }
    }

    private func disable() async throws {
        status = "Removing routes…"
        let out = try await engine.remove()
        enabled = false
        status = "Bypass OFF — \(out)"
    }

    // MARK: website list

    /// Download (when stale) and resolve the Iranian website list in the
    /// background, then re-apply routes so the new IPs take effect.
    func refreshWebsites(force: Bool) {
        guard websiteTask == nil else { return }
        let store = domainStore
        websiteTask = Task { [weak self] in
            guard let self else { return }
            do {
                let exclude = self.listStore.loadCached()
                let agg = try await store.update(force: force, exclude: exclude) { done, total in
                    DispatchQueue.main.async {
                        guard self.websiteTask != nil else { return }
                        self.status = "Resolving websites… \(done)/\(total)"
                    }
                }
                self.status = "Website list ready — \(agg.count) IPs bypassed"
                self.websiteTask = nil
                self.refreshInfo()
                if self.enabled { await self.reapplyIfNeeded(force: true) }
            } catch {
                self.status = "⚠️ Website list: \(error.localizedDescription)"
                self.websiteTask = nil
                self.refreshInfo()
            }
        }
    }

    func updateWebsites() {
        guard !busy else { return }
        guard websiteTask == nil else {
            status = "Website list is already updating…"
            return
        }
        refreshWebsites(force: true)
    }

    func addCustomDomain() {
        let raw = newDomain.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return }
        do {
            let d = try domainStore.addCustom(raw)
            newDomain = ""
            customDomains = domainStore.loadCustom()
            status = "Added \(d) — resolving…"
            resolveCustomDomains()
        } catch {
            status = "⚠️ \(error.localizedDescription)"
        }
    }

    func removeCustomDomain(_ d: String) {
        do {
            try domainStore.removeCustom(d)
            customDomains = domainStore.loadCustom()
            status = "Removed \(d)"
            resolveCustomDomains()
        } catch {
            status = "⚠️ \(error.localizedDescription)"
        }
    }

    private func resolveCustomDomains() {
        let store = domainStore
        Task { [weak self] in
            guard let self else { return }
            do {
                _ = try await Task.detached(priority: .utility) { try store.resolveCustomSync() }.value
                self.refreshInfo()
                if self.enabled { await self.reapplyIfNeeded(force: true) }
            } catch {
                self.status = "⚠️ \(error.localizedDescription)"
            }
        }
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

            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("Bypass extra websites").font(.caption).bold()
                    Spacer()
                    if !vm.customDomains.isEmpty {
                        Text("\(vm.customDomains.count) added")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                Text("Domains are resolved to IPs and routed outside the VPN (same switch).")
                    .font(.caption2).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    TextField("example.com", text: $vm.newDomain)
                        .textFieldStyle(.roundedBorder)
                        .font(.caption)
                        .onSubmit { vm.addCustomDomain() }
                    Button("Add") { vm.addCustomDomain() }
                        .controlSize(.small)
                        .disabled(vm.busy || vm.newDomain.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                if vm.customDomains.isEmpty {
                    Text("No custom domains yet — add one above.")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                } else {
                    // A bare ScrollView has no intrinsic height, so inside the
                    // MenuBarExtra window (which sizes to its content) it collapses
                    // to zero and the rows never appear. Give it an explicit height
                    // that grows with the number of domains, capped so it scrolls.
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(vm.customDomains, id: \.self) { d in
                                HStack(spacing: 6) {
                                    Image(systemName: "globe")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                    Text(d)
                                        .font(.caption2)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Spacer(minLength: 4)
                                    Button {
                                        vm.removeCustomDomain(d)
                                    } label: {
                                        Image(systemName: "trash")
                                    }
                                    .buttonStyle(.borderless)
                                    .controlSize(.mini)
                                    .help("Remove \(d)")
                                }
                                .frame(height: 18)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    .frame(height: min(CGFloat(vm.customDomains.count) * 20 + 4, 160))
                }
            }

            Divider()

            HStack {
                Button("Update IP list") { vm.updateList() }
                    .disabled(vm.busy)
                Button("Update websites") { vm.updateWebsites() }
                    .disabled(vm.busy)
                Spacer()
            }
            .buttonStyle(.bordered)
            .controlSize(.small)

            HStack {
                Button("GitHub repo") { NSWorkspace.shared.open(IPListStore.repoPageURL) }
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(14)
        .frame(width: 360)
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

if args.contains("--site-categories") {
    do {
        let data = try downloadSync(DomainListStore.geositeURL)
        let all = try Proto.parseGeoSiteList(data)
        for k in all.keys.sorted() { print("\(k): \(all[k]!.count) domains") }
    } catch {
        print("error: \(error.localizedDescription)")
        exit(1)
    }
    exit(0)
}
if args.contains("--update-websites") {
    do {
        let store = DomainListStore()
        let exclude = IPListStore().loadCached()
        let t0 = Date()
        let n = try store.updateSync(force: true, exclude: exclude) { done, total in
            if done % 1000 == 0 { FileHandle.standardError.write("resolved \(done)/\(total)\n".data(using: .utf8)!) }
        }
        let secs = Int(Date().timeIntervalSince(t0))
        print("website IPv4 routes: \(n.count) (after excluding \(exclude.count) Iranian ranges) in \(secs)s")
    } catch {
        print("error: \(error.localizedDescription)")
        exit(1)
    }
    exit(0)
}
if let i = args.firstIndex(of: "--dump-domains") {
    do {
        let all = try Proto.parseGeoSiteList(try downloadSync(DomainListStore.geositeURL))
        let cat = (i + 1 < args.count && !args[i + 1].hasPrefix("-")) ? args[i + 1] : "category-ir"
        let list = all[cat] ?? all[cat.uppercased()] ?? []
        print("\(cat): \(list.count) domains")
        for d in list.prefix(30) { print("  \(d)") }
    } catch {
        print("error: \(error.localizedDescription)")
        exit(1)
    }
    exit(0)
}
if let i = args.firstIndex(of: "--resolve"), i + 1 < args.count {
    let host = args[i + 1]
    let ips = DNS.resolveIPv4(host)
    print(ips.isEmpty ? "no IPv4 found" : ips.map { IPv4.string($0) }.joined(separator: "\n"))
    exit(0)
}
if args.contains("--custom-domains") {
    let store = DomainListStore()
    let list = store.loadCustom()
    if list.isEmpty {
        print("no custom domains")
    } else {
        print("\(list.count) custom domain(s):")
        for d in list { print("  \(d)") }
    }
    exit(0)
}
if let i = args.firstIndex(of: "--remove-domain"), i + 1 < args.count {
    let store = DomainListStore()
    let raw = args[i + 1]
    guard let d = DomainListStore.normalizeDomain(raw) else {
        print("error: “\(raw)” doesn’t look like a domain"); exit(1)
    }
    do {
        try store.removeCustom(d)
        print("removed \(d)")
    } catch {
        print("error: \(error.localizedDescription)"); exit(1)
    }
    exit(0)
}
if args.contains("--status") {
    let e = RouteEngine()
    print("applied record: \(e.hasAppliedRecord())")
    print("routes valid:   \(e.appliedRoutesValid())")
    print("needs reapply:  \(e.needsReapply())")
    if let m = (try? String(contentsOf: e.appliedMetaURL, encoding: .utf8))?.split(separator: "\n").map(String.init) {
        print("meta:           \(m.joined(separator: " / "))")
    } else {
        print("meta:           (none)")
    }
    if let g = e.defaultGateway() {
        print("gateway:        \(g.gw) (\(g.iface)) addr=\(e.interfaceIPv4(g.iface) ?? "-")")
    }
    exit(0)
}
if args.contains("--apply") || args.contains("--remove") {
    let e = RouteEngine()
    do {
        if args.contains("--remove") {
            let out = try e.removeSync()
            print("remove: \(out)")
        } else {
            let cidrs = aggregate(IPListStore().loadCached() + DomainListStore().loadResolved())
            guard let g = e.defaultGateway() else { print("error: no gateway"); exit(1) }
            print("applying \(cidrs.count) routes via \(g.gw) (\(g.iface))…")
            let out = try e.applySync(cidrs: cidrs, gateway: g.gw, iface: g.iface)
            print("apply: \(out)")
        }
    } catch {
        print("error: \(error.localizedDescription)")
        exit(1)
    }
    exit(0)
}
if args.contains("--instances") {
    let bid = Bundle.main.bundleIdentifier ?? "local.iranbypass"
    let apps = NSRunningApplication.runningApplications(withBundleIdentifier: bid)
    print("\(apps.count) instance(s) of \(bid):")
    for a in apps {
        print("  pid=\(a.processIdentifier) started=\(a.launchDate.map { "\($0)" } ?? "-")")
    }
    exit(0)
}

// Single-instance guard: launching a second copy (e.g. from another path) would
// add a second menu bar icon, each with its own on/off state. If another live
// instance of this bundle exists, exit quietly (after briefly waiting in case a
// previous instance is still shutting down).
if let bid = Bundle.main.bundleIdentifier, !args.contains("--allow-multi") {
    let me = NSRunningApplication.current
    func liveOthers() -> [NSRunningApplication] {
        NSRunningApplication.runningApplications(withBundleIdentifier: bid)
            .filter { $0.processIdentifier != me.processIdentifier && !$0.isTerminated }
    }
    var waited = 0
    while !liveOthers().isEmpty && waited < 2000 {
        usleep(200_000)
        waited += 200
    }
    if !liveOthers().isEmpty { exit(0) }
}

IranBypassApp.main()
