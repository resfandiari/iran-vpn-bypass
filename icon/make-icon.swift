// App icon generator for IranBypass.
// Usage: swift icon/make-icon.swift <output-iconset-dir>
// Draws every size Apple's iconset expects, then `iconutil -c icns` builds the .icns.

import AppKit

let outDir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"

let sizes: [(name: String, px: Int)] = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
]

func newRep(w: Int, h: Int) -> NSBitmapImageRep? {
    NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h,
                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                     isPlanar: false, colorSpaceName: NSColorSpaceName.deviceRGB,
                     bytesPerRow: 0, bitsPerPixel: 0)
}

/// Recolor a template (symbol) image to solid white.
func tintWhite(_ img: NSImage) -> NSImage {
    let w = max(Int(img.size.width.rounded(.up)), 1)
    let h = max(Int(img.size.height.rounded(.up)), 1)
    guard let rep = newRep(w: w, h: h) else { return img }
    rep.size = img.size
    if let ctx = NSGraphicsContext(bitmapImageRep: rep) {
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = ctx
        img.draw(in: NSRect(origin: .zero, size: img.size), from: .zero,
                 operation: .sourceOver, fraction: 1)
        let cg = ctx.cgContext
        cg.saveGState()
        cg.setBlendMode(.sourceAtop)
        cg.setFillColor(NSColor.white.cgColor)
        cg.fill(NSRect(origin: .zero, size: img.size))
        cg.restoreGState()
        NSGraphicsContext.restoreGraphicsState()
    }
    let out = NSImage(size: img.size)
    out.addRepresentation(rep)
    return out
}

func render(px: Int) -> Data? {
    guard let rep = newRep(w: px, h: px), let ctx = NSGraphicsContext(bitmapImageRep: rep) else { return nil }
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = ctx
    defer { NSGraphicsContext.restoreGraphicsState() }
    let s = CGFloat(px)

    // Background: Big Sur-style rounded square (824/1024 box, radius 185.4/1024)
    let inset = s * 0.125
    let box = NSRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let path = NSBezierPath(roundedRect: box, xRadius: s * 0.1805, yRadius: s * 0.1805)

    let shadow = NSShadow()
    shadow.shadowBlurRadius = s * 0.02
    shadow.shadowOffset = NSSize(width: 0, height: -s * 0.008)
    shadow.shadowColor = NSColor.black.withAlphaComponent(0.25)
    shadow.set()
    NSColor(red: 0.03, green: 0.30, blue: 0.82, alpha: 1).setFill()
    path.fill()
    NSShadow().set() // clear shadow before the gradient pass

    NSGraphicsContext.current?.saveGraphicsState()
    path.addClip()
    if let g = NSGradient(colors: [
        NSColor(red: 0.18, green: 0.58, blue: 1.00, alpha: 1),
        NSColor(red: 0.02, green: 0.28, blue: 0.78, alpha: 1),
    ]) {
        g.draw(in: box, angle: -55)
    }
    NSGraphicsContext.current?.restoreGraphicsState()

    // Foreground: white shield (same glyph family as the menu bar icon)
    if let base = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: nil) {
        let ps = s * 0.52
        let scaled = base.withSymbolConfiguration(.init(pointSize: ps, weight: .medium)) ?? base
        let white = tintWhite(scaled)
        let d = NSRect(x: (s - white.size.width) / 2, y: (s - white.size.height) / 2,
                       width: white.size.width, height: white.size.height)
        white.draw(in: d, from: .zero, operation: .sourceOver, fraction: 1)
    }

    return rep.representation(using: .png, properties: [:])
}

try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)
for (name, px) in sizes {
    guard let data = render(px: px) else {
        print("failed to render \(name)"); exit(1)
    }
    try data.write(to: URL(fileURLWithPath: outDir).appendingPathComponent(name))
    print("wrote \(name) (\(px)px)")
}
