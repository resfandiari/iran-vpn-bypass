#!/bin/bash
# Build IranBypass.app into ./dist
set -euo pipefail
cd "$(dirname "$0")"

APP="dist/IranBypass.app"
rm -rf dist
mkdir -p "$APP/Contents/MacOS"

swiftc -O -o "$APP/Contents/MacOS/IranBypass" main.swift
cp Info.plist "$APP/Contents/Info.plist"
codesign --force --sign - "$APP" >/dev/null 2>&1 || true

echo "Built $APP"
