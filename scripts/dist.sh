#!/bin/sh
# Builds ferry for every OS from this Mac into dist/<os>-<arch>/.
# Needs: rustup targets (musl x64/arm64, windows-gnu), zig, cargo-zigbuild.
set -eu
cd "$(dirname "$0")/.."
PATH="$(dirname "$(rustup which cargo)"):$PATH"
SIGN_ID="${FERRY_SIGN_ID:-Developer ID Application: Ryan Vogel (9G68SMNHEU)}"

mkdir -p dist/macos-arm64 dist/linux-x64 dist/linux-arm64 dist/windows-x64
cargo build --release
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
cargo zigbuild --release --target x86_64-pc-windows-gnu

cp target/release/ferry dist/macos-arm64/ferry
# A stable signing identity keeps macOS privacy grants across updates.
codesign --force -s "$SIGN_ID" --identifier dev.vogel.ferry --timestamp=none dist/macos-arm64/ferry
cp target/x86_64-unknown-linux-musl/release/ferry dist/linux-x64/ferry
cp target/aarch64-unknown-linux-musl/release/ferry dist/linux-arm64/ferry
cp target/x86_64-pc-windows-gnu/release/ferry.exe dist/windows-x64/ferry.exe

# Release assets, named the way install.sh and install.ps1 fetch them.
rm -rf dist/release && mkdir -p dist/release
cp dist/macos-arm64/ferry dist/release/ferry-macos-arm64
cp dist/linux-x64/ferry dist/release/ferry-linux-x64
cp dist/linux-arm64/ferry dist/release/ferry-linux-arm64
cp dist/windows-x64/ferry.exe dist/release/ferry-windows-x64.exe
(cd dist/release && shasum -a 256 ferry-* > SHA256SUMS)
ls -l dist/release
