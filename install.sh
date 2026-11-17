#!/bin/sh
# Installs ferry on macOS or Linux: downloads the release binary for this
# machine, checks it against the published checksum, and runs `ferry install`
# (background service that starts at boot).
#
#   curl -fsSL https://raw.githubusercontent.com/R44VC0RP/ferry/main/install.sh | sh
#
# Arguments go to `ferry install`, e.g. `... | sh -s -- --name laptop`.
set -eu

REPO="R44VC0RP/ferry"
BASE="https://github.com/$REPO/releases/latest/download"

# Everything runs from a function so a download cut off halfway runs nothing.
main() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) asset=ferry-macos-arm64 ;;
    Linux-x86_64) asset=ferry-linux-x64 ;;
    Linux-aarch64 | Linux-arm64) asset=ferry-linux-arm64 ;;
    *)
      echo "ferry: no prebuilt binary for $(uname -s) $(uname -m)." >&2
      echo "Build it instead: cargo install --git https://github.com/$REPO && ferry install" >&2
      exit 1
      ;;
  esac

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/ferry" "$BASE/$asset"
  curl -fsSL -o "$tmp/SHA256SUMS" "$BASE/SHA256SUMS"

  want=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$tmp/ferry" | awk '{ print $1 }')
  else
    got=$(shasum -a 256 "$tmp/ferry" | awk '{ print $1 }')
  fi
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    echo "ferry: checksum mismatch for $asset, not installing." >&2
    exit 1
  fi

  chmod +x "$tmp/ferry"
  "$tmp/ferry" install "$@"
}

main "$@"
