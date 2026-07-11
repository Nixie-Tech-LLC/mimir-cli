#!/usr/bin/env sh
# Install the mimir CLI on Linux/macOS. Downloads the latest release binary from GitHub.
#   curl -fsSL https://raw.githubusercontent.com/Nixie-Tech-LLC/mimir-cli/main/install.sh | sh
# Override: MIMIR_VERSION=v0.2.0  INSTALL_DIR=~/.local/bin  sh install.sh
set -eu

REPO="Nixie-Tech-LLC/mimir-cli"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux|darwin) ;; *) echo "unsupported OS: $os (use Scoop on Windows)"; exit 1;; esac
arch=$(uname -m)
case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo "unsupported arch: $arch"; exit 1;; esac

if [ "${MIMIR_VERSION:-}" != "" ]; then
  tag="$MIMIR_VERSION"; case "$tag" in v*) ;; *) tag="v$tag";; esac
else
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*: *"//;s/"//')
fi
[ -n "$tag" ] || { echo "no release found for $REPO"; exit 1; }
ver=${tag#v}

asset="mimir_${ver}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$asset"
echo "Installing mimir $ver ($os/$arch) -> $INSTALL_DIR"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/$asset" || { echo "download failed: $url"; exit 1; }
tar -xzf "$tmp/$asset" -C "$tmp"
if [ -w "$INSTALL_DIR" ]; then install -m 0755 "$tmp/mimir" "$INSTALL_DIR/mimir"; else sudo install -m 0755 "$tmp/mimir" "$INSTALL_DIR/mimir"; fi
echo "Installed: $("$INSTALL_DIR/mimir" version)"
