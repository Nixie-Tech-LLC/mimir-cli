#!/usr/bin/env sh
# Install the mimir CLI on Linux/macOS. Downloads the latest `cli/v*` release binary from GitHub.
#   curl -fsSL https://raw.githubusercontent.com/Nixie-Tech-LLC/mimir-cli/main/install.sh | sh
# Override: MIMIR_VERSION=v0.2.0  INSTALL_DIR=~/.local/bin  sh install.sh
set -eu

REPO="Nixie-Tech-LLC/mimir-cli"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in linux|darwin) ;; *) echo "unsupported OS: $os (use Scoop on Windows)"; exit 1;; esac
arch=$(uname -m)
case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo "unsupported arch: $arch"; exit 1;; esac

# resolve the latest cli/v* tag (the repo may hold non-CLI releases too)
if [ "${MIMIR_VERSION:-}" != "" ]; then
  tag="$MIMIR_VERSION"; case "$tag" in cli/*) ;; *) tag="cli/$tag";; esac
else
  tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=30" \
    | grep -o '"tag_name": *"cli/[^"]*"' | head -1 | sed 's/.*"cli\//cli\//;s/"//')
fi
[ -n "$tag" ] || { echo "no cli/v* release found"; exit 1; }
ver=${tag#cli/}; ver=${ver#v}

asset="mimir_${ver}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$tag/$asset"
echo "Installing mimir $ver ($os/$arch) -> $INSTALL_DIR"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/$asset" || { echo "download failed: $url"; exit 1; }
tar -xzf "$tmp/$asset" -C "$tmp"
if [ -w "$INSTALL_DIR" ]; then install -m 0755 "$tmp/mimir" "$INSTALL_DIR/mimir"; else sudo install -m 0755 "$tmp/mimir" "$INSTALL_DIR/mimir"; fi
echo "Installed: $("$INSTALL_DIR/mimir" version)"
