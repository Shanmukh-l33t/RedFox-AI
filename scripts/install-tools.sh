#!/usr/bin/env bash
# Install the scanner binaries RedFox adapters use into tools/bin.
# Linux/macOS. Windows: use scripts/install-tools.ps1.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/tools/bin"
TMP="$(mktemp -d)"
mkdir -p "$BIN"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$os" in
  linux)  plat="linux" ;;
  darwin) plat="macOS" ;;
  *) echo "unsupported OS: $os (use install-tools.ps1 on Windows)" >&2; exit 1 ;;
esac
case "$arch" in
  x86_64|amd64) a="amd64" ;;
  aarch64|arm64) a="arm64" ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

latest_url() { # repo, regex
  curl -fsSL "https://api.github.com/repos/$1/releases/latest" \
    | grep -o '"browser_download_url": *"[^"]*"' \
    | sed 's/.*"\(http[^"]*\)"/\1/' \
    | grep -E "$2" | head -1
}

install_pkg() { # name, repo, pattern
  local name=$1 repo=$2 pattern=$3 url dest
  url="$(latest_url "$repo" "$pattern")"
  if [ -z "$url" ]; then
    echo "!! no release asset for $name ($pattern) — skipping"
    return 0
  fi
  echo "-> $name  $url"
  dest="$TMP/$name"
  mkdir -p "$dest"
  case "$url" in
    *.zip)    curl -fsSL "$url" -o "$TMP/$name.zip" && unzip -qo "$TMP/$name.zip" -d "$dest" ;;
    *.tar.gz) curl -fsSL "$url" -o "$TMP/$name.tgz" && tar -xzf "$TMP/$name.tgz" -C "$dest" ;;
    *) echo "!! unsupported archive for $name: $url"; return 0 ;;
  esac || { echo "!! download/extract failed for $name"; return 0; }
  find "$dest" -type f -name "$name" -exec cp {} "$BIN/" \;
  [ -f "$BIN/$name" ] && chmod +x "$BIN/$name" || echo "!! $name binary not found in archive"
}

# ProjectDiscovery ship .zip on linux/windows and .zip on macOS; ffuf ships .tar.gz.
install_pkg nuclei    projectdiscovery/nuclei    "${os}_${a}\.(zip|tar\.gz)$"
install_pkg httpx     projectdiscovery/httpx     "${os}_${a}\.(zip|tar\.gz)$"
install_pkg subfinder projectdiscovery/subfinder "${os}_${a}\.(zip|tar\.gz)$"
install_pkg ffuf      ffuf/ffuf                 "${os}_${a}\.(zip|tar\.gz)$"

if ! command -v nmap >/dev/null; then
  echo "!! nmap is not installed. Install it with your package manager:"
  echo "     Debian/Ubuntu: sudo apt install nmap"
  echo "     macOS:         brew install nmap"
fi
command -v ruby >/dev/null || echo "!! ruby missing: the whatweb adapter needs it"
command -v sslscan >/dev/null || echo "!! sslscan missing: install it for TLS checks (optional)"

rm -rf "$TMP"
echo
echo "Installed into $BIN:"
ls -1 "$BIN" | sed 's/^/  /'
echo
echo "Run 'nuclei -update-templates' once, then 'redfox tools' to confirm."