#!/usr/bin/env bash
# Install the scanner binaries RedFox adapters use into tools/bin.
# Linux/macOS. Windows: use scripts/install-tools.ps1.
set -euo pipefail

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

install_zip() { # name, repo, pattern
  local name=$1 repo=$2 pattern=$3 url
  url="$(latest_url "$repo" "$pattern")"
  if [ -z "$url" ]; then echo "!! no release asset for $name ($pattern)"; return 1; fi
  echo "-> $name  $url"
  curl -fsSL "$url" -o "$TMP/$name.zip"
  if command -v unzip >/dev/null; then unzip -qo "$TMP/$name.zip" -d "$TMP/$name"
  else python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$TMP/$name.zip" "$TMP/$name"; fi
  find "$TMP/$name" -type f -name "$name" -perm -u+x -exec cp {} "$BIN/" \; 2>/dev/null || \
    find "$TMP/$name" -type f -name "$name" -exec cp {} "$BIN/" \;
  chmod +x "$BIN/$name"
}

install_zip nuclei   projectdiscovery/nuclei   "${os}_${a}\.zip"
install_zip httpx    projectdiscovery/httpx    "${os}_${a}\.zip"
install_zip subfinder projectdiscovery/subfinder "${os}_${a}\.zip"
install_zip ffuf     ffuf/ffuf                 "${os}_${a}\.zip"

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