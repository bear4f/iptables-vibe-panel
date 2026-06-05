#!/usr/bin/env bash
set -euo pipefail

RAW_BASE="${IPT_VIBE_RAW_BASE:-https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main}"
TARGET="/usr/local/bin/ipt-vibe"
SHORTCUT="/usr/local/bin/zf"
STATE_DIR="/etc/ipt-vibe-panel"
OLD_SERVICE="/etc/systemd/system/iptables-vibe-panel.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root. Example: curl -fsSL $RAW_BASE/install.sh | sudo bash"
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables curl ca-certificates dnsutils
else
  echo "apt-get not found. Please make sure iptables, curl and DNS tools are installed."
fi

mkdir -p "$STATE_DIR"

if systemctl list-unit-files 2>/dev/null | grep -q '^iptables-vibe-panel.service'; then
  systemctl disable --now iptables-vibe-panel >/dev/null 2>&1 || true
fi
rm -f "$OLD_SERVICE"
systemctl daemon-reload >/dev/null 2>&1 || true

if [ -f "ipt-vibe.sh" ]; then
  install -m 0755 ipt-vibe.sh "$TARGET"
else
  curl -fsSL "$RAW_BASE/ipt-vibe.sh" -o "$TARGET"
  chmod 0755 "$TARGET"
fi

ln -sf "$TARGET" "$SHORTCUT"

echo "Installed terminal panel."
echo "Run: zf"
echo "Or : ipt-vibe"
