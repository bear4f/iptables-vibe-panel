#!/usr/bin/env bash
# POSIX sh 兼容（可用 sh/bash/ash 运行）：不用数组、不用 pipefail。
set -eu

TARGET="/usr/local/bin/ipt-vibe"
SHORTCUT="/usr/local/bin/zf"
STATE_DIR="/etc/ipt-vibe-panel"
OLD_SERVICE="/etc/systemd/system/iptables-vibe-panel.service"

# 主源 + 国内可达镜像。GitHub raw 在部分网络会被干扰（返回 400 / 超时），
# 逐个尝试直到某个镜像成功。可用环境变量 IPT_VIBE_RAW_BASE 指定优先源。
MIRRORS="
https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main
https://cdn.jsdelivr.net/gh/bear4f/iptables-vibe-panel@main
https://ghproxy.net/https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main
https://raw.gitmirror.com/bear4f/iptables-vibe-panel/main
https://gh-proxy.com/https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main
"
if [ -n "${IPT_VIBE_RAW_BASE:-}" ]; then
  MIRRORS="$IPT_VIBE_RAW_BASE
$MIRRORS"
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root. Example: curl -fsSL <install-url> | sudo bash"
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get update || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables iptables-persistent netfilter-persistent curl ca-certificates dnsutils || true
else
  echo "apt-get not found. Please make sure iptables, ip6tables, curl and DNS tools are installed."
fi

mkdir -p "$STATE_DIR"

# 清理旧版可能遗留的常驻服务
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^iptables-vibe-panel.service'; then
  systemctl disable --now iptables-vibe-panel >/dev/null 2>&1 || true
fi
rm -f "$OLD_SERVICE"
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true

# 逐镜像下载 ipt-vibe.sh，校验非空 + 含 VERSION 标记（避免把 400/HTML 错误页当成脚本）。
fetch_panel(){
  tmp="$STATE_DIR/.ipt-vibe.dl.$$"
  for base in $MIRRORS; do
    echo "Downloading ipt-vibe.sh from: $base"
    if curl -fsSL "$base/ipt-vibe.sh" -o "$tmp" 2>/dev/null && [ -s "$tmp" ] && grep -q '^VERSION=' "$tmp"; then
      install -m 0755 "$tmp" "$TARGET"; rm -f "$tmp"; return 0
    fi
    rm -f "$tmp"
    echo "  -> failed, trying next mirror..."
  done
  return 1
}

if [ -f "ipt-vibe.sh" ]; then
  install -m 0755 ipt-vibe.sh "$TARGET"
elif ! fetch_panel; then
  echo "All download sources failed. Check network / GitHub access,"
  echo "or set IPT_VIBE_RAW_BASE to a reachable mirror and retry."
  exit 1
fi

ln -sf "$TARGET" "$SHORTCUT"

echo "Installed terminal panel."
echo "Run: zf"
echo "Or : ipt-vibe"
