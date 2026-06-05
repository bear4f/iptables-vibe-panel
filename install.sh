#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/iptables-vibe-panel"
SERVICE_FILE="/etc/systemd/system/iptables-vibe-panel.service"
PORT="${IPT_VIBE_PORT:-8088}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3
fi

if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables
fi

if ! command -v netfilter-persistent >/dev/null 2>&1; then
  echo "netfilter-persistent is not installed; rules will be saved to /etc/iptables/rules.v4."
  echo "Recommended on Debian/Ubuntu: apt-get install -y iptables-persistent netfilter-persistent"
fi

mkdir -p "$APP_DIR" /etc/ipt-vibe-panel
install -m 0755 app.py "$APP_DIR/app.py"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=iptables Vibe Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=IPT_VIBE_PORT=$PORT
ExecStart=/usr/bin/python3 $APP_DIR/app.py --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable iptables-vibe-panel
systemctl restart iptables-vibe-panel

echo "Installed. Open: http://SERVER_IP:$PORT"
echo "Status: systemctl status iptables-vibe-panel --no-pager"
