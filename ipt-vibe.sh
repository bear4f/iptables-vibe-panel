#!/usr/bin/env bash
set -uo pipefail

APP_NAME="iptables Vibe Panel"
VERSION="0.5.0"
RAW_BASE="${IPT_VIBE_RAW_BASE:-https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main}"
STATE_DIR="/etc/ipt-vibe-panel"
RULES_FILE="$STATE_DIR/rules.conf"
BACKUP_DIR="$STATE_DIR/backups"
LOG_FILE="$STATE_DIR/panel.log"
TAG="ipt-vibe:"

# Realm 用户态双栈转发引擎（用于 IPv6 入口、IPv6->IPv4 跨族转发，iptables DNAT 做不到）。
REALM_VERSION="${IPT_VIBE_REALM_VERSION:-v2.9.6}"
REALM_BIN="/usr/local/bin/realm"
REALM_CONF="$STATE_DIR/realm.toml"
REALM_SERVICE="ipt-vibe-realm.service"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; RESET='\033[0m'

need_root(){ [ "$(id -u)" -eq 0 ] || { echo -e "${RED}请使用 root 运行：sudo zf${RESET}"; exit 1; }; }
ensure_dirs(){ mkdir -p "$STATE_DIR" "$BACKUP_DIR"; touch "$RULES_FILE"; }
log(){
  mkdir -p "$STATE_DIR" 2>/dev/null
  echo "[$(date '+%F %T')] $*" >> "$LOG_FILE" 2>/dev/null
  if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)" -gt 1048576 ]; then
    tail -n 500 "$LOG_FILE" > "$LOG_FILE.tmp" 2>/dev/null && mv "$LOG_FILE.tmp" "$LOG_FILE" 2>/dev/null || true
  fi
}
line(){ echo -e "${BLUE}========================================${RESET}"; }
short_line(){ echo -e "${YELLOW}----------------------------------------${RESET}"; }

read_tty(){
  local __var="$1" prompt="$2"
  if [ -r /dev/tty ]; then
    IFS= read -r -p "$prompt" "$__var" < /dev/tty
  else
    IFS= read -r -p "$prompt" "$__var"
  fi
}
trim(){ printf '%s' "$1" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
pause(){ local _p; echo; read_tty _p "按 Enter 返回菜单..." || true; }

os_name(){ if [ -r /etc/os-release ]; then . /etc/os-release; echo "${PRETTY_NAME:-Linux}"; else uname -sr; fi; }
iptables_backend(){ command -v iptables >/dev/null 2>&1 && iptables --version 2>/dev/null | sed 's/^iptables //' || echo "未安装"; }
ip_forward_status(){ [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] && echo "已开启" || echo "未开启"; }
conntrack_status(){
  local c m
  c=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
  m=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
  [ -n "$c" ] && [ -n "$m" ] && echo "$c / $m" || echo "未加载"
}
mem_status(){ free -m 2>/dev/null | awk '/^Mem:/{printf "%sMB / %sMB", $3, $2}' || echo "未知"; }
managed_count(){ grep -cv '^\s*\(#\|$\)' "$RULES_FILE" 2>/dev/null || echo 0; }
enabled_count(){ awk -F'|' '$3=="1"{c++} END{print c+0}' "$RULES_FILE" 2>/dev/null; }
valid_port(){ echo "$1" | grep -Eq '^[0-9]+$' && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
valid_ip4_or_empty(){
  [ -z "$1" ] && return 0
  echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
  local o oldifs="$IFS"; IFS='.'
  for o in $1; do [ "$o" -ge 0 ] && [ "$o" -le 255 ] || { IFS="$oldifs"; return 1; }; done
  IFS="$oldifs"
}
valid_host(){ local h="$1"; [ -n "$h" ] || return 1; echo "$h" | grep -Eq '^[A-Za-z0-9._-]+$' || return 1; echo "$h" | grep -Eq '(^-|-$|\.\.)' && return 1; return 0; }
is_ipv4(){ echo "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; }
is_ipv6(){ echo "$1" | grep -Eq '^[0-9A-Fa-f:]+$' && echo "$1" | grep -q ':'; }
# 单条来源条目校验：IPv4/CIDR 或 IPv6/CIDR。
valid_allow_entry(){
  local e="$1" ipp pfx o
  if echo "$e" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
    ipp="${e%%/*}"; case "$e" in */*) pfx="${e#*/}";; *) pfx=32;; esac
    { [ "$pfx" -ge 0 ] && [ "$pfx" -le 32 ]; } 2>/dev/null || return 1
    local oldifs="$IFS"; IFS='.'
    for o in $ipp; do { [ "$o" -ge 0 ] && [ "$o" -le 255 ]; } 2>/dev/null || { IFS="$oldifs"; return 1; }; done
    IFS="$oldifs"; return 0
  fi
  # IPv6/CIDR：宽松校验，最终由 ip6tables 兜底判定
  if echo "$e" | grep -Eq '^[0-9A-Fa-f:]+(/[0-9]{1,3})?$' && echo "$e" | grep -q ':'; then
    case "$e" in */*) pfx="${e#*/}"; { [ "$pfx" -ge 0 ] && [ "$pfx" -le 128 ]; } 2>/dev/null || return 1;; esac
    return 0
  fi
  return 1
}
# 来源白名单：逗号分隔的 IPv4/IPv6（可带 CIDR），留空表示允许所有来源。
valid_allow_or_empty(){
  [ -z "$1" ] && return 0
  local e
  for e in $(echo "$1" | tr ',' ' '); do valid_allow_entry "$e" || return 1; done
  return 0
}
# 从来源白名单里取出 IPv4 / IPv6 条目（逗号分隔）。
allow_v4(){ local e out=""; for e in $(echo "$1" | tr ',' ' '); do case "$e" in *:*) ;; *) out="${out:+$out,}$e";; esac; done; echo "$out"; }
allow_v6(){ local e out=""; for e in $(echo "$1" | tr ',' ' '); do case "$e" in *:*) out="${out:+$out,}$e";; esac; done; echo "$out"; }

# 本机是否有全局可路由的公网 IPv6（排除 fe80 链路本地与 fc00::/7 ULA）。
has_public_ipv6(){
  ip -6 addr show scope global 2>/dev/null | awk '/inet6/{print $2}' \
    | grep -Eqv '^(fe80|fc|fd)' 2>/dev/null
}
# 本机主用 IPv4 是否为私网/CGNAT（说明在 NAT 后面，iptables DNAT 收不到外部到公网 IP 的流量）。
ipv4_is_nat(){
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  [ -n "$ip" ] || ip=$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | head -1 | cut -d/ -f1)
  [ -n "$ip" ] || return 1
  echo "$ip" | grep -Eq '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'
}

resolve_host(){
  local host="$1" ip=""
  if echo "$host" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then echo "$host"; return 0; fi
  if command -v getent >/dev/null 2>&1; then
    ip=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')
    echo "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && { echo "$ip"; return 0; }
  fi
  if command -v host >/dev/null 2>&1; then
    ip=$(host -t A "$host" 2>/dev/null | awk '/has address/ {print $4; exit}')
    echo "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && { echo "$ip"; return 0; }
  fi
  return 1
}

next_id(){ date +%s%N | cut -c1-12; }
port_label(){ [ "$1" = "$2" ] && echo "$1" || echo "$1-$2"; }
port_match(){ [ "$1" = "$2" ] && echo "$1" || echo "$1:$2"; }
dnat_target(){ [ "$2" = "$3" ] && echo "$1:$2" || echo "$1:$2-$3"; }

install_deps(){
  clear; line; echo -e "${CYAN}安装/检查依赖${RESET}"; line
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables iptables-persistent netfilter-persistent curl ca-certificates dnsutils
  else
    echo -e "${YELLOW}未检测到 apt-get，请手动安装 iptables、curl。${RESET}"
  fi
  echo -e "${GREEN}依赖检查完成。${RESET}"; pause
}

enable_forward(){
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
  if [ -d /etc/sysctl.d ]; then
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-ipt-vibe-panel.conf
  else
    touch /etc/sysctl.conf
    sed -i '/^\s*#\?\s*net\.ipv4\.ip_forward\s*=/d' /etc/sysctl.conf
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  fi
  sysctl -p >/dev/null 2>&1 || true
}

# conntrack 调优：转发节点的内存主要消耗在内核连接跟踪表上。
# 默认 tcp established 超时是 432000 秒（5 天），空闲连接会长期占用内存，
# 高流量/UDP(VPN) 场景下连接跟踪表膨胀，容易触发 OOM 导致死机或重启。
# 这里缩短过期时间，让陈旧连接尽快释放，从源头压低内存占用；
# 同时按内存自动扩容连接跟踪表并加大哈希桶，避免高并发时“table full”丢包。
tune_conntrack(){
  modprobe nf_conntrack 2>/dev/null || true
  [ -d /etc/modules-load.d ] && echo 'nf_conntrack' > /etc/modules-load.d/ipt-vibe.conf 2>/dev/null || true

  # 依据物理内存自动计算连接跟踪表上限：既避免高流量时“table full”导致丢包，
  # 又不至于在小内存 VPS 上把内存吃满触发 OOM（每条连接约 300 字节）。
  local ram_mb ctmax hashsize
  ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null)
  { [ -n "$ram_mb" ] && [ "$ram_mb" -gt 0 ] 2>/dev/null; } || ram_mb=1024
  ctmax=$((ram_mb*256))
  [ "$ctmax" -lt 65536 ] && ctmax=65536
  [ "$ctmax" -gt 1048576 ] && ctmax=1048576
  hashsize=$((ctmax/8)); [ "$hashsize" -lt 16384 ] && hashsize=16384

  # hashsize 是模块参数（非 sysctl）：加大哈希桶可缩短冲突链、加快查表，
  # 降低高并发下的查找开销与丢包。live 写入 /sys，并落 modprobe.d 让重启后仍生效。
  echo "$hashsize" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
  [ -d /etc/modprobe.d ] && echo "options nf_conntrack hashsize=$hashsize" > /etc/modprobe.d/ipt-vibe-conntrack.conf 2>/dev/null || true

  local f=/etc/sysctl.d/99-ipt-vibe-conntrack.conf
  cat > "$f" <<EOF
# ipt-vibe-panel: 转发节点 conntrack 调优，降低内存占用、加快连接过期回收、减少丢包
net.netfilter.nf_conntrack_max = $ctmax
# 中转链路常见非对称/乱序，be_liberal=1 避免把窗口外的正常包误判为 INVALID 而丢弃
net.netfilter.nf_conntrack_tcp_be_liberal = 1
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_generic_timeout = 120
# UDP/VPN 依赖 NAT 映射存活，超时略放宽，减少 keepalive 间隙丢失映射导致的重连/丢包
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
EOF
  sysctl -p "$f" >/dev/null 2>&1 || true
}

backup_rules(){
  ensure_dirs
  command -v iptables-save >/dev/null 2>&1 || { echo ""; return; }
  local file="$BACKUP_DIR/iptables-$(date +%Y%m%d-%H%M%S).rules"
  iptables-save > "$file"
  # 仅保留最近 10 份备份，避免备份目录无限增长占用磁盘
  ls -1t "$BACKUP_DIR"/iptables-*.rules 2>/dev/null | tail -n +11 | while IFS= read -r old; do rm -f "$old"; done
  echo "$file"
}

# 保证规则在重启/死机后能自动恢复。
# 之前只把规则写进 /etc/iptables/rules.v4，但如果系统没装 netfilter-persistent，
# 开机时没有任何东西去加载这个文件，重启后转发规则就全部丢失，必须手动重新应用。
# 这里按可用能力自动落地一个开机恢复机制（systemd oneshot 或 cron @reboot）。
ensure_boot_restore(){
  local iptr ip6tr
  iptr=$(command -v iptables-restore 2>/dev/null) || iptr=/sbin/iptables-restore
  ip6tr=$(command -v ip6tables-restore 2>/dev/null) || ip6tr=/sbin/ip6tables-restore
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/ipt-vibe-restore.service <<EOF
[Unit]
Description=Restore ipt-vibe-panel iptables rules on boot
DefaultDependencies=no
After=systemd-modules-load.service local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'test -f /etc/iptables/rules.v4 && $iptr < /etc/iptables/rules.v4'
ExecStart=/bin/sh -c 'test -f /etc/iptables/rules.v6 && $ip6tr < /etc/iptables/rules.v6 || true'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable ipt-vibe-restore.service >/dev/null 2>&1 || true
    echo "ipt-vibe-restore.service (systemd)"
  elif [ -d /etc/cron.d ]; then
    { printf '@reboot root %s < /etc/iptables/rules.v4\n' "$iptr"
      printf '@reboot root test -f /etc/iptables/rules.v6 && %s < /etc/iptables/rules.v6\n' "$ip6tr"
    } > /etc/cron.d/ipt-vibe-restore
    chmod 0644 /etc/cron.d/ipt-vibe-restore 2>/dev/null || true
    echo "cron @reboot"
  else
    echo "/etc/iptables/rules.v4（无法安装开机恢复，请手动安装 iptables-persistent）"
  fi
}

save_persistent(){
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  if command -v netfilter-persistent >/dev/null 2>&1; then
    # 已安装 netfilter-persistent，其自带的 systemd 服务会在开机时恢复 rules.v4/rules.v6
    netfilter-persistent save >/dev/null 2>&1 || true
    echo "netfilter-persistent"
  else
    ensure_boot_restore
  fi
}

delete_chain_by_comment(){
  local table="$1" chain="$2" cmd="${3:-iptables}" num=""
  command -v "$cmd" >/dev/null 2>&1 || return 0
  while true; do
    if [ -n "$table" ]; then
      num=$("$cmd" -t "$table" -L "$chain" --line-numbers -n 2>/dev/null | awk -v tag="$TAG" 'index($0,tag){print $1; exit}')
    else
      num=$("$cmd" -L "$chain" --line-numbers -n 2>/dev/null | awk -v tag="$TAG" 'index($0,tag){print $1; exit}')
    fi
    [ -n "$num" ] || break
    if [ -n "$table" ]; then "$cmd" -t "$table" -D "$chain" "$num" >/dev/null 2>&1 || break; else "$cmd" -D "$chain" "$num" >/dev/null 2>&1 || break; fi
  done
}

# 应用一批全局（与单条规则无关）的转发优化规则。
# MSS 钳制：按路径 MTU 修正 TCP 三次握手时通告的 MSS，避免大包在中转/隧道
# 链路上因 PMTU 黑洞被丢弃，导致 TCP 卡死/丢包（网页打不开、大文件卡住的常见根因）。
apply_global_rules(){
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "${TAG}mss" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
}

delete_managed_iptables_rules(){
  command -v iptables >/dev/null 2>&1 || return 0
  delete_chain_by_comment nat PREROUTING
  delete_chain_by_comment nat POSTROUTING
  delete_chain_by_comment mangle FORWARD
  delete_chain_by_comment "" FORWARD
  delete_chain_by_comment "" INPUT
  # Realm 白名单可能在 ip6tables INPUT 上留有规则，一并清理。
  delete_chain_by_comment "" INPUT ip6tables
  command -v iptables-save >/dev/null 2>&1 || return 0
  iptables-save | grep -- "$TAG" | grep '^-A ' | while IFS= read -r rule; do
    local chain del_rule
    chain=$(echo "$rule" | awk '{print $2}')
    del_rule=$(echo "$rule" | sed 's/^-A /-D /')
    if [ "$chain" = "PREROUTING" ] || [ "$chain" = "POSTROUTING" ]; then iptables -t nat $del_rule >/dev/null 2>&1 || true; else iptables $del_rule >/dev/null 2>&1 || true; fi
  done
}

add_rule_to_iptables(){
  local id="$1" listen_ip="$2" ls="$3" le="$4" target_host="$5" ts="$6" te="$7" protos="$8" allow="${9:-}"
  local ip mark lp tp target proto pre fwd
  ip=$(resolve_host "$target_host") || { echo -e "${RED}目标解析失败：$target_host${RESET}"; return 1; }
  [ -n "$ip" ] || { echo -e "${RED}目标解析为空：$target_host${RESET}"; return 1; }
  echo -e "${CYAN}解析：$target_host -> $ip${RESET}"
  [ -n "$allow" ] && echo -e "${CYAN}来源限制：仅 $allow 可访问${RESET}"
  mark="${TAG}${id}"; lp=$(port_match "$ls" "$le"); tp=$(port_match "$ts" "$te"); target=$(dnat_target "$ip" "$ts" "$te")
  for proto in $(echo "$protos" | tr ',' ' '); do
    # 只对白名单来源做 DNAT：非白名单流量在入口就不被转发，
    # 落到中转机本地的关闭端口（连接被拒），躲避 GFW/扫描器对代理端口的主动探测。
    pre="iptables -t nat -A PREROUTING -p $proto"
    [ -n "$listen_ip" ] && pre="$pre -d $listen_ip"
    [ -n "$allow" ] && pre="$pre -s $allow"
    $pre --dport "$lp" -m comment --comment "$mark" -j DNAT --to-destination "$target" || return 1
    iptables -t nat -A POSTROUTING -p "$proto" -d "$ip" --dport "$tp" -m comment --comment "$mark" -j MASQUERADE || return 1
    fwd="iptables -A FORWARD -p $proto -d $ip --dport $tp"
    [ -n "$allow" ] && fwd="$fwd -s $allow"
    $fwd -m comment --comment "$mark" -j ACCEPT || return 1
    iptables -A FORWARD -p "$proto" -s "$ip" --sport "$tp" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$mark" -j ACCEPT || true
  done
  awk -F'|' -v id="$id" -v ip="$ip" 'BEGIN{OFS="|"} $1==id{$11=ip} {print}' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"
}

# ============================ Realm 双栈引擎 ============================
# iptables DNAT 只能在同一地址族内转发（IPv4->IPv4），无法处理 IPv6 入口或
# IPv6->IPv4 跨族。Realm 是用户态 socket relay：监听 [::] 同时接受 IPv4/IPv6，
# 再主动向目标（IPv4 或 IPv6）建立连接，天然完成跨族转发。
have_ip6tables(){ command -v ip6tables >/dev/null 2>&1; }
realm_installed(){ [ -x "$REALM_BIN" ]; }
realm_running(){ command -v systemctl >/dev/null 2>&1 && systemctl is-active "$REALM_SERVICE" >/dev/null 2>&1; }
realm_status(){
  if ! realm_installed; then echo "未安装"; return; fi
  if realm_running; then echo "运行中（$("$REALM_BIN" -v 2>/dev/null | awk '{print $2}')）"; else echo "已安装未运行"; fi
}
realm_arch_triple(){
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64-unknown-linux-musl";;
    aarch64|arm64) echo "aarch64-unknown-linux-musl";;
    armv7l|armv7|armhf) echo "armv7-unknown-linux-musleabihf";;
    *) return 1;;
  esac
}
install_realm(){
  local quiet="${1:-}" triple url tmp
  triple=$(realm_arch_triple) || { [ -z "$quiet" ] && echo -e "${RED}不支持的 CPU 架构：$(uname -m)${RESET}"; return 1; }
  command -v curl >/dev/null 2>&1 || { [ -z "$quiet" ] && echo -e "${RED}未找到 curl，请先用菜单 1 安装依赖。${RESET}"; return 1; }
  mkdir -p "$STATE_DIR"; tmp="$STATE_DIR/.realm.dl.$$"
  url="https://github.com/zhboner/realm/releases/download/${REALM_VERSION}/realm-${triple}.tar.gz"
  [ -z "$quiet" ] && echo -e "${YELLOW}正在下载 Realm ${REALM_VERSION}（${triple}）...${RESET}"
  if ! curl -fsSL "$url" -o "$tmp.tgz" 2>/dev/null; then [ -z "$quiet" ] && echo -e "${RED}下载失败：$url${RESET}"; rm -f "$tmp.tgz"; return 1; fi
  rm -f "$STATE_DIR/realm"
  tar xzf "$tmp.tgz" -C "$STATE_DIR" realm 2>/dev/null || tar xzf "$tmp.tgz" -C "$STATE_DIR" 2>/dev/null || { rm -f "$tmp.tgz"; [ -z "$quiet" ] && echo -e "${RED}解压失败。${RESET}"; return 1; }
  rm -f "$tmp.tgz"
  [ -f "$STATE_DIR/realm" ] || { [ -z "$quiet" ] && echo -e "${RED}解压后未找到 realm 二进制。${RESET}"; return 1; }
  chmod 0755 "$STATE_DIR/realm" 2>/dev/null || true
  mv -f "$STATE_DIR/realm" "$REALM_BIN" || { [ -z "$quiet" ] && echo -e "${RED}安装到 $REALM_BIN 失败（需 root）。${RESET}"; return 1; }
  [ -z "$quiet" ] && echo -e "${GREEN}Realm 已就绪：$("$REALM_BIN" -v 2>/dev/null | head -1)${RESET}"
  log "realm installed ${REALM_VERSION}"; return 0
}
install_realm_menu(){ clear; line; echo -e "${CYAN}安装/更新 Realm 双栈引擎${RESET}"; line; need_root; install_realm; pause; }

# 决定单条规则实际使用哪个引擎：auto 时按“目标族 + 本机能力”自动判断。
effective_engine(){
  local eng="$1" target="$2" listen_ip="$3"
  [ "$eng" = "iptables" ] && { echo "iptables"; return; }
  [ "$eng" = "realm" ] && { echo "realm"; return; }
  # auto：
  is_ipv6 "$target" && { echo "realm"; return; }          # 目标是 IPv6 -> iptables 跨不了族
  is_ipv6 "$listen_ip" && { echo "realm"; return; }        # 指定 IPv6 监听
  # 本机在 NAT/CGNAT IPv4 之后（或没有 IPv4 出口）但有公网 IPv6 -> 走 realm 用 IPv6 入口
  if has_public_ipv6 && { ipv4_is_nat || ! ip -4 route get 1.1.1.1 >/dev/null 2>&1; }; then echo "realm"; return; fi
  echo "iptables"   # 默认：IPv4 -> IPv4 走内核 DNAT，性能最好
}

# 累加 realm endpoint（支持等长端口段，逐端口展开）。结果追加到全局 REALM_ENDPOINTS。
REALM_ENDPOINTS=""; REALM_UDP="false"
realm_add_endpoints(){
  local listen_ip="$1" ls="$2" le="$3" target_host="$4" ts="$5" protos="$6" name="$7"
  local laddr raddr i lport tport
  if [ -z "$listen_ip" ]; then laddr="[::]"; elif is_ipv6 "$listen_ip"; then laddr="[$listen_ip]"; else laddr="$listen_ip"; fi
  if is_ipv6 "$target_host"; then raddr="[$target_host]"; else raddr="$target_host"; fi
  case "$protos" in *udp*) REALM_UDP="true";; esac
  i=0
  while [ $((ls+i)) -le "$le" ]; do
    lport=$((ls+i)); tport=$((ts+i))
    REALM_ENDPOINTS="${REALM_ENDPOINTS}
# ${name}
[[endpoints]]
listen = \"${laddr}:${lport}\"
remote = \"${raddr}:${tport}\"
"
    i=$((i+1))
  done
}

write_realm_config(){
  ensure_dirs
  {
    echo "# 由 ipt-vibe-panel 自动生成，请勿手改（重新“应用规则”会覆盖）"
    echo "[log]"; echo "level = \"warn\""; echo "output = \"stdout\""; echo
    echo "[dns]"; echo "mode = \"ipv4_and_ipv6\""; echo "protocol = \"tcp_and_udp\""
    echo "min_ttl = 60"; echo "max_ttl = 600"; echo
    echo "[network]"; echo "no_tcp = false"; echo "use_udp = ${REALM_UDP}"
    echo "tcp_timeout = 5"; echo "udp_timeout = 30"
    printf '%s\n' "$REALM_ENDPOINTS"
  } > "$REALM_CONF"
}

ensure_realm_service(){
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat > "/etc/systemd/system/$REALM_SERVICE" <<EOF
[Unit]
Description=ipt-vibe-panel realm relay (dual-stack / IPv6 to IPv4)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$REALM_BIN -c $REALM_CONF
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable "$REALM_SERVICE" >/dev/null 2>&1 || true
    systemctl restart "$REALM_SERVICE" >/dev/null 2>&1 || true
    realm_running && echo "systemd（运行中）" || echo "systemd（启动失败，看 journalctl -u $REALM_SERVICE）"
  else
    echo "无 systemd，无法常驻 realm（可改用 iptables 引擎）"
  fi
}
stop_remove_realm_service(){
  if command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/$REALM_SERVICE" ]; then
    systemctl disable --now "$REALM_SERVICE" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$REALM_SERVICE"; systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$REALM_CONF" 2>/dev/null || true
}

# Realm 规则的来源白名单：realm 本身无 ACL，这里用 INPUT 防火墙限制监听端口。
# 仅放行白名单来源（IPv4 用 iptables，IPv6 用 ip6tables），其余到该端口的新连接丢弃。
apply_realm_firewall(){
  local id="$1" listen_ip="$2" ls="$3" le="$4" protos="$5" allow="$6"
  [ -n "$allow" ] || return 0
  local mark="${TAG}${id}" proto lp v4 v6
  lp=$(port_match "$ls" "$le"); v4=$(allow_v4 "$allow"); v6=$(allow_v6 "$allow")
  for proto in $(echo "$protos" | tr ',' ' '); do
    if command -v iptables >/dev/null 2>&1; then
      [ -n "$v4" ] && iptables -A INPUT -p "$proto" --dport "$lp" -s "$v4" -m comment --comment "$mark" -j ACCEPT 2>/dev/null || true
      iptables -A INPUT -p "$proto" --dport "$lp" -m comment --comment "$mark" -j DROP 2>/dev/null || true
    fi
    if have_ip6tables; then
      [ -n "$v6" ] && ip6tables -A INPUT -p "$proto" --dport "$lp" -s "$v6" -m comment --comment "$mark" -j ACCEPT 2>/dev/null || true
      ip6tables -A INPUT -p "$proto" --dport "$lp" -m comment --comment "$mark" -j DROP 2>/dev/null || true
    fi
  done
}
# ========================== Realm 双栈引擎 END ==========================

# 删除单条规则（按其唯一备注 ipt-vibe:ID）在 nat/filter 表里的所有条目。
# 用于 DDNS 刷新时“只替换 IP 变了的这一条”，不影响其它规则。
delete_iptables_by_mark(){
  local mark="$1" spec table chain num
  for spec in "nat PREROUTING" "nat POSTROUTING" "filter FORWARD"; do
    set -- $spec; table="$1"; chain="$2"
    while :; do
      num=$(iptables -t "$table" -L "$chain" --line-numbers -n 2>/dev/null | awk -v m="$mark" 'index($0,m){print $1; exit}')
      [ -n "$num" ] || break
      iptables -t "$table" -D "$chain" "$num" >/dev/null 2>&1 || break
    done
  done
}

# 是否存在“启用中且目标是域名（非纯 IPv4）”的规则。
# 纯 IPv4 只含数字和点；域名一定含字母/下划线/连字符。
# 用字符类判断而非区间量词 {n,m}，兼容 Debian 默认的 mawk（不支持区间正则）。
has_domain_rule(){
  awk -F'|' '$3=="1" && $7 ~ /[A-Za-z_-]/ {found=1} END{exit found?0:1}' "$RULES_FILE" 2>/dev/null
}

self_bin(){ local b="/usr/local/bin/ipt-vibe"; [ -x "$b" ] || b=$(command -v ipt-vibe 2>/dev/null || echo "$b"); echo "$b"; }
DDNS_INTERVAL_MIN=2

ddns_status(){
  if { command -v systemctl >/dev/null 2>&1 && systemctl is-enabled ipt-vibe-ddns.timer >/dev/null 2>&1; } || [ -f /etc/cron.d/ipt-vibe-ddns ]; then
    echo "开启（每${DDNS_INTERVAL_MIN}分钟）"
  else
    echo "关闭"
  fi
}

# 安装“域名目标自动刷新”定时任务：iptables DNAT 只能写死 IP，无法跟随域名变化。
# DDNS 家宽 IP 变化后，若不重新解析并改写 DNAT，转发会一直指向旧 IP 而失效。
# 这里用 systemd timer（无则 cron 兜底）周期性执行 `ipt-vibe --refresh-ddns`。
ensure_ddns_timer(){
  local bin; bin=$(self_bin)
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/ipt-vibe-ddns.service <<EOF
[Unit]
Description=ipt-vibe-panel DDNS refresh (re-resolve domain targets and update DNAT)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$bin --refresh-ddns
EOF
    cat > /etc/systemd/system/ipt-vibe-ddns.timer <<EOF
[Unit]
Description=Periodically refresh ipt-vibe-panel domain (DDNS) targets

[Timer]
OnBootSec=1min
OnUnitActiveSec=${DDNS_INTERVAL_MIN}min
AccuracySec=15s

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now ipt-vibe-ddns.timer >/dev/null 2>&1 || true
    echo "systemd timer"
  elif [ -d /etc/cron.d ]; then
    printf '*/%s * * * * root %s --refresh-ddns >/dev/null 2>&1\n' "$DDNS_INTERVAL_MIN" "$bin" > /etc/cron.d/ipt-vibe-ddns
    chmod 0644 /etc/cron.d/ipt-vibe-ddns 2>/dev/null || true
    echo "cron @${DDNS_INTERVAL_MIN}min"
  else
    echo "无法安装（缺少 systemd/cron）"
  fi
}

remove_ddns_timer(){
  if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/ipt-vibe-ddns.timer ]; then
    systemctl disable --now ipt-vibe-ddns.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ipt-vibe-ddns.timer /etc/systemd/system/ipt-vibe-ddns.service
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f /etc/cron.d/ipt-vibe-ddns 2>/dev/null || true
}

# 非交互模式（由定时器调用）：逐条检查域名目标，只有解析出的 IP 与上次记录不同时，
# 才删除并重建这一条规则。解析失败/无变化时不动任何规则，避免误伤正常转发。
refresh_ddns(){
  need_root; ensure_dirs
  command -v iptables >/dev/null 2>&1 || exit 0
  local id name enabled listen_ip ls le target_host ts te protos resolved allow newip changed=0
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved allow engine; do
    [ -z "$id" ] && continue
    [ "$enabled" = "1" ] || continue
    # 只处理 iptables 引擎的域名规则；realm 规则的 DNS 由 realm 自身按 TTL 重解析。
    [ "$(effective_engine "${engine:-auto}" "$target_host" "$listen_ip")" = "iptables" ] || continue
    echo "$target_host" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && continue
    newip=$(resolve_host "$target_host" 2>/dev/null) || continue
    [ -n "$newip" ] || continue
    [ "$newip" = "$resolved" ] && continue
    log "ddns change: $name $target_host $resolved -> $newip"
    delete_iptables_by_mark "${TAG}${id}"
    if add_rule_to_iptables "$id" "$listen_ip" "$ls" "$le" "$target_host" "$ts" "$te" "$protos" "$allow" >/dev/null 2>&1; then
      changed=1
    else
      log "ddns reapply failed: $name ($target_host)"
    fi
  done < "$RULES_FILE"
  if [ "$changed" = "1" ]; then save_persistent >/dev/null 2>&1 || true; log "ddns refresh persisted"; fi
  exit 0
}

apply_rules(){
  clear; line; echo -e "${CYAN}应用转发规则${RESET}"; line
  if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1; then echo -e "${RED}iptables 或 iptables-save 不可用，请先安装依赖。${RESET}"; pause; return; fi
  ensure_dirs; enable_forward; tune_conntrack
  local bak saved ok=0 fail=0 realm_ok=0 realm_needed=0 ipt_domain=0 eng
  bak=$(backup_rules); [ -n "$bak" ] && echo -e "${YELLOW}已备份：$bak${RESET}"
  delete_managed_iptables_rules
  apply_global_rules
  REALM_ENDPOINTS=""; REALM_UDP="false"
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved allow engine; do
    [ -z "$id" ] && continue; [ "$enabled" = "1" ] || continue
    eng=$(effective_engine "${engine:-auto}" "$target_host" "$listen_ip")
    if [ "$eng" = "realm" ]; then
      realm_add_endpoints "$listen_ip" "$ls" "$le" "$target_host" "$ts" "$protos" "$name"
      apply_realm_firewall "$id" "$listen_ip" "$ls" "$le" "$protos" "$allow"
      realm_needed=1; realm_ok=$((realm_ok+1))
      echo -e "${CYAN}[realm] $name  ${listen_ip:-[::]}:$(port_label "$ls" "$le") -> $target_host:$(port_label "$ts" "$te")${RESET}"
    else
      if add_rule_to_iptables "$id" "$listen_ip" "$ls" "$le" "$target_host" "$ts" "$te" "$protos" "$allow"; then
        ok=$((ok+1)); echo "$target_host" | grep -Eq '[A-Za-z_-]' && ipt_domain=1
      else echo -e "${RED}应用失败：$name ($target_host)${RESET}"; fail=$((fail+1)); fi
    fi
  done < "$RULES_FILE"
  saved=$(save_persistent)
  # Realm 引擎：有 realm 规则则（必要时自动安装）写配置并拉起服务；否则停用清理。
  if [ "$realm_needed" = "1" ]; then
    if ! realm_installed; then
      echo -e "${YELLOW}检测到需要 Realm 双栈引擎，正在自动安装 ${REALM_VERSION}...${RESET}"
      install_realm quiet || echo -e "${RED}Realm 自动安装失败，realm 规则暂未生效。可用菜单“安装 Realm”重试。${RESET}"
    fi
    if realm_installed; then
      write_realm_config
      echo -e "${GREEN}Realm 引擎：$(ensure_realm_service)，共 $realm_ok 条${RESET}"
    fi
  else
    stop_remove_realm_service
  fi
  echo -e "${GREEN}完成：iptables 成功 $ok / 失败 $fail；realm $realm_ok。持久化：$saved${RESET}"
  # DDNS 自动刷新只针对 iptables 引擎的域名规则（realm 由自身 DNS TTL 自动重解析）。
  if [ "$ipt_domain" = "1" ]; then
    echo -e "${GREEN}域名目标自动刷新：已启用（$(ensure_ddns_timer)，每 ${DDNS_INTERVAL_MIN} 分钟）${RESET}"
  else
    remove_ddns_timer
  fi
  log "apply ipt_ok=$ok fail=$fail realm=$realm_ok"; pause
}

list_rules(){
  clear; line; echo -e "${CYAN}转发规则列表${RESET}"; line; ensure_dirs
  if ! grep -q '^[^#[:space:]]' "$RULES_FILE"; then echo -e "${YELLOW}暂无规则。${RESET}"; pause; return; fi
  printf "%-4s %-5s %-8s %-17s %-22s %-7s %-13s %s\n" "序号" "状态" "引擎" "入口" "目标" "协议" "来源限制" "名称"; short_line
  local n=1 st lip lport tport eng
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved allow engine; do
    [ -z "$id" ] && continue
    [ "$enabled" = "1" ] && st="启用" || st="停用"; lip=${listen_ip:-[::]}; lport=$(port_label "$ls" "$le"); tport=$(port_label "$ts" "$te")
    eng="${engine:-auto}"; [ "$eng" = "auto" ] && eng="auto>$(effective_engine auto "$target_host" "$listen_ip")"
    printf "%-4s %-5s %-8s %-17s %-22s %-7s %-13s %s\n" "$n" "$st" "$eng" "$lip:$lport" "$target_host:$tport" "$protos" "${allow:-全部}" "$name"
    n=$((n+1))
  done < "$RULES_FILE"; pause
}

read_default(){ local prompt="$1" def="${2:-}" val=""; if [ -n "$def" ]; then read_tty val "$prompt [$def]: " || return 1; RD="${val:-$def}"; else read_tty val "$prompt: " || return 1; RD="$val"; fi; RD=$(trim "$RD"); }
collect_rule_fields(){
  local old_name="$1" old_enabled="$2" old_lip="$3" old_ls="$4" old_le="$5" old_host="$6" old_ts="$7" old_te="$8" old_protos="$9" old_allow="${10:-}" old_engine="${11:-auto}" pc dc ec gc dg
  read_default "规则名称" "$old_name" || return 1; R_NAME="$RD"
  read_default "监听 IP，留空=全部（IPv6 走 Realm 时留空即 [::] 双栈）" "$old_lip" || return 1; R_LIP="$RD"
  read_default "入口起始端口" "$old_ls" || return 1; R_LS="$RD"
  read_default "入口结束端口，留空等于起始端口" "$old_le" || return 1; R_LE="${RD:-$R_LS}"
  read_default "目标 IP/域名（可 IPv4/IPv6/域名）" "$old_host" || return 1; R_HOST="$RD"
  read_default "目标起始端口" "$old_ts" || return 1; R_TS="$RD"
  read_default "目标结束端口，留空等于起始端口" "$old_te" || return 1; R_TE="${RD:-$R_TS}"
  echo "协议：1) TCP  2) UDP  3) TCP+UDP"; dc="3"; [ "$old_protos" = "tcp" ] && dc="1"; [ "$old_protos" = "udp" ] && dc="2"
  read_default "请选择协议" "$dc" || return 1; pc="$RD"
  case "$pc" in 1|tcp|TCP) R_PROTOS="tcp";; 2|udp|UDP) R_PROTOS="udp";; 3|both|BOTH|all|ALL) R_PROTOS="tcp,udp";; *) echo -e "${RED}协议无效。${RESET}"; return 1;; esac
  echo "转发引擎：1) Auto(推荐)  2) Realm 双栈(IPv6 入口/IPv6→IPv4 跨族)  3) iptables(纯 IPv4 内核转发)"
  dg="1"; [ "$old_engine" = "realm" ] && dg="2"; [ "$old_engine" = "iptables" ] && dg="3"
  read_default "请选择转发引擎" "$dg" || return 1; gc="$RD"
  case "$gc" in 1|auto|AUTO) R_ENGINE="auto";; 2|realm|Realm|REALM) R_ENGINE="realm";; 3|iptables|IPTABLES|ipt) R_ENGINE="iptables";; *) echo -e "${RED}引擎无效。${RESET}"; return 1;; esac
  read_default "仅允许的来源 IP/CIDR，逗号分隔，留空=允许所有（建议填客户端/家宽IP，躲避GFW主动探测）" "$old_allow" || return 1; R_ALLOW="$RD"
  read_default "是否启用？1启用/0停用" "${old_enabled:-1}" || return 1; ec="$RD"
  case "$ec" in 1|y|Y|yes|YES|on|ON) R_ENABLED="1";; 0|n|N|no|NO|off|OFF) R_ENABLED="0";; *) echo -e "${RED}状态无效。${RESET}"; return 1;; esac
  valid_allow_or_empty "$R_ALLOW" || { echo -e "${RED}来源白名单格式无效（示例：1.2.3.4 或 1.2.3.0/24 或 2001:db8::1，多个用逗号）。${RESET}"; return 1; }
  { [ -z "$R_LIP" ] || valid_ip4_or_empty "$R_LIP" || is_ipv6 "$R_LIP"; } || { echo -e "${RED}监听 IP 无效。${RESET}"; return 1; }
  valid_port "$R_LS" || { echo -e "${RED}入口端口无效。${RESET}"; return 1; }
  valid_port "$R_LE" || { echo -e "${RED}入口结束端口无效。${RESET}"; return 1; }
  { valid_host "$R_HOST" || is_ipv6 "$R_HOST"; } || { echo -e "${RED}目标地址无效。${RESET}"; return 1; }
  valid_port "$R_TS" || { echo -e "${RED}目标端口无效。${RESET}"; return 1; }
  valid_port "$R_TE" || { echo -e "${RED}目标结束端口无效。${RESET}"; return 1; }
  [ "$R_LS" -le "$R_LE" ] && [ "$R_TS" -le "$R_TE" ] || { echo -e "${RED}端口范围反了。${RESET}"; return 1; }
  [ $((R_LE-R_LS)) -eq $((R_TE-R_TS)) ] || { echo -e "${RED}入口端口段和目标端口段长度必须一致。${RESET}"; return 1; }
  # iptables 引擎只能处理 IPv4；涉及 IPv6 时必须用 Realm/Auto。
  if [ "$R_ENGINE" = "iptables" ] && { is_ipv6 "$R_HOST" || is_ipv6 "$R_LIP"; }; then
    echo -e "${RED}iptables 引擎不支持 IPv6（跨族/IPv6 入口请选 Realm 或 Auto）。${RESET}"; return 1
  fi
  [ -n "$R_NAME" ] || R_NAME="${R_LS}-to-${R_HOST}-${R_TS}"
}

add_rule(){ clear; line; echo -e "${CYAN}添加转发规则${RESET}"; line; ensure_dirs; collect_rule_fields "" "1" "" "" "" "" "" "" "tcp,udp" "" "auto" || { pause; return; }; local id; id=$(next_id); echo "$id|$R_NAME|$R_ENABLED|$R_LIP|$R_LS|$R_LE|$R_HOST|$R_TS|$R_TE|$R_PROTOS||$R_ALLOW|$R_ENGINE" >> "$RULES_FILE"; echo -e "${GREEN}规则已添加。选择“应用规则”后生效。${RESET}"; pause; }
select_rule_id(){
  ensure_dirs; grep -q '^[^#[:space:]]' "$RULES_FILE" || { echo -e "${YELLOW}暂无规则。${RESET}"; return 1; }
  local n=1 choice
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved allow engine; do [ -z "$id" ] && continue; echo "$n) $name  $target_host:$ts  [$protos] [${engine:-auto}]"; n=$((n+1)); done < "$RULES_FILE"
  read_tty choice "请选择序号: " || return 1; choice=$(trim "$choice"); echo "$choice" | grep -Eq '^[0-9]+$' || return 1
  n=1
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved allow engine; do [ -z "$id" ] && continue; if [ "$n" -eq "$choice" ]; then SELECTED_LINE="$id|$name|$enabled|$listen_ip|$ls|$le|$target_host|$ts|$te|$protos|$resolved|$allow|${engine:-auto}"; return 0; fi; n=$((n+1)); done < "$RULES_FILE"
  return 1
}
delete_rule(){ clear; line; echo -e "${CYAN}删除转发规则${RESET}"; line; select_rule_id || { echo -e "${RED}选择无效。${RESET}"; pause; return; }; local id name yn; IFS='|' read -r id name _ <<< "$SELECTED_LINE"; read_tty yn "确认删除 $name ? [y/N]: " || yn=""; case "$yn" in y|Y) awk -F'|' -v id="$id" '$1 != id {print}' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"; echo -e "${GREEN}已删除配置。选择“应用规则”后同步到系统。${RESET}";; *) echo "已取消。";; esac; pause; }
edit_rule(){ clear; line; echo -e "${CYAN}修改转发规则${RESET}"; line; select_rule_id || { echo -e "${RED}选择无效。${RESET}"; pause; return; }; local id name enabled lip ls le host ts te protos resolved allow engine; IFS='|' read -r id name enabled lip ls le host ts te protos resolved allow engine <<< "$SELECTED_LINE"; collect_rule_fields "$name" "$enabled" "$lip" "$ls" "$le" "$host" "$ts" "$te" "$protos" "$allow" "${engine:-auto}" || { pause; return; }; awk -F'|' -v id="$id" -v newline="$id|$R_NAME|$R_ENABLED|$R_LIP|$R_LS|$R_LE|$R_HOST|$R_TS|$R_TE|$R_PROTOS|$resolved|$R_ALLOW|$R_ENGINE" 'BEGIN{OFS="|"} $1==id{print newline; next} {print}' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"; echo -e "${GREEN}规则已修改。选择“应用规则”后生效。${RESET}"; pause; }
show_current_iptables(){ clear; line; echo -e "${CYAN}当前本工具管理的 iptables 规则${RESET}"; line; iptables-save 2>/dev/null | grep -- "$TAG" || echo -e "${YELLOW}当前系统中没有本工具管理的规则。${RESET}"; pause; }
backup_restore(){
  clear; line; echo -e "${CYAN}备份与恢复${RESET}"; line
  echo "1) 立即备份当前 iptables"; echo "2) 查看备份文件"; echo "3) 从备份恢复"; echo "0) 返回"
  local c f file; read_tty c "请选择: " || return; c=$(trim "$c")
  case "$c" in
    1) f=$(backup_rules); echo -e "${GREEN}已备份：$f${RESET}";;
    2) ls -lh "$BACKUP_DIR" 2>/dev/null || true;;
    3) ls -1 "$BACKUP_DIR"/*.rules 2>/dev/null || { echo "暂无备份。"; pause; return; }; read_tty file "请输入完整备份路径: " || file=""; if [ -f "$file" ] && command -v iptables-restore >/dev/null 2>&1; then iptables-restore < "$file" && echo -e "${GREEN}已恢复。${RESET}"; save_persistent >/dev/null; else echo -e "${RED}备份文件不存在或 iptables-restore 不可用。${RESET}"; fi;;
  esac
  pause
}
uninstall_panel(){ clear; line; echo -e "${CYAN}卸载面板${RESET}"; line; local clean; read_tty clean "是否同时删除本工具管理的 iptables 规则？[y/N]: " || clean=""; if [ "$clean" = "y" ] || [ "$clean" = "Y" ]; then backup_rules >/dev/null; delete_managed_iptables_rules; save_persistent >/dev/null; fi; if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/ipt-vibe-restore.service ]; then systemctl disable --now ipt-vibe-restore.service >/dev/null 2>&1 || true; rm -f /etc/systemd/system/ipt-vibe-restore.service; systemctl daemon-reload >/dev/null 2>&1 || true; fi; rm -f /etc/cron.d/ipt-vibe-restore; remove_ddns_timer; stop_remove_realm_service; rm -f "$REALM_BIN"; rm -f /usr/local/bin/ipt-vibe /usr/local/bin/zf; echo -e "${GREEN}命令与 Realm 服务已移除。配置目录保留：$STATE_DIR${RESET}"; pause; }

# 自更新：从 GitHub 拉取最新 ipt-vibe.sh 覆盖当前命令。
# 下载后先做校验（非空 + bash 语法 + 含 VERSION 标记），避免半截/被劫持的文件把面板写坏。
# 用「同目录临时文件 + 原子 mv」替换，保证正在运行的脚本读的是旧 inode，替换过程安全。
update_panel(){
  clear; line; echo -e "${CYAN}更新到最新版${RESET}"; line
  if ! command -v curl >/dev/null 2>&1; then echo -e "${RED}未找到 curl，请先用菜单 1 安装依赖。${RESET}"; pause; return; fi
  local target dir tmp new_ver yn
  target="/usr/local/bin/ipt-vibe"; [ -e "$target" ] || target=$(command -v ipt-vibe 2>/dev/null || echo "$target")
  dir=$(dirname "$target"); tmp="$dir/.ipt-vibe.update.$$"
  echo -e "当前版本：${GREEN}v$VERSION${RESET}"
  echo -e "${YELLOW}正在下载：$RAW_BASE/ipt-vibe.sh${RESET}"
  if ! curl -fsSL "$RAW_BASE/ipt-vibe.sh" -o "$tmp" 2>/dev/null; then
    echo -e "${RED}下载失败，请检查网络或 GitHub 连通性。原版本未改动。${RESET}"; rm -f "$tmp"; pause; return
  fi
  if [ ! -s "$tmp" ] || ! bash -n "$tmp" 2>/dev/null || ! grep -q '^VERSION=' "$tmp"; then
    echo -e "${RED}下载内容无效或语法异常，已放弃更新。原版本未改动。${RESET}"; rm -f "$tmp"; pause; return
  fi
  new_ver=$(awk -F'"' '/^VERSION=/{print $2; exit}' "$tmp")
  echo -e "最新版本：${GREEN}v$new_ver${RESET}"
  if [ "$new_ver" = "$VERSION" ]; then
    read_tty yn "已是最新版本，仍要强制覆盖安装？[y/N]: " || yn=""
    case "$yn" in y|Y) ;; *) rm -f "$tmp"; echo "已取消。"; pause; return;; esac
  fi
  mkdir -p "$STATE_DIR" 2>/dev/null; cp -f "$target" "$STATE_DIR/ipt-vibe.prev" 2>/dev/null || true
  chmod 0755 "$tmp" 2>/dev/null || true
  if ! mv -f "$tmp" "$target"; then
    echo -e "${RED}写入 $target 失败，请确认以 root 运行。${RESET}"; rm -f "$tmp"; pause; return
  fi
  ln -sf "$target" /usr/local/bin/zf 2>/dev/null || true
  log "update $VERSION -> $new_ver"
  echo -e "${GREEN}已更新到 v$new_ver（旧版本备份：$STATE_DIR/ipt-vibe.prev）。${RESET}"
  echo -e "${YELLOW}即将以新版本重启面板...${RESET}"; sleep 1
  exec "$target"
}

header(){ clear; line; echo -e "${CYAN}              $APP_NAME v$VERSION${RESET}"; line; echo -e "当前时间：${YELLOW}$(date '+%F %T')${RESET}"; echo -e "系统版本：${GREEN}$(os_name)${RESET}"; echo -e "内核版本：${GREEN}$(uname -r)${RESET}"; echo -e "iptables：${GREEN}$(iptables_backend)${RESET}"; echo -e "IPv4转发：${GREEN}$(ip_forward_status)${RESET}"; echo -e "连接跟踪：${GREEN}$(conntrack_status)${RESET} | 内存 ${GREEN}$(mem_status)${RESET}"; echo -e "规则数量：${GREEN}$(managed_count)${RESET} | 启用 ${GREEN}$(enabled_count)${RESET}"; echo -e "域名(DDNS)自动刷新：${GREEN}$(ddns_status)${RESET}"; echo -e "Realm 双栈引擎：${GREEN}$(realm_status)${RESET} | 公网IPv6 ${GREEN}$(has_public_ipv6 && echo 有 || echo 无)${RESET}"; echo -e "面板类型：${GREEN}SSH 终端菜单，不开放 HTTP 端口${RESET}"; line; }
main_menu(){
  need_root; ensure_dirs
  while true; do
    header
    echo "1. 安装/检查依赖"; echo "2. 添加转发规则"; echo "3. 查看转发规则"; echo "4. 修改转发规则"; echo "5. 删除转发规则"; echo "6. 应用规则（iptables/Realm 自动分流）"; echo "7. 查看当前 iptables 规则"; echo "8. 备份与恢复"; echo "9. 卸载面板命令"; echo "10. 更新到最新版"; echo "11. 安装/更新 Realm 双栈引擎"; echo "0. 退出"; short_line
    local choice
    if ! read_tty choice "请输入选项: "; then
      echo; echo -e "${RED}未检测到可交互键盘输入。请在 SSH 终端里直接运行：sudo zf${RESET}"; exit 1
    fi
    choice=$(trim "$choice")
    [ -z "$choice" ] && continue
    case "$choice" in
      1) install_deps;; 2) add_rule;; 3) list_rules;; 4) edit_rule;; 5) delete_rule;; 6) apply_rules;; 7) show_current_iptables;; 8) backup_restore;; 9) uninstall_panel;; 10) update_panel;; 11) install_realm_menu;; 0) exit 0;; *) echo "无效选项：$choice"; sleep 1;;
    esac
  done
}
# 非交互子命令：由 DDNS 定时器调用，不进入菜单。
case "${1:-}" in
  --refresh-ddns|refresh-ddns) refresh_ddns;;
esac
main_menu
