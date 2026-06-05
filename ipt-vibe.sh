#!/usr/bin/env bash
set -uo pipefail

APP_NAME="iptables Vibe Panel"
VERSION="0.2.3"
STATE_DIR="/etc/ipt-vibe-panel"
RULES_FILE="$STATE_DIR/rules.conf"
BACKUP_DIR="$STATE_DIR/backups"
LOG_FILE="$STATE_DIR/panel.log"
TAG="ipt-vibe:"

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; RESET='\033[0m'

need_root(){ [ "$(id -u)" -eq 0 ] || { echo -e "${RED}请使用 root 运行：sudo zf${RESET}"; exit 1; }; }
ensure_dirs(){ mkdir -p "$STATE_DIR" "$BACKUP_DIR"; touch "$RULES_FILE"; }
log(){ mkdir -p "$STATE_DIR" 2>/dev/null; echo "[$(date '+%F %T')] $*" >> "$LOG_FILE" 2>/dev/null; }
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
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables curl ca-certificates dnsutils
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

backup_rules(){ ensure_dirs; local file="$BACKUP_DIR/iptables-$(date +%Y%m%d-%H%M%S).rules"; command -v iptables-save >/dev/null 2>&1 && { iptables-save > "$file"; echo "$file"; } || echo ""; }
save_persistent(){ if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; echo "netfilter-persistent"; else mkdir -p /etc/iptables; iptables-save > /etc/iptables/rules.v4; echo "/etc/iptables/rules.v4"; fi; }

delete_chain_by_comment(){
  local table="$1" chain="$2" num=""
  while true; do
    if [ -n "$table" ]; then
      num=$(iptables -t "$table" -L "$chain" --line-numbers -n 2>/dev/null | awk -v tag="$TAG" '$0 ~ tag {print $1; exit}')
    else
      num=$(iptables -L "$chain" --line-numbers -n 2>/dev/null | awk -v tag="$TAG" '$0 ~ tag {print $1; exit}')
    fi
    [ -n "$num" ] || break
    if [ -n "$table" ]; then iptables -t "$table" -D "$chain" "$num" >/dev/null 2>&1 || break; else iptables -D "$chain" "$num" >/dev/null 2>&1 || break; fi
  done
}

delete_managed_iptables_rules(){
  command -v iptables >/dev/null 2>&1 || return 0
  delete_chain_by_comment nat PREROUTING
  delete_chain_by_comment nat POSTROUTING
  delete_chain_by_comment "" FORWARD
  command -v iptables-save >/dev/null 2>&1 || return 0
  iptables-save | grep -- "$TAG" | grep '^-A ' | while IFS= read -r rule; do
    local chain del_rule
    chain=$(echo "$rule" | awk '{print $2}')
    del_rule=$(echo "$rule" | sed 's/^-A /-D /')
    if [ "$chain" = "PREROUTING" ] || [ "$chain" = "POSTROUTING" ]; then iptables -t nat $del_rule >/dev/null 2>&1 || true; else iptables $del_rule >/dev/null 2>&1 || true; fi
  done
}

add_rule_to_iptables(){
  local id="$1" listen_ip="$2" ls="$3" le="$4" target_host="$5" ts="$6" te="$7" protos="$8"
  local ip mark lp tp target proto pre
  ip=$(resolve_host "$target_host") || { echo -e "${RED}目标解析失败：$target_host${RESET}"; return 1; }
  [ -n "$ip" ] || { echo -e "${RED}目标解析为空：$target_host${RESET}"; return 1; }
  echo -e "${CYAN}解析：$target_host -> $ip${RESET}"
  mark="${TAG}${id}"; lp=$(port_match "$ls" "$le"); tp=$(port_match "$ts" "$te"); target=$(dnat_target "$ip" "$ts" "$te")
  for proto in $(echo "$protos" | tr ',' ' '); do
    pre="iptables -t nat -A PREROUTING -p $proto"
    [ -n "$listen_ip" ] && pre="$pre -d $listen_ip"
    $pre --dport "$lp" -m comment --comment "$mark" -j DNAT --to-destination "$target" || return 1
    iptables -t nat -A POSTROUTING -p "$proto" -d "$ip" --dport "$tp" -m comment --comment "$mark" -j MASQUERADE || return 1
    iptables -A FORWARD -p "$proto" -d "$ip" --dport "$tp" -m comment --comment "$mark" -j ACCEPT || return 1
    iptables -A FORWARD -p "$proto" -s "$ip" --sport "$tp" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$mark" -j ACCEPT || true
  done
  awk -F'|' -v id="$id" -v ip="$ip" 'BEGIN{OFS="|"} $1==id{$11=ip} {print}' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"
}

apply_rules(){
  clear; line; echo -e "${CYAN}应用转发规则${RESET}"; line
  if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1; then echo -e "${RED}iptables 或 iptables-save 不可用，请先安装依赖。${RESET}"; pause; return; fi
  ensure_dirs; enable_forward
  local bak saved ok=0 fail=0
  bak=$(backup_rules); [ -n "$bak" ] && echo -e "${YELLOW}已备份：$bak${RESET}"
  delete_managed_iptables_rules
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved; do
    [ -z "$id" ] && continue; [ "$enabled" = "1" ] || continue
    if add_rule_to_iptables "$id" "$listen_ip" "$ls" "$le" "$target_host" "$ts" "$te" "$protos"; then ok=$((ok+1)); else echo -e "${RED}应用失败：$name ($target_host)${RESET}"; fail=$((fail+1)); fi
  done < "$RULES_FILE"
  saved=$(save_persistent)
  echo -e "${GREEN}完成：成功 $ok，失败 $fail。持久化：$saved${RESET}"
  log "apply ok=$ok fail=$fail"; pause
}

list_rules(){
  clear; line; echo -e "${CYAN}转发规则列表${RESET}"; line; ensure_dirs
  if ! grep -q '^[^#[:space:]]' "$RULES_FILE"; then echo -e "${YELLOW}暂无规则。${RESET}"; pause; return; fi
  printf "%-4s %-8s %-18s %-25s %-9s %-15s %s\n" "序号" "状态" "入口" "目标" "协议" "解析IP" "名称"; short_line
  local n=1 st lip lport tport
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved; do
    [ -z "$id" ] && continue
    [ "$enabled" = "1" ] && st="启用" || st="停用"; lip=${listen_ip:-0.0.0.0}; lport=$(port_label "$ls" "$le"); tport=$(port_label "$ts" "$te")
    printf "%-4s %-8s %-18s %-25s %-9s %-15s %s\n" "$n" "$st" "$lip:$lport" "$target_host:$tport" "$protos" "${resolved:-无}" "$name"
    n=$((n+1))
  done < "$RULES_FILE"; pause
}

read_default(){ local prompt="$1" def="${2:-}" val=""; if [ -n "$def" ]; then read_tty val "$prompt [$def]: " || return 1; RD="${val:-$def}"; else read_tty val "$prompt: " || return 1; RD="$val"; fi; RD=$(trim "$RD"); }
collect_rule_fields(){
  local old_name="$1" old_enabled="$2" old_lip="$3" old_ls="$4" old_le="$5" old_host="$6" old_ts="$7" old_te="$8" old_protos="$9" pc dc ec
  read_default "规则名称" "$old_name" || return 1; R_NAME="$RD"
  read_default "监听 IP，留空表示全部" "$old_lip" || return 1; R_LIP="$RD"
  read_default "入口起始端口" "$old_ls" || return 1; R_LS="$RD"
  read_default "入口结束端口，留空等于起始端口" "$old_le" || return 1; R_LE="${RD:-$R_LS}"
  read_default "目标 IP/域名" "$old_host" || return 1; R_HOST="$RD"
  read_default "目标起始端口" "$old_ts" || return 1; R_TS="$RD"
  read_default "目标结束端口，留空等于起始端口" "$old_te" || return 1; R_TE="${RD:-$R_TS}"
  echo "协议：1) TCP  2) UDP  3) TCP+UDP"; dc="3"; [ "$old_protos" = "tcp" ] && dc="1"; [ "$old_protos" = "udp" ] && dc="2"
  read_default "请选择协议" "$dc" || return 1; pc="$RD"
  case "$pc" in 1|tcp|TCP) R_PROTOS="tcp";; 2|udp|UDP) R_PROTOS="udp";; 3|both|BOTH|all|ALL) R_PROTOS="tcp,udp";; *) echo -e "${RED}协议无效。${RESET}"; return 1;; esac
  read_default "是否启用？1启用/0停用" "${old_enabled:-1}" || return 1; ec="$RD"
  case "$ec" in 1|y|Y|yes|YES|on|ON) R_ENABLED="1";; 0|n|N|no|NO|off|OFF) R_ENABLED="0";; *) echo -e "${RED}状态无效。${RESET}"; return 1;; esac
  valid_ip4_or_empty "$R_LIP" || { echo -e "${RED}监听 IP 无效。${RESET}"; return 1; }
  valid_port "$R_LS" || { echo -e "${RED}入口端口无效。${RESET}"; return 1; }
  valid_port "$R_LE" || { echo -e "${RED}入口结束端口无效。${RESET}"; return 1; }
  valid_host "$R_HOST" || { echo -e "${RED}目标地址无效。${RESET}"; return 1; }
  valid_port "$R_TS" || { echo -e "${RED}目标端口无效。${RESET}"; return 1; }
  valid_port "$R_TE" || { echo -e "${RED}目标结束端口无效。${RESET}"; return 1; }
  [ "$R_LS" -le "$R_LE" ] && [ "$R_TS" -le "$R_TE" ] || { echo -e "${RED}端口范围反了。${RESET}"; return 1; }
  [ $((R_LE-R_LS)) -eq $((R_TE-R_TS)) ] || { echo -e "${RED}入口端口段和目标端口段长度必须一致。${RESET}"; return 1; }
  [ -n "$R_NAME" ] || R_NAME="${R_LS}-to-${R_HOST}-${R_TS}"
}

add_rule(){ clear; line; echo -e "${CYAN}添加转发规则${RESET}"; line; ensure_dirs; collect_rule_fields "" "1" "" "" "" "" "" "" "tcp,udp" || { pause; return; }; local id; id=$(next_id); echo "$id|$R_NAME|$R_ENABLED|$R_LIP|$R_LS|$R_LE|$R_HOST|$R_TS|$R_TE|$R_PROTOS|" >> "$RULES_FILE"; echo -e "${GREEN}规则已添加。选择“应用规则”后生效。${RESET}"; pause; }
select_rule_id(){
  ensure_dirs; grep -q '^[^#[:space:]]' "$RULES_FILE" || { echo -e "${YELLOW}暂无规则。${RESET}"; return 1; }
  local n=1 choice
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved; do [ -z "$id" ] && continue; echo "$n) $name  $target_host:$ts  [$protos]"; n=$((n+1)); done < "$RULES_FILE"
  read_tty choice "请选择序号: " || return 1; choice=$(trim "$choice"); echo "$choice" | grep -Eq '^[0-9]+$' || return 1
  n=1
  while IFS='|' read -r id name enabled listen_ip ls le target_host ts te protos resolved; do [ -z "$id" ] && continue; if [ "$n" -eq "$choice" ]; then SELECTED_LINE="$id|$name|$enabled|$listen_ip|$ls|$le|$target_host|$ts|$te|$protos|$resolved"; return 0; fi; n=$((n+1)); done < "$RULES_FILE"
  return 1
}
delete_rule(){ clear; line; echo -e "${CYAN}删除转发规则${RESET}"; line; select_rule_id || { echo -e "${RED}选择无效。${RESET}"; pause; return; }; local id name yn; IFS='|' read -r id name _ <<< "$SELECTED_LINE"; read_tty yn "确认删除 $name ? [y/N]: " || yn=""; case "$yn" in y|Y) awk -F'|' -v id="$id" '$1 != id {print}' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"; echo -e "${GREEN}已删除配置。选择“应用规则”后同步到系统。${RESET}";; *) echo "已取消。";; esac; pause; }
edit_rule(){ clear; line; echo -e "${CYAN}修改转发规则${RESET}"; line; select_rule_id || { echo -e "${RED}选择无效。${RESET}"; pause; return; }; local id name enabled lip ls le host ts te protos resolved; IFS='|' read -r id name enabled lip ls le host ts te protos resolved <<< "$SELECTED_LINE"; collect_rule_fields "$name" "$enabled" "$lip" "$ls" "$le" "$host" "$ts" "$te" "$protos" || { pause; return; }; awk -F'|' -v id="$id" -v newline="$id|$R_NAME|$R_ENABLED|$R_LIP|$R_LS|$R_LE|$R_HOST|$R_TS|$R_TE|$R_PROTOS|$resolved" 'BEGIN{OFS="|"} $1==id{print newline; next} {print}' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"; echo -e "${GREEN}规则已修改。选择“应用规则”后生效。${RESET}"; pause; }
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
uninstall_panel(){ clear; line; echo -e "${CYAN}卸载面板${RESET}"; line; local clean; read_tty clean "是否同时删除本工具管理的 iptables 规则？[y/N]: " || clean=""; if [ "$clean" = "y" ] || [ "$clean" = "Y" ]; then backup_rules >/dev/null; delete_managed_iptables_rules; save_persistent >/dev/null; fi; rm -f /usr/local/bin/ipt-vibe /usr/local/bin/zf; echo -e "${GREEN}命令已移除。配置目录保留：$STATE_DIR${RESET}"; pause; }

header(){ clear; line; echo -e "${CYAN}              $APP_NAME v$VERSION${RESET}"; line; echo -e "当前时间：${YELLOW}$(date '+%F %T')${RESET}"; echo -e "系统版本：${GREEN}$(os_name)${RESET}"; echo -e "内核版本：${GREEN}$(uname -r)${RESET}"; echo -e "iptables：${GREEN}$(iptables_backend)${RESET}"; echo -e "IPv4转发：${GREEN}$(ip_forward_status)${RESET}"; echo -e "规则数量：${GREEN}$(managed_count)${RESET} | 启用 ${GREEN}$(enabled_count)${RESET}"; echo -e "面板类型：${GREEN}SSH 终端菜单，不开放 HTTP 端口${RESET}"; line; }
main_menu(){
  need_root; ensure_dirs
  while true; do
    header
    echo "1. 安装/检查依赖"; echo "2. 添加转发规则"; echo "3. 查看转发规则"; echo "4. 修改转发规则"; echo "5. 删除转发规则"; echo "6. 应用规则到 iptables"; echo "7. 查看当前 iptables 规则"; echo "8. 备份与恢复"; echo "9. 卸载面板命令"; echo "0. 退出"; short_line
    local choice
    if ! read_tty choice "请输入选项: "; then
      echo; echo -e "${RED}未检测到可交互键盘输入。请在 SSH 终端里直接运行：sudo zf${RESET}"; exit 1
    fi
    choice=$(trim "$choice")
    [ -z "$choice" ] && continue
    case "$choice" in
      1) install_deps;; 2) add_rule;; 3) list_rules;; 4) edit_rule;; 5) delete_rule;; 6) apply_rules;; 7) show_current_iptables;; 8) backup_restore;; 9) uninstall_panel;; 0) exit 0;; *) echo "无效选项：$choice"; sleep 1;;
    esac
  done
}
main_menu
