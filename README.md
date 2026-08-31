# iptables Vibe Panel

一个在 VPS/SSH 终端里运行的 iptables 端口转发可视化菜单面板。

它不是 HTTP 网站，不开放管理端口，也不启动后台 Web 服务。安装后在 SSH 里输入 `zf` 或 `ipt-vibe`，即可打开类似脚本面板的交互菜单。

## 一键安装 / 更新

推荐在 VPS 上直接执行：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh | sudo bash
```

> 安装脚本会在下载 `ipt-vibe.sh` 时自动尝试多个镜像（GitHub raw → jsdelivr → ghproxy → gitmirror），主源被墙时会自动回退，无需手动干预。

### GitHub 被墙 / 报 `curl: (22) ... error: 400`（国内网络常见）

如果连 `install.sh` 本身都拉不下来（`raw.githubusercontent.com` 被干扰），改用镜像拉安装脚本，并让它也从镜像拉主程序：

```bash
# 方式一：jsdelivr 镜像
curl -fsSL https://cdn.jsdelivr.net/gh/bear4f/iptables-vibe-panel@main/install.sh \
  | IPT_VIBE_RAW_BASE="https://cdn.jsdelivr.net/gh/bear4f/iptables-vibe-panel@main" sudo -E bash

# 方式二：ghproxy 反代（拉实时最新）
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh \
  | IPT_VIBE_RAW_BASE="https://ghproxy.net/https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main" sudo -E bash
```

> 请用 `bash` 运行，不要用 `ash`。`sudo -E` 用于把 `IPT_VIBE_RAW_BASE` 传进 root 环境。

安装或更新完成后，单独执行下面的命令打开面板：

```bash
sudo zf
```

也可以使用完整命令：

```bash
sudo ipt-vibe
```

> 注意：安装命令和 `sudo zf` 请分开执行，不要写在同一行。面板需要从 SSH 终端读取键盘输入。

如果你的系统不适合管道执行，使用下载后执行：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh -o /tmp/iptables-vibe-panel-install.sh
sudo bash /tmp/iptables-vibe-panel-install.sh
sudo zf
```

## 当前版本

当前脚本版本：`v0.6.1`

`v0.6.1` —— **下载源镜像自动回退**：`raw.githubusercontent.com` 在国内常被干扰（`curl (22) error 400`/超时）。安装脚本与面板内「更新到最新版」现在会依次尝试 GitHub raw → jsdelivr → ghproxy → gitmirror，任一可达即成功；下载后校验非空 + 语法 + 版本标记，避免把错误页当成脚本。install.sh 改为 POSIX sh 兼容（`sh`/`bash` 均可）。

`v0.6.0` —— **iptables 原生双栈（IPv4 + IPv6，纯内核转发）**：

- **iptables / ip6tables 双栈**：每条规则按目标地址族自动选引擎 —— IPv4→IPv4 用 `iptables` 的 nat 表，IPv6→IPv6 用 `ip6tables` 的 nat 表，全程内核 DNAT/MASQUERADE 转发，无用户态进程、无额外二进制。
- **自动识别地址族**：目标或监听是 IPv6 字面量 → 走 ip6tables；IPv4 → 走 iptables；域名按监听族优先，否则先查 A、再查 AAAA。规则列表新增「族」列显示 IPv4/IPv6。
- **同步开启 IPv6 转发**：`net.ipv6.conf.all.forwarding=1`；IPv6 规则持久化到 `/etc/iptables/rules.v6` 并开机恢复。
- **来源白名单双栈**：白名单可混填 IPv4 与 IPv6/CIDR，按规则族自动取对应族的条目做 `-s` 限制（防 GFW 主动探测）。
- **DDNS 双栈**：域名目标按族分别刷新（v4 查 A、v6 查 AAAA），IP 变化时只重建该条规则。
- **MSS 钳制双栈**：`iptables` 与 `ip6tables` 的 `mangle FORWARD` 都加 TCPMSS 钳制，减少大包黑洞丢包。

> ⚠️ **重要限制：iptables/ip6tables 只能做同族 NAT，做不了 IPv6→IPv4 跨族（NAT64）**。netfilter 的 DNAT 不跨地址族。若你的机器是「公网 IPv6 入口 + 仅 IPv4 落地」这类跨族需求，iptables 双栈覆盖不了，需要 NAT64（Jool/TAYGA）或用户态中继（如 Realm）——本面板 `v0.6.0` 起专注纯 iptables 双栈，不再内置 Realm。落地机若同时有 IPv6，请把目标填 IPv6 走 v6→v6 即可。

> 从 `v0.5.0`（曾内置 Realm）升级上来时，应用规则会自动停用并移除遗留的 `ipt-vibe-realm.service` 与 realm 二进制。

`v0.4.1` 修复致命问题 —— **DDNS 域名目标 IP 变化后转发失效**：

- **问题**：iptables 的 DNAT 只能写死目标 IP，域名是在「应用规则」那一刻解析并固化进规则的。目标是动态家宽 + DDNS 域名时，家宽公网 IP 一变，规则仍指向旧 IP，转发就断了，必须手动重新「应用规则」。
- **修复**：新增「域名(DDNS)自动刷新」。只要存在启用中的域名目标规则，应用规则时会自动安装一个定时任务（systemd timer，无则 cron 兜底），每 2 分钟重新解析一次域名；**仅当解析出的 IP 与上次不同才自动删除并重建这一条规则**（其它规则、纯 IP 规则一律不动），随后持久化。解析失败或无变化时不动任何规则，避免误伤正常转发。
- 面板顶部新增「域名(DDNS)自动刷新：开启/关闭」状态。卸载面板会一并移除该定时任务。
- 顺带修复一个可移植性问题：域名/IP 判别改用字符类正则，兼容 Debian 默认的 `mawk`（不支持 `{n,m}` 区间正则）。

`v0.4.0` 聚焦「转发更稳不丢包」和「保护转发机不被 GFW 审查」：

- **TCP MSS 钳制（防大包黑洞丢包）**：应用规则时自动在 `mangle FORWARD` 加一条 `TCPMSS --clamp-mss-to-pmtu`，按路径 MTU 修正 TCP 握手通告的 MSS。中转机到落地机若经隧道/不同 MTU 链路，大包常因 PMTU 黑洞被丢弃，表现为网页打不开、大文件卡住、SSH 卡死。钳制后这类丢包基本消除。
- **连接跟踪表按内存自动扩容 + 加大哈希桶**：旧版只缩短超时，高并发时仍可能 `nf_conntrack: table full` 丢包。新版按物理内存自动计算 `nf_conntrack_max`（约每条 300 字节，范围 65536–1048576，小内存不 OOM、大内存不丢包），并把哈希桶 `hashsize` 同步放大（写 `/sys` 并落 `modprobe.d`，重启后仍生效）。
- **`tcp_be_liberal=1`（减少误判丢包）**：中转链路常见非对称/乱序，默认窗口跟踪会把窗口外的正常包判为 `INVALID` 丢弃。开启宽松模式后不再误杀，转发更稳。
- **UDP/VPN 超时放宽**：`udp_timeout` 30→60、`udp_timeout_stream` 120→180，减少 keepalive 间隙丢失 NAT 映射导致的重连/丢包。
- **来源白名单（保护转发机不被 GFW 主动探测）**：每条规则可填「仅允许的来源 IP/CIDR」（逗号分隔，留空=允许所有）。填入客户端/家宽 IP 后，只有白名单来源才会被 DNAT 转发，其他来源在入口就被拒绝，落到中转机的关闭端口——GFW/扫描器的主动探测无法命中代理端口，大幅降低中转机被识别封锁的概率。

`v0.3.1` 新增：

- **面板内一键更新**：菜单新增 `10. 更新到最新版`，直接从 GitHub 拉取最新脚本覆盖当前命令，更新后自动以新版本重启面板。下载后会做校验（非空 + bash 语法 + 版本标记），并用「原子替换」避免半截/被劫持的文件把面板写坏；旧版本备份在 `/etc/ipt-vibe-panel/ipt-vibe.prev`。

`v0.3.0` 重点修复：

- **重启/死机后规则丢失**：以前只把规则写进 `/etc/iptables/rules.v4`，若系统没装 `netfilter-persistent`，开机时没有任何服务去加载它，重启后转发全部失效，必须手动重新应用。现在会自动落地开机恢复机制：优先用 `netfilter-persistent`；没有时自动创建 systemd oneshot 服务 `ipt-vibe-restore.service`；再没有 systemd 时用 `cron @reboot` 兜底。安装脚本也会一并安装 `iptables-persistent`。
- **内存占用高 / 偶发死机重启**：转发节点的内存主要消耗在内核 `nf_conntrack` 连接跟踪表上，默认 TCP established 超时长达 5 天，空闲连接长期驻留内存，UDP/VPN 高流量时连接跟踪表膨胀，容易触发 OOM 导致死机或重启。新版应用规则时会写入 conntrack 调优（缩短过期时间），从源头压低内存占用。
- 面板顶部新增“连接跟踪 count/max”和“内存”实时状态，方便观察内存问题。
- 备份目录只保留最近 10 份，日志超过 1MB 自动截断，避免磁盘无限增长。

`v0.2.3` 修复：

- 菜单输入强制从 SSH 终端读取，避免安装管道后一直提示“无效选项”。
- 清理旧的异常 DNAT 规则，例如 `--to-destination :10773`。
- 为转发规则补充回程 `FORWARD` 放行，提升 VPN/UDP 转发兼容性。
- 安装依赖时补充 `dnsutils`，域名目标解析更稳定。

进入面板后，顶部应显示：

```text
iptables Vibe Panel v0.6.1
```

如果仍显示旧版本，请重新执行一键安装命令。

## 面板功能

- 安装/检查依赖。
- 添加端口转发规则。
- 查看转发规则。
- 修改转发规则。
- 删除转发规则。
- 应用规则到 iptables。
- 查看当前本工具管理的 iptables 规则。
- 备份与恢复。
- 卸载面板命令。
- 更新到最新版（面板内一键自更新）。

## 规则能力

- 支持 TCP、UDP、TCP+UDP。
- 支持 iptables 原生双栈：IPv4→IPv4 用 iptables、IPv6→IPv6 用 ip6tables，按目标族自动选择（仅同族，不做跨族 NAT64）。
- 支持单端口和等长端口段转发。
- 支持目标 IPv4 或域名，应用规则时自动解析域名。
- 目标为域名时自动跟随 DDNS：后台每 2 分钟重解析，IP 变了自动改写 DNAT，无需手动重应用。
- 支持每条规则设置「来源白名单」（IP/CIDR，逗号分隔），只放行指定来源，躲避 GFW/扫描器主动探测。
- 自动 MSS 钳制、conntrack 自动扩容与调优，转发更稳、更少丢包。
- 自动开启 IPv4 转发：`net.ipv4.ip_forward=1`。
- 应用前备份当前 `iptables-save` 输出。
- 只管理带 `ipt-vibe:` 标记的规则，不主动删除其他手工规则。
- 自动检测系统、iptables 后端、IPv4 转发状态。

## 应用规则后应该看到什么

例如入口端口 `10773` 转发到文档示例目标 `198.51.100.10:10773`，并选择 TCP+UDP，应用后查看当前 iptables 规则，应该类似：

```bash
-A PREROUTING -p tcp --dport 10773 -m comment --comment "ipt-vibe:规则ID" -j DNAT --to-destination 198.51.100.10:10773
-A PREROUTING -p udp --dport 10773 -m comment --comment "ipt-vibe:规则ID" -j DNAT --to-destination 198.51.100.10:10773
-A POSTROUTING -d 198.51.100.10/32 -p tcp --dport 10773 -m comment --comment "ipt-vibe:规则ID" -j MASQUERADE
-A POSTROUTING -d 198.51.100.10/32 -p udp --dport 10773 -m comment --comment "ipt-vibe:规则ID" -j MASQUERADE
-A FORWARD -d 198.51.100.10/32 -p tcp --dport 10773 -m comment --comment "ipt-vibe:规则ID" -j ACCEPT
-A FORWARD -d 198.51.100.10/32 -p udp --dport 10773 -m comment --comment "ipt-vibe:规则ID" -j ACCEPT
```

此外 `mangle` 表会有一条全局 MSS 钳制规则（防大包黑洞丢包）：

```bash
-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "ipt-vibe:mss" -j TCPMSS --clamp-mss-to-pmtu
```

如果该规则设置了来源白名单（例如只允许 `203.0.113.7`），DNAT 规则会带上 `-s`，非白名单来源不会被转发：

```bash
-A PREROUTING -s 203.0.113.7/32 -p tcp --dport 10773 -m comment --comment "ipt-vibe:规则ID" -j DNAT --to-destination 198.51.100.10:10773
```

不应该再出现这种坏规则：

```bash
--to-destination :10773
```

如果曾经出现过坏规则，进入面板选择 `6. 应用规则到 iptables`，新版会先清理旧的 `ipt-vibe:` 规则，再重新生成。

## 兼容策略

默认执行后端是 `iptables`，这是 Debian 10 的稳妥选择。Debian 10 可能使用 `iptables-legacy`，新系统也可能让 `iptables` 指向 `nf_tables` 后端；面板会显示 `iptables --version` 和后端类型，但仍通过 iptables 命令管理规则。

`v0.6.0` 起支持 iptables 原生双栈：IPv4→IPv4 用 `iptables` 的 nat 表，IPv6→IPv6 用 `ip6tables` 的 nat 表，按每条规则的目标地址族自动选择。**仅限同族**；netfilter 不做 IPv6→IPv4 跨族 NAT64（见上文「重要限制」）。

## 克隆仓库安装

```bash
git clone https://github.com/bear4f/iptables-vibe-panel.git
cd iptables-vibe-panel
sudo bash install.sh
sudo zf
```

## 文件位置

- 主命令：`/usr/local/bin/ipt-vibe`
- 快捷命令：`/usr/local/bin/zf`
- 状态库：`/etc/ipt-vibe-panel/rules.conf`
- 备份目录：`/etc/ipt-vibe-panel/backups`
- 日志：`/etc/ipt-vibe-panel/panel.log`

## 应用规则时做什么

1. 检查 root 权限、`iptables`、`iptables-save`。
2. 开启 IPv4/IPv6 转发：`net.ipv4.ip_forward=1`、`net.ipv6.conf.all.forwarding=1`。
3. 写入 conntrack 调优：缩短过期时间降低内存占用，按内存自动扩容 `nf_conntrack_max` 与哈希桶、开启 `tcp_be_liberal` 减少丢包。
4. 备份当前 `iptables-save` 输出（仅保留最近 10 份）。
5. 删除所有带 `ipt-vibe:` 备注的旧规则（iptables 与 ip6tables）。
6. 应用全局优化：`iptables`/`ip6tables` 的 `mangle FORWARD` 加 TCP MSS 钳制（`--clamp-mss-to-pmtu`）。
7. 按每条规则的目标地址族重建：IPv4 用 `iptables`、IPv6 用 `ip6tables`（带来源白名单时只对白名单来源做 DNAT）。
8. 持久化并安装开机自动恢复：优先 `netfilter-persistent`；否则自动创建 systemd oneshot 服务 `ipt-vibe-restore.service`（同时恢复 `rules.v4` 与 `rules.v6`）；再否则用 `cron @reboot` 兜底。

## 常见问题

### 一直提示“无效选项”

请先更新到 `v0.2.3`：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh | sudo bash
sudo zf
```

安装命令和打开面板命令必须分开执行。不要这样写：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh | sudo bash sudo zf
```

### 使用 `bash <(curl ...)` 报 `/dev/fd/63` 不存在

部分低版本或精简系统不支持这种方式。请改用管道安装：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh | sudo bash
```

或下载后执行：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh -o /tmp/iptables-vibe-panel-install.sh
sudo bash /tmp/iptables-vibe-panel-install.sh
```

### VPN 协议转发后仍不可用

请检查：

- 面板已选择 TCP+UDP 或正确的协议。
- 已在面板中选择 `6. 应用规则到 iptables`。
- 查看规则时没有 `--to-destination :端口` 这种坏规则。
- 云厂商安全组已放行入口端口。
- 目标服务器允许来自中转 VPS 公网 IP 的连接。

### 重启 / 死机后转发失效，必须手动重新应用（v0.3.0 已修复）

原因：旧版只把规则写进 `/etc/iptables/rules.v4`，但系统若没装 `netfilter-persistent`，开机时没有任何东西加载它，重启后规则全部丢失。

请先更新到 `v0.3.0` 并重新“应用规则”，新版会自动安装开机恢复机制。确认是否生效：

```bash
# 方式一：systemd 恢复服务（新版无 netfilter-persistent 时自动创建）
systemctl status ipt-vibe-restore.service
systemctl is-enabled ipt-vibe-restore.service

# 方式二：已安装 netfilter-persistent 时
systemctl is-enabled netfilter-persistent

# 持久化文件是否存在、且包含你的规则
cat /etc/iptables/rules.v4 | grep ipt-vibe

# 不重启也能演练一次开机恢复
iptables -F && iptables -t nat -F   # 谨慎：会清空当前规则
iptables-restore < /etc/iptables/rules.v4
iptables-save | grep ipt-vibe
```

### 内存占用高 / 偶发死机重启（v0.3.0 已缓解）

转发节点内存主要消耗在内核连接跟踪表 `nf_conntrack` 上。排查：

```bash
# 当前连接跟踪数 / 上限，接近上限会丢包并占用大量内存
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max

# 是否出现表满丢包 或 OOM（死机/重启的常见原因）
dmesg | grep -i 'nf_conntrack: table full'
dmesg | grep -i 'out of memory\|oom-kill'

# 内存总览
free -m
```

新版应用规则时会写入 `/etc/sysctl.d/99-ipt-vibe-conntrack.conf`，把默认 5 天的 TCP established 超时降到 1 天，并缩短其他状态超时，让陈旧连接尽快释放。如仍接近上限，可按 VPS 内存适当调整（约每条 300 字节）：

```bash
# 例如把上限设为 131072（约 40MB），按需修改
sysctl -w net.netfilter.nf_conntrack_max=131072
echo 'net.netfilter.nf_conntrack_max = 131072' > /etc/sysctl.d/99-ipt-vibe-ctmax.conf
```

> v0.4.0 起 `nf_conntrack_max` 会按物理内存自动计算，一般无需手动设置。

### 转发经常丢包 / 网页打不开、大文件卡住 / SSH 卡死（v0.4.0 已优化）

多数是「大包被 PMTU 黑洞丢弃」或「连接跟踪表满/误判」导致。v0.4.0 应用规则时会自动：

- 加 TCP MSS 钳制，按路径 MTU 修正握手 MSS，消除大包黑洞丢包；
- 按内存自动扩容连接跟踪表并加大哈希桶，避免 `table full` 丢包；
- 开启 `nf_conntrack_tcp_be_liberal`，避免中转链路乱序包被误判 `INVALID` 丢弃。

排查命令：

```bash
# 确认 MSS 钳制规则已生效
iptables -t mangle -S FORWARD | grep TCPMSS

# 是否出现连接跟踪表满丢包
dmesg | grep -i 'nf_conntrack: table full'

# 查看当前 MTU（中转与落地两端对比，隧道链路常见 1400 左右）
ip link | grep mtu
```

### 目标是 DDNS 域名，家宽 IP 换了以后转发就断（v0.4.1 已修复）

iptables 的 DNAT 规则里只能写死 IP，域名是在「应用规则」时解析并固化的，之后不会自动跟随域名变化。v0.4.1 起，只要有启用中的域名目标规则，应用规则时会自动装一个定时任务，每 2 分钟重解析域名，IP 变了就自动改写这一条规则。

确认自动刷新是否在跑：

```bash
# systemd 版
systemctl status ipt-vibe-ddns.timer
systemctl list-timers | grep ipt-vibe-ddns

# cron 版
cat /etc/cron.d/ipt-vibe-ddns

# 手动立即刷新一次（等不及 2 分钟时）
sudo ipt-vibe --refresh-ddns

# 看刷新日志（IP 变化会记录 old -> new）
grep ddns /etc/ipt-vibe-panel/panel.log
```

> 说明：刷新只在「解析出的新 IP 与上次不同」时才动规则，且只重建变化的那一条；解析失败时保持原样，不会误删正在工作的转发。刷新间隔受域名 TTL 影响，DDNS 记录 TTL 越低跟随越快。

### IPv6 转发不通 / 想做 IPv6→IPv6 中转

`v0.6.0` 起支持 IPv6：目标填 IPv6 地址（或只有 AAAA 记录的域名），面板会自动用 `ip6tables` 建规则。核对：

```bash
# 确认 ip6tables 存在、IPv6 转发已开
command -v ip6tables && cat /proc/sys/net/ipv6/conf/all/forwarding

# 查看本工具管理的 v6 规则
sudo ip6tables -t nat -S PREROUTING | grep ipt-vibe

# 云厂商安全组要放行入口端口的 IPv6；落地机要允许来自中转机 IPv6 的连接
```

### 公网 IPv6 入口 + 仅 IPv4 落地：iptables 双栈做不了（跨族限制）

如果中转机是「公网 IPv6 可入站，但落地机只有 IPv4」，这是 **IPv6→IPv4 跨族（NAT64）**，`iptables`/`ip6tables` 都做不到 —— netfilter 的 DNAT 不跨地址族，这不是配置问题，是机制限制。

可选方案：

- 落地机若能开 IPv6：目标改填落地机的 IPv6，本面板走 v6→v6 即可。
- 确需 IPv6→IPv4：用 NAT64（Jool / TAYGA）或用户态中继（如 Realm / gost），本面板 `v0.6.0` 起不内置这类跨族方案。

### 想让转发端口只对自己开放，躲避 GFW 主动探测

在「添加/修改转发规则」时，把「仅允许的来源 IP/CIDR」填成你的客户端出口 IP（家宽公网 IP、其他服务器 IP，可多个用逗号）。填写后只有这些来源能被转发，GFW/扫描器扫到该端口时连接会被直接拒绝，无法探测代理特征。留空则和以前一样对所有来源开放。

> 提示：家宽 IP 会变动，变了记得回面板更新白名单，否则自己也会被挡在外面。

## 常用命令

打开面板：

```bash
sudo zf
```

查看配置：

```bash
cat /etc/ipt-vibe-panel/rules.conf
```

查看备份：

```bash
ls -lh /etc/ipt-vibe-panel/backups
```

## 安全说明

本项目只提供 SSH 终端菜单，不提供 HTTP 后台，不监听 `8088` 或其他管理端口。安装脚本会清理旧版可能遗留的 `iptables-vibe-panel.service` systemd 服务文件。

v0.6.0 为纯 iptables/ip6tables 双栈,不再内置任何常驻转发进程;从曾内置 Realm 的 v0.5.0 升级上来时,应用规则会自动停用并移除遗留的 `ipt-vibe-realm.service` 与 realm 二进制。

v0.3.0 为了让规则在重启后自动恢复，可能会创建一个 systemd oneshot 服务 `ipt-vibe-restore.service`。它是 `Type=oneshot`：仅在开机时执行一次 `iptables-restore` 后立即退出，不常驻、不监听端口、不占用运行内存。若系统已装 `netfilter-persistent` 则复用它、不创建该服务。卸载面板时会一并移除。
