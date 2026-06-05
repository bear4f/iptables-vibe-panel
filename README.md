# iptables Vibe Panel

一个在 VPS/SSH 终端里运行的 iptables 端口转发可视化菜单面板。

它不是 HTTP 网站，不开放管理端口，也不启动后台 Web 服务。安装后在 SSH 里输入 `zf` 或 `ipt-vibe`，即可打开类似脚本面板的交互菜单。

## 一键安装 / 更新

推荐在 VPS 上直接执行：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh | sudo bash
```

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

当前脚本版本：`v0.2.3`

`v0.2.3` 重点修复：

- 菜单输入强制从 SSH 终端读取，避免安装管道后一直提示“无效选项”。
- 清理旧的异常 DNAT 规则，例如 `--to-destination :10773`。
- 为转发规则补充回程 `FORWARD` 放行，提升 VPN/UDP 转发兼容性。
- 安装依赖时补充 `dnsutils`，域名目标解析更稳定。

进入面板后，顶部应显示：

```text
iptables Vibe Panel v0.2.3
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

## 规则能力

- 支持 TCP、UDP、TCP+UDP。
- 支持单端口和等长端口段转发。
- 支持目标 IPv4 或域名，应用规则时自动解析域名。
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

不应该再出现这种坏规则：

```bash
--to-destination :10773
```

如果曾经出现过坏规则，进入面板选择 `6. 应用规则到 iptables`，新版会先清理旧的 `ipt-vibe:` 规则，再重新生成。

## 兼容策略

默认执行后端是 `iptables`，这是 Debian 10 的稳妥选择。Debian 10 可能使用 `iptables-legacy`，新系统也可能让 `iptables` 指向 `nf_tables` 后端；面板会显示 `iptables --version` 和后端类型，但仍通过 iptables 命令管理规则。

当前版本专注 IPv4 DNAT。IPv6/nftables 原生规则可以后续按同一状态库扩展。

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
2. 开启 IPv4 转发：`net.ipv4.ip_forward=1`。
3. 备份当前 `iptables-save` 输出。
4. 删除所有带 `ipt-vibe:` 备注的旧规则。
5. 根据面板状态库重建启用中的规则。
6. 优先用 `netfilter-persistent save` 保存；没有该工具时写入 `/etc/iptables/rules.v4`。

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
