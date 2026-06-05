# iptables Vibe Panel

一个在 VPS/SSH 终端里运行的 iptables 端口转发可视化菜单面板。它不是 HTTP 网站，不开放管理端口；安装后在 SSH 里输入 `zf` 或 `ipt-vibe` 即可打开类似脚本面板的交互菜单。

## 一键安装

推荐在 VPS 上直接执行：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh | sudo bash
```

如果你的系统不适合管道执行，使用下载后执行：

```bash
curl -fsSL https://raw.githubusercontent.com/bear4f/iptables-vibe-panel/main/install.sh -o /tmp/iptables-vibe-panel-install.sh
sudo bash /tmp/iptables-vibe-panel-install.sh
```

安装完成后打开面板：

```bash
zf
```

也可以使用完整命令：

```bash
ipt-vibe
```

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
- 应用前备份当前 `iptables-save` 输出。
- 只管理带 `ipt-vibe:` 标记的规则，不主动删除其他手工规则。
- 自动检测系统、iptables 后端、IPv4 转发状态。

## 兼容策略

默认执行后端是 `iptables`，这是 Debian 10 的稳妥选择。Debian 10 可能使用 `iptables-legacy`，新系统也可能让 `iptables` 指向 `nf_tables` 后端；面板会显示 `iptables --version` 和后端类型，但仍通过 iptables 命令管理规则。

当前版本专注 IPv4 DNAT。IPv6/nftables 原生规则可以后续按同一状态库扩展。

## 克隆仓库安装

```bash
git clone https://github.com/bear4f/iptables-vibe-panel.git
cd iptables-vibe-panel
sudo bash install.sh
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

## 常用命令

打开面板：

```bash
zf
```

查看配置：

```bash
cat /etc/ipt-vibe-panel/rules.conf
```

查看备份：

```bash
ls -lh /etc/ipt-vibe-panel/backups
```
