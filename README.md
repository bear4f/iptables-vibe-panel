# iptables Vibe Panel

一个轻量的 iptables 端口转发可视化面板，面向 Debian 10+、Ubuntu 和常见 systemd Linux 服务器。项目不依赖 npm 或第三方 Python 包，适合低版本 Debian 环境。

## 整合思路

- 借鉴 `arloor/iptablesUtils`：保留简单直观的 `入口端口 -> 目标主机:目标端口` 模型，并支持域名解析。
- 借鉴 `exing567/iptables-control`：每条规则使用 `comment` 标记，应用前备份，添加 `PREROUTING DNAT`、`POSTROUTING MASQUERADE`、`FORWARD ACCEPT` 三类规则，并保存持久化配置。
- 借鉴 `endview/nftpf`：启动时检测系统、iptables 后端、nftables 可用性、IPv4 转发状态；规则状态独立保存，只管理自己标记的规则。

## 兼容策略

默认执行后端是 `iptables`，这是 Debian 10 的稳妥选择。Debian 10 可能使用 `iptables-legacy`，新系统也可能让 `iptables` 指向 `nf_tables` 后端；面板会在状态页显示 `iptables --version` 和后端类型，但仍通过 iptables 命令管理规则。

当前版本专注 IPv4 DNAT。IPv6/nftables 原生规则可以后续按同一状态库扩展。

## 部署

```bash
cd iptables-vibe-panel
sudo bash install.sh
```

默认监听：

```text
http://服务器IP:8088
```

自定义端口：

```bash
sudo IPT_VIBE_PORT=8090 bash install.sh
```

## 手动运行

```bash
sudo python3 app.py --host 0.0.0.0 --port 8088
```

## 文件位置

- 程序目录：`/opt/iptables-vibe-panel`
- 状态库：`/etc/ipt-vibe-panel/rules.json`
- 备份目录：`/etc/ipt-vibe-panel/backups`
- 日志：`/etc/ipt-vibe-panel/panel.log`
- systemd 服务：`iptables-vibe-panel`

## 应用规则时做什么

1. 检查 root 权限、`iptables`、`iptables-save`。
2. 开启 IPv4 转发：`net.ipv4.ip_forward=1`。
3. 备份当前 `iptables-save` 输出。
4. 删除所有带 `ipt-vibe:` 备注的旧规则。
5. 根据面板状态库重建启用中的规则。
6. 优先用 `netfilter-persistent save` 保存；没有该工具时写入 `/etc/iptables/rules.v4`。

## 建议

生产环境请限制面板访问来源，例如只监听内网、配合反向代理认证，或用防火墙只允许管理员 IP 访问 `8088`。
