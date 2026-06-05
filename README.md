# iptables Vibe Panel

一个轻量的 iptables 端口转发可视化操作面板，面向 Debian 10+、Ubuntu 和常见 systemd Linux 服务器。项目不依赖 npm 或第三方 Python 包，适合低版本 Debian 环境。

## 功能

- 在网页面板里新增、编辑、删除端口转发规则。
- 支持 TCP、UDP、TCP+UDP。
- 支持目标 IPv4 或域名，应用规则时自动解析域名。
- 应用前备份当前 `iptables-save` 输出。
- 只管理带 `ipt-vibe:` 标记的规则，不主动删除其他手工规则。
- 自动检测系统、iptables 后端、nftables 可用性、IPv4 转发状态。

## 兼容策略

默认执行后端是 `iptables`，这是 Debian 10 的稳妥选择。Debian 10 可能使用 `iptables-legacy`，新系统也可能让 `iptables` 指向 `nf_tables` 后端；面板会在状态页显示 `iptables --version` 和后端类型，但仍通过 iptables 命令管理规则。

当前版本专注 IPv4 DNAT。IPv6/nftables 原生规则可以后续按同一状态库扩展。

## 部署

安装时必须显式设置面板监听端口，不内置默认端口。

交互式安装：

```bash
cd iptables-vibe-panel
sudo bash install.sh
```

非交互式安装：

```bash
sudo IPT_VIBE_PORT=8090 bash install.sh
```

安装完成后打开：

```text
http://服务器IP:你设置的端口
```

## 手动运行

手动运行也必须指定端口：

```bash
sudo python3 app.py --host 0.0.0.0 --port 8090
```

或：

```bash
sudo IPT_VIBE_PORT=8090 python3 app.py --host 0.0.0.0
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

生产环境请限制面板访问来源，例如只监听内网、配合反向代理认证，或用防火墙只允许管理员 IP 访问你设置的面板端口。
