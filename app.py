#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

APP = "iptables-vibe-panel"
TAG = "ipt-vibe:"
CONFIG_DIR = Path(os.environ.get("IPT_VIBE_CONFIG_DIR", "/etc/ipt-vibe-panel"))
STATE_FILE = CONFIG_DIR / "rules.json"
BACKUP_DIR = CONFIG_DIR / "backups"
LOG_FILE = CONFIG_DIR / "panel.log"


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(text):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (now(), text))
    except OSError:
        pass


def cmd(args, check=False):
    p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        raise RuntimeError("%s: %s" % (" ".join(args), p.stderr.strip()))
    return p


def exists(name):
    return shutil.which(name) is not None


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def ensure_dirs():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE_FILE.exists():
        STATE_FILE.write_text("[]\n", encoding="utf-8")


def read_rules():
    ensure_dirs()
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8") or "[]")
    except Exception:
        data = []
    return data if isinstance(data, list) else []


def write_rules(items):
    ensure_dirs()
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(STATE_FILE)


def os_release():
    out = {}
    p = Path("/etc/os-release")
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v.strip().strip('"')
    return out


def iptables_info():
    if not exists("iptables"):
        return {"installed": False}
    text = (cmd(["iptables", "--version"]).stdout or "").strip()
    backend = "nf_tables" if "nf_tables" in text else ("legacy" if "legacy" in text else "unknown")
    return {"installed": True, "text": text, "backend": backend}


def status():
    osr = os_release()
    try:
        ip_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except OSError:
        ip_forward = "unknown"
    return {
        "app": APP,
        "root": is_root(),
        "os": {
            "name": osr.get("PRETTY_NAME") or platform.platform(),
            "id": osr.get("ID", ""),
            "version_id": osr.get("VERSION_ID", ""),
            "kernel": platform.release(),
        },
        "iptables": iptables_info(),
        "iptables_save": exists("iptables-save"),
        "nft": exists("nft"),
        "netfilter_persistent": exists("netfilter-persistent"),
        "ip_forward": ip_forward,
        "config_dir": str(CONFIG_DIR),
        "managed_rules": len(read_rules()),
    }


def parse_port(value, name):
    try:
        value = int(value)
    except Exception:
        raise ValueError("%s must be a number" % name)
    if value < 1 or value > 65535:
        raise ValueError("%s must be 1-65535" % name)
    return value


def parse_protocols(value):
    raw = str(value or "both").lower().replace(",", " ").split()
    if "both" in raw or not raw:
        raw = ["tcp", "udp"]
    out = []
    for proto in raw:
        if proto not in ("tcp", "udp"):
            raise ValueError("protocol must be tcp, udp, or both")
        if proto not in out:
            out.append(proto)
    return out


def parse_host(value):
    host = str(value or "").strip()
    if not host or " " in host or "/" in host or "|" in host:
        raise ValueError("target host is invalid")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if len(host) > 253 or host.startswith(".") or host.endswith(".") or ".." in host:
        raise ValueError("target host is invalid")
    for label in host.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError("target host is invalid")
        if not all(c.isalnum() or c == "-" for c in label):
            raise ValueError("target host is invalid")
    return host


def resolve_ipv4(value):
    try:
        ipaddress.IPv4Address(value)
        return value
    except Exception:
        pass
    if exists("getent"):
        p = cmd(["getent", "ahostsv4", value])
        for line in p.stdout.splitlines():
            first = line.split()[0] if line.split() else ""
            try:
                ipaddress.IPv4Address(first)
                return first
            except Exception:
                pass
    for fam, _, _, _, addr in socket.getaddrinfo(value, None, socket.AF_INET):
        if fam == socket.AF_INET:
            return addr[0]
    raise ValueError("failed to resolve %s" % value)


def normalize_rule(data, old=None):
    old = old or {}
    listen_start = parse_port(data.get("listen_port_start") or data.get("listen_port"), "listen port")
    listen_end = parse_port(data.get("listen_port_end") or listen_start, "listen end port")
    target_start = parse_port(data.get("target_port_start") or data.get("target_port"), "target port")
    target_end = parse_port(data.get("target_port_end") or target_start, "target end port")
    if listen_start > listen_end or target_start > target_end:
        raise ValueError("port range is reversed")
    if listen_end - listen_start != target_end - target_start:
        raise ValueError("listen and target ranges must have the same length")
    listen_ip = str(data.get("listen_ip") or "").strip()
    if listen_ip:
        ipaddress.IPv4Address(listen_ip)
    target_host = parse_host(data.get("target_host"))
    rule_id = old.get("id") or uuid.uuid4().hex[:12]
    name = str(data.get("name") or old.get("name") or ("%s-to-%s" % (listen_start, target_host))).strip()[:80]
    enabled = data.get("enabled", old.get("enabled", True))
    if isinstance(enabled, str):
        enabled = enabled.lower() not in ("0", "false", "off", "no")
    return {
        "id": rule_id,
        "name": name,
        "enabled": bool(enabled),
        "listen_ip": listen_ip,
        "listen_port_start": listen_start,
        "listen_port_end": listen_end,
        "target_host": target_host,
        "target_port_start": target_start,
        "target_port_end": target_end,
        "protocols": parse_protocols(data.get("protocols") or data.get("protocol")),
        "resolved_ip": old.get("resolved_ip", ""),
        "created_at": old.get("created_at") or now(),
        "updated_at": now(),
    }


def port_span(a, b):
    return str(a) if a == b else "%s:%s" % (a, b)


def dnat_target(ip, a, b):
    return "%s:%s" % (ip, a) if a == b else "%s:%s-%s" % (ip, a, b)


def comment(rule):
    return TAG + rule["id"]


def ensure_runtime_ready():
    if not is_root():
        raise RuntimeError("run as root to apply iptables rules")
    if not exists("iptables") or not exists("iptables-save"):
        raise RuntimeError("iptables and iptables-save are required")
    cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    sysctl_dir = Path("/etc/sysctl.d")
    if sysctl_dir.exists():
        (sysctl_dir / "99-ipt-vibe-panel.conf").write_text("net.ipv4.ip_forward=1\n", encoding="utf-8")


def backup_rules():
    ensure_dirs()
    if not exists("iptables-save"):
        return ""
    path = BACKUP_DIR / ("iptables-%s.rules" % time.strftime("%Y%m%d-%H%M%S"))
    path.write_text(cmd(["iptables-save"]).stdout, encoding="utf-8")
    return str(path)


def delete_managed_rules():
    p = cmd(["iptables-save"])
    for line in p.stdout.splitlines():
        if TAG not in line or not line.startswith("-A "):
            continue
        args = line.replace("-A ", "-D ", 1).split()
        if line.startswith("-A PREROUTING") or line.startswith("-A POSTROUTING"):
            cmd(["iptables", "-t", "nat"] + args)
        else:
            cmd(["iptables"] + args)


def add_rule_to_iptables(rule):
    ip = resolve_ipv4(rule["target_host"])
    rule["resolved_ip"] = ip
    listen_ports = port_span(rule["listen_port_start"], rule["listen_port_end"])
    target_ports = port_span(rule["target_port_start"], rule["target_port_end"])
    target = dnat_target(ip, rule["target_port_start"], rule["target_port_end"])
    mark = comment(rule)
    for proto in rule["protocols"]:
        pre = ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", proto]
        if rule["listen_ip"]:
            pre += ["-d", rule["listen_ip"]]
        pre += ["--dport", listen_ports, "-m", "comment", "--comment", mark, "-j", "DNAT", "--to-destination", target]
        post = ["iptables", "-t", "nat", "-A", "POSTROUTING", "-p", proto, "-d", ip, "--dport", target_ports, "-m", "comment", "--comment", mark, "-j", "MASQUERADE"]
        forward = ["iptables", "-A", "FORWARD", "-p", proto, "-d", ip, "--dport", target_ports, "-m", "comment", "--comment", mark, "-j", "ACCEPT"]
        cmd(pre, True)
        cmd(post, True)
        cmd(forward, True)


def persist_rules():
    if exists("netfilter-persistent"):
        cmd(["netfilter-persistent", "save"])
        return "netfilter-persistent"
    target_dir = Path("/etc/iptables")
    target_dir.mkdir(parents=True, exist_ok=True)
    out = target_dir / "rules.v4"
    out.write_text(cmd(["iptables-save"], True).stdout, encoding="utf-8")
    return str(out)


def apply_rules():
    ensure_runtime_ready()
    items = read_rules()
    backup = backup_rules()
    delete_managed_rules()
    count = 0
    for rule in items:
        if rule.get("enabled", True):
            add_rule_to_iptables(rule)
            count += 1
    saved_to = persist_rules()
    write_rules(items)
    log("applied %s rules" % count)
    return {"ok": True, "applied": count, "backup": backup, "saved_to": saved_to}


HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>iptables Vibe Panel</title><style>body{margin:0;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f7f9;color:#17202a}header{position:sticky;top:0;background:#fff;border-bottom:1px solid #d7dde5}main,.bar{max-width:1180px;margin:auto}.bar{min-height:64px;display:flex;align-items:center;justify-content:space-between;padding:0 18px}main{display:grid;grid-template-columns:320px 1fr;gap:16px;padding:18px}aside,section{background:#fff;border:1px solid #d7dde5;border-radius:8px;padding:16px}h1{font-size:20px}h2{font-size:15px}.kv{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid #edf1f5;padding:8px 0}.kv span:first-child{color:#667085}form{display:grid;grid-template-columns:repeat(6,1fr);gap:10px}label{display:grid;gap:5px;font-size:12px;color:#667085}.wide{grid-column:span 2}.full{grid-column:1/-1}input,select,button{min-height:36px;border:1px solid #d7dde5;border-radius:6px;padding:0 10px;font:inherit}button{background:#fff;font-weight:650;cursor:pointer}.primary{background:#1677ff;color:#fff}.good{background:#12a150;color:#fff}.danger{color:#d92d20}table{width:100%;border-collapse:collapse;table-layout:fixed;margin-top:14px}td,th{border-bottom:1px solid #edf1f5;padding:10px 8px;text-align:left;font-size:13px;word-break:break-word}.pill{display:inline-flex;padding:3px 8px;border-radius:999px;background:#eef6ff;color:#175cd3}.off{background:#f2f4f7;color:#667085}.msg{margin-top:12px;color:#667085;font-size:13px}@media(max-width:900px){main{grid-template-columns:1fr}form{grid-template-columns:repeat(2,1fr)}.wide{grid-column:span 2}}</style></head><body><header><div class="bar"><h1>iptables Vibe Panel</h1><div><button id="refresh">刷新</button> <button id="apply" class="good">应用到系统</button></div></div></header><main><aside><h2>系统状态</h2><div id="status"></div><div id="msg" class="msg"></div></aside><section><h2>端口转发</h2><form id="form"><input type="hidden" name="id"><label class="wide">名称<input name="name" placeholder="home-https"></label><label>监听端口<input name="listen_port_start" required placeholder="8443"></label><label>结束端口<input name="listen_port_end" placeholder="留空=单端口"></label><label class="wide">目标 IP / 域名<input name="target_host" required placeholder="home.example.com"></label><label>目标端口<input name="target_port_start" required placeholder="443"></label><label>目标结束<input name="target_port_end" placeholder="留空=单端口"></label><label>监听 IP<input name="listen_ip" placeholder="留空为全部"></label><label>协议<select name="protocols"><option value="both">TCP + UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label>状态<select name="enabled"><option value="true">启用</option><option value="false">停用</option></select></label><div class="full"><button class="primary">保存规则</button> <button type="button" id="reset">清空</button></div></form><table><thead><tr><th>规则</th><th>入口</th><th>目标</th><th>协议</th><th>状态</th><th>操作</th></tr></thead><tbody id="rules"></tbody></table></section></main><script>const $=i=>document.getElementById(i);const say=(t,b=false)=>{$('msg').textContent=t||'';$('msg').style.color=b?'#d92d20':'#667085'};async function api(p,o){const r=await fetch(p,o);const d=await r.json();if(!r.ok||d.ok===false)throw new Error(d.error||'请求失败');return d}function pp(a,b){return a===b?a:`${a}-${b}`}function inbound(r){return `${r.listen_ip||'0.0.0.0'}:${pp(r.listen_port_start,r.listen_port_end)}`}function target(r){return `${r.target_host}:${pp(r.target_port_start,r.target_port_end)}`}function drawStatus(s){let rows=[['系统',s.os.name],['内核',s.os.kernel],['权限',s.root?'root':'非 root'],['iptables',s.iptables.installed?s.iptables.text:'未安装'],['后端',s.iptables.backend||'-'],['持久化',s.netfilter_persistent?'netfilter-persistent':'/etc/iptables/rules.v4'],['IPv4 转发',s.ip_forward],['配置目录',s.config_dir]];$('status').innerHTML=rows.map(x=>`<div class="kv"><span>${x[0]}</span><span>${x[1]}</span></div>`).join('')}function drawRules(rs){$('rules').innerHTML=rs.map(r=>`<tr><td>${r.name}<br><small>${r.id}</small></td><td>${inbound(r)}</td><td>${target(r)}${r.resolved_ip?`<br><small>${r.resolved_ip}</small>`:''}</td><td>${r.protocols.join(' + ')}</td><td><span class="pill ${r.enabled?'':'off'}">${r.enabled?'启用':'停用'}</span></td><td><button onclick='edit(${JSON.stringify(r)})'>编辑</button> <button class="danger" onclick='delRule("${r.id}")'>删除</button></td></tr>`).join('')}async function load(){let s=await api('/api/status');let r=await api('/api/rules');drawStatus(s);drawRules(r.rules||[])}window.edit=r=>{let f=$('form');for(let k of ['id','name','listen_ip','listen_port_start','listen_port_end','target_host','target_port_start','target_port_end'])f[k].value=r[k]||'';f.protocols.value=r.protocols.length===2?'both':r.protocols[0];f.enabled.value=String(!!r.enabled);say('正在编辑 '+r.name)};window.delRule=async id=>{if(!confirm('删除这条规则？应用后才会更新系统。'))return;try{await api('/api/rules/'+id,{method:'DELETE'});await load();say('已删除，记得应用到系统')}catch(e){say(e.message,true)}};$('form').onsubmit=async e=>{e.preventDefault();let f=e.currentTarget;let body=Object.fromEntries(new FormData(f).entries());body.enabled=body.enabled==='true';try{let path=body.id?'/api/rules/'+body.id:'/api/rules';await api(path,{method:body.id?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});f.reset();f.id.value='';await load();say('已保存，点应用到系统生效')}catch(e){say(e.message,true)}};$('reset').onclick=()=>{$('form').reset();$('form').id.value='';say('')};$('refresh').onclick=()=>load().catch(e=>say(e.message,true));$('apply').onclick=async()=>{if(!confirm('将备份当前 iptables，并重建本面板管理的规则。继续？'))return;try{$('apply').disabled=true;let r=await api('/api/apply',{method:'POST'});await load();say(`已应用 ${r.applied} 条规则，备份：${r.backup||'无'}`)}catch(e){say(e.message,true)}finally{$('apply').disabled=false}};load().catch(e=>say(e.message,true));</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "IptVibePanel/1.0"

    def send_json(self, code, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        return json.loads(self.rfile.read(n).decode("utf-8")) if n else {}

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/":
                raw = HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            elif path == "/api/status":
                self.send_json(200, status())
            elif path == "/api/rules":
                self.send_json(200, {"ok": True, "rules": read_rules()})
            else:
                self.send_json(404, {"ok": False, "error": "not found"})
        except Exception as exc:
            self.send_json(500, {"ok": False, "error": str(exc)})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/rules":
                items = read_rules()
                item = normalize_rule(self.body())
                items.append(item)
                write_rules(items)
                self.send_json(200, {"ok": True, "rule": item})
            elif path == "/api/apply":
                self.send_json(200, apply_rules())
            else:
                self.send_json(404, {"ok": False, "error": "not found"})
        except Exception as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})

    def do_PUT(self):
        path = urlparse(self.path).path
        try:
            if not path.startswith("/api/rules/"):
                self.send_json(404, {"ok": False, "error": "not found"})
                return
            rid = path.rsplit("/", 1)[-1]
            items = read_rules()
            for idx, old in enumerate(items):
                if old.get("id") == rid:
                    items[idx] = normalize_rule(self.body(), old)
                    write_rules(items)
                    self.send_json(200, {"ok": True, "rule": items[idx]})
                    return
            self.send_json(404, {"ok": False, "error": "rule not found"})
        except Exception as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})

    def do_DELETE(self):
        path = urlparse(self.path).path
        if path.startswith("/api/rules/"):
            rid = path.rsplit("/", 1)[-1]
            write_rules([r for r in read_rules() if r.get("id") != rid])
            self.send_json(200, {"ok": True})
        else:
            self.send_json(404, {"ok": False, "error": "not found"})

    def log_message(self, fmt, *args):
        log("%s - %s" % (self.address_string(), fmt % args))


def parse_runtime_port(parser, args):
    value = args.port if args.port is not None else os.environ.get("IPT_VIBE_PORT")
    if value in (None, ""):
        parser.error("panel listen port is required; use --port PORT or IPT_VIBE_PORT=PORT")
    port = parse_port(value, "panel listen port")
    return port


def main():
    parser = argparse.ArgumentParser(description=APP)
    parser.add_argument("--host", default=os.environ.get("IPT_VIBE_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=None, help="panel listen port; required")
    args = parser.parse_args()
    runtime_port = parse_runtime_port(parser, args)
    ensure_dirs()
    print("%s listening on http://%s:%s" % (APP, args.host, runtime_port))
    ThreadingHTTPServer((args.host, runtime_port), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
