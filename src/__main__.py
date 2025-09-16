import os
import sys
import base64
import json
import sqlite3
import subprocess
import yaml
from pathlib import Path
from typing import Optional

import typer
import requests
from rich import print
from rich.table import Table
from urllib.parse import urlsplit, parse_qs, unquote

app = typer.Typer(help="Heresy: Xray-Core 管理 CLI")


def data_dir() -> Path:
    home = Path.home()
    return home / ".heresy"


def db_path() -> Path:
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / "heresy.db"


def config_path() -> Path:
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / "xray_config.json"


def app_config_path() -> Path:
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / "config.json"


def hy2_config_path() -> Path:
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / "hy2_config.yaml"


HY2_SOCKS_PORT = 10810
HY2_HTTP_PORT = 10811


def load_app_config() -> dict:
    p = app_config_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_app_config(cfg: dict) -> None:
    app_config_path().write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def ensure_schema(conn: sqlite3.Connection) -> None:
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS subscribes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL
        );
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subscribe_id INTEGER,
            protocol TEXT NOT NULL,
            uuid TEXT NOT NULL,
            addr TEXT NOT NULL,
            port INTEGER NOT NULL,
            info TEXT,
            type TEXT,
            encryption TEXT,
            security TEXT,
            extra_params TEXT
        );
        """
    )
    conn.commit()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()))
    ensure_schema(conn)
    return conn


subscribe_app = typer.Typer(help="订阅管理")
node_app = typer.Typer(help="节点管理")
config_app = typer.Typer(help="配置管理")
proxy_app = typer.Typer(help="代理进程")
sysproxy_app = typer.Typer(help="系统代理")
diag_app = typer.Typer(help="诊断信息")

app.add_typer(subscribe_app, name="subscribe")
app.add_typer(node_app, name="node")
app.add_typer(config_app, name="config")
app.add_typer(proxy_app, name="proxy")
app.add_typer(sysproxy_app, name="sys-proxy")
app.add_typer(diag_app, name="diag")


@subscribe_app.command("add")
def sub_add(name: str = typer.Option(...), url: str = typer.Option(...)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO subscribes(name,url) VALUES(?,?)", (name, url))
    conn.commit()
    print("[green]添加订阅成功[/green]")


@subscribe_app.command("list")
def sub_list():
    conn = get_conn()
    rows = conn.execute("SELECT id,name,url FROM subscribes ORDER BY id").fetchall()
    if not rows:
        print("[yellow]暂无订阅[/yellow]")
        return
    t = Table("ID", "名称", "URL")
    for r in rows:
        t.add_row(str(r[0]), r[1], r[2])
    print(t)


from typing import Optional


def _first(q: dict, key: str, default: Optional[str] = None) -> Optional[str]:
    v = q.get(key)
    if not v:
        return default
    return v[0]


def _parse_vless(link: str):
    u = urlsplit(link)
    uuid = u.username or ""
    addr = u.hostname or ""
    port = int(u.port or 443)
    q = parse_qs(u.query)
    security = (_first(q, "security", "none") or "none").lower()
    ntype = (_first(q, "type", "tcp") or "tcp").lower()
    sni = _first(q, "sni") or _first(q, "peer")
    host = _first(q, "host")
    path = _first(q, "path")
    service_name = _first(q, "serviceName")
    fp = _first(q, "fp") or _first(q, "fingerprint")
    # REALITY 专有参数
    pbk = _first(q, "pbk") or _first(q, "publicKey")
    sid = _first(q, "sid") or _first(q, "shortId")
    spx = _first(q, "spx") or _first(q, "spiderX")
    flow = _first(q, "flow")
    info = unquote(u.fragment or "")
    extra = {k: v for k, v in {
        "sni": sni,
        "host": host,
        "path": path,
        "serviceName": service_name,
        "fp": fp,
        "pbk": pbk,
        "sid": sid,
        "spx": spx,
        "flow": flow,
    }.items() if v}
    return {
        "protocol": "vless",
        "uuid": uuid,
        "addr": addr,
        "port": port,
        "info": info,
        "type": ntype,
        "encryption": "none",
        "security": security,
        "extra_params": json.dumps(extra, ensure_ascii=False) if extra else None,
    }


def _parse_vmess(link: str):
    payload_b64 = link.split("://", 1)[1]
    try:
        data = base64.b64decode(payload_b64 + "==").decode("utf-8", errors="ignore")
        cfg = json.loads(data)
    except Exception:
        return None
    addr = cfg.get("add") or cfg.get("addr") or cfg.get("host") or ""
    port = int(cfg.get("port") or 443)
    uuid = cfg.get("id") or ""
    info = cfg.get("ps") or ""
    ntype = (cfg.get("net") or "tcp").lower()
    tls = cfg.get("tls") or "none"
    scy = cfg.get("scy") or "auto"
    aid = int(cfg.get("aid") or cfg.get("alterId") or 0)
    host = cfg.get("host") or None
    path = cfg.get("path") or None
    sni = cfg.get("sni") or None
    return {
        "protocol": "vmess",
        "uuid": uuid,
        "addr": addr,
        "port": port,
        "info": info,
        "type": ntype,
        "encryption": scy,
        "security": tls,
        "extra_params": json.dumps({k: v for k, v in {"host": host, "path": path, "sni": sni, "aid": aid}.items() if v not in (None, "")}, ensure_ascii=False),
    }


def _parse_trojan(link: str):
    u = urlsplit(link)
    password = u.username or ""
    addr = u.hostname or ""
    port = int(u.port or 443)
    q = parse_qs(u.query)
    sni = _first(q, "sni")
    ntype = (_first(q, "type", "tcp") or "tcp").lower()
    host = _first(q, "host")
    path = _first(q, "path")
    service_name = _first(q, "serviceName")
    info = unquote(u.fragment or "")
    extra = {k: v for k, v in {"sni": sni, "host": host, "path": path, "serviceName": service_name}.items() if v}
    return {
        "protocol": "trojan",
        "uuid": password,  # 复用 uuid 字段存放密码
        "addr": addr,
        "port": port,
        "info": info,
        "type": ntype,
        "encryption": None,
        "security": "tls",  # trojan 默认使用 tls
        "extra_params": json.dumps(extra, ensure_ascii=False) if extra else None,
    }


def _parse_hy2(link: str):
    u = urlsplit(link)
    user = u.username or ""
    pwd = u.password or ""
    addr = u.hostname or ""
    port = int(u.port or 443)
    q = parse_qs(u.query)
    sni = _first(q, "sni") or None
    obfs = _first(q, "obfs") or None
    obfs_pwd = _first(q, "obfs-password") or _first(q, "obfsPassword") or None
    insecure = _first(q, "insecure") == "1"
    info = unquote(u.fragment or "")
    return {
        "protocol": "hy2",
        "uuid": f"{user}:{pwd}" if user or pwd else (user or pwd or ""),
        "addr": addr,
        "port": port,
        "info": info,
        "type": None,
        "encryption": obfs,
        "security": "tls",
        "extra_params": json.dumps({k: v for k, v in {"sni": sni, "obfs": obfs, "obfs_password": obfs_pwd, "insecure": insecure}.items() if v is not None}, ensure_ascii=False),
    }


def _parse_ss(link: str):
    # 支持两种：ss://base64(method:password@host:port)#tag 或 ss://method:password@host:port#tag
    body = link.split("://", 1)[1]
    tag = ""
    if "#" in body:
        body, tag_enc = body.split("#", 1)
        try:
            tag = unquote(tag_enc)
        except Exception:
            tag = tag_enc
    parsed = body
    if "@" not in body:
        # base64 格式
        try:
            decoded = base64.b64decode(body + "==").decode("utf-8", errors="ignore")
            parsed = decoded
        except Exception:
            return None
    # method:password@host:port
    try:
        cred, server = parsed.split("@", 1)
        method, password = cred.split(":", 1)
        host, port_s = server.rsplit(":", 1)
        port = int(port_s)
    except Exception:
        return None
    return {
        "protocol": "shadowsocks",
        "uuid": password,
        "addr": host,
        "port": port,
        "info": tag,
        "type": None,
        "encryption": method,
        "security": None,
        "extra_params": None,
    }


def parse_node_link(link: str):
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vless":
        return _parse_vless(link)
    if scheme == "vmess":
        return _parse_vmess(link)
    if scheme == "trojan":
        return _parse_trojan(link)
    if scheme in ("hy2", "hysteria2"):
        return _parse_hy2(link)
    if scheme == "ss":
        return _parse_ss(link)
    return None


@subscribe_app.command("update")
def sub_update(id: Optional[int] = typer.Argument(None), all: bool = typer.Option(False, "--all", help="更新全部订阅")):
    conn = get_conn()
    cur = conn.cursor()
    targets = []
    if all:
        targets = cur.execute("SELECT id,name,url FROM subscribes").fetchall()
    elif id is not None:
        row = cur.execute("SELECT id,name,url FROM subscribes WHERE id=?", (id,)).fetchone()
        if row:
            targets = [row]
    else:
        print("[red]请提供订阅 ID 或使用 --all[/red]")
        raise typer.Exit(1)

    for sid, name, url in targets:
        print(f"更新订阅: {name}")
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            b64 = resp.text.strip()
        except Exception as e:
            print(f"[red]下载失败[/red]: {e}")
            continue

        try:
            content = base64.b64decode(b64 + "==").decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"[red]解码失败[/red]: {e}")
            continue

        lines = [x.strip() for x in content.splitlines() if x.strip()]
        ok, fail = 0, 0
        try:
            cur.execute("BEGIN")
            cur.execute("DELETE FROM nodes WHERE subscribe_id=?", (sid,))
            for line in lines:
                node = parse_node_link(line)
                if not node:
                    fail += 1
                    continue
                cur.execute(
                    """
                    INSERT INTO nodes(subscribe_id, protocol, uuid, addr, port, info, type, encryption, security, extra_params)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (sid, node["protocol"], node["uuid"], node["addr"], node["port"], node["info"], node["type"], node["encryption"], node["security"], node["extra_params"]),
                )
                ok += 1
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[red]写入失败[/red]: {e}
内容可能已回滚")
            continue
        print(f"[green]完成[/green] 成功 {ok} 条，失败 {fail} 条")


@node_app.command("list")
def node_list(subscribe: Optional[int] = typer.Option(None)):
    conn = get_conn()
    if subscribe is None:
        rows = conn.execute("SELECT id,protocol,addr,port,info FROM nodes ORDER BY id").fetchall()
    else:
        rows = conn.execute("SELECT id,protocol,addr,port,info FROM nodes WHERE subscribe_id=? ORDER BY id", (subscribe,)).fetchall()
    if not rows:
        print("[yellow]暂无节点[/yellow]")
        return
    cfg = load_app_config()
    current_id = cfg.get("current_node_id")
    t = Table("ID", "协议", "地址", "端口", "状态", "别名")
    for r in rows:
        status = "当前" if current_id == r[0] else ""
        t.add_row(str(r[0]), r[1], r[2], str(r[3]), status, (r[4] or "")[:30])
    print(t)


@node_app.command("select")
def node_select(id: int = typer.Argument(...)):
    conn = get_conn()
    row = conn.execute("SELECT id,protocol,uuid,addr,port,info FROM nodes WHERE id=?", (id,)).fetchone()
    if not row:
        print("[red]未找到该节点[/red]")
        raise typer.Exit(1)
    cfg = load_app_config()
    cfg["current_node_id"] = id
    save_app_config(cfg)
    print("[green]已选择节点[/green]")


def default_inbounds():
    return [
        {
            "tag": "socks-in",
            "port": 10808,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
        {
            "tag": "http-in",
            "port": 10809,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        },
    ]


def default_routing():
    return {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"type": "field", "outboundTag": "direct", "domain": ["domain:baidu.com", "domain:qq.com", "domain:bilibili.com", "geosite:cn"]},
            {"type": "field", "outboundTag": "direct", "ip": ["geoip:private", "geoip:cn"]},
            {"type": "field", "port": "53", "network": "udp", "outboundTag": "dns-out"},
        ],
    }


def outbound_for_node(node: dict) -> dict:
    proto = node["protocol"].lower()
    addr = node["addr"]
    port = node["port"]
    stream = {}
    ntype = (node.get("type") or "tcp").lower()
    if ntype:
        stream["network"] = ntype

    # security / TLS
    security = (node.get("security") or "none").lower()
    extra = None
    try:
        extra = json.loads(node.get("extra_params") or "null")
    except Exception:
        extra = None
    if security == "tls":
        stream["security"] = "tls"
        tls_settings = {}
        sni = extra.get("sni") if isinstance(extra, dict) else None
        if sni:
            tls_settings["serverName"] = sni
        if tls_settings:
            stream["tlsSettings"] = tls_settings
    elif security == "reality":
        stream["security"] = "reality"
        rset = {}
        if isinstance(extra, dict):
            if extra.get("sni"):
                rset["serverName"] = extra.get("sni")
            if extra.get("pbk"):
                rset["publicKey"] = extra.get("pbk")
            if extra.get("sid"):
                rset["shortId"] = extra.get("sid")
            if extra.get("spx"):
                rset["spiderX"] = extra.get("spx")
            if extra.get("fp"):
                rset["fingerprint"] = extra.get("fp")
        if rset:
            stream["realitySettings"] = rset

    # transport settings
    if ntype == "ws":
        ws = {}
        if extra and extra.get("path"):
            ws["path"] = extra.get("path")
        if extra and extra.get("host"):
            ws["headers"] = {"Host": extra.get("host")}
        if ws:
            stream["wsSettings"] = ws
    elif ntype == "grpc":
        if extra and extra.get("serviceName"):
            stream["grpcSettings"] = {"serviceName": extra.get("serviceName")}

    if proto == "vless":
        users = [{"id": node["uuid"], "encryption": node.get("encryption") or "none"}]
        if isinstance(extra, dict) and extra.get("flow"):
            users[0]["flow"] = extra.get("flow")
        return {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [
                    {
                        "address": addr,
                        "port": port,
                        "users": users,
                    }
                ]
            },
            "streamSettings": stream or None,
        }
    if proto == "vmess":
        aid = 0
        if isinstance(extra, dict) and extra.get("aid") is not None:
            try:
                aid = int(extra.get("aid"))
            except Exception:
                aid = 0
        return {
            "protocol": "vmess",
            "tag": "proxy",
            "settings": {
                "vnext": [
                    {
                        "address": addr,
                        "port": port,
                        "users": [
                            {"id": node["uuid"], "alterId": aid, "security": node.get("encryption") or "auto"}
                        ],
                    }
                ]
            },
            "streamSettings": stream or None,
        }
    if proto == "trojan":
        sni = None
        if extra and extra.get("sni"):
            sni = extra.get("sni")
        settings = {
            "servers": [
                {
                    "address": addr,
                    "port": port,
                    "password": node["uuid"],
                    **({"sni": sni} if sni else {}),
                }
            ]
        }
        return {
            "protocol": "trojan",
            "tag": "proxy",
            "settings": settings,
            "streamSettings": stream or None,
        }
    if proto == "shadowsocks":
        return {
            "protocol": "shadowsocks",
            "tag": "proxy",
            "settings": {
                "servers": [
                    {
                        "address": addr,
                        "port": port,
                        "method": node.get("encryption") or "aes-128-gcm",
                        "password": node["uuid"],
                    }
                ]
            },
        }
    if proto in ("hy2", "hysteria2"):
        # 将出站改为连接到本地 hy2 客户端 socks
        return {
            "protocol": "socks",
            "tag": "proxy",
            "settings": {
                "servers": [
                    {"address": "127.0.0.1", "port": HY2_SOCKS_PORT}
                ]
            }
        }
    return {"protocol": proto, "settings": {}, "tag": "proxy"}


@config_app.command("generate")
def config_generate():
    cfg = load_app_config()
    node_id = cfg.get("current_node_id")
    if not node_id:
        print("[red]未选择当前节点[/red]")
        raise typer.Exit(1)
    conn = get_conn()
    r = conn.execute("SELECT id,protocol,uuid,addr,port,info,type,encryption,security,extra_params FROM nodes WHERE id=?", (node_id,)).fetchone()
    if not r:
        print("[red]当前节点已不存在[/red]")
        raise typer.Exit(1)
    node = {"id": r[0], "protocol": r[1], "uuid": r[2], "addr": r[3], "port": r[4], "info": r[5], "type": r[6], "encryption": r[7], "security": r[8], "extra_params": r[9]}
    # hy2: 生成 hysteria2 客户端配置，xray 出站走本地 socks
    if node["protocol"].lower() in ("hy2", "hysteria2"):
        try:
            extra = json.loads(node.get("extra_params") or "null")
        except Exception:
            extra = {}
        user = node["uuid"] or ""
        password = user
        if ":" in user:
            password = user.split(":", 1)[1]
        hy_cfg = {
            "server": f"{node['addr']}:{node['port']}",
            "auth": password,
            "tls": {
                **({"sni": extra.get("sni")} if isinstance(extra, dict) and extra.get("sni") else {}),
                "insecure": bool(extra.get("insecure", False)) if isinstance(extra, dict) else False,
            },
        }
        if isinstance(extra, dict) and extra.get("obfs"):
            hy_cfg["obfs"] = {"type": extra.get("obfs"), "password": extra.get("obfs_password") or extra.get("obfs-password")}
        hy_cfg["socks5"] = {"listen": f"127.0.0.1:{HY2_SOCKS_PORT}"}
        hy_cfg["http"] = {"listen": f"127.0.0.1:{HY2_HTTP_PORT}"}
        # 清理空
        if not hy_cfg.get("tls", {}).get("sni"):
            hy_cfg["tls"].pop("sni", None)
        if hy_cfg.get("obfs", {}).get("type") is None:
            hy_cfg.pop("obfs", None)
        from yaml import safe_dump
        hy2_config_path().write_text(safe_dump(hy_cfg, sort_keys=False, allow_unicode=True), encoding="utf-8")
    xcfg = {
        "log": {"loglevel": "warning"},
        "inbounds": default_inbounds(),
        "outbounds": [
            outbound_for_node(node),
            {"protocol": "freedom", "tag": "direct", "settings": {}},
            {"protocol": "blackhole", "tag": "block", "settings": {}},
            {"protocol": "dns", "tag": "dns-out"},
        ],
        "routing": default_routing(),
    }
    config_path().write_text(json.dumps(xcfg, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[green]已生成配置[/green]: {config_path()}")


@config_app.command("path")
def config_show_path():
    print(str(config_path()))


def is_xray_running() -> bool:
    if sys.platform.startswith("win"):
        try:
            out = subprocess.check_output(["tasklist"], creationflags=subprocess.CREATE_NO_WINDOW)
            return b"xray.exe" in out
        except Exception:
            return False
    else:
        try:
            subprocess.check_call(["pgrep", "-x", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False


@proxy_app.command("status")
def proxy_status():
    print("运行中" if is_xray_running() else "已停止")


@proxy_app.command("start")
def proxy_start(xray: str = typer.Option("xray")):
    if is_xray_running():
        print("[yellow]Xray 已在运行[/yellow]")
        return
    if not config_path().exists():
        print("[red]未找到配置，请先执行 config generate[/red]")
        raise typer.Exit(1)
    # 如为 hy2 节点，先启动 hysteria2 客户端
    cfg = load_app_config()
    node_id = cfg.get("current_node_id")
    if node_id:
        conn = get_conn()
        r = conn.execute("SELECT protocol FROM nodes WHERE id=?", (node_id,)).fetchone()
        if r and (r[0] or "").lower() in ("hy2", "hysteria2"):
            if not hy2_config_path().exists():
                print("[red]未找到 hy2 配置，请先执行 config generate[/red]")
                raise typer.Exit(1)
            hysteria = "hysteria"
            try:
                if sys.platform.startswith("win"):
                    subprocess.Popen([hysteria, "-c", str(hy2_config_path())], creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    subprocess.Popen([hysteria, "-c", str(hy2_config_path())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("[green]已启动 Hysteria2 客户端[/green]")
            except FileNotFoundError:
                print("[red]未找到 hysteria 可执行文件，请安装或将其加入 PATH[/red]")
                raise typer.Exit(1)
    try:
        if sys.platform.startswith("win"):
            subprocess.Popen([xray, "-c", str(config_path())], creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            subprocess.Popen([xray, "-c", str(config_path())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[green]已启动 Xray[/green]")
    except FileNotFoundError:
        print("[red]未找到 xray 可执行文件，请通过 --xray 指定路径[/red]")


@proxy_app.command("stop")
def proxy_stop():
    if is_xray_running():
        try:
            if sys.platform.startswith("win"):
                subprocess.call(["taskkill", "/F", "/IM", "xray.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                subprocess.call(["pkill", "-x", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[green]已停止 Xray[/green]")
        except Exception as e:
            print(f"[red]停止失败[/red]: {e}")
    # 停止 hysteria2（如果在运行）
    try:
        if sys.platform.startswith("win"):
            subprocess.call(["taskkill", "/F", "/IM", "hysteria-windows-amd64.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.call(["taskkill", "/F", "/IM", "hysteria.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            subprocess.call(["pkill", "-x", "hysteria"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[green]已停止 Hysteria2 客户端（如在运行）[/green]")
    except Exception:
        pass


def set_system_proxy(enable: bool, http_port: int = 10809, socks_port: int = 10808) -> bool:
    if sys.platform.startswith("win"):
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
                if enable:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{http_port}")
            return True
        except Exception:
            return False
    else:
        # GNOME 环境
        try:
            mode = "manual" if enable else "none"
            subprocess.call(["gsettings", "set", "org.gnome.system.proxy", "mode", mode])
            if enable:
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.http", "host", "127.0.0.1"]) 
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.http", "port", str(http_port)])
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.https", "host", "127.0.0.1"]) 
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.https", "port", str(http_port)])
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"]) 
                subprocess.call(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(socks_port)])
            return True
        except Exception:
            return False


@sysproxy_app.command("enable")
def sysproxy_enable(port: int = typer.Option(10809), socks: int = typer.Option(10808)):
    ok = set_system_proxy(True, http_port=port, socks_port=socks)
    print("[green]已开启系统代理[/green]" if ok else "[red]开启系统代理失败[/red]")


@sysproxy_app.command("disable")
def sysproxy_disable():
    ok = set_system_proxy(False)
    print("[green]已关闭系统代理[/green]" if ok else "[red]关闭系统代理失败[/red]")


@diag_app.command("info")
def diag_info():
    cfg = load_app_config()
    node_id = cfg.get("current_node_id")
    print(f"数据目录: {data_dir()}")
    print(f"数据库路径: {db_path()}")
    print(f"配置路径: {config_path()}")
    print(f"当前节点: {node_id if node_id else '未选择'}")
    print(f"Xray 进程: {'运行中' if is_xray_running() else '已停止'}")


if __name__ == "__main__":
    app()


