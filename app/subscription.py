"""订阅拉取 + 解析 + 去重 + 过滤 → sing-box outbound。

支持四种输入：base64 明文链接列表、明文链接列表、Clash/mihomo YAML、sing-box 出站 JSON。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field

import httpx

DEFAULT_PORTS = {"http": 80, "https": 443, "socks": 1080, "socks5": 1080}


class SubError(Exception):
    pass


@dataclass
class ParsedNode:
    name: str
    protocol: str
    host: str
    port: int
    outbound: dict
    uri: str
    fingerprint: str = ""

    def finalize(self) -> "ParsedNode":
        # 去重指纹：不含节点名（订阅常给同名节点），只认"连得上就一样"的连接参数
        ob = self.outbound
        tls = ob.get("tls") or {}
        key = json.dumps({
            "t": ob.get("type"), "s": ob.get("server"), "p": ob.get("server_port"),
            "u": ob.get("username"), "pw": ob.get("password"), "uuid": ob.get("uuid"),
            "m": ob.get("method"), "flow": ob.get("flow"),
            "tr": ob.get("transport"),
            "ts": tls.get("server_name"), "ti": tls.get("insecure"),
        }, sort_keys=True, ensure_ascii=False)
        self.fingerprint = hashlib.sha1(key.encode()).hexdigest()[:20]
        return self


def _tls(opts: dict, default_sni: str | None = None) -> dict | None:
    sec = (opts.get("security") or "").lower()
    if sec not in ("tls", "reality", "xtls"):
        # trojan 默认走 TLS
        if opts.get("_trojan_default_tls"):
            sec = "tls"
        else:
            return None
    sni = opts.get("sni") or opts.get("peer") or default_sni
    tls: dict = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if opts.get("alpn"):
        tls["alpn"] = [a for a in urllib.parse.unquote(opts["alpn"]).split(",") if a]
    if opts.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": opts["fp"]}
    if opts.get("allowInsecure") in ("1", "true") or opts.get("insecure") in ("1", "true"):
        tls["insecure"] = True
    if opts.get("ech"):
        ech = _ech_config(urllib.parse.unquote(opts["ech"]))
        if ech:
            tls["ech"] = ech
    if sec == "reality" and opts.get("pbk"):
        tls["reality"] = {"enabled": True, "public_key": opts["pbk"], "short_id": opts.get("sid", "")}
    return tls


def _ech_config(value: str) -> dict | None:
    """节点链接里的 ech 参数有两种写法，sing-box 的 `config` 只吃 base64 的 ECHConfigList：

      1) 原生 ECHConfigList（base64）        → 直接用
      2) `host+https://doh/dns-query`        → 通过 DoH 的 HTTPS 记录取 ech 字段

    订阅里常见的是第 2 种。此时 sing-box 会自己去解析 DoH 的 HTTPS 记录拿真实 ECHConfigList，
    所以这里带上 query_server_name 是关键，不能把整个字符串当配置塞进 config（会报
    "invalid ECH configs pem" 直接起不来）。

    解析出来的值不是合法 base64 时直接丢弃 ECH —— 丢一个扩展字段比整个空间起不来好得多。
    """
    v = (value or "").strip()
    if not v:
        return None
    if "+" in v:
        sni, _, doh = v.partition("+")
        try:
            host = urllib.parse.urlsplit(doh).hostname or ""
        except ValueError:
            return None
        if not host:
            return None
        out = {"enabled": True}
        if sni:
            out["query_server_name"] = sni.strip()
        return out
    try:
        raw = _b64pad(v)
    except SubError:
        return None
    if len(raw) < 8:
        return None
    return {"enabled": True, "config": [v]}


# ---------------------------------------------------------------- 拉取

async def fetch(url: str, user_agent: str = "subswarm/1.0", timeout: float = 25.0) -> str:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.get(url, headers={"User-Agent": user_agent, "Accept": "*/*"})
    except httpx.HTTPError as e:
        raise SubError(f"拉取失败：{type(e).__name__}: {e}") from e
    if r.status_code != 200:
        raise SubError(f"拉取失败：HTTP {r.status_code}")
    return r.text


# ---------------------------------------------------------------- 协议 → outbound

def _b64pad(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except (binascii.Error, ValueError) as e:
        raise SubError(f"base64 解码失败：{e}") from e


def _q(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}
    sec = (opts.get("security") or "").lower()
    if sec not in ("tls", "reality", "xtls"):
        # trojan 默认走 TLS
        if opts.get("_trojan_default_tls"):
            sec = "tls"
        else:
            return None
    sni = opts.get("sni") or opts.get("peer") or default_sni
    tls: dict = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if opts.get("alpn"):
        tls["alpn"] = [a for a in urllib.parse.unquote(opts["alpn"]).split(",") if a]
    if opts.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": opts["fp"]}
    if opts.get("allowInsecure") in ("1", "true") or opts.get("insecure") in ("1", "true"):
        tls["insecure"] = True
    if opts.get("ech"):
        tls["ech"] = {"enabled": True, "config": [urllib.parse.unquote(opts["ech"])]}
    if sec == "reality" and opts.get("pbk"):
        tls["reality"] = {"enabled": True, "public_key": opts["pbk"], "short_id": opts.get("sid", "")}
    return tls


def _transport(opts: dict) -> dict | None:
    t = (opts.get("type") or opts.get("net") or "tcp").lower()
    hs = {"path": urllib.parse.unquote(opts["path"])} if opts.get("path") else {}
    if opts.get("host"):
        hs["host"] = urllib.parse.unquote(opts["host"])
    if t in ("ws", "websocket"):
        tr = {"type": "ws", "path": hs.get("path", "/")}
        if "host" in hs:
            tr["headers"] = {"Host": hs["host"]}
        return tr
    if t in ("grpc", "gun"):
        return {"type": "grpc", "service_name": urllib.parse.unquote(opts.get("serviceName") or opts.get("path") or "")}
    if t in ("h2", "http"):
        return {"type": "http", "host": [hs["host"]] if "host" in hs else [], "path": hs.get("path", "/")}
    if t in ("httpupgrade",):
        tr = {"type": "httpupgrade", "path": hs.get("path", "/")}
        if "host" in hs:
            tr["host"] = hs["host"]
        return tr
    if t in ("tcp", "") and opts.get("headerType") == "http":
        req = {"path": [hs.get("path", "/")]}
        if "host" in hs:
            req["headers"] = {"Host": [hs["host"]]}
        return {"type": "http", "host": [hs["host"]] if "host" in hs else [], "path": hs.get("path", "/")}
    return None


def _port(scheme: str, p) -> int:
    try:
        v = int(p)
        if 0 < v < 65536:
            return v
    except (TypeError, ValueError):
        pass
    return DEFAULT_PORTS.get(scheme, 443)


def parse_uri(uri: str) -> ParsedNode | None:
    uri = uri.strip()
    if not uri or uri.startswith("#") or "://" not in uri:
        return None
    scheme = uri.split("://", 1)[0].lower()
    name = ""
    if "#" in uri:
        uri, _, frag = uri.partition("#")
        name = urllib.parse.unquote(frag).strip()

    if scheme == "vmess":
        raw = _b64pad(uri.split("://", 1)[1]).decode("utf-8", "replace")
        try:
            j = json.loads(raw)
        except json.JSONDecodeError as e:
            raise SubError(f"vmess 解析失败：{e}") from e
        host, port = j.get("add", ""), _port("vmess", j.get("port"))
        name = name or j.get("ps", "")
        opts = {"security": j.get("tls", ""), "type": j.get("net", "tcp"),
                "path": j.get("path", ""), "host": j.get("host", ""), "sni": j.get("sni", ""),
                "fp": j.get("fp", ""), "alpn": j.get("alpn", ""), "allowInsecure": j.get("allowInsecure")}
        if (j.get("net") or "") == "grpc":
            opts["serviceName"] = j.get("path", "")
        ob = {"type": "vmess", "tag": "", "server": host, "server_port": port,
              "uuid": j.get("id", ""), "security": j.get("scy") or "auto", "alter_id": int(j.get("aid") or 0)}
        tls = _tls(opts, default_sni=j.get("host") or host)
        if tls:
            ob["tls"] = tls
        tr = _transport(opts)
        if tr:
            ob["transport"] = tr
        return ParsedNode(name or host, "vmess", host, port, ob, uri).finalize()

    u = urllib.parse.urlsplit(uri if "://" in uri else scheme + "://" + uri)
    host = u.hostname or ""
    port = _port(scheme, u.port)
    user = urllib.parse.unquote(u.username or "")
    opts = _q(u.query)

    if scheme in ("ss", "shadowsocks"):
        # SIP002: ss://base64(method:pass)@host:port  —— 凭据整体 base64，可能缺 padding
        if "@" in (u.netloc or ""):
            raw = urllib.parse.unquote(u.username or "")
            if ":" not in raw:
                try:
                    raw = _b64pad(raw).decode("utf-8", "replace")
                except SubError:
                    pass
            method, _, pw = raw.partition(":")
            pw = urllib.parse.unquote(pw)
        else:
            dec = _b64pad(u.netloc).decode("utf-8", "replace")
            method, _, pw = dec.partition(":")
        if not host or not method:
            return None
        ob = {"type": "shadowsocks", "tag": "", "server": host, "server_port": port,
              "method": method, "password": pw}
        return ParsedNode(name or f"{host}:{port}", "ss", host, port, ob, uri).finalize()

    if scheme in ("socks", "socks5", "http", "https"):
        t = "socks" if scheme.startswith("socks") else "http"
        ob = {"type": t, "tag": "", "server": host, "server_port": port}
        if user:
            ob["username"] = user
            ob["password"] = urllib.parse.unquote(u.password or "")
        tls = _tls(opts, default_sni=host) if t == "http" else None
        if tls:
            ob["tls"] = tls
        return ParsedNode(name or f"{host}:{port}", t, host, port, ob, uri).finalize()

    if scheme == "trojan":
        if not host:
            return None
        ob = {"type": "trojan", "tag": "", "server": host, "server_port": port, "password": user}
        opts["_trojan_default_tls"] = True
        tls = _tls(opts, default_sni=opts.get("host") or host)
        if tls:
            ob["tls"] = tls
        tr = _transport(opts)
        if tr:
            ob["transport"] = tr
        return ParsedNode(name or f"{host}:{port}", "trojan", host, port, ob, uri).finalize()

    if scheme in ("vless", "vless-reality"):
        flow = opts.get("flow", "")
        ob = {"type": "vless", "tag": "", "server": host, "server_port": port, "uuid": user}
        if flow:
            ob["flow"] = flow
        if (opts.get("encryption") or "none").lower() not in ("none", ""):
            ob["packet_encoding"] = opts["encryption"]
        tls = _tls(opts, default_sni=opts.get("sni") or opts.get("host") or host)
        if tls:
            ob["tls"] = tls
        tr = _transport(opts)
        if tr:
            ob["transport"] = tr
        return ParsedNode(name or f"{host}:{port}", "vless", host, port, ob, uri).finalize()

    if scheme in ("hysteria2", "hy2"):
        ob = {"type": "hysteria2", "tag": "", "server": host, "server_port": port, "password": user}
        if opts.get("obfs") or opts.get("obfs-password"):
            ob["obfs"] = {"type": opts.get("obfs", "salamander"), "password": opts.get("obfs-password", "")}
        ob["tls"] = {"enabled": True, "server_name": opts.get("sni") or host,
                     "insecure": opts.get("insecure") in ("1", "true")}
        return ParsedNode(name or f"{host}:{port}", "hysteria2", host, port, ob, uri).finalize()

    if scheme == "tuic":
        ver = opts.get("congestion_control") and 5 or (5 if "@" in (u.netloc or "") and ":" in user else 4)
        ob = {"type": "tuic", "tag": "", "server": host, "server_port": port, "uuid": user,
              "password": urllib.parse.unquote(u.password or ""), "congestion_control": opts.get("congestion_control", "bbr")}
        ob["tls"] = {"enabled": True, "server_name": opts.get("sni") or host,
                     "alpn": [a for a in urllib.parse.unquote(opts.get("alpn", "h3")).split(",") if a],
                     "insecure": opts.get("allow_insecure") in ("1", "true")}
        del ver
        return ParsedNode(name or f"{host}:{port}", "tuic", host, port, ob, uri).finalize()

    return None  # 未知协议忽略


# ---------------------------------------------------------------- Clash / sing-box 输入

_CLASH_TO_SINGBOX_TYPE = {
    "ss": "shadowsocks", "ssr": "shadowsocksr", "vmess": "vmess", "vless": "vless",
    "trojan": "trojan", "hysteria": "hysteria", "hysteria2": "hysteria2", "tuic": "tuic",
    "http": "http", "socks5": "socks", "anytls": "anytls",
}


def parse_clash(data) -> list[ParsedNode]:
    """把 Clash proxies 列表映射成 sing-box outbound。只覆盖常见字段。"""
    if isinstance(data, str):
        try:
            import yaml  # 可选依赖；没装就跳过
        except ImportError as e:
            raise SubError("输入像 Clash YAML，但镜像缺少 pyyaml 依赖") from e
        data = yaml.safe_load(data) or {}
    proxies = (data or {}).get("proxies") or []
    out: list[ParsedNode] = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        typ = _CLASH_TO_SINGBOX_TYPE.get(str(p.get("type", "")).lower())
        if not typ:
            continue
        host, port = p.get("server"), _port(typ, p.get("port"))
        if not host:
            continue
        ob: dict = {"type": typ, "tag": "", "server": host, "server_port": port}
        for src, dst in (("cipher", "method"), ("password", "password"), ("uuid", "uuid"),
                         ("alterId", "alter_id"), ("flow", "flow")):
            if p.get(src) is not None:
                ob[dst] = p[src]
        if typ == "shadowsocksr":
            ob["type"] = "shadowsocks"
            if p.get("protocol"):
                ob["plugin"] = "obfs-local"
        if p.get("tls") or p.get("sni") or p.get("skip-cert-verify") is not None:
            ob["tls"] = {"enabled": True, "server_name": p.get("sni") or p.get("servername") or host,
                         "insecure": bool(p.get("skip-cert-verify"))}
            if p.get("alpn"):
                ob["tls"]["alpn"] = p["alpn"]
            if p.get("client-fingerprint"):
                ob["tls"]["utls"] = {"enabled": True, "fingerprint": p["client-fingerprint"]}
        net = (p.get("network") or "").lower()
        if net in ("ws", "grpc", "h2", "http", "httpupgrade"):
            tr: dict = {"type": "http" if net == "h2" else net}
            wsp = p.get("ws-opts") or {}
            grpcp = p.get("grpc-opts") or {}
            h2p = p.get("h2-opts") or {}
            if net == "ws":
                tr["path"] = wsp.get("path", "/")
                if wsp.get("headers", {}).get("Host"):
                    tr["headers"] = {"Host": wsp["headers"]["Host"]}
            elif net == "grpc":
                tr = {"type": "grpc", "service_name": grpcp.get("grpc-service-name", "")}
            else:
                tr["path"] = h2p.get("path", "/")
                tr["host"] = h2p.get("host", [])
            ob["transport"] = tr
        name = p.get("name") or f"{host}:{port}"
        out.append(ParsedNode(name, typ, host, port, ob, json.dumps(p, ensure_ascii=False)).finalize())
    return out

def parse_singbox_json(data) -> list[ParsedNode]:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as e:
            raise SubError(f"sing-box 配置解析失败：{e}") from e
    out: list[ParsedNode] = []
    for ob in (data or {}).get("outbounds") or []:
        if not isinstance(ob, dict) or not ob.get("server"):
            continue
        ob = dict(ob)
        tag = ob.get("tag") or ""
        ob["tag"] = ""
        out.append(ParsedNode(tag or f'{ob["server"]}:{ob.get("server_port")}',
                              ob.get("type", "?"), ob["server"], int(ob.get("server_port", 443)),
                              ob, json.dumps(ob, ensure_ascii=False)).finalize())
    return out


# ---------------------------------------------------------------- 总入口

_URI_RE = re.compile(r"^[a-z0-9\-]+://", re.I)


def parse_subscription(text: str) -> list[ParsedNode]:
    """自动识别格式。识别不出来就抛 SubError（不要静默返回空）。"""
    t = text.strip()
    if not t:
        raise SubError("订阅内容为空")

    # 1) 明文链接 / 半明文（可能有 HTML 注释和空行）
    lines = [l.strip() for l in t.splitlines() if l.strip() and not l.strip().startswith("//")]
    uri_lines = [l for l in lines if _URI_RE.match(l)]
    if uri_lines and len(uri_lines) >= max(1, len(lines) // 2):
        nodes = []
        errors = []
        for l in uri_lines:
            try:
                n = parse_uri(l)
            except SubError as e:
                errors.append(str(e))
                continue
            if n:
                nodes.append(n)
        if nodes:
            return nodes
        if errors:
            raise SubError("；".join(errors[:3]))

    # 2) JSON（sing-box / 单个 outbound）
    if t.startswith("{") or t.startswith("["):
        return parse_singbox_json(json.loads(t) if t.startswith("[") else t)

    # 3) Clash YAML
    if "proxies:" in t or t.startswith("proxy-groups:"):
        return parse_clash(t)

    # 4) base64
    try:
        dec = _b64pad(t).decode("utf-8", "replace")
    except SubError:
        dec = ""
    if dec.strip():
        dlines = [l.strip() for l in dec.splitlines() if l.strip() and not l.strip().startswith("//")]
        if any(_URI_RE.match(l) for l in dlines):
            nodes = []
            for l in dlines:
                if not _URI_RE.match(l):
                    continue
                try:
                    n = parse_uri(l)
                except SubError:
                    continue
                if n:
                    nodes.append(n)
            if nodes:
                return nodes
        if "proxies:" in dec:
            return parse_clash(dec)
        if dec.lstrip().startswith("{"):
            return parse_singbox_json(dec)

    raise SubError("无法识别的订阅格式（既不是链接列表、base64、Clash YAML，也不是 sing-box JSON）")


# ---------------------------------------------------------------- 过滤 / 去重

def dedupe(nodes: list[ParsedNode]) -> tuple[list[ParsedNode], int]:
    seen: dict[str, ParsedNode] = {}
    dup = 0
    for n in nodes:
        prev = seen.get(n.fingerprint)
        if prev is None:
            seen[n.fingerprint] = n
        else:
            dup += 1
            # 保留名字更长的（通常更有信息量）
            if len(n.name) > len(prev.name):
                seen[n.fingerprint] = n
    return list(seen.values()), dup


def apply_filters(nodes: list[ParsedNode], f: dict) -> tuple[list[ParsedNode], dict]:
    """f 里都是字符串（来自 settings 表）。返回 (保留, 统计)。"""
    protos = {p.strip().lower() for p in (f.get("filter_protocols") or "").split(",") if p.strip()}
    bad_ports = {int(x) for x in (f.get("filter_port_blacklist") or "").replace(" ", "").split(",") if x.strip().isdigit()}
    kws = [k.strip().lower() for k in (f.get("filter_exclude_keywords") or "").split(",") if k.strip()]
    max_nodes = int(f.get("filter_max_nodes_per_space") or 0)

    stat = {"protocol": 0, "port": 0, "keyword": 0, "limit": 0}
    kept: list[ParsedNode] = []
    for n in nodes:
        if protos and n.protocol.lower() not in protos:
            stat["protocol"] += 1
            continue
        if n.port in bad_ports:
            stat["port"] += 1
            continue
        low = n.name.lower()
        if any(k in low for k in kws):
            stat["keyword"] += 1
            continue
        kept.append(n)

    if max_nodes > 0 and len(kept) > max_nodes:
        stat["limit"] = len(kept) - max_nodes
        kept = kept[:max_nodes]
    return kept, stat


def space_default_name(url: str, index: int) -> str:
    host = urllib.parse.urlsplit(url).hostname or f"space{index}"
    return f"{host}#{index}"
