"""对外代理服务：SOCKS5(:1080) + HTTP(:1081)。

核心行为（需求原文）：每条新建连接 → 随机挑一个订阅空间 → 在该空间随机挑一个节点。
选择发生在握手时一次，之后该连接固定走这个节点（长连接/下载/WebSocket 才不会中途断）。

本模块只管协议与随机选择，真正的出站由被选空间的 sing-box 完成（把字节泵到它的 socks 入站）。
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import logging
import struct
import time

from .registry import Registry

log = logging.getLogger("subswarm.proxy")

SOCKS_VERSION = 5
CMD_CONNECT = 1
ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6 = 1, 3, 4
REP_OK, REP_GENERAL, REP_NOT_ALLOWED, REP_HOST_UNREACH, REP_CMD_UNSUPPORTED, REP_ATYP = 0, 1, 2, 4, 7, 8


class ConnStats:
    def __init__(self) -> None:
        self.active = 0
        self.total = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.errors = 0


class Dispatcher:
    """随机选点 + 把客户端流转发到选中空间的 sing-box socks 入站。"""

    def __init__(self, reg: Registry, db, stats: ConnStats):
        self.reg = reg
        self.db = db
        self.stats = stats
        self._sem: asyncio.Semaphore | None = None
        self._limit = 0

    def _semaphore(self, limit: int) -> asyncio.Semaphore:
        if self._sem is None or limit != self._limit:
            self._sem = asyncio.Semaphore(limit)
            self._limit = limit
        return self._sem

    # ------------------------------------------------------------------ 选点
    def choose(self):
        return self.reg.pick()

    async def connect_upstream(self, socks_port: int, host: str, port: int, outbound_tag: str = "") -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """连到本空间 sing-box 的 socks 入站，并用 SOCKS5 用户名指定要走的节点。

        sing-box 的 socks 入站支持「用户名 = outbound tag」来选择出口 ——
        这正是「每条连接随机挑一个节点」真正落地的地方：随机选中哪个节点，
        就把它的 tag 当用户名传进去，sing-box 就只走那一个节点。
        """
        reader, writer = await asyncio.open_connection("127.0.0.1", socks_port)
        try:
            if outbound_tag:
                writer.write(bytes([SOCKS_VERSION, 1, 2]))   # 只提供 USERPASS
                await writer.drain()
                ver, method = await reader.readexactly(2)
                if ver != SOCKS_VERSION or method != 2:
                    raise OSError("上游 socks 不支持用户名选路")
                tag = outbound_tag.encode()
                writer.write(bytes([1, len(tag)]) + tag + bytes([0]))
                await writer.drain()
                if (await reader.readexactly(2))[1] != 0:
                    raise OSError(f"上游 socks 拒绝节点 {outbound_tag}")
            else:
                writer.write(bytes([SOCKS_VERSION, 1, 0]))   # no-auth（仅 127.0.0.1）
                await writer.drain()
                ver, method = await reader.readexactly(2)
                if ver != SOCKS_VERSION or method != 0:
                    raise OSError("上游 socks 协商失败")
            try:
                ip = ipaddress.ip_address(host)
                atyp, addr = (ATYP_IPV4, ip.packed) if ip.version == 4 else (ATYP_IPV6, ip.packed)
            except ValueError:
                hb = host.encode("idna", "ignore")
                atyp, addr = ATYP_DOMAIN, bytes([len(hb)]) + hb
        except Exception:
            writer.close()
            raise
        writer.write(bytes([SOCKS_VERSION, CMD_CONNECT, 0, atyp]) + addr + struct.pack(">H", port))
        await writer.drain()
        head = await reader.readexactly(4)
        if head[1] != REP_OK:
            writer.close()
            raise OSError(f"上游拒绝连接（rep={head[1]}）")
        # 吃掉 bind 地址
        if head[3] == ATYP_IPV4:
            await reader.readexactly(6)
        elif head[3] == ATYP_IPV6:
            await reader.readexactly(18)
        else:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln + 2)
        return reader, writer

    async def serve(self, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter,
                    target: str, port: int, proto: str, client_ip: str,
                    retry: int, limit: int):
        """选点→连上游→双向泵。失败时换一个空间重试（默认 1 次）。"""
        sem = self._semaphore(limit)
        async with sem:
            self.stats.active += 1
            self.stats.total += 1
            t0 = time.time()
            last_err = "无可用节点"
            for attempt in range(retry + 1):
                pick = self.choose()
                if pick is None:
                    last_err = "节点池为空（没有 healthy/unknown 节点）"
                    break
                sp, node = pick.space, pick.node
                upstream_w = None
                try:
                    up_r, up_w = await asyncio.wait_for(
                        self.connect_upstream(sp.socks_port, target, port, node.outbound_tag), timeout=15)
                    upstream_w = up_w
                    self._log(client_ip, proto, target, port, sp, node, True,
                              f"attempt={attempt} connect_ms={int((time.time()-t0)*1000)}")
                    await self.pump(client_r, client_w, up_r, up_w)
                    return
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as e:
                    last_err = f"{type(e).__name__}: {e}"
                    self._log(client_ip, proto, target, port, sp, node, False, f"attempt={attempt} {last_err}")
                    if upstream_w is not None:
                        upstream_w.close()
                    continue
                except asyncio.CancelledError:
                    if upstream_w is not None:
                        upstream_w.close()
                    raise
                finally:
                    self.stats.active -= 1 if attempt == retry else 0
            self.stats.active = max(0, self.stats.active)
            self.stats.errors += 1
            raise ProxyError(last_err)

    async def pump(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
                   ur: asyncio.StreamReader, uw: asyncio.StreamWriter) -> None:
        """双向泵。任一侧 EOF/异常 → 取消另一侧并关闭两条连接。"""
        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter, counter: str) -> None:
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
                    setattr(self.stats, counter, getattr(self.stats, counter) + len(data))
            finally:
                try:
                    dst.write_eof()      # 传播半关闭，让对端知道我们发完了
                except (OSError, RuntimeError):
                    pass

        up = asyncio.create_task(copy(cr, uw, "bytes_up"))
        down = asyncio.create_task(copy(ur, cw, "bytes_down"))
        try:
            done, pending = await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            for t in done | pending:
                try:
                    await t
                except (asyncio.CancelledError, OSError, ConnectionError):
                    pass
        finally:
            for w in (uw, cw):
                try:
                    w.close()
                except OSError:
                    pass

    def _log(self, client, proto, target, port, sp, node, ok, detail):
        try:
            self.db.log_conn(client=client, proto=proto, target=f"{target}:{port}",
                             space_id=sp.id, space_name=sp.name, node_id=node.id,
                             node_name=node.name, ok=ok, detail=detail)
        except Exception as e:  # noqa: BLE001
            log.debug("写连接日志失败：%s", e)


class ProxyError(Exception):
    pass


def _resolve_literal(host: str) -> str:
    return host


# ---------------------------------------------------------------------- SOCKS5

async def handle_socks5(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                        dispatcher: Dispatcher, auth: tuple[str, str] | None,
                        retry: int, limit: int) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    client_ip = peer[0]
    try:
        head = await asyncio.wait_for(reader.readexactly(2), timeout=15)
        if head[0] != SOCKS_VERSION:
            return
        nmethods = head[1]
        methods = await reader.readexactly(nmethods)
        if auth:
            if 2 not in methods:
                writer.write(bytes([SOCKS_VERSION, 0xFF]))
                await writer.drain()
                return
            writer.write(bytes([SOCKS_VERSION, 2]))
            await writer.drain()
            ver = (await reader.readexactly(1))[0]
            ulen = (await reader.readexactly(1))[0]
            user = (await reader.readexactly(ulen)).decode("utf-8", "replace")
            plen = (await reader.readexactly(1))[0]
            pw = (await reader.readexactly(plen)).decode("utf-8", "replace")
            if ver != 1 or (user, pw) != auth:
                writer.write(bytes([1, 1]))
                await writer.drain()
                return
            writer.write(bytes([1, 0]))
            await writer.drain()
        else:
            if 0 not in methods:
                writer.write(bytes([SOCKS_VERSION, 0xFF]))
                await writer.drain()
                return
            writer.write(bytes([SOCKS_VERSION, 0]))
            await writer.drain()

        req = await asyncio.wait_for(reader.readexactly(4), timeout=15)
        ver, cmd, _rsv, atyp = req
        if atyp == ATYP_IPV4:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif ATYP_IPV6:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        elif ATYP_DOMAIN:
            ln = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(ln)).decode("idna", "replace")
        else:
            await _socks_reply(writer, REP_ATYP)
            return
        port = struct.unpack(">H", await reader.readexactly(2))[0]

        if cmd != CMD_CONNECT:
            # BIND / UDP ASSOCIATE 未实现，明确拒绝而不是假装支持
            await _socks_reply(writer, REP_CMD_UNSUPPORTED)
            return
        await _socks_reply(writer, REP_OK)   # 先回成功：目标由上游 sing-box 去连
        await dispatcher.serve(reader, writer, host, port, "socks5", client_ip, retry, limit)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    except ProxyError as e:
        log.debug("socks5 代理失败 client=%s：%s", client_ip, e)
        await _socks_reply(writer, REP_HOST_UNREACH)
    except Exception as e:  # noqa: BLE001
        log.debug("socks5 处理异常：%s", e)
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def _socks_reply(writer: asyncio.StreamWriter, rep: int) -> None:
    try:
        writer.write(bytes([SOCKS_VERSION, rep, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
    except (OSError, ConnectionError):
        pass


# ---------------------------------------------------------------------- HTTP

HOP_HEADERS = {"proxy-connection", "proxy-authorization", "connection", "keep-alive",
               "te", "trailer", "transfer-encoding", "upgrade"}


async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                      dispatcher: Dispatcher, auth: tuple[str, str] | None,
                      retry: int, limit: int) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    client_ip = peer[0]
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=20)
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split()
        if len(parts) < 3:
            await _http_error(writer, 400, "Bad Request")
            return
        method, target, version = parts[0].upper(), parts[1], parts[2]
        headers: list[tuple[str, str]] = []
        for ln in lines[1:]:
            if not ln or ":" not in ln:
                continue
            k, _, v = ln.partition(":")
            headers.append((k.strip(), v.strip()))
        hmap = {k.lower(): v for k, v in headers}

        if auth:
            got = hmap.get("proxy-authorization", "")
            if not got.lower().startswith("basic "):
                await _http_auth(writer)
                return
            try:
                dec = base64.b64decode(got.split(None, 1)[1]).decode("utf-8", "replace")
            except (binascii.Error, ValueError, IndexError):
                await _http_auth(writer)
                return
            u, _, p = dec.partition(":")
            if (u, p) != auth:
                await _http_auth(writer)
                return

        headers = [(k, v) for k, v in headers if k.lower() not in HOP_HEADERS]

        if method == "CONNECT":
            host, _, port_s = target.partition(":")
            port = int(port_s or 443)
            await dispatcher.serve(reader, writer, host, port, "http-connect", client_ip, retry, limit)
            return

        # 普通绝对 URI 请求：改写成 origin-form 再转发
        from urllib.parse import urlsplit
        u = urlsplit(target if "://" in target else f"http://{hmap.get('host', target)}")
        if not u.hostname:
            await _http_error(writer, 400, "Bad Request")
            return
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        out = [f"{method} {path} {version}"]
        has_host = any(k.lower() == "host" for k, _ in headers)
        if not has_host:
            out.append(f"Host: {u.hostname}")
        out += [f"{k}: {v}" for k, v in headers]
        body = b"\r\n".join(x.encode("latin-1") for x in out) + b"\r\n\r\n"
        up_r, up_w = await _first_hop(dispatcher, u.hostname, u.port or 80, client_ip, "http")
        up_w.write(body)
        await up_w.drain()
        await dispatcher.pump(reader, writer, up_r, up_w)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    except ProxyError as e:
        await _http_error(writer, 503, f"no upstream: {e}")
    except Exception as e:  # noqa: BLE001
        log.debug("http 处理异常：%s", e)
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def _first_hop(dispatcher: Dispatcher, host: str, port: int, client_ip: str, proto: str):
    pick = dispatcher.choose()
    if pick is None:
        raise ProxyError("节点池为空")
    sp, node = pick.space, pick.node
    try:
        r, w = await asyncio.wait_for(dispatcher.connect_upstream(sp.socks_port, host, port, node.outbound_tag), timeout=15)
    except (OSError, asyncio.TimeoutError) as e:
        dispatcher._log(client_ip, proto, host, port, sp, node, False, f"{type(e).__name__}: {e}")
        raise ProxyError(str(e)) from e
    dispatcher._log(client_ip, proto, host, port, sp, node, True, "first-hop")
    return r, w


async def _http_error(writer: asyncio.StreamWriter, code: int, text: str) -> None:
    try:
        body = text.encode()
        writer.write(f"HTTP/1.1 {code} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await writer.drain()
    except (OSError, ConnectionError):
        pass


async def _http_auth(writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"subswarm\"\r\n"
                     b"Content-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
    except (OSError, ConnectionError):
        pass


# ---------------------------------------------------------------------- 服务启动

def _parse_basic(v: str | None) -> tuple[str, str] | None:
    if not v:
        return None
    dec = base64.b64decode(v).decode("utf-8", "replace")
    u, _, p = dec.partition(":")
    return (u, p)


class ProxyServers:
    def __init__(self, dispatcher: Dispatcher, db):
        self.d = dispatcher
        self.db = db
        self.servers: list[asyncio.AbstractServer] = []

    async def start(self, bind: str, socks_port: int, http_port: int) -> None:
        st = self.db.all_settings()
        auth = _parse_basic(st.get("proxy_auth_b64") or None)
        retry = int(st.get("connect_retry", "1"))
        limit = int(st.get("max_connections", "512"))

        async def on_socks(r, w):
            await handle_socks5(r, w, self.d, auth, retry, limit)

        async def on_http(r, w):
            await handle_http(r, w, self.d, auth, retry, limit)

        self.servers.append(await asyncio.start_server(on_socks, bind, socks_port, limit=4096))
        self.servers.append(await asyncio.start_server(on_http, bind, http_port, limit=4096))
        log.info("代理已启动：SOCKS5 %s:%s / HTTP %s:%s（认证=%s）",
                 bind, socks_port, bind, http_port, "开" if auth else "关")

    async def stop(self) -> None:
        for s in self.servers:
            s.close()
        for s in self.servers:
            try:
                await s.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self.servers.clear()
