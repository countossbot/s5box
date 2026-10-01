"""对外代理服务：SOCKS5(:1080) + HTTP(:1081)。

核心行为（需求原文）：每条新建连接 → 随机挑一个订阅空间 → 在该空间随机挑一个节点。
选择发生在握手时一次，之后该连接固定走这个节点（长连接/下载/WebSocket 才不会中途断）。

本模块只管协议与随机选择，真正的出站由被选空间的 sing-box 完成（把字节泵到它的 socks 入站）。
"""
from __future__ import annotations

import asyncio
import base64
import hmac
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


def _socks_addr(host: str) -> tuple[int, bytes]:
    """把目标主机编码成 SOCKS5 的 ATYP + 地址字节。

    注意：绝不能写 host.encode("idna", "ignore") —— idna 编解码器不接受
    "ignore" 这个错误处理器，会抛 UnicodeError（"unsupported error handling"），
    而且它只处理 ASCII 域名。这里对非 ASCII 域名退回 UTF-8 字节，
    由上游 sing-box 的 sniff/解析去处理。
    """
    h = (host or "").strip()
    # 先剥掉 IPv6 的方括号写法（[::1] / [2001:db8::1]）。
    # 不剥的话 ip_address 会拒绝、落到域名分支，把 "[::1]" 当成域名发出去 ——
    # 必然是解析失败。RFC 3986 里方括号只是 URI 里的分隔语法，不是地址的一部分。
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # 去掉 IPv6 可能带的 zone id（fe80::1%eth0）—— SOCKS5 协议里没有这个字段
    if "%" in h:
        h = h.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(h)
        return (ATYP_IPV4, ip.packed) if ip.version == 4 else (ATYP_IPV6, ip.packed)
    except ValueError:
        pass
    if not h:
        raise OSError("目标主机为空")
    try:
        hb = h.encode("idna")
    except (UnicodeError, UnicodeDecodeError):
        hb = h.encode("utf-8")
    if len(hb) > 255:
        raise OSError("目标域名过长")
    return ATYP_DOMAIN, bytes([len(hb)]) + hb


class Dispatcher:
    """随机选点 + 把客户端流转发到选中空间的 sing-box socks 入站。"""

    def __init__(self, reg: Registry, logs, stats: ConnStats):
        self.reg = reg
        self.logs = logs          # LogBuffer：内存环形缓冲 + SQLite
        self.stats = stats
        # 每个 sing-box 实例(socks 起始端口)上的活跃连接数。
        # 供 SingBoxManager 在重建实例前判断"能否安全重启"：
        # 有在途长连接时先等它跑完，避免 killpg 掐断 LLM 流式响应。
        self.active_by_port: dict[int, int] = {}

        self._limit = 0

    def _semaphore(self, limit: int) -> asyncio.Semaphore:
        if self._sem is None or limit != self._limit:
            self._sem = asyncio.Semaphore(limit)
            self._limit = limit
        return self._sem

    # --- 选点
    def choose(self) -> Pick:
        """为一条新连接选点。

        返回的 Pick.mode 决定后续走法：global 走节点专属 socks 入站，direct 本地
        直连目标。选点只在握手时发生一次，之后该连接固定，长连接/下载不会中途换。
        """
        return self.reg.pick()

    async def connect_upstream(self, node_port: int | None, host: str, port: int
                               ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """连到「选中节点专属」的本地 socks 入站。

        每个节点在 sing-box 里对应一个独立入站端口（socks_port + 节点序号），
        路由规则保证该入站的流量只走那个节点。所以随机选中哪个节点，
        就只要连它对应的端口即可 —— 选路是物理确定的，不依赖隐式机制。

        node_port 为 None 表示 direct 模式：不经 sing-box，直接连目标。
        直连刻意不走 sing-box 的 direct 出站 —— 那只会多一跳本地转发，既不改
        DNS 也不改日志（日志由本模块自己记），还要为每个空间多占一个端口。
        """
        if node_port is None:      # direct 模式：不经 sing-box，直接连目标
            return await asyncio.open_connection(host, port)
        reader, writer = await asyncio.open_connection("127.0.0.1", node_port)
        try:
            writer.write(bytes([SOCKS_VERSION, 1, 0]))       # no-auth，仅 127.0.0.1
            await writer.drain()
            ver, method = await reader.readexactly(2)
            if ver != SOCKS_VERSION or method != 0:
                raise OSError("上游 socks 协商失败")
            atyp, addr = _socks_addr(host)
            writer.write(bytes([SOCKS_VERSION, CMD_CONNECT, 0, atyp]) + addr + struct.pack(">H", port))
            await writer.drain()
            head = await reader.readexactly(4)
            if head[1] != REP_OK:
                raise OSError(f"上游拒绝连接（rep={head[1]}）")
            if head[3] == ATYP_IPV4:
                await reader.readexactly(6)
            elif head[3] == ATYP_IPV6:
                await reader.readexactly(18)
            else:
                ln = (await reader.readexactly(1))[0]
                await reader.readexactly(ln + 2)
            return reader, writer
        except Exception:
            writer.close()
            raise

    async def pump(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter,
                   ur: asyncio.StreamReader, uw: asyncio.StreamWriter,
                   node_port: int | None = None) -> None:
        """双向泵：客户端 ↔ 上游节点。

        要点（踩过的坑都在这里）：
        * 两个方向必须各自独立跑完，谁先结束都不能掐断另一个方向
          （之前用 FIRST_COMPLETED，客户端没有新数据的瞬间就把连接拆了）。
        * 一个方向读到 EOF 时，只关闭**对应的那个写方向**（半关闭），
          让对端把剩余数据发完，而不是立刻 close() —— 立刻 close 会把
          还在缓冲区里的响应丢掉（表现为代理返回 0 字节）。
        """
        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter, counter: str) -> bool:
            """返回 True 表示读到 EOF（正常收尾），False 表示中途出错。"""
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        # 半关闭：告诉对端"我发完了"，但先不要关整条连接
                        try:
                            if dst.can_write_eof():
                                dst.write_eof()
                                await dst.drain()
                        except (OSError, RuntimeError, ConnectionError):
                            pass
                        return True
                    dst.write(data)
                    await dst.drain()
                    setattr(self.stats, counter, getattr(self.stats, counter) + len(data))
            except (ConnectionError, OSError, RuntimeError) as e:
                log.debug("泵送方向 %s 中断：%s", counter, e)
                return False

        # 记账：连接存续期间占用该实例一个名额。管理器重建实例前会读这个
        # 计数，有在途长连接时先等待，避免 killpg 掐断正在读取的流式响应。
        # 用 getattr 容错：测试里会用 Dispatcher.__new__ 绕过 __init__。
        counts = getattr(self, "active_by_port", None)
        if node_port is not None and counts is not None:
            counts[node_port] = counts.get(node_port, 0) + 1

        up = asyncio.create_task(copy(cr, uw, "bytes_up"))
        down = asyncio.create_task(copy(ur, cw, "bytes_down"))
        try:
            # 两个方向都跑完才收工，保证不丢数据
            await asyncio.gather(up, down, return_exceptions=True)
        finally:
            if node_port is not None and counts is not None:
                left = counts.get(node_port, 1) - 1
                if left > 0:
                    counts[node_port] = left
                else:
                    counts.pop(node_port, None)
            for t in (up, down):
                if not t.done():
                    t.cancel()
            for w in (uw, cw):
                try:
                    w.close()
                except OSError:
                    pass
            for w in (uw, cw):
                try:
                    await w.wait_closed()
                except (OSError, ConnectionError, Exception):  # noqa: BLE001
                    pass

    def _log(self, client, proto, target, port, sp, node, ok, detail):
        """记录这次连接命中了哪个空间/节点。self.logs 是 LogBuffer：
        它同时写内存环形缓冲（面板实时看）和 SQLite（持久化）。
        这里必须用 LogBuffer.add —— 之前误调 db.log_conn，日志全部被静默丢弃。

        sp/node 在 direct 模式下是 None（没走节点是正常的，不是错误），
        所以取 id/name 时要兜底，否则直连的每一条日志都会抛 AttributeError。
        """
        try:
            self.logs.add(client=client, proto=proto, target=f"{target}:{port}",
                          space_id=sp.id if sp else None,
                          space_name=sp.name if sp else "-",
                          node_id=node.id if node else None,
                          node_name=node.name if node else "直连",
                          ok=ok, detail=detail)
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
    t_socks = time.time()
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
            # 恒定时间比较，避免时序侧信道
            if ver != 1 or not (hmac.compare_digest(user, auth[0]) and hmac.compare_digest(pw, auth[1])):
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
        # 注意：这里必须写 atyp == ATYP_xxx。之前误写成 `elif ATYP_IPV6:`
        # （少了 == 比较），而 ATYP_IPV6=4 / ATYP_DOMAIN=3 都是真值，
        # 导致所有请求都走进 IPv6 分支、把域名字节当 16 字节地址读掉，
        # 残留的 3 个字节（如 6d01bb）随后被当应用数据转发给上游，
        # 表现就是"经代理访问任何 HTTPS 都握手失败"。
        if atyp == ATYP_IPV4:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif atyp == ATYP_IPV6:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        elif atyp == ATYP_DOMAIN:
            ln = (await reader.readexactly(1))[0]
            raw_host = await reader.readexactly(ln)
            # 注意：不能写 bytes.decode("idna", "replace") —— "idna" 是编解码器名，
            # 不是错误处理器名，会抛 UnicodeError，导致域名解析失败、端口字节
            # 残留在流里被当成应用数据转发（表现为 TLS 首字节变成 6d01bb...）。
            try:
                host = raw_host.decode("idna")
            except (UnicodeError, UnicodeDecodeError):
                host = raw_host.decode("utf-8", "replace")
        else:
            await _socks_reply(writer, REP_ATYP)
            return
        port = struct.unpack(">H", await reader.readexactly(2))[0]

        if cmd != CMD_CONNECT:
            # BIND / UDP ASSOCIATE 未实现，明确拒绝而不是假装支持
            await _socks_reply(writer, REP_CMD_UNSUPPORTED)
            return
        # 必须先选点并连上上游、拿到上游的 CONNECT 结果，再回复客户端。
        # 反过来（先回 OK 再连上游）会造成严重错乱：客户端收到 OK 后立刻发
        # TLS ClientHello，而这段时间我们还在连上游，那批字节会被丢掉，
        # 表现为 "SSL: WRONG_VERSION_NUMBER"。
        pick = dispatcher.choose()
        if pick is None:
            await _socks_reply(writer, REP_HOST_UNREACH)
            return
        try:
            up_r, up_w = await asyncio.wait_for(
                dispatcher.connect_upstream(pick.node_port, host, port), timeout=15)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as e:
            dispatcher._log(client_ip, "socks5", host, port, pick.space, pick.node, False, str(e)[:80])
            await _socks_reply(writer, REP_HOST_UNREACH)
            return
        dispatcher._log(client_ip, "socks5", host, port, pick.space, pick.node, True,
                        f"connect_ms={int((time.time() - t_socks) * 1000)}")
        await _socks_reply(writer, REP_OK)
        await dispatcher.pump(reader, writer, up_r, up_w, pick.node_port)
    except ProxyError:
        await _socks_reply(writer, REP_HOST_UNREACH)
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
            if not (hmac.compare_digest(u, auth[0]) and hmac.compare_digest(p, auth[1])):
                await _http_auth(writer)
                return

        headers = [(k, v) for k, v in headers if k.lower() not in HOP_HEADERS]

        if method == "CONNECT":
            host, _, port_s = target.partition(":")
            try:
                port = int(port_s or 443)
            except ValueError:
                await _http_error(writer, 400, "Bad CONNECT target")
                return
            # 与 socks 同理：先连上上游，确认通了再回 200 给客户端，
            # 否则客户端收到 200 后立刻开始 TLS 握手，字节会被丢。
            pick = dispatcher.choose()
            if pick is None:
                await _http_error(writer, 503, "no available node")
                return
            t0 = time.time()
            try:
                up_r, up_w = await asyncio.wait_for(
                    dispatcher.connect_upstream(pick.node_port, host, port), timeout=15)
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as e:
                dispatcher._log(client_ip, "http-connect", host, port, pick.space, pick.node, False, str(e)[:80])
                await _http_error(writer, 502, "upstream failed")
                return
            dispatcher._log(client_ip, "http-connect", host, port, pick.space, pick.node, True,
                            f"connect_ms={int((time.time() - t0) * 1000)}")
            try:
                writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: s5box\r\n\r\n")
                await writer.drain()
            except (OSError, ConnectionError):
                up_w.close()
                return
            await dispatcher.pump(reader, writer, up_r, up_w, pick.node_port)
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
        await dispatcher.pump(reader, writer, up_r, up_w, pick.node_port)
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
    """普通 HTTP（非 CONNECT）请求的出口选择与建连。"""
    pick = dispatcher.choose()
    if pick is None:
        raise ProxyError("节点池为空")
    sp, node = pick.space, pick.node
    try:
        r, w = await asyncio.wait_for(
            dispatcher.connect_upstream(pick.node_port, host, port), timeout=15)
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
