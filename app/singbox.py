"""sing-box 每空间一个实例：配置生成、子进程管理、Clash API 控制。

隔离理由：空间之间不能互相影响；删/停一个空间直接杀进程，不用全量 reload 掐断在途连接。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from pathlib import Path

import httpx

from . import config

log = logging.getLogger("subswarm.singbox")


def _free_port(start: int) -> int:
    for p in range(start, start + 500):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("找不到空闲端口")


def _extract_ip(body: str) -> str | None:
    """从探测响应里取出出口 IP。

    兼容几种常见返回：
      httpbin.org/ip  -> {"origin": "1.2.3.4"}  或  {"origin": "1.2.3.4, 5.6.7.8"}
      ipify           -> 纯文本 "1.2.3.4"
      cdn-cgi/trace   -> 多行 "ip=1.2.3.4"
    """
    if not body:
        return None
    text = body.strip()
    if not text:
        return None
    # JSON
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict):
            for key in ("origin", "ip", "query", "YourFuckingIPAddress"):
                val = data.get(key)
                if isinstance(val, str) and val.strip():
                    return val.split(",")[0].strip()[:64]
        return None
    # trace 形式的键值行
    for line in text.splitlines():
        if line.startswith("ip="):
            return line[3:].strip()[:64]
    # 纯文本 IP
    first = text.split()[0] if text.split() else ""
    return first[:64] if first else None


class SpaceInstance:
    """一个订阅空间 = 一个 sing-box 进程（私有 socks 入站 + clash api）。"""

    def __init__(self, space_id: int, workdir: Path, socks_port: int, api_port: int):
        self.space_id = space_id
        self.workdir = workdir
        self.socks_port = socks_port
        self.api_port = api_port
        self.proc: asyncio.subprocess.Process | None = None
        self.log_tail: list[str] = []
        self._log_task: asyncio.Task | None = None
        self._reader_task: asyncio.Task | None = None
        self._stopping = False

    # ---- 配置 ----
    def build_config(self, nodes: list[dict], log_level: str = "warn") -> dict:
        outbounds: list[dict] = []
        # 可选的上游 DNS 覆盖。默认留空 → 用系统解析器（最稳）。
        dns_remote = os.getenv("SINGBOX_DNS_SERVER", "").strip()
        outbounds: list[dict] = []
        for i, n in enumerate(nodes):
            ob = json.loads(n["outbound_json"]) if isinstance(n["outbound_json"], str) else dict(n["outbound_json"])
            ob["tag"] = f"n{i}"          # 只含 ascii，绕开 tag 编码问题
            outbounds.append(ob)
        outbounds.append({"type": "direct", "tag": "direct"})
        return {
            "log": {"level": log_level, "timestamp": True},
            # DNS 默认走系统解析器（Docker 的 127.0.0.11 / 宿主 resolv.conf）。
            # 绝不要硬编码 1.1.1.1 或 223.5.5.5：容器所在网络未必能直连它们，
            # 一旦连不上，节点域名的解析全部超时 → 探测全失败、连 cache_file 都初始化不了。
            # 需要指定上游 DNS 时设 SINGBOX_DNS_SERVER（例如 223.5.5.5）。
            "dns": {
                "servers": [
                    {"type": "local", "tag": "local"},
                    *([{"type": "udp", "tag": "remote", "server": dns_remote, "detour": "direct"}]
                      if dns_remote else []),
                ],
                "strategy": "prefer_ipv4",
            },
            # 每个节点一个独立 socks 入站：第 i 个节点监听 self.socks_port + i，
            # route 规则把该入站的流量强制走第 i 个节点。
            # 这样"随机选中的节点"是物理确定的（连哪个端口就走哪个节点），
            # 不依赖 sing-box 的任何隐式选路机制 —— 之前用 SOCKS5 用户名传 tag 的
            # 做法 sing-box 并不支持，导致代理全部失败。
            "inbounds": [
                {"type": "socks", "tag": f"in{i}", "listen": "127.0.0.1",
                 "listen_port": self.socks_port + i}
                for i in range(len(nodes))
            ],
            "outbounds": outbounds,
            "route": {
                "rules": [
                    {"action": "sniff"},
                    *[{"inbound": [f"in{i}"], "outbound": f"n{i}"} for i in range(len(nodes))],
                ],
                # 1.14 要求显式声明默认解析器，否则直接 FATAL 拒绝启动
                "default_domain_resolver": {"server": "remote" if dns_remote else "local"},
                # 入站流量默认走第一个节点；分发器会在每条连接上用 SOCKS5 用户名
                # 指定本次随机选中的节点 tag（见 proxy.py connect_upstream）。
                # 这里绝不能是 "direct"：那会让客户端流量绕过节点直连出去。
                "final": "n0",
                "auto_detect_interface": True,
            },
            "experimental": {
                "clash_api": {"external_controller": f"127.0.0.1:{self.api_port}"},
                "cache_file": {"enabled": True, "path": str(self.workdir / f"cache-{self.space_id}.db")},
            },
        }

    @property
    def config_path(self) -> Path:
        return self.workdir / f"space-{self.space_id}.json"

    def write_config(self, nodes: list[dict], log_level: str = "warn") -> None:
        """先写临时文件再原子的 rename —— 半截配置会让 sing-box 起不来。"""
        self.workdir.mkdir(parents=True, exist_ok=True)
        tmp = self.config_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.build_config(nodes, log_level), ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.config_path)
        # 校验配置合法（起不来就别起，日志里能看到原因）
        subprocess_check = os.popen(f'"{config.SINGBOX_BIN}" check -c "{self.config_path}" 2>&1').read()
        if "error" in subprocess_check.lower() or "fatal" in subprocess_check.lower():
            raise RuntimeError(f"sing-box 配置校验失败：{subprocess_check.strip()[:500]}")

    # ---- 进程 ----
    async def start(self) -> None:
        if self.proc and self.proc.returncode is None:
            await self.reload()
            return
        self._stopping = False
        self.proc = await asyncio.create_subprocess_exec(
            config.SINGBOX_BIN, "run", "-c", str(self.config_path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        self._reader_task = asyncio.create_task(self._drain_logs())
        if not await self._wait_ready():
            tail = "\n".join(self.log_tail[-8:])
            await self.stop()
            raise RuntimeError(f"sing-box 启动失败或未就绪：{tail}")

    async def _drain_logs(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            while True:
                line = await self.proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip()
                self.log_tail.append(text)
                del self.log_tail[:-100]
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            log.debug("space %s 日志读取结束：%s", self.space_id, e)

    async def _wait_ready(self, timeout: float = 12.0) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout
        async with httpx.AsyncClient(timeout=1.0) as c:
            while asyncio.get_running_loop().time() < deadline:
                if self.proc and self.proc.returncode is not None:
                    return False
                try:
                    r = await c.get(f"http://127.0.0.1:{self.api_port}/version")
                    if r.status_code == 200:
                        return True
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.2)
        return False

    async def reload(self) -> None:
        """原地重载配置；失败就整体重启进程。"""
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.put(f"http://127.0.0.1:{self.api_port}/configs",
                                params={"force": "true"}, content=self.config_path.read_bytes())
            if r.status_code in (200, 204):
                return
            log.warning("space %s 重载返回 %s，改为重启", self.space_id, r.status_code)
        except httpx.HTTPError as e:
            log.warning("space %s 重载失败（%s），改为重启", self.space_id, e)
        await self.stop()
        await self.start()

    async def stop(self, grace: float = 5.0) -> None:
        self._stopping = True
        for t in (self._reader_task, self._log_task):
            if t and not t.done():
                t.cancel()
        self._reader_task = self._log_task = None

        proc, self.proc = self.proc, None
        if proc is None:
            return
        if proc.returncode is None:
            try:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=grace)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
            except ProcessLookupError:
                pass
        # 无论走哪条路径都要回收，避免僵尸进程
        try:
            await proc.wait()
        except Exception:  # noqa: BLE001
            pass

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    def cleanup_files(self) -> None:
        for p in (self.config_path, self.workdir / f"cache-{self.space_id}.db"):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass


class SingBoxManager:
    """管理所有空间的实例；端口分配与生命周期集中在这里。"""

    def __init__(self, workdir: Path, api_port_base: int | None = None):
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.api_port_base = api_port_base or config.SINGBOX_API_PORT_BASE
        self._instances: dict[int, SpaceInstance] = {}
        self._next_socks = 11080
        self._next_api = self.api_port_base

    def instance(self, space_id: int) -> SpaceInstance:
        inst = self._instances.get(space_id)
        if inst is None:
            inst = SpaceInstance(space_id, self.workdir, _free_port(self._next_socks), _free_port(self._next_api))
            self._next_socks = inst.socks_port + 1
            self._next_api = inst.api_port + 1
            self._instances[space_id] = inst
        return inst

    async def apply(self, space_id: int, nodes: list[dict], start: bool = True) -> SpaceInstance:
        inst = self.instance(space_id)
        if start:
            await inst.stop()                 # 先停：配置变了要干净重启（端口沿用）
            inst.write_config(nodes)
            await inst.start()
        return inst

    async def stop_space(self, space_id: int, cleanup: bool = False) -> None:
        inst = self._instances.pop(space_id, None)
        if inst is None:
            return
        await inst.stop()
        if cleanup:
            inst.cleanup_files()

    async def stop_all(self) -> None:
        """关停全部子进程（先子进程，后文件）。"""
        for sid in list(self._instances):
            try:
                await self.stop_space(sid)
            except Exception as e:  # noqa: BLE001
                log.warning("关停空间 %s 出错：%s", sid, e)

    # ---- Clash API 操作 ----
    async def delay(self, space_id: int, tag: str, url: str, timeout_ms: int,
                    fallback_urls: list[str] | None = None) -> tuple[bool, int | None, str | None]:
        """通过 sing-box 的 URLTest 真实请求一次，返回 (ok, delay_ms, err)。

        会依次尝试 url 和 fallback_urls：探测目标本身被墙/不可达时，
        不能把所有节点都判成坏的（单个 URL 的可用性不该等于节点的可用性）。
        """
        inst = self._instances.get(space_id)
        if inst is None or not inst.alive:
            return False, None, "sing-box 未运行"
        last_err = "未尝试"
        # 只试第一个 fallback：探测 URL 的可用性不该让单节点探测时间成倍增长
        # （64 节点 × 3 个 URL × 5s = 16 分钟一轮，会把自己卡死）
        for probe_url in [url, *(fallback_urls or [])[:1]]:
            if not probe_url:
                continue
            try:
                async with httpx.AsyncClient(timeout=timeout_ms / 1000 + 2) as c:
                    r = await c.get(f"http://127.0.0.1:{inst.api_port}/proxies/{tag}/delay",
                                    params={"url": probe_url, "timeout": timeout_ms})
            except httpx.HTTPError as e:
                last_err = f"{type(e).__name__}"
                continue
            if r.status_code == 200:
                body = r.json()
                if "delay" in body:
                    return True, int(body["delay"]), None
                last_err = str(body.get("message", body))[:120]
            else:
                last_err = r.text.strip()[:120] or f"HTTP {r.status_code}"
        return False, None, last_err

    async def probe_via_socks(self, space_id: int, tag: str, node_port: int,
                              url: str, timeout_ms: int) -> tuple[bool, int | None, str | None, str | None]:
        """经「指定节点的专属 socks 入站」真实请求一次，并解析响应里的出口 IP。

        返回 (ok, delay_ms, error, exit_ip)。

        为什么直连专属端口而不是用 clash 的 /delay：
          * /delay 只证明"这个 outbound 能连通目标"，它不经过入站路由，
            拿到的东西无法用来核对"随机选中的节点是否真的生效"。
          * 请求自己的入站端口 = 走的是分发器完全相同的链路，
            探测结论对"客户端实际能不能用"才有意义。
          * 顺带直接拿到 httpbin.org/ip 返回的 origin，就是该节点的出口 IP。
        """
        if not node_port:
            return False, None, "节点端口未知", None
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(proxy=f"socks5://127.0.0.1:{node_port}",
                                         timeout=timeout_ms / 1000) as c:
                r = await c.get(url)
        except Exception as e:  # noqa: BLE001  socks/网络/超时都算失败
            return False, None, f"{type(e).__name__}: {str(e)[:80]}", None
        elapsed = int((time.monotonic() - t0) * 1000)
        if r.status_code != 200:
            return False, elapsed, f"HTTP {r.status_code}", None
        return True, elapsed, None, _extract_ip(r.text)

    async def version(self) -> str:
        for inst in self._instances.values():
            if inst.alive:
                try:
                    async with httpx.AsyncClient(timeout=2.0) as c:
                        r = await c.get(f"http://127.0.0.1:{inst.api_port}/version")
                        return r.json().get("version", "?")
                except (httpx.HTTPError, ValueError):
                    continue
        return "未运行"
