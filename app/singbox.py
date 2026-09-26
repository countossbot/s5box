"""sing-box 每空间一个实例：配置生成、子进程管理、Clash API 控制。

隔离理由：空间之间不能互相影响；删/停一个空间直接杀进程，不用全量 reload 掐断在途连接。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
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
            "inbounds": [
                {"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": self.socks_port},
            ],
            "outbounds": outbounds,
            "route": {
                "rules": [{"action": "sniff"}],
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
    async def delay(self, space_id: int, tag: str, url: str, timeout_ms: int) -> tuple[bool, int | None, str | None]:
        inst = self._instances.get(space_id)
        if inst is None or not inst.alive:
            return False, None, "sing-box 未运行"
        try:
            async with httpx.AsyncClient(timeout=timeout_ms / 1000 + 2) as c:
                r = await c.get(f"http://127.0.0.1:{inst.api_port}/proxies/{tag}/delay",
                                params={"url": url, "timeout": timeout_ms})
        except httpx.HTTPError as e:
            return False, None, f"{type(e).__name__}"
        if r.status_code != 200:
            return False, None, r.text.strip()[:120] or f"HTTP {r.status_code}"
        body = r.json()
        if "delay" in body:
            return True, int(body["delay"]), None
        return False, None, str(body.get("message", body))[:120]

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
