"""sing-box 每空间一个实例：配置生成、子进程管理、Clash API 控制。

隔离理由：空间之间不能互相影响；删/停一个空间直接杀进程，不用全量 reload 掐断在途连接。
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import ipaddress
import logging
import os
import socket
import subprocess
import time
import urllib.parse
from collections.abc import Awaitable, Callable
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


async def _resolve_family(host: str, family: str, timeout: float) -> str | None:
    """把域名解析成指定地址族的一个地址；解析不出返回 None。

    用 asyncio 的 getaddrinfo，family 过滤 AF_INET / AF_INET6。
    """
    if not host:
        return None
    fam = socket.AF_INET if family == "ipv4" else socket.AF_INET6
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=fam, type=socket.SOCK_STREAM),
            timeout=max(1.0, timeout))
    except (OSError, asyncio.TimeoutError):
        return None
    for info in infos:
        return info[4][0]
    return None


VALID_IP_STRATEGIES = ("prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only")


def _dns_strategy(value: str) -> str:
    """把设置里的 ip_strategy 映射成 sing-box 的 dns.strategy 取值。

    sing-box 支持 prefer_ipv4 / prefer_ipv6 / ipv4_only / ipv6_only，
    与我们的取值一一对应；非法值退回 prefer_ipv4（安全默认）。
    """
    v = (value or "").strip().lower()
    return v if v in VALID_IP_STRATEGIES else "prefer_ipv4"


class SpaceInstance:
    """一个订阅空间 = 一个 sing-box 进程（私有 socks 入站 + clash api）。"""

    def __init__(self, space_id: int, workdir: Path, socks_port: int, api_port: int,
                 manager: "SingBoxManager | None" = None):
        self.space_id = space_id
        self.workdir = workdir
        self.socks_port = socks_port
        self.api_port = api_port
        # 本空间当前声明的 socks 端口块大小；节点变多时会向上扩容
        self.socks_block = SingBoxManager.SOCKS_BLOCK
        # 扩容后回写到 manager，让后续新空间分配时能避让
        self.manager = manager
        self.proc: asyncio.subprocess.Process | None = None
        self.log_tail: list[str] = []
        self._log_task: asyncio.Task | None = None
        self._reader_task: asyncio.Task | None = None
        self._stopping = False
        # ---- 看门狗相关状态 ----
        # desired 表示"这个空间*应该*有进程在跑"，是唯一权威的期望状态：
        # 看门狗只认它，不看进程是否存在，否则会与拓扑变化自愈互相抢着重启。
        self.desired = False
        # 单把锁保护 start/stop/reload 的整段临界区。没有它，两个协程可以
        # 同时通过 start() 开头的自检（此时 self.proc 都还是 None），各起一个
        # 进程抢同一个端口，旧句柄被覆盖后再没人 wait() 它 —— 真僵尸进程。
        self._lock = asyncio.Lock()
        self.generation = 0
        self._restarts = 0
        self._next_retry_at = 0.0
        self._last_error: str | None = None
        self._degraded = False

    # ---- 配置 ----
    def build_config(self, nodes: list[dict], log_level: str = "warn",
                     ip_strategy: str = "prefer_ipv4") -> dict:
        outbounds: list[dict] = []
        # 可选的上游 DNS 覆盖。默认留空 → 用系统解析器（最稳）。
        dns_remote = os.getenv("SINGBOX_DNS_SERVER", "").strip()
        outbounds: list[dict] = []
        used = []                        # 只保留真正生成了出站的节点下标
        for i, n in enumerate(nodes):
            try:
                ob = json.loads(n["outbound_json"]) if isinstance(n["outbound_json"], str) else dict(n["outbound_json"])
            except (ValueError, TypeError):
                log.warning("空间 %s 第 %s 个节点的出站配置无法解析，跳过", self.space_id, i)
                continue
            if not ob.get("type") or not ob.get("server"):
                # 半截配置（例如历史脏数据）会让 sing-box 以
                # "unknown outbound type:" FATAL 起不来，必须在这里拦掉
                log.warning("空间 %s 第 %s 个节点缺少 type/server，跳过", self.space_id, i)
                continue
            ob["tag"] = f"n{i}"          # 只含 ascii，绕开 tag 编码问题
            outbounds.append(ob)
            used.append(i)
        self._used_indexes = used
        # 块必须放得下所有节点下标，否则会溢出到下一个空间的端口段，
        # 表现为"连 A 的端口却走到了 B 的节点"。
        # 注意不能直接报错：cap<=0（不限量）是合法配置，节点数无上限，
        # 一旦越界就让空间永远起不来。改为按需扩容本空间的块，并登记占用，
        # 使后续新空间的 _alloc_socks_base() 自动避让。
        if used:
            need = max(used) + 1
            if need > self.socks_block:
                self.socks_block = need
                if self.manager is not None:
                    self.manager.note_socks_extent(self.space_id, need)
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
                # 由设置里的 ip_strategy 决定（prefer_ipv4/prefer_ipv6/ipv4_only/ipv6_only）
                "strategy": _dns_strategy(ip_strategy),
            },
            # 每个节点一个独立 socks 入站：第 i 个节点监听 self.socks_port + i，
            # route 规则把该入站的流量强制走第 i 个节点。
            # 这样"随机选中的节点"是物理确定的（连哪个端口就走哪个节点），
            # 不依赖 sing-box 的任何隐式选路机制 —— 之前用 SOCKS5 用户名传 tag 的
            # 做法 sing-box 并不支持，导致代理全部失败。
            "inbounds": [
                {"type": "socks", "tag": f"in{i}", "listen": "127.0.0.1",
                 "listen_port": self.socks_port + i}
                for i in used
            ],

            "outbounds": outbounds,
            "route": {
                "rules": [
                    {"action": "sniff"},
                    *[{"inbound": [f"in{i}"], "outbound": f"n{i}"} for i in used],
                ],
                # 1.14 要求显式声明默认解析器，否则直接 FATAL 拒绝启动
                "default_domain_resolver": {"server": "remote" if dns_remote else "local"},
                # 入站流量默认走第一个节点；分发器会在每条连接上用 SOCKS5 用户名
                # 指定本次随机选中的节点 tag（见 proxy.py connect_upstream）。
                # 绝不能写死 "n0"：一个节点都没有时（刚建空间/全被删光），
                # sing-box 会以 "default outbound not found: n0" FATAL 起不来。
                # 没有节点时退回 direct，保证进程能起来、也保证有节点时流量不会绕开节点。
                "final": f"n{used[0]}" if used else "direct",
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

    def write_config(self, nodes: list[dict], log_level: str = "warn",
                     ip_strategy: str = "prefer_ipv4") -> None:
        """先写临时文件再原子的 rename —— 半截配置会让 sing-box 起不来。"""
        self.workdir.mkdir(parents=True, exist_ok=True)
        tmp = self.config_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.build_config(nodes, log_level, ip_strategy), ensure_ascii=False),
                       encoding="utf-8")
        os.replace(tmp, self.config_path)
        self._validate_config()

    def _validate_config(self) -> None:
        """校验配置合法（起不来就别起，日志里能看到原因）。"""
        # 用参数列表调用而不是拼 shell 字符串：配置路径来自 DATA_DIR/空间 ID，
        # 避免路径里出现 shell 元字符被解释执行。
        try:
            proc = subprocess.run(
                [config.SINGBOX_BIN, "check", "-c", str(self.config_path)],
                capture_output=True, text=True, timeout=15,
            )
        except FileNotFoundError:
            # sing-box 没安装时不该阻断配置生成：运行期启动会再次报错
            log.warning("未找到 sing-box 可执行文件 %s，跳过配置校验", config.SINGBOX_BIN)
            return
        except subprocess.TimeoutExpired:
            raise RuntimeError("sing-box 配置校验超时") from None
        out = proc.stdout or ""
        if proc.stderr:
            out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0 or "fatal" in out.lower():
            raise RuntimeError(f"sing-box 配置校验失败：{out.strip()[:500]}")

    # ---- 进程 ----
    async def start(self) -> None:
        """公开入口：拿锁后走内核，避免并发双起抢端口。"""
        async with self._lock:
            await self._start_locked()

    async def _start_locked(self) -> None:
        """调用方必须已持有 self._lock；reload() 复用同一内核，避免不可重入死锁。"""
        if self.proc and self.proc.returncode is None:
            await self._reload_locked()
            return
        self.proc = await asyncio.create_subprocess_exec(
            config.SINGBOX_BIN, "run", "-c", str(self.config_path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            # 独立进程组：sing-box 自己还可能 fork 子进程，kill 时一并带走，
            # 避免留下孤儿进程占着端口。
            start_new_session=True,
        )
        try:
            self._validate_config()
        except BaseException:
            await self._stop_locked()
            raise
        self.generation += 1
        self._log_task = asyncio.create_task(self._drain_logs())
        try:
            await self._wait_ready()
        except BaseException:
            # 启动失败必须把半启动的进程收干净，否则它占着端口没人管
            await self._stop_locked()
            raise
        # 只有真正就绪才算"应该有进程在跑"
        self.desired = True


    async def _drain_logs(self) -> None:
        try:
            proc = self.proc
            stream = proc.stdout if proc else None
            if stream is None:
                return
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip()
                self.log_tail.append(text)
                del self.log_tail[:-100]
            # EOF 时 returncode 可能还没被设置（进程刚死但 asyncio 尚未 reap），
            # 此时 alive 会短暂返回 True，看门狗会漏掉这次崩溃。显式 wait() 一次，
            # 确保退出码就绪。注意用的是局部 proc：self.proc 可能已被 stop() 置 None
            # 或已被换成新进程，等错对象会挂住或误判。
            await proc.wait()
            # 只有"本该在跑"却退了才算非预期退出；主动 stop() 会先置 desired=False
            # 并把 self.proc 置 None，所以这里能自然区分主动与崩溃。
            if self.desired and self.proc is proc:
                log.warning("space %s sing-box 进程非预期退出：returncode=%s",
                            self.space_id, proc.returncode)
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
        """公开入口：整体持锁，内部只能调 _xxx_locked 内核。"""
        async with self._lock:
            await self._reload_locked()

    async def _reload_locked(self) -> None:
        """原地重载配置；失败就整体重启进程。调用方必须已持有 self._lock。

        这里必须调 _stop_locked()/_start_locked() 而不是 stop()/start()：
        asyncio.Lock 不可重入，内部再拿一次锁会直接死锁。
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.put(f"http://127.0.0.1:{self.api_port}/configs",
                                params={"force": "true"}, content=self.config_path.read_bytes())
            if r.status_code in (200, 204):
                return
            log.warning("space %s 重载返回 %s，改为重启", self.space_id, r.status_code)
        except httpx.HTTPError as e:
            log.warning("space %s 重载失败（%s），改为重启", self.space_id, e)
        await self._stop_locked()
        await self._start_locked()

    async def stop(self, grace: float = 5.0) -> None:
        """公开入口：拿锁后走内核。"""
        async with self._lock:
            await self._stop_locked(grace)

    async def _stop_locked(self, grace: float = 5.0) -> None:
        self.desired = False
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
        # 看门狗不直接调 inst.start()：那会与"拓扑变化自愈"形成两条互相竞争的
        # 重建路径（一个刚 start 另一个又 stop，或两边各起一个进程）。统一走
        # app.main.rebuild_space_instance，由 app/main.py 注入回调（singbox.py
        # 里 import app.main 会循环导入）。
        self._rebuild_cb: Callable[[int], Awaitable[None]] | None = None
        self._watchdog_task: asyncio.Task | None = None
        # 单实例连续失败到此上限就放弃重试，避免崩溃-重启死循环刷 CPU
        self.MAX_RESTARTS = 5

    def set_rebuild_callback(self, cb: Callable[[int], Awaitable[None]]) -> None:
        """注入重建回调（一般是 app.main.rebuild_space_instance）。"""
        self._rebuild_cb = cb

    # 每个空间 socks 端口的初始块大小。块会在节点变多时按需扩容
    # （见 SpaceInstance.build_config），所以这里只是起点，不是硬上限。
    SOCKS_BLOCK = 512

    def _occupied(self, exclude_space: int | None = None) -> list[tuple[int, int]]:
        """已占用的 [起始, 结束] 端口区间（socks 块 + api 端口）。

        api 端口也一并纳入：它原本不参与避让，且 _free_port 的搜索窗
        （start+500）小于 SOCKS_BLOCK，会让块之间悄悄重叠。
        """
        spans: list[tuple[int, int]] = []
        for sid, i in self._instances.items():
            if sid == exclude_space:
                continue
            spans.append((i.socks_port, i.socks_port + i.socks_block - 1))
            spans.append((i.api_port, i.api_port))
        return spans

    def note_socks_extent(self, space_id: int, block: int) -> None:
        """空间扩容端口块后登记，供后续新空间避让。"""
        inst = self._instances.get(space_id)
        if inst is not None and block > inst.socks_block:
            inst.socks_block = block

    @staticmethod
    def _first_gap(spans: list[tuple[int, int]], start: int, size: int) -> int | None:
        """在 spans 之外找一段长度 size 的空档，从 start 起找。"""
        p = start
        for _ in range(1000):                     # 有界，避免极端情况死循环
            cand = _free_port(p)
            end = cand + size - 1
            hit = [(lo, hi) for lo, hi in spans if not (end < lo or cand > hi)]
            if not hit:
                return cand
            p = max(hi for _, hi in hit) + 1
        return None

    def _alloc_socks_base(self) -> int:
        """给新空间分配一个不与任何已占用区间重叠的块起点。"""
        cand = self._first_gap(self._occupied(), self._next_socks, self.SOCKS_BLOCK)
        if cand is None:
            raise RuntimeError("无法为空间分配不重叠的 socks 端口块，端口空间已耗尽")
        self._next_socks = cand + self.SOCKS_BLOCK
        return cand

    def _alloc_api_port(self) -> int:
        """api 端口同样必须避让所有已占用区间，否则会与别的空间撞端口。"""
        cand = self._first_gap(self._occupied(), self._next_api, 1)
        if cand is None:
            raise RuntimeError("无法为空间分配不冲突的 API 端口")
        self._next_api = cand + 1
        return cand

    def instance(self, space_id: int) -> SpaceInstance:
        inst = self._instances.get(space_id)
        if inst is None:
            inst = SpaceInstance(space_id, self.workdir,
                                 self._alloc_socks_base(), self._alloc_api_port(),
                                 manager=self)
            self._instances[space_id] = inst
        return inst

    async def apply(self, space_id: int, nodes: list[dict], start: bool = True,
                    ip_strategy: str = "prefer_ipv4") -> SpaceInstance:
        inst = self.instance(space_id)
        if start:
            await inst.stop()                 # 先停：配置变了要干净重启（端口沿用）
            inst.write_config(nodes, ip_strategy=ip_strategy)
            await inst.start()
        return inst

    async def stop_space(self, space_id: int, cleanup: bool = False) -> None:
        inst = self._instances.get(space_id)
        if inst is not None:
            # 必须在 pop 之前清掉期望状态：看门狗下一轮拿到的快照里若还留着
            # 这个实例且 desired=True，就会把刚删掉的空间又拉起来。
            inst.desired = False
        inst = self._instances.pop(space_id, None)
        if inst is None:
            return
        await inst.stop()
        if cleanup:
            inst.cleanup_files()

    async def stop_all(self) -> None:
        """关停全部子进程（先子进程，后文件）。"""
        # 先统一清期望状态，再逐个停：否则停到一半看门狗 tick 会把还没停的
        # 实例当成"崩了"而重建，关停序列永远走不完。
        for inst in list(self._instances.values()):
            inst.desired = False
        for sid in list(self._instances):
            try:
                await self.stop_space(sid)
            except Exception as e:  # noqa: BLE001
                log.warning("关停空间 %s 出错：%s", sid, e)

    # ---- 崩溃看门狗 ----
    async def start_watchdog(self, interval: float = 5.0) -> None:
        """启动看门狗后台 task（幂等：已在跑就不重复起）。"""
        if self._watchdog_task and not self._watchdog_task.done():
            return
        self._watchdog_task = asyncio.create_task(self.watchdog_loop(interval))

    async def stop_watchdog(self) -> None:
        """取消并等待看门狗 task。

        必须在 stop_all() 之前调用：先停 task 再停子进程，否则看门狗会在
        关停过程中把进程重新拉起来（遵循项目"先停子进程/任务，再放句柄"的规则）。
        """
        t, self._watchdog_task = self._watchdog_task, None
        if t is None or t.done():
            return
        t.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await t

    async def watchdog_loop(self, interval: float = 5.0) -> None:
        """周期性检查"本该在跑却不在跑"的实例，交给重建回调统一拉起。

        绝不自己调 inst.start()：那会让"崩溃自愈"和"拓扑变化自愈"变成两条
        互相竞争的重建路径。
        """
        while True:
            await asyncio.sleep(interval)
            # list() 快照：stop_space() 会在遍历期间 pop，直接迭代 dict 会
            # RuntimeError: dictionary changed size during iteration
            for space_id, inst in list(self._instances.items()):
                if not inst.desired or inst.alive or inst._degraded:
                    continue
                # 退避未到点就跳过，避免崩溃-重启死循环刷 CPU
                if time.monotonic() < inst._next_retry_at:
                    continue
                if self._rebuild_cb is None:
                    log.warning("space %s 需要重建但未注入回调，跳过", space_id)
                    inst._degraded = True
                    continue
                try:
                    await self._rebuild_cb(space_id)
                except RuntimeError as e:
                    # RuntimeError = 配置校验失败/端口占用等确定性失败，
                    # 重试多少次都一样，直接放弃，不要进退避循环。
                    inst._degraded = True
                    inst._last_error = str(e)
                    log.warning("space %s 重建遇到确定性失败，放弃重试：%s", space_id, e)
                    continue
                except Exception as e:  # noqa: BLE001
                    inst._restarts += 1
                    inst._last_error = str(e)
                    backoff = min(2 ** (inst._restarts - 1), 60)
                    inst._next_retry_at = time.monotonic() + backoff
                    log.warning("space %s 重建失败（第 %s 次，%ss 后重试）：%s",
                                space_id, inst._restarts, backoff, e)
                else:
                    if inst.alive:
                        inst._restarts = 0
                        inst._last_error = None
                        log.info("space %s sing-box 已由看门狗重新拉起", space_id)
                        continue
                    # 回调没报错但进程仍没活：同样计入失败次数
                    inst._restarts += 1
                    backoff = min(2 ** (inst._restarts - 1), 60)
                    inst._next_retry_at = time.monotonic() + backoff
                    inst._last_error = "重建后进程仍未运行"
                    log.warning("space %s 重建后仍未运行（第 %s 次，%ss 后重试）",
                                space_id, inst._restarts, backoff)
                if inst._restarts >= self.MAX_RESTARTS:
                    inst._degraded = True
                    log.warning("space %s 连续 %s 次重建失败，停止重试（degraded），"
                                "最后错误：%s", space_id, inst._restarts, inst._last_error)

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
                              url: str, timeout_ms: int,
                              family: str | None = None) -> tuple[bool, int | None, str | None, str | None]:
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
        # family 指定时，先确认目标域名能解析出该族的地址。
        # 注意：**不能**把 URL 里的域名替换成解析出来的 IP 再请求 ——
        # 那样 TLS 的 SNI 会变成 IP，证书校验必然失败
        # （实测：替换后 5/5 节点全部 CERTIFICATE_VERIFY_FAILED，
        # 而不替换时同样节点 5/5 成功）。
        # 这里只做"该族是否可达"的前置判断，请求本身仍用原域名，
        # 由 sing-box 的 dns.strategy 决定实际走哪一栈。
        host = urllib.parse.urlsplit(url).hostname or ""
        if family in ("ipv4", "ipv6"):
            try:
                ip = ipaddress.ip_address(host)
                if (family == "ipv4") != (ip.version == 4):
                    return False, None, f"{host} 不是 {family} 地址", None
            except ValueError:
                resolved = await _resolve_family(host, family, timeout_ms / 1000)
                if not resolved:
                    return False, None, f"无法解析出 {family} 地址：{host}", None
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
