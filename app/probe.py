"""探测调度器：空间内串行、跨空间并行（需求原文：在每个空间内按顺序探测）。

一次探测 = 通过该空间的 sing-box socks 入站，真实发一次 HTTP 请求。
不能用 TCP 连通性代替：这些节点是 trojan+ws+tls，TCP 通了也可能握手失败。
"""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

from . import registry as reg_mod
from .singbox import SingBoxManager

log = logging.getLogger("subswarm.probe")


class ProbeRunner:
    def __init__(self, db, manager: SingBoxManager, reg: reg_mod.Registry):
        self.db = db
        self.manager = manager
        self.reg = reg
        self._tasks: dict[int, asyncio.Task] = {}
        self._locks: dict[int, asyncio.Lock] = {}
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self._loop_task: asyncio.Task | None = None
        self.last_round_at: float | None = None
        self.round_running = False

    # ------------------------------------------------------------ 单节点探测
    async def probe_one(self, space_id: int, tag: str, url: str, timeout_ms: int,
                        fallback_urls: list[str] | None = None) -> tuple[bool, int | None, str | None]:
        return await self.manager.delay(space_id, tag, url, timeout_ms, fallback_urls)

    @staticmethod
    def _fallbacks(st: dict) -> list[str]:
        return [u.strip() for u in (st.get("probe_fallback_urls") or "").split(",") if u.strip()]

    async def fetch_exit_ip(self, socks_port: int, timeout: float = 6.0) -> str | None:
        """顺带取出口 IP（面板用来显示节点落地 / 识别"所有节点其实同一中转"）。

        这是纯粹的附加信息：任何异常（含缺 socksio 依赖）都必须吞掉，不能影响探测结论。
        """
        try:
            async with httpx.AsyncClient(proxy=f"socks5://127.0.0.1:{socks_port}", timeout=timeout) as c:
                r = await c.get("https://api.ipify.org")
                if r.status_code == 200:
                    return r.text.strip()[:64]
        except Exception:  # noqa: BLE001  查不到出口 IP 不算探测失败
            pass
        return None

    # ------------------------------------------------------------ 空间内一轮（串行）
    async def probe_space(self, space_id: int) -> dict:
        """空间内按 id 顺序逐个探测；同一空间永不并发。"""
        lock = self._locks.setdefault(space_id, asyncio.Lock())
        if lock.locked():
            return {"space_id": space_id, "skipped": "该空间已有一轮探测在跑"}
        async with lock:
            st = self.db.all_settings()
            url = st.get("probe_url", "http://www.gstatic.com/generate_204")
            timeout_ms = int(float(st.get("probe_timeout", "5")) * 1000)
            fallbacks = self._fallbacks(st)
            threshold = int(st.get("failure_threshold", "3"))
            auto_delete = st.get("auto_delete", "true").lower() in ("1", "true", "yes")
            with_exit_ip = st.get("probe_exit_ip", "true").lower() in ("1", "true", "yes")

            inst = self.manager.instance(space_id)
            if not inst.alive:
                return {"space_id": space_id, "error": "sing-box 未运行，跳过探测"}

            rows = self.db.nodes(space_id, include_deleted=False)
            # 顺序：unknown/cooling 优先（它们最需要判决），其余按 id
            rows = sorted(rows, key=lambda r: (0 if r["state"] in ("unknown", "cooling") else 1, r["id"]))
            result = {"space_id": space_id, "probed": 0, "ok": 0, "fail": 0, "deleted": 0}
            for r in rows:
                if self._stop.is_set():
                    break
                tag = f"n{self._tag_index(space_id, r['id'])}"
                ok, delay, err = await self.probe_one(space_id, tag, url, timeout_ms, fallbacks)
                exit_ip = None
                if ok and with_exit_ip:
                    exit_ip = await self.fetch_exit_ip(inst.socks_port)
                new_state = self.db.record_probe(r["id"], ok, delay, err, exit_ip, threshold, auto_delete)
                result["probed"] += 1
                result["ok" if ok else "fail"] += 1
                if new_state == "deleted":
                    result["deleted"] += 1
                    log.warning("空间 %s 自动删除节点 %s(%s:%s)：%s", space_id, r["name"], r["host"], r["port"], err)
                await asyncio.sleep(0)   # 让出事件循环，别饿死代理分发
            self.rebuild()
            return result

    def _tag_index(self, space_id: int, node_id: int) -> int:
        for s in self.reg.spaces():
            if s.id == space_id:
                for n in s.nodes:
                    if n.id == node_id:
                        return int(n.outbound_tag.lstrip("n") or 0)
        return 0

    # ------------------------------------------------------------ 全量一轮（跨空间并行）
    async def probe_all(self, only_space: int | None = None) -> list[dict]:
        self.round_running = True
        try:
            spaces = [s["id"] for s in self.db.spaces() if s["enabled"]]
            if only_space is not None:
                spaces = [only_space]
            if not spaces:
                return [{"error": "没有启用的空间"}]
            return list(await asyncio.gather(*[self.probe_space(s) for s in spaces]))
        finally:
            self.round_running = False
            self.last_round_at = time.time()

    def rebuild(self) -> None:
        ports = {sid: inst.socks_port for sid, inst in self.manager._instances.items()}
        new = reg_mod.build_registry(self.db, ports)
        self.reg.replace(new.spaces())

    # ------------------------------------------------------------ 后台循环
    async def start_loop(self) -> None:
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        try:
            await asyncio.sleep(3)     # 让启动流程先跑完
            while not self._stop.is_set():
                try:
                    await self.probe_all()
                except asyncio.CancelledError:
                    raise
                except Exception as e:  # noqa: BLE001
                    log.exception("探测轮次异常：%s", e)
                interval = float(self.db.get_setting("probe_interval", "300") or 300)
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=max(30.0, interval))
                except asyncio.TimeoutError:
                    pass
                # 顺手清历史探测记录，避免 DB 无限膨胀
                try:
                    self.db.purge_probes()
                except Exception:  # noqa: BLE001
                    pass
        except asyncio.CancelledError:
            raise

    def trigger(self) -> None:
        """面板点"立即探测"→ 叫醒循环。"""
        self._wake.set()

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            try:
                await self._loop_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._loop_task = None
        for t in list(self._tasks.values()):
            if not t.done():
                t.cancel()
        for t in list(self._tasks.values()):
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._tasks.clear()
