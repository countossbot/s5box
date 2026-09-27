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
        # 由 main 注入：节点被删/被淘汰后重建该空间的 sing-box 配置
        self.on_topology_changed = None
        # 当前探测进度（面板轮询用）：空间内是串行的，所以单份就够
        self._progress: dict | None = None

    async def _topology_changed(self, space_id: int) -> None:
        if self.on_topology_changed is None:
            return
        try:
            await self.on_topology_changed(space_id)
        except Exception as e:  # noqa: BLE001
            log.warning("空间 %s 拓扑变更后重建失败：%s", space_id, e)

    # ------------------------------------------------------------ 单节点探测
    # 地址族常量
    FAM_IPV4 = "ipv4"
    FAM_IPV6 = "ipv6"

    @staticmethod
    def families_for(strategy: str) -> list[str]:
        """IP 策略 → 要**依次测试**的地址族顺序。

        prefer_* 两类都测（先测偏好的一族，失败再试另一族）——
        这是"优先"的字面语义：不是"只用这一族"，而是"先试这一族"。
        *_only 只测一族。
        """
        v = (strategy or "").strip().lower()
        if v == "ipv6_only":
            return [ProbeRunner.FAM_IPV6]
        if v == "ipv4_only":
            return [ProbeRunner.FAM_IPV4]
        if v == "prefer_ipv6":
            return [ProbeRunner.FAM_IPV6, ProbeRunner.FAM_IPV4]
        return [ProbeRunner.FAM_IPV4, ProbeRunner.FAM_IPV6]      # prefer_ipv4 及默认

    async def probe_one(self, space_id: int, tag: str, url: str, timeout_ms: int,
                        fallback_urls: list[str] | None = None,
                        want_ip: bool = False, family: str | None = None,
                        ) -> tuple[bool, int | None, str | None, str | None]:
        """探测单个节点。

        返回 (ok, delay_ms, error, exit_ip)。
        family 指定地址族（"ipv4"/"ipv6"/None）。为 None 时按 probe_url 的默认解析。

        做法是给请求绑定一个「已解析的地址」：先用该族的解析器解析目标域名，
        再带着解析结果发起请求，从而确保这次探测确实走的是指定的一栈。
        """
        port = self._port_of(space_id, tag)
        if want_ip:
            return await self.manager.probe_via_socks(
                space_id, tag, port, url, timeout_ms, family=family)
        ok, delay, err = await self.manager.delay(space_id, tag, url, timeout_ms, fallback_urls)
        return ok, delay, err, None

    async def probe_node_both_families(self, space_id: int, tag: str, url: str, timeout_ms: int,
                                       strategy: str, want_ip: bool, failfast: bool = True,
                                       ) -> tuple[bool, int | None, str | None, str | None, str | None]:
        """按策略**依次**测试地址族，返回 (ok, delay, err, exit_ip, family)。

        顺序语义：
          * 上一族成功 → 立即返回（failfast，不做无谓的二次请求）
          * 上一族失败 → 继续下一族
          * 全部失败 → 返回最后一次的错误
        """
        families = self.families_for(strategy)
        last = (False, None, "未尝试", None)
        for fam in families:
            ok, delay, err, ip = await self.probe_one(
                space_id, tag, url, timeout_ms, None, want_ip=want_ip, family=fam)
            if ok:
                return True, delay, None, ip, fam
            last = (False, delay, err, None, fam)
            if failfast:
                continue
        return last[0], last[1], last[2], last[3], last[4]

    def _port_of(self, space_id: int, tag: str) -> int:
        """节点 tag（nN）→ 它的专属 socks 入站端口。"""
        for sp in self.reg.spaces():
            if sp.id == space_id:
                for n in sp.nodes:
                    if n.outbound_tag == tag:
                        return n.socks_port
        return 0

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

            # 探测前先重建注册表：本轮可能因为上一轮删节点而让编号发生变化，
            # 用旧快照里的 tag 去连端口会摸到"另一个节点"，探测结论就是错的。
            self.rebuild()
            inst = self.manager.instance(space_id)
            if not inst.alive:
                return {"space_id": space_id, "error": "sing-box 未运行，跳过探测"}

            rows = self.db.nodes(space_id, include_deleted=False)
            # 把上轮遗留的 retry_pending 也纳入本轮（可能上轮中途超时中断了）
            # 顺序：unknown/cooling 优先（它们最需要判决），其余按 id
            rows = sorted(rows, key=lambda r: (0 if r["state"] in ("unknown", "cooling") else 1, r["id"]))
            retry_once = st.get("probe_retry_failed_once", "true").lower() in ("1", "true", "yes")
            ip_strategy = st.get("ip_strategy", "prefer_ipv4")
            row_family: dict[int, str] = {}
            # 进度：先按总数报状态，前端轮询 /api/probe/progress
            self._progress = {
                "space_id": space_id, "phase": "first", "done": 0,
                "total": len(rows), "ok": 0, "fail": 0,
                "started_at": time.time(), "finished": False,
            }
            result = {"space_id": space_id, "probed": 0, "ok": 0, "fail": 0,
                      "retried": 0, "recovered": 0, "deleted": 0}
            budget = float(st.get("probe_round_budget", "600"))
            deadline = time.monotonic() + budget

            async def probe_and_record(row, phase: str) -> bool:
                """探测一个节点并把结果写库。返回是否可用。

                phase="first" —— 本轮首测：失败只标记 retry_pending，绝不删
                phase="retry" —— 重测：仍失败就标记 deleted（随后物理删除）
                """
                tag = f"n{self._tag_index(space_id, row['id'])}"
                # 按 ip_strategy 依次测试地址族（prefer_* 会测两栈）
                ok, delay, err, body_ip, used_fam = await self.probe_node_both_families(
                    space_id, tag, url, timeout_ms, ip_strategy, with_exit_ip)
                if used_fam:
                    row_family[row["id"]] = used_fam
                exit_ip = body_ip
                if ok and with_exit_ip and not exit_ip:
                    # 响应体里没解析出 IP 时，退回单独的取 IP 请求
                    exit_ip = await self.fetch_exit_ip(self._port_of(space_id, tag))
                self.db.record_probe(
                    row["id"], ok, delay, err, exit_ip, threshold, auto_delete,
                    mark_failed_as=("retry_pending" if phase == "first" else "deleted"),
                )
                result["probed"] += 1
                result["ok" if ok else "fail"] += 1
                if self._progress:
                    self._progress["done"] = result["probed"]
                    self._progress["ok"] = result["ok"]
                    self._progress["fail"] = result["fail"]
                    self._progress["current"] = row["name"]
                return ok

            # ---- 第一阶段：空间内按顺序全跑一遍（需求 3：失败就跳过，继续后面的节点）----
            failed_rows = []
            for r in rows:
                if self._stop.is_set():
                    break
                if time.monotonic() > deadline:
                    result["truncated"] = True
                    log.warning("空间 %s 本轮探测超时（%ss），已探测 %s 个，剩余下轮继续",
                                space_id, int(budget), result["probed"])
                    break
                if not await probe_and_record(r, "first"):
                    failed_rows.append(r)
                await asyncio.sleep(0)   # 让出事件循环，别饿死代理分发

            # ---- 第二阶段：整轮跑完后，只对本轮失败的节点重测一次 ----
            still_failed = []
            if retry_once and failed_rows and self._stop.is_set() is False:
                log.info("空间 %s 本轮 %s 个节点失败，开始重测", space_id, len(failed_rows))
                if self._progress:
                    self._progress["phase"] = "retry"
                for r in failed_rows:
                    if self._stop.is_set() or time.monotonic() > deadline:
                        still_failed.extend(failed_rows[failed_rows.index(r):])
                        break
                    result["retried"] += 1
                    if await probe_and_record(r, "retry"):
                        result["recovered"] += 1
                    else:
                        still_failed.append(r)
                    await asyncio.sleep(0)

            # ---- 仍失败的：彻底删除，空间里不再保留任何相关信息（需求 3）----
            if auto_delete and still_failed:
                ids = [r["id"] for r in still_failed]
                for r in still_failed:
                    log.warning("空间 %s 重测仍失败，删除节点 %s(%s:%s)",
                                space_id, r["name"], r["host"], r["port"])
                self.db.hard_delete_nodes(ids)
                result["deleted"] = len(ids)
                # 删除会让后面所有节点的编号前移，必须立刻重建，
                # 否则接下来的容量淘汰/下一轮探测会拿旧编号连错端口
                self.rebuild()
                await self._topology_changed(space_id)

            # ---- 延迟过滤（探测后才有效：解析阶段还不知道延迟）----
            # 超阈值的节点按"不合格"处理并**物理删除**，与其它删除语义一致。
            max_delay = int(st.get("filter_max_delay_ms", "0") or 0)
            slow_ids = []
            if max_delay > 0:
                for r in self.db.nodes(space_id, include_deleted=False):
                    if r["delay_ms"] is not None and r["delay_ms"] > max_delay:
                        slow_ids.append(r["id"])
                if slow_ids:
                    for r in self.db.nodes(space_id, include_deleted=False):
                        if r["id"] in slow_ids:
                            log.info("空间 %s 延迟 %sms 超过阈值 %sms，删除节点 %s",
                                     space_id, r["delay_ms"], max_delay, r["name"])
                    self.db.hard_delete_nodes(slow_ids)
                    result["slow_filtered"] = len(slow_ids)

            # ---- 容量上限兜底（需求 1）----
            cap = int(st.get("filter_max_nodes_per_space", "100") or 0)
            evict = self.db.enforce_node_cap(space_id, cap, st.get("node_cap_evict_strategy", "worst"))
            result["cap"] = cap
            result["evicted"] = evict.get("evicted", 0)

            # 重建注册表；只要拓扑变了就同时重建 sing-box 配置，
            # 保证"注册表里的 tag/端口"和"sing-box 实例的真实入站"始终一致
            self.rebuild()
            if self._progress:
                self._progress["finished"] = True
                self._progress["phase"] = "done"
            if result["deleted"] or result["evicted"] or result.get("slow_filtered"):
                await self._topology_changed(space_id)
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

    def progress(self) -> dict | None:
        """当前探测进度快照（给 /api/probe/progress 用）。"""
        p = self._progress
        if not p:
            return None
        elapsed = max(0.001, time.time() - p.get("started_at", time.time()))
        done, total = p.get("done", 0), max(1, p.get("total", 1))
        eta = None
        if not p.get("finished") and done:
            eta = int(elapsed / done * (total - done))
        return {**p, "elapsed": int(elapsed), "eta": eta,
                "percent": min(100, int(done * 100 / total))}

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
