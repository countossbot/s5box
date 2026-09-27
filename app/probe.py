"""探测调度器：空间内串行、跨空间并行（需求原文：在每个空间内按顺序探测）。

一次探测 = 通过该空间的 sing-box socks 入站，真实发一次 HTTP 请求。
不能用 TCP 连通性代替：这些节点是 trojan+ws+tls，TCP 通了也可能握手失败。
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time

import httpx

from . import registry as reg_mod
from .singbox import SingBoxManager, ip_family_of

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
    async def family_available(family: str) -> bool:
        """本机网络栈是否支持该地址族（结果缓存，避免每节点重复探测）。

        只检查本机栈能力，**不对外连接** —— 对外探测会受网络策略影响，
        把"某个地址被墙"误判成"本机没有这一族"，从而静默关掉双栈探测。

        没有 IPv6 栈时（Docker 默认如此），对每个节点都去解析 AAAA
        纯属浪费时间，也会把失败原因误导成"节点不可用"。
        """
        key = f"_fam_ok_{family}"
        cached = getattr(ProbeRunner, key, None)
        if cached is not None:
            return cached
        loop = asyncio.get_running_loop()
        fam = socket.AF_INET if family == "ipv4" else socket.AF_INET6

        # 判断"本机是否具备该族出口"，只看**本机网络栈**能力，
        # 不做对外连接测试 —— 之前用连接 1.1.1.1:443 来判断，
        # 结果在任何屏蔽该地址的网络里都会误判成"IPv4 不可用"，
        # 进而静默关掉双栈探测（实测踩到：容器 IPv4 明明正常，
        # 却报 ipv4=False，prefer_* 因此退化成单栈）。
        ok = await ProbeRunner._has_usable_family(fam)
        setattr(ProbeRunner, key, ok)
        return ok

    @staticmethod
    async def _has_usable_family(fam: int) -> bool:
        """本机是否存在该族的**非回环**地址。

        只判"有没有本机地址"是不够的：IPv6 的回环 ::1 在几乎所有
        Linux 容器里都存在（即使完全没有 IPv6 出口），
        只看它会把"没有 IPv6"误判成"有"。
        所以这里显式排除 loopback / link-local 之外的地址，
        并且要求至少有一个非回环地址可用。
        """
        import ipaddress
        loop = asyncio.get_running_loop()
        candidates = []
        # 1) 本机主机名
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(socket.gethostname(), None, family=fam), timeout=3)
            candidates += [i[4][0] for i in infos]
        except (OSError, asyncio.TimeoutError):
            pass
        # 2) 直接读网卡地址（getaddrinfo 拿不到时更可靠）
        if not candidates:
            try:
                for info in socket.getaddrinfo(None, 0, family=fam,
                                               type=socket.SOCK_STREAM,
                                               flags=socket.AI_PASSIVE):
                    candidates.append(info[4][0])
            except OSError:
                pass
        for addr in candidates:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                continue
            if fam == socket.AF_INET6 and getattr(ip, "ipv4_mapped", None):
                continue
            return True
        return False

    @classmethod
    def reset_family_cache(cls) -> None:
        for f in ("ipv4", "ipv6"):
            if hasattr(cls, f"_fam_ok_{f}"):
                delattr(cls, f"_fam_ok_{f}")

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

        fallback_urls：主 URL 失败后依次尝试的备用地址（want_ip=True 时用的是
        probe_via_socks，即通过 Clash API 发请求，fallback 由该接口自行处理）。
        family 指定时出口 IP 会做地址族校验，族不符的 IP 记为 None（见
        singbox.probe_via_socks 的假阳性说明），但**不影响 ok**。
        """
        port = self._port_of(space_id, tag)
        if want_ip:
            # 走 probe_via_socks 时 family 已在 singbox 内校验，这里不重复。
            return await self.manager.probe_via_socks(
                space_id, tag, port, url, timeout_ms, family=family)
        # 不带 IP 的路径（want_ip=False）：主 URL 失败后依次试 fallback，
        # 任一个通就算通。fallback 只在主 URL 失败时才发请求，不给正常路径加延迟。
        attempts = [url, *(fallback_urls or [])]
        last_err: str | None = None
        for u in attempts:
            ok, delay, err = await self.manager.delay(space_id, tag, u, timeout_ms, None)
            if ok:
                return ok, delay, None, None
            last_err = err
        return False, None, last_err, None

    async def probe_node_both_families(self, space_id: int, tag: str, url: str, timeout_ms: int,
                                       strategy: str, want_ip: bool,
                                       fallbacks: list[str] | None = None,
                                       ) -> tuple[bool, int | None, str | None, str | None, str | None,
                                                  str | None, str | None]:
        """按策略**依次**测试地址族。

        返回 (ok, delay, err, exit_ip, family, ip_v4, ip_v6)：
        前五项是"最终采用的结果"（成功那一族，或全失败时最后一族），
        ip_v4/ip_v6 是两族各自拿到的出口 IP（没拿到或族不符时为 None），
        供调用方落库到 exit_ip_v4 / exit_ip_v6 —— 单靠 exit_ip 一个字段
        没法表达"两栈分别是什么出口"。

        顺序语义：
          * 某一族成功 → 立即返回成功结果（成功即短路，不做无谓的二次请求）
          * 某一族失败 → 继续下一族（**绝不允许**因为第一族失败就跳过第二族，
            否则只会 v4 的节点会被误判为不可用）
          * 全部失败 → 返回最后一次的错误

        fallbacks：主 URL 失败后依次尝试的备用探测地址，转交给单节点探测。
        """
        families = self.families_for(strategy)
        # 本机没有该族出口时直接跳过 —— 否则每个节点都白跑一次，
        # 还会把"本机无 IPv6"误报成"节点不可用"
        if len(families) > 1:
            usable = []
            for f in families:
                if await self.family_available(f):
                    usable.append(f)
            if usable:
                families = usable
                # 两族都不可用（极端情况）时保留原顺序，让错误信息如实反映
        last = (False, None, "未尝试", None, None)
        fam_ips: dict[str, str | None] = {}
        for fam in families:
            ok, delay, err, ip = await self.probe_one(
                space_id, tag, url, timeout_ms, fallbacks, want_ip=want_ip, family=fam)
            fam_ips[fam] = ip if ok else None
            if ok:
                return True, delay, None, ip, fam, fam_ips.get("ipv4"), fam_ips.get("ipv6")
            last = (False, delay, err, None, fam)
        return last[0], last[1], last[2], last[3], last[4], fam_ips.get("ipv4"), fam_ips.get("ipv6")

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

    async def fetch_exit_ip(self, socks_port: int, timeout: float = 6.0,
                            family: str | None = None,
                            st: dict | None = None) -> str | None:
        """顺带取出口 IP（面板用来显示节点落地 / 识别"所有节点其实同一中转"）。

        这是纯粹的附加信息：任何异常（含缺 socksio 依赖）都必须吞掉，不能影响探测结论。

        取 IP 的 URL 从设置 exit_ip_url 读：以前硬编码 api.ipify.org，镜像被墙
        或想换源时完全改不动。读不到设置时才退回同一个硬编码值兜底。

        family 指定时做假阳性校验：拿到的 IP 必须真属于该族，否则返回 None
        （探测本身是通的，只是这个 IP 不能算作该族的出口）。
        """
        url = (st or {}).get("exit_ip_url") or "https://api.ipify.org"
        try:
            async with httpx.AsyncClient(proxy=f"socks5://127.0.0.1:{socks_port}", timeout=timeout) as c:
                r = await c.get(url)
                if r.status_code == 200:
                    ip = r.text.strip()[:64]
                    if family in ("ipv4", "ipv6") and ip_family_of(ip) != family:
                        log.warning("取到的出口 IP %s 不属于本轮测试族 %s，记为未知", ip, family)
                        return None
                    return ip
        except Exception:  # noqa: BLE001  查不到出口 IP 不算探测失败
            pass
        return None

    async def probe_specific(self, space_id: int, node_ids: list[int]) -> dict:
        """只探测指定的一批节点（订阅刷新后探"新进来的"那些）。

        与 probe_space 共用同一套两阶段判定：
          首测失败 → retry_pending 跳过 → 整批跑完只重测失败的 → 仍失败才删。
        同一空间有锁，所以与正在跑的整轮探测不会冲突。
        """
        if not node_ids:
            return {"space_id": space_id, "probed": 0}
        lock = self._locks.setdefault(space_id, asyncio.Lock())
        async with lock:
            st = self.db.all_settings()
            # 默认值与 config.DEFAULT_SETTINGS["probe_url"] 对齐：以前这里硬编码
            # ipinfo.io/ip，与自动轮询用的 gstatic generate_204 不一致，同一个
            # "默认探测地址"有两套口径，行为随入口漂移。
            url = st.get("probe_url") or "https://httpbin.org/ip"
            timeout_ms = int(float(st.get("probe_timeout", "5")) * 1000)
            threshold = int(st.get("failure_threshold", "1"))
            auto_delete = st.get("auto_delete", "true").lower() in ("1", "true", "yes")
            with_exit_ip = st.get("probe_exit_ip_from_body", "true").lower() in ("1", "true", "yes")
            retry_once = st.get("probe_retry_failed_once", "true").lower() in ("1", "true", "yes")
            # 与转发路径同源：必须走同一个解析函数，否则探测时按 A 策略建连、
            # 真实转发按 B 策略，延迟与出口 IP 全对不上。
            ip_strategy = self.db.resolve_ip_strategy(self.db.get_space(space_id))
            ProbeRunner.reset_family_cache()

            inst = self.manager.instance(space_id)
            if not inst.alive:
                log.warning("空间 %s 的 sing-box 未运行，跳过新节点探测", space_id)
                return {"space_id": space_id, "error": "sing-box 未运行，跳过探测"}

            want = set(node_ids)
            rows = [r for r in self.db.nodes(space_id, include_deleted=False) if r["id"] in want]
            result = {"space_id": space_id, "probed": 0, "ok": 0, "fail": 0,
                      "retried": 0, "recovered": 0, "deleted": 0}

            async def probe_and_record(row, phase: str) -> bool:
                tag = f"n{self._tag_index(space_id, row['id'])}"
                fallbacks = self._fallbacks(st)
                (ok, delay, err, body_ip, _fam, ip_v4, ip_v6) = await self.probe_node_both_families(
                    space_id, tag, url, timeout_ms, ip_strategy, with_exit_ip, fallbacks)
                exit_ip = body_ip
                if ok and with_exit_ip and not exit_ip:
                    exit_ip = await self.fetch_exit_ip(
                        self._port_of(space_id, tag), family=_fam, st=st)
                # 首测失败先挂起重测；重测仍失败时才决定归宿：
                #   开启自动删除 → deleted；关闭自动删除 → cooling（失败待重测的稳态）
                # 之前这里恒传 retry_pending，导致关闭自动删除后节点永远卡在
                # retry_pending，而 cooling 这个状态在整个生产路径里从未被写入过。
                if phase == "first":
                    failed_as = "retry_pending"
                else:
                    failed_as = "deleted" if auto_delete else "cooling"
                self.db.record_probe(row["id"], ok, delay, err, exit_ip, threshold, auto_delete,
                                     mark_failed_as=failed_as,
                                     exit_ip_v4=ip_v4, exit_ip_v6=ip_v6, used_family=_fam if ok else None)
                result["probed"] += 1
                result["ok" if ok else "fail"] += 1
                return ok

            failed = []
            for r in rows:
                if self._stop.is_set():
                    break
                if not await probe_and_record(r, "first"):
                    failed.append(r)
                await asyncio.sleep(0)

            still = []
            if retry_once and failed:
                for r in failed:
                    if self._stop.is_set():
                        still.append(r)
                        continue
                    result["retried"] += 1
                    if await probe_and_record(r, "retry"):
                        result["recovered"] += 1
                    else:
                        still.append(r)
                    await asyncio.sleep(0)

            if auto_delete and still:
                ids = [r["id"] for r in still]
                for r in still:
                    log.warning("空间 %s 新节点 %s(%s:%s) 重测仍失败，删除",
                                space_id, r["name"], r["host"], r["port"])
                self.db.hard_delete_nodes(ids)
                result["deleted"] = len(ids)

            self.rebuild()
            if result["deleted"] or result["recovered"]:
                await self._topology_changed(space_id)
            log.info("空间 %s 新节点探测完成：探测 %s，可用 %s，删除 %s",
                     space_id, result["probed"], result["ok"], result["deleted"])
            return result

    def schedule_probe(self, space_id: int, node_ids: list[int]) -> None:
        """在后台探测一批新节点，不阻塞调用方（HTTP 请求立即返回）。"""
        if not node_ids:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self.probe_specific(space_id, node_ids))
        self._tasks[id(task)] = task
        task.add_done_callback(lambda t: self._tasks.pop(id(t), None))

    # ------------------------------------------------------------ 空间内一轮（串行）
    async def probe_space(self, space_id: int) -> dict:
        """空间内按 id 顺序逐个探测；同一空间永不并发。"""
        lock = self._locks.setdefault(space_id, asyncio.Lock())
        if lock.locked():
            return {"space_id": space_id, "skipped": "该空间已有一轮探测在跑"}
        async with lock:
            st = self.db.all_settings()
            # 默认值与 config.DEFAULT_SETTINGS["probe_url"] 对齐：以前这里硬编码
            # generate_204，响应体里根本没有 IP，导致自动轮询永远探不到出口 IP。
            url = st.get("probe_url") or "https://httpbin.org/ip"
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
                # 实例起不来（例如该空间当前没有任何节点）时明确跳过，
                # 不要让一次探测失败影响整个调度循环
                log.warning("空间 %s 的 sing-box 未运行，跳过本轮探测", space_id)
                return {"space_id": space_id, "error": "sing-box 未运行，跳过探测"}

            rows = self.db.nodes(space_id, include_deleted=False)
            # 把上轮遗留的 retry_pending 也纳入本轮（可能上轮中途超时中断了）
            # 顺序：unknown/cooling 优先（它们最需要判决），其余按 id
            rows = sorted(rows, key=lambda r: (0 if r["state"] in ("unknown", "cooling") else 1, r["id"]))
            retry_once = st.get("probe_retry_failed_once", "true").lower() in ("1", "true", "yes")
            # 同 probe_space：走统一解析入口，保证探测与转发的策略一致。
            ip_strategy = self.db.resolve_ip_strategy(self.db.get_space(space_id))
            # 每轮重新探测一次地址族可用性（网络环境可能变化）
            ProbeRunner.reset_family_cache()
            # （原先这里维护 row_family 映射，但全仓库无人读取 —— 地址族从没落库，
            #  双栈结果白算。现在改用 record_probe 的 used_family 字段显式持久化。）
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
                (ok, delay, err, body_ip, used_fam, ip_v4, ip_v6) = await self.probe_node_both_families(
                    space_id, tag, url, timeout_ms, ip_strategy, with_exit_ip, fallbacks)
                exit_ip = body_ip
                if ok and with_exit_ip and not exit_ip:
                    # 响应体里没解析出 IP 时，退回单独的取 IP 请求
                    exit_ip = await self.fetch_exit_ip(
                        self._port_of(space_id, tag), family=used_fam, st=st)
                self.db.record_probe(
                    row["id"], ok, delay, err, exit_ip, threshold, auto_delete,
                    mark_failed_as=("retry_pending" if phase == "first"
                                    else ("deleted" if auto_delete else "cooling")),
                    exit_ip_v4=ip_v4, exit_ip_v6=ip_v6, used_family=used_fam if ok else None,
                )
                result["probed"] += 1
                result["ok" if ok else "fail"] += 1
                if self._progress:
                    self._progress["done"] = result["probed"]
                    self._progress["ok"] = result["ok"]
                    self._progress["fail"] = result["fail"]
                    self._progress["current"] = row["name"]
                    if phase == "retry":
                        self._progress["retry_done"] = self._progress.get("retry_done", 0) + 1
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
                    self._progress["retry_total"] = len(failed_rows)
                    self._progress["retry_done"] = 0
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
        """当前探测进度快照（给 /api/probe/progress 用）。

        进度口径要注意：重测阶段会**重复探测**第一阶段失败的节点，
        所以累计的 done 会超过第一阶段的总数。之前直接拿
        done/total 算百分比，导致出现 "7/5"、100% 之后还在涨、
        ETA 变成负数这类明显错乱的显示。
        现在把两个阶段的工作量分开算：
          第一阶段总量 = total
          第二阶段总量 = 第一阶段失败的个数（进入重测时才知道）
        """
        p = self._progress
        if not p:
            return None
        elapsed = max(0.001, time.time() - p.get("started_at", time.time()))
        first_total = max(1, p.get("total", 1))
        phase = p.get("phase")
        done_all = p.get("done", 0)

        if phase == "retry":
            retry_total = p.get("retry_total", 0)
            retry_done = p.get("retry_done", 0)
            done = first_total + retry_done          # 累计完成量
            total = first_total + max(retry_total, retry_done)
            phase_done, phase_total = retry_done, retry_total
        else:
            done = min(done_all, first_total)
            total = first_total
            phase_done, phase_total = done, first_total

        total = max(total, done, 1)
        percent = min(100, int(done * 100 / total))
        eta = None
        if not p.get("finished") and done:
            remain = max(0, total - done)
            eta = int(elapsed / done * remain) if remain else 0

        return {**p, "elapsed": int(elapsed), "eta": eta,
                "done": done, "total": total,
                "percent": percent,
                "phase_done": phase_done, "phase_total": phase_total}

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
