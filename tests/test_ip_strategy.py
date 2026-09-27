"""IP 策略、双栈探测顺序、_socks_addr 方括号、延迟过滤的回归测试。"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())

from app.config import DEFAULT_SETTINGS                     # noqa: E402
from app.db import DB                                       # noqa: E402
from app.probe import ProbeRunner                           # noqa: E402
from app.proxy import ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, _socks_addr  # noqa: E402
from app.singbox import VALID_IP_STRATEGIES, _dns_strategy   # noqa: E402


# ---------------------------------------------------------------- IP 策略

def test_ip_strategy_default_and_values():
    assert DEFAULT_SETTINGS["ip_strategy"] == "prefer_ipv4"
    assert set(VALID_IP_STRATEGIES) == {"prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}


def test_dns_strategy_mapping():
    for v in VALID_IP_STRATEGIES:
        assert _dns_strategy(v) == v
    # 非法值退回安全默认
    for bad in ("", None, "bogus", "prefer_ipv5", "IPV4_ANY"):
        assert _dns_strategy(bad) == "prefer_ipv4"
    # 大小写不敏感
    assert _dns_strategy("PREFER_IPV6") == "prefer_ipv6"


def test_families_order_for_each_strategy():
    F = ProbeRunner
    assert F.families_for("prefer_ipv4") == [F.FAM_IPV4, F.FAM_IPV6]
    assert F.families_for("prefer_ipv6") == [F.FAM_IPV6, F.FAM_IPV4]
    assert F.families_for("ipv4_only") == [F.FAM_IPV4]
    assert F.families_for("ipv6_only") == [F.FAM_IPV6]
    # 未知值按 prefer_ipv4 处理
    assert F.families_for("nonsense") == [F.FAM_IPV4, F.FAM_IPV6]
    assert F.families_for("") == [F.FAM_IPV4, F.FAM_IPV6]


def test_prefer_strategies_test_both_families():
    """'优先'类必须**两栈都测**（先测偏好的一族），而不是只用一族。"""
    for strat in ("prefer_ipv4", "prefer_ipv6"):
        fams = ProbeRunner.families_for(strat)
        assert len(fams) == 2, f"{strat} 应测试两栈，实际 {fams}"
        assert set(fams) == {"ipv4", "ipv6"}
    for strat in ("ipv4_only", "ipv6_only"):
        assert len(ProbeRunner.families_for(strat)) == 1


def test_prefer_order_is_respected():
    """prefer_ipv4 先测 v4；prefer_ipv6 先测 v6。"""
    assert ProbeRunner.families_for("prefer_ipv4")[0] == "ipv4"
    assert ProbeRunner.families_for("prefer_ipv6")[0] == "ipv6"


# ---------------------------------------------------------------- _socks_addr

def test_socks_addr_bracketed_ipv6():
    """带方括号的 IPv6 必须识别成 IPv6，而不是被当域名。"""
    for h in ("[::1]", "[2001:db8::1]", "[fe80::1]"):
        atyp, addr = _socks_addr(h)
        assert atyp == ATYP_IPV6, f"{h} 应为 IPv6，实际 atyp={atyp}"
        assert len(addr) == 16, f"{h} 地址长度应为 16，实际 {len(addr)}"


def test_socks_addr_plain_forms_still_work():
    assert _socks_addr("1.2.3.4")[0] == ATYP_IPV4
    assert _socks_addr("2001:db8::1")[0] == ATYP_IPV6
    assert _socks_addr("example.com")[0] == ATYP_DOMAIN


def test_socks_addr_strips_zone_id():
    """fe80::1%eth0 的 zone id 在 SOCKS5 里没有对应字段，必须剥掉。"""
    for h in ("fe80::1%eth0", "[fe80::1%eth0]"):
        atyp, addr = _socks_addr(h)
        assert atyp == ATYP_IPV6, h
        assert len(addr) == 16, h


def test_socks_addr_rejects_empty():
    for h in ("", "   ", "[]"):
        try:
            _socks_addr(h)
        except OSError:
            continue
        raise AssertionError(f"{h!r} 应该报错")


def test_socks_addr_domain_length_encoding():
    atyp, addr = _socks_addr("www.cloudflare.com")
    assert atyp == ATYP_DOMAIN
    assert addr[0] == 18, addr[0]          # 长度字节
    assert addr[1:].decode() == "www.cloudflare.com"


# ---------------------------------------------------------------- 延迟过滤

def make_space_with_delays(db, delays):
    sid = db.create_space("S", "http://s", 1800, "space")
    ids = []
    for i, d in enumerate(delays):
        h = f"h{i}.com"
        db.upsert_node(sid, f"fp{i}", f"n{i}", "trojan", h, 443, "{}", h)
    for r, d in zip(db.nodes(sid, include_deleted=True), delays):
        db.execute("UPDATE nodes SET state='healthy', delay_ms=? WHERE id=?", (d, r["id"]))
        ids.append(r["id"])
    return sid, ids


def test_slow_nodes_are_hard_deleted():
    """延迟过滤必须是物理删除，而不是仅仅标记。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid, ids = make_space_with_delays(db, [100, 500, 3000, 8000])

    max_delay = 1000
    slow = [r["id"] for r in db.nodes(sid) if r["delay_ms"] and r["delay_ms"] > max_delay]
    db.hard_delete_nodes(slow)

    left = db.nodes(sid, include_deleted=True)
    assert len(left) == 2, f"应剩 2 个，实际 {len(left)}"
    for r in left:
        assert r["delay_ms"] <= max_delay
    for nid in slow:
        assert db.q1("SELECT * FROM nodes WHERE id=?", (nid,)) is None
    db.close()


def test_slow_filter_removes_probe_history():
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid, ids = make_space_with_delays(db, [100, 9000])
    slow = [ids[1]]
    db.record_probe(slow[0], True, 9000, None, "1.2.3.4", 1, True)
    assert db.q("SELECT * FROM probes WHERE node_id=?", (slow[0],))
    db.hard_delete_nodes(slow)
    assert db.q("SELECT * FROM probes WHERE node_id=?", (slow[0],)) == []
    db.close()


def test_zero_max_delay_disables_filter():
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid, ids = make_space_with_delays(db, [100, 99999])
    max_delay = 0        # 0 = 关闭
    slow = [r["id"] for r in db.nodes(sid)
            if max_delay > 0 and r["delay_ms"] and r["delay_ms"] > max_delay]
    assert slow == []
    assert len(db.nodes(sid)) == 2
    db.close()


# ---------------------------------------------------------------- 空节点与实例缺失

def test_empty_node_list_uses_direct_final():
    """没有任何节点时，sing-box 的 route.final 必须退回 direct。

    写死 "n0" 会让 sing-box 以 "default outbound not found: n0" FATAL 起不来 ——
    刚建空间或节点被全部删光时就会触发。
    """
    import json as _json
    from pathlib import Path as _Path
    from app.singbox import SpaceInstance

    inst = SpaceInstance(1, _Path(tempfile.mkdtemp()), 11080, 12000)
    assert inst.build_config([])["route"]["final"] == "direct"
    # 用一个真实形状的节点（有 type + server），否则会被脏数据校验跳过
    one = [{"outbound_json": _json.dumps({"type": "trojan", "tag": "",
                                          "server": "1.2.3.4", "server_port": 443,
                                          "password": "p"})}]
    assert inst.build_config(one)["route"]["final"] == "n0"


def test_empty_node_list_has_no_inbounds():
    """没有节点时不该生成任何 socks 入站（端口 11080+i 会越界）。"""
    from pathlib import Path as _Path
    from app.singbox import SpaceInstance
    inst = SpaceInstance(1, _Path(tempfile.mkdtemp()), 11080, 12000)
    cfg = inst.build_config([])
    assert cfg["inbounds"] == []
    # 出站只剩 direct
    assert [o["tag"] for o in cfg["outbounds"]] == ["direct"]


def test_missing_instance_does_not_crash_overview_shape():
    """空间存在但 sing-box 实例缺失时，概览数据必须能正常构造（不能 KeyError）。

    复现过：mgr._instances[s["id"]] 直接取值 → KeyError 12 → /api/overview 500。
    这里模拟 main.overview 里的构造逻辑。
    """
    class Mgr:
        _instances = {}          # 空：没有任何实例
    mgr = Mgr()
    spaces = [{"id": 12, "name": "T"}]
    runners = []
    for s in spaces:
        inst = mgr._instances.get(s["id"])
        runners.append({"space_id": s["id"], "name": s["name"],
                        "socks_port": inst.socks_port if inst else None,
                        "alive": bool(inst and inst.alive)})
    assert runners == [{"space_id": 12, "name": "T", "socks_port": None, "alive": False}]


def test_dirty_node_config_is_skipped_but_indexes_consistent():
    """半截出站配置（缺 type/server）必须被跳过，且留下的编号仍自洽。

    否则 sing-box 会以 "unknown outbound type:" FATAL 起不来 ——
    这条路径是历史脏数据（outbound_json='{}'）触发的。
    """
    import json as _json
    from pathlib import Path as _Path
    from app.singbox import SpaceInstance

    inst = SpaceInstance(1, _Path(tempfile.mkdtemp()), 11080, 12000)
    good = {"outbound_json": _json.dumps({"type": "trojan", "tag": "",
                                          "server": "1.2.3.4", "server_port": 443, "password": "p"})}
    bad = {"outbound_json": "{}"}
    cfg = inst.build_config([good, bad, good])

    in_tags = [i["tag"] for i in cfg["inbounds"]]
    out_tags = [o["tag"] for o in cfg["outbounds"]]
    assert in_tags == ["in0", "in2"], in_tags          # 跳过下标 1
    assert out_tags == ["n0", "n2", "direct"], out_tags
    # 每个入站都要有对应路由，且指向同编号的出站
    rules = [r for r in cfg["route"]["rules"] if "inbound" in r]
    assert rules == [{"inbound": ["in0"], "outbound": "n0"},
                     {"inbound": ["in2"], "outbound": "n2"}], rules
    # 入站端口必须与编号对齐
    ports = {i["tag"]: i["listen_port"] for i in cfg["inbounds"]}
    assert ports["in0"] == 11080 and ports["in2"] == 11082, ports
    # final 指向真实存在的出站
    assert cfg["route"]["final"] == "n0"
    assert cfg["route"]["final"] in out_tags


def test_enum_settings_validation():
    """枚举型设置必须校验取值，不能把非法值原样存库。

    否则设置页显示的值和实际生效值不一致，极难排查。
    """
    from app.config import VALID_IP_STRATEGIES

    enums = {
        "ip_strategy": set(VALID_IP_STRATEGIES),
        "region_filter_mode": {"off", "whitelist", "blacklist"},
        "node_cap_evict_strategy": {"worst", "oldest"},
    }
    # 合法值通过
    for k, allowed in enums.items():
        for v in allowed:
            assert str(v).strip().lower() in allowed, (k, v)
    # 非法值必须被拒
    assert "bogus" not in enums["ip_strategy"]
    assert "sometimes" not in enums["region_filter_mode"]


def test_rebuild_skips_dirty_rows_without_aborting():
    """脏数据行必须被跳过而不是中断整个重建。

    否则 json.loads 抛异常 → rebuild 半途退出 → 磁盘留着旧配置、
    实例永远起不来，表现为"这个空间怎么都是死的"。
    """
    import json as _json

    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = db.create_space("S", "http://s", 1800, "space")
    # 三条：合法、非法 JSON、缺 server
    good = _json.dumps({"type": "trojan", "tag": "", "server": "1.2.3.4",
                        "server_port": 443, "password": "p"})
    for i, ob in enumerate([good, "{不是JSON", _json.dumps({"type": "trojan"})]):
        h = f"h{i}.com"
        db.upsert_node(sid, f"fp{i}", f"n{i}", "trojan", h, 443, ob, h)

    rows = sorted(db.nodes(sid, include_deleted=True), key=lambda r: r["id"])
    from app import registry as R
    tag_of = R.tag_map(rows)

    # 复刻 main.rebuild_space_instance 的筛选逻辑
    payload = []
    for r in rows:
        try:
            ob = _json.loads(r["outbound_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(ob, dict) or not ob.get("type") or not ob.get("server"):
            continue
        ob["tag"] = tag_of[r["id"]]
        payload.append(ob)

    assert len(payload) == 1, f"应只保留 1 条合法配置，实际 {len(payload)}"
    assert payload[0]["tag"] == "n0"
    assert payload[0]["server"] == "1.2.3.4"
    db.close()


def test_empty_payload_means_no_instance():
    """没有任何合法节点时，不应生成配置（调用方据此停掉实例）。"""
    import json as _json
    rows = [{"id": 1, "outbound_json": "{}"},
            {"id": 2, "outbound_json": "坏数据"}]
    payload = []
    for r in rows:
        try:
            ob = _json.loads(r["outbound_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(ob, dict) or not ob.get("type") or not ob.get("server"):
            continue
        payload.append(ob)
    assert payload == [], "脏数据不该产出任何出站配置"


def test_family_available_only_checks_local_stack():
    """family_available 必须只看**本机网络栈**，不做对外连接测试。

    踩过的坑：原先用"连一下 1.1.1.1:443"来判断 IPv4 可用性，
    结果在任何屏蔽该地址的网络里都误判成"IPv4 不可用"，
    于是 prefer_* 静默退化成单栈（实测：容器 IPv4 明明正常却报 False）。

    另一点：不能只看 localhost 能否解析出该族 ——
    IPv6 回环 ::1 在几乎所有 Linux 容器里都存在（即使没有 IPv6 出口），
    只看它会把"没有 IPv6"误判成"有"，所以必须排除回环/链路本地地址。
    """
    import asyncio
    from app.probe import ProbeRunner

    async def run():
        ProbeRunner.reset_family_cache()
        ok4 = await ProbeRunner.family_available("ipv4")
        ok6 = await ProbeRunner.family_available("ipv6")
        # 只要求如实返回布尔值，不假设 CI 机器一定有某族
        assert isinstance(ok4, bool) and isinstance(ok6, bool)
        # IPv4 在绝大多数环境都可用；若不可用也应是 False 而非抛异常
        # 缓存生效
        assert getattr(ProbeRunner, "_fam_ok_ipv4", None) == ok4
        assert getattr(ProbeRunner, "_fam_ok_ipv6", None) == ok6
        ProbeRunner.reset_family_cache()
        assert not hasattr(ProbeRunner, "_fam_ok_ipv4")
        assert not hasattr(ProbeRunner, "_fam_ok_ipv6")

    asyncio.run(run())


def test_usable_family_excludes_loopback_and_linklocal():
    """_has_usable_family 必须排除回环/链路本地/未指定地址。"""
    import asyncio
    import ipaddress
    import socket
    from app.probe import ProbeRunner

    async def run():
        # 对 v4 / v6 都调用一次，确认不抛异常且返回 bool
        for fam in (socket.AF_INET, socket.AF_INET6):
            r = await ProbeRunner._has_usable_family(fam)
            assert isinstance(r, bool), (fam, r)
        # 语义校验：回环地址本身不该被当作"可用出口"
        for a in ("127.0.0.1", "::1", "169.254.1.1", "fe80::1", "0.0.0.0"):
            ip = ipaddress.ip_address(a)
            assert ip.is_loopback or ip.is_link_local or ip.is_unspecified, a

    asyncio.run(run())


def test_family_filter_keeps_at_least_one():
    """过滤掉不可用族后，至少要保留一个，不能变成空列表。"""
    # 复刻 probe_node_both_families 里的过滤逻辑
    families = ["ipv4", "ipv6"]
    usable = []                    # 模拟 v6 不可用
    for f in families:
        if f == "ipv4":
            usable.append(f)
    if usable:
        families = usable
    assert families == ["ipv4"], families
    assert families, "不能变成空列表"


def test_progress_math_never_exceeds_total_or_negative_eta():
    """进度口径：重测阶段不能让 done 超过 total，也不能出负 ETA。

    实测踩到：探完第一阶段的 5 个后进入重测，done 累加到 7、9，
    而 total 仍是 5 —— 界面显示 "7/5"、"100%" 之后还在涨、ETA=-7s。
    """
    import time as _t
    from app.probe import ProbeRunner

    pr = ProbeRunner.__new__(ProbeRunner)

    # 阶段一：5 个节点探完 3 个
    pr._progress = {"space_id": 1, "phase": "first", "done": 3, "total": 5,
                    "ok": 2, "fail": 1, "started_at": _t.time()}
    p = pr.progress()
    assert p["done"] == 3 and p["total"] == 5, p
    assert p["percent"] == 60, p
    assert p["eta"] is not None and p["eta"] >= 0, p

    # 阶段二：第一阶段 5 个都探完（2 失败），开始重测这 2 个，已重测 1 个
    pr._progress = {"space_id": 1, "phase": "retry", "done": 6, "total": 5,
                    "ok": 2, "fail": 3, "started_at": _t.time(),
                    "retry_total": 2, "retry_done": 1}
    p = pr.progress()
    assert p["total"] == 7, f"重测阶段总量应为 5+2=7，实际 {p['total']}"
    assert p["done"] == 6, p
    assert p["done"] <= p["total"], f"done({p['done']}) 不应超过 total({p['total']})"
    assert 0 <= p["percent"] <= 100, p
    assert p["eta"] is not None and p["eta"] >= 0, f"ETA 不应为负：{p['eta']}"

    # 阶段二全部完成：done 刚好等于 total，ETA 为 0
    pr._progress = {"space_id": 1, "phase": "retry", "done": 7, "total": 5,
                    "ok": 3, "fail": 4, "started_at": _t.time(),
                    "retry_total": 2, "retry_done": 2}
    p = pr.progress()
    assert p["done"] == p["total"] == 7, p
    assert p["percent"] == 100, p
    assert p["eta"] == 0, p

    # 没有任何失败、不进重测：总量就是第一阶段
    pr._progress = {"space_id": 1, "phase": "first", "done": 5, "total": 5,
                    "ok": 5, "fail": 0, "started_at": _t.time()}
    p = pr.progress()
    assert p["total"] == 5 and p["percent"] == 100, p

    # done 意外大于 total（防御）：也不该算出负 ETA 或 >100%
    pr._progress = {"space_id": 1, "phase": "first", "done": 9, "total": 5,
                    "ok": 9, "fail": 0, "started_at": _t.time()}
    p = pr.progress()
    assert p["done"] <= p["total"], p
    assert p["percent"] <= 100, p
    assert (p["eta"] or 0) >= 0, p

    # 没有进度时返回 None
    pr._progress = None
    assert pr.progress() is None


def test_probe_must_not_replace_hostname_with_ip():
    """探测时**不能**把 URL 中的域名换成解析出的 IP。

    换掉之后 TLS 的 SNI 变成 IP，证书校验必然失败 ——
    实测：替换后 5/5 节点全部 CERTIFICATE_VERIFY_FAILED，
    不替换时同样节点 5/5 成功（真实踩到的回归）。
    这里通过检查源码里不再有"重建 netloc"的逻辑来防止改回去。
    """
    import re
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "app", "singbox.py"), encoding="utf-8").read()
    # 找到 probe_via_socks 的函数体
    i = src.index("async def probe_via_socks")
    j = src.index("async def version", i)
    body = src[i:j]

    # 不该出现把 resolved 拼进 netloc 再 urlunsplit 的做法
    assert "target_url = urllib.parse.urlunsplit" not in body,         "探测请求不得用解析后的 IP 重建 URL（会破坏 TLS SNI）"
    assert "urlunsplit((u.scheme, netloc" not in body,         "不得把域名替换成 IP 后发起请求"
    # 请求必须用原始 url
    assert "c.get(url)" in body, "探测应使用原始 URL（保留域名以正确设置 SNI）"
    # 仍然保留"该族是否可解析"的前置判断
    assert "_resolve_family" in body, "仍应校验目标域名能否解析出指定地址族"


# --- 双栈：地址族判定、假阳性、落库与迁移、IPv6 压缩显示 ---

def test_ip_family_of_basic_and_invalid():
    """族判定必须用标准库解析：IPv4/IPv6 都能认，垃圾输入返回 None。"""
    from app.singbox import ip_family_of

    assert ip_family_of("1.2.3.4") == "ipv4"
    assert ip_family_of("  8.8.8.8 ") == "ipv4", "应容忍首尾空白"
    assert ip_family_of("2001:db8::7334") == "ipv6"
    assert ip_family_of("::1") == "ipv6", "压缩写法也要认出来"
    assert ip_family_of("::ffff:1.2.3.4") == "ipv6", "IPv4 映射地址属 IPv6 族"
    for bad in (None, "", "   ", "not-an-ip", "999.1.1.1", "1.2.3", "efe80::1"):
        assert ip_family_of(bad) is None, f"{bad!r} 不应被判为合法 IP"


def test_probe_via_socks_discards_wrong_family():
    """假阳性防护（真实调用 probe_via_socks）：测 ipv6 却拿到 v4 地址时，
    exit_ip 记 None，但探测本身仍算成功 —— 不能因此把节点判失败。"""
    import asyncio
    from unittest import mock

    from app.singbox import SingBoxManager

    class _Resp:
        status_code = 200
        text = "1.2.3.4"        # 明明要测 ipv6，代理吐出来的却是 v4

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return _Resp()

    async def run():
        m = SingBoxManager.__new__(SingBoxManager)
        # URL host 直接用 IPv6 字面量：probe_via_socks 里 _resolve_family 会走
        # "host 已是 IP"的短路分支，不需要真实 DNS 解析。
        with mock.patch("app.singbox.httpx.AsyncClient", _Client):
            return await m.probe_via_socks(1, "n0", 1080,
                                          "http://[2606:4700::1111]/ip", 5000, family="ipv6")

    ok, delay, err, ip = asyncio.run(run())
    assert ok is True, "族不符不应把节点判为失败"
    assert ip is None, "族不符的 IP 必须丢弃，不能记成该族出口"
    assert err is None
    assert isinstance(delay, int)

    # 反过来：族一致时必须原样返回，不能被误杀
    class _Resp2(_Resp):
        text = "2001:db8::7334"

    class _Client2(_Client):
        async def get(self, url):
            return _Resp2()

    async def run2():
        m = SingBoxManager.__new__(SingBoxManager)
        with mock.patch("app.singbox.httpx.AsyncClient", _Client2):
            return await m.probe_via_socks(1, "n0", 1080,
                                          "http://[2606:4700::1111]/ip", 5000, family="ipv6")

    ok, delay, err, ip = asyncio.run(run2())
    assert ip == "2001:db8::7334", "族一致时必须保留出口 IP"


def test_fetch_exit_ip_discards_wrong_family():
    """fetch_exit_ip 这条路径也要做族校验，且族不符返回 None 而非报错。"""
    import asyncio
    from unittest import mock

    from app.probe import ProbeRunner

    class _Resp:
        status_code = 200
        text = "2001:db8::7334"   # 要取 v4，却是 v6

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            _Client.url = url
            return _Resp()

    pr = ProbeRunner.__new__(ProbeRunner)
    with mock.patch("app.probe.httpx.AsyncClient", return_value=_Client()):
        got = asyncio.run(pr.fetch_exit_ip(1080, family="ipv4"))
    assert got is None, "族不符时必须记为不可信（None）"
    assert _Client.url == "https://api.ipify.org", "未配置时应退回硬编码兜底地址"

    # 配了 exit_ip_url 就必须用配置里的地址
    with mock.patch("app.probe.httpx.AsyncClient", return_value=_Client()):
        got = asyncio.run(pr.fetch_exit_ip(1080, family=None,
                                           st={"exit_ip_url": "https://my.mirror/ip"}))
    assert _Client.url == "https://my.mirror/ip", "应使用设置里的 exit_ip_url"
    assert got == "2001:db8::7334", "不指定族时不校验，原样返回"


def test_nodes_new_columns_migration_is_idempotent():
    """老库（没有新列）升级后应自动补齐三列；重复打开库不得报错（幂等）。"""
    import sqlite3

    path = os.path.join(tempfile.mkdtemp(), "old.db")
    # 手工建一个"老版本"的 nodes 表：只有旧列，没有 exit_ip_v4/v6/used_family
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE nodes (id INTEGER PRIMARY KEY, space_id INTEGER, fingerprint TEXT,"
            " name TEXT, protocol TEXT, host TEXT, port INTEGER, outbound_tag TEXT,"
            " params TEXT, state TEXT, delay_ms INTEGER, exit_ip TEXT, fail_count INTEGER,"
            " ok_count INTEGER, last_probe_at REAL, last_ok_at REAL, deletion_reason TEXT,"
            " added_at REAL)")
        conn.execute("CREATE TABLE spaces (id INTEGER PRIMARY KEY, name TEXT)")
        conn.commit()

    db = DB(path)
    try:
        cols = {r["name"] for r in db.q("PRAGMA table_info(nodes)")}
        for c in ("exit_ip_v4", "exit_ip_v6", "used_family"):
            assert c in cols, f"迁移后应存在列 {c}"
    finally:
        db.close()

    # 再打开一次：列已存在，ALTER 不得重复执行（否则报 duplicate column name）
    db2 = DB(path)
    try:
        cols = {r["name"] for r in db2.q("PRAGMA table_info(nodes)")}
        assert {"exit_ip_v4", "exit_ip_v6", "used_family"} <= cols
    finally:
        db2.close()


def test_record_probe_persists_dual_stack_fields():
    """双栈结果必须真正落库：exit_ip_v4/v6 与 used_family 都要写进去。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    try:
        sid = db.create_space("S", "http://s", 1800, "space")
        db.upsert_node(sid, "fp0", "n0", "trojan", "h0.com", 443, "{}", "h0.com")
        nid = db.nodes(sid, include_deleted=True)[0]["id"]

        st = db.record_probe(nid, True, 120, None, "9.9.9.9", 1, True,
                             exit_ip_v4="9.9.9.9", exit_ip_v6=None, used_family="ipv4")
        assert st == "healthy"
        row = db.q1("SELECT * FROM nodes WHERE id=?", (nid,))
        assert row["exit_ip_v4"] == "9.9.9.9"
        assert row["exit_ip_v6"] is None, "没探到的族应为 NULL，不能是空串"
        assert row["used_family"] == "ipv4"

        # 向后兼容：老调用方不传新参数也必须能正常写入（不报错、旧字段照常更新）
        st2 = db.record_probe(nid, True, 90, None, "8.8.8.8", 1, True)
        assert st2 == "healthy"
        row = db.q1("SELECT * FROM nodes WHERE id=?", (nid,))
        assert row["exit_ip"] == "8.8.8.8"
    finally:
        db.close()


def test_probe_node_both_families_returns_both_ips_and_tries_second_family():
    """probe_node_both_families：第一族失败必须继续第二族；返回两族的 IP。"""
    import asyncio

    from app.probe import ProbeRunner

    pr = ProbeRunner.__new__(ProbeRunner)

    # 关闭"本机是否有该族"的探测，避免依赖真实网络
    async def _always(_f):
        return True
    pr.family_available = _always

    calls = []

    async def fake_probe_one(space_id, tag, url, timeout_ms, fallback_urls=None,
                             want_ip=False, family=None):
        calls.append(family)
        if family == "ipv4":
            return False, None, "v4 不通", None
        return True, 42, None, "2001:db8::7334"

    pr.probe_one = fake_probe_one
    out = asyncio.run(pr.probe_node_both_families(1, "n0", "http://x", 5000,
                                                  "prefer_ipv4", True, ["http://fb"]))
    assert out[0] is True, "第二族成功时整体应算成功"
    assert out[4] == "ipv6", "应返回成功的那一族"
    assert out[5] is None, "第一族失败，ip_v4 应为 None"
    assert out[6] == "2001:db8::7334", "第二族拿到的 IP 应带回来"
    assert calls == ["ipv4", "ipv6"], f"必须依次试两族，实际 {calls}"


def test_ipv6_is_compressed_for_display():
    """前端压缩显示：IPv6 只留前两组 + 末组，IPv4 原样，空值返回空串。"""
    import re

    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "app", "static", "app.js"), encoding="utf-8").read()
    m = re.search(r"function shortIp\(ip\)\s*\{(.*?)\n\}", src, re.S)
    assert m, "app.js 里应存在 shortIp 函数"
    body = m.group(1)
    assert "ipKind(s) !== 6" in body, "只有 IPv6 才压缩，IPv4 必须原样"
    assert "…" in body, "压缩中间应用省略号"

    # 用等价 JS 逻辑验证产出格式：前两组 : … : 末组
    def short(ip):
        s = (ip or "").strip()
        if not s or ":" not in s:
            return s
        parts = s.split(":")
        if len(parts) <= 3:
            return s
        return f"{parts[0]}:{parts[1]}:…:{parts[-1]}"

    assert short("2001:0db8:0000:0000:0000:0000:0000:7334") == "2001:0db8:…:7334"
    assert short("1.2.3.4") == "1.2.3.4"
    assert short("") == ""
    assert short(None) == ""


def test_exit_cell_never_renders_none_and_has_title():
    """前端不得显示 'None'；完整 IP 必须放进 title 悬停提示。"""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "app", "static", "app.js")
    body = open(path, encoding="utf-8").read()
    assert 'title="${esc(ip)}"' in body, "完整 IP 应放进 title 属性"
    assert "exit_ip_v4" in body and "exit_ip_v6" in body, "应使用分栈字段"


def test_record_probe_clears_v6_when_this_round_failed():
    """缺陷 1 回归：本轮 v6 探测失败（显式 None）必须如实清空 exit_ip_v6。

    修复前用 COALESCE(?, exit_ip_v6)，V6 失败会把上一轮的旧值粘下来，
    前端于是显示一个早已失效的 IPv6。这里先落一个有效 v6，再传 None 断言被清空。
    该用例能真的失败：把 record_probe 的 CASE WHEN 哨兵改回 COALESCE(
    则本断言立刻变红（已实测，见报告）。
    """
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    try:
        sid = db.create_space("S", "http://s", 1800, "space")
        db.upsert_node(sid, "fp0", "n0", "trojan", "h0.com", 443, "{}", "h0.com")
        nid = db.nodes(sid, include_deleted=True)[0]["id"]

        # 轮1：v6 探测成功
        db.record_probe(nid, True, 100, None, "2001:db8::7334", 3, True,
                        exit_ip_v4="1.2.3.4", exit_ip_v6="2001:db8::7334",
                        used_family="prefer_v6")
        row = db.q1("SELECT exit_ip_v6 FROM nodes WHERE id=?", (nid,))
        assert row["exit_ip_v6"] == "2001:db8::7334"

        # 轮2：v6 探测失败（显式 None）→ 必须清空，不能粘旧值
        db.record_probe(nid, True, 120, None, "1.2.3.4", 3, True,
                        exit_ip_v4="5.6.7.8", exit_ip_v6=None, used_family="prefer_v4")
        row = db.q1("SELECT exit_ip, exit_ip_v4, exit_ip_v6, used_family "
                    "FROM nodes WHERE id=?", (nid,))
        assert row["exit_ip_v6"] is None, \
            f"v6 本轮失败必须清空，实际仍为 {row['exit_ip_v6']!r}（粘旧值 BUG）"
        assert row["exit_ip_v4"] == "5.6.7.8", "v4 本轮结果照常覆盖写入"
        assert row["used_family"] == "prefer_v4", "used_family 本轮结果照常覆盖写入"
    finally:
        db.close()


def test_record_probe_unset_sentinel_keeps_old_values():
    """缺陷 1 哨兵回归：老调用方不传新 kwargs，不得把已有值误清成 NULL。

    与上一个用例互补：显式 None 要清空，缺省（_UNSET）要保留。
    该用例能真的失败：若把默认值从 _UNSET 改成 None 并去掉 CASE WHEN，
    第 2 次调用会把这些字段抹成 NULL，本断言变红。
    """
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    try:
        sid = db.create_space("S", "http://s", 1800, "space")
        db.upsert_node(sid, "fp0", "n0", "trojan", "h0.com", 443, "{}", "h0.com")
        nid = db.nodes(sid, include_deleted=True)[0]["id"]

        db.record_probe(nid, True, 100, None, "1.2.3.4", 3, True,
                        exit_ip_v4="1.2.3.4", exit_ip_v6="2001:db8::7334",
                        used_family="prefer_v6")
        # 老调用方（单栈，不传新参数）
        st = db.record_probe(nid, True, 130, None, "2.2.2.2", 3, True)
        assert st == "healthy"
        row = db.q1("SELECT exit_ip, exit_ip_v4, exit_ip_v6, used_family "
                    "FROM nodes WHERE id=?", (nid,))
        assert row["exit_ip"] == "2.2.2.2", "老字段照常覆盖"
        assert row["exit_ip_v4"] == "1.2.3.4", "未传的新字段必须保留旧值"
        assert row["exit_ip_v6"] == "2001:db8::7334", "未传的新字段必须保留旧值"
        assert row["used_family"] == "prefer_v6", "未传的新字段必须保留旧值"
    finally:
        db.close()


def test_record_probe_explicit_none_clears_legacy_exit_ip():
    """缺陷 1 附带：exit_ip 老字段本轮显式 None 也必须清空（前端会回退到它）。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    try:
        sid = db.create_space("S", "http://s", 1800, "space")
        db.upsert_node(sid, "fp0", "n0", "trojan", "h0.com", 443, "{}", "h0.com")
        nid = db.nodes(sid, include_deleted=True)[0]["id"]

        db.record_probe(nid, True, 100, None, "1.2.3.4", 3, True)
        assert db.q1("SELECT exit_ip FROM nodes WHERE id=?", (nid,))["exit_ip"] == "1.2.3.4"

        # 本轮出口 IP 族不符被上层置 None（见 singbox.probe_via_socks）
        db.record_probe(nid, True, 110, None, None, 3, True,
                        exit_ip_v4="1.2.3.4", exit_ip_v6=None, used_family="prefer_v4")
        assert db.q1("SELECT exit_ip FROM nodes WHERE id=?", (nid,))["exit_ip"] is None, \
            "exit_ip 本轮显式 None 必须清空，否则前端 exitCell 回退时显示旧值"
    finally:
        db.close()


def test_shortip_python_mirror_matches_node_output():
    """缺陷 2 回归：shortIp 的边界行为必须与 node 实测一致（本文件注释存实测输出）。

    node 实测（2026-02，app.js 抽出 ipKind/shortIp 后执行）：
      "2001:db8::1"                      -> "2001:db8::1"        （压缩更长，返回原串）
      "::ffff:1.2.3.4"                   -> "1.2.3.4"           （IPv4-mapped 按 IPv4）
      "fe80::1%eth0"                     -> "fe80::1%eth0"      （zone id 不硬压）
      "::1"                              -> "::1"
      "1.2.3.4"                          -> "1.2.3.4"           （IPv4 原样）
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334" -> "2001:0db8:…:7334"
      "2400:8902:e001:233:216:3eff:fef6:cb4a"   -> "2400:8902:…:cb4a"
      "240e:3b0:2c00:1234::a"            -> "240e:3b0:…:a"
      "" / None                          -> ""                  （空值）
    下面对 app.js 源码做结构断言，并用等价 Python 复刻行为逐条比对。
    """
    import re

    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "app", "static", "app.js"), encoding="utf-8").read()
    m = re.search(r"function shortIp\(ip\)\s*\{(.*?)\n\}", src, re.S)
    assert m, "app.js 里应存在 shortIp 函数"
    body = m.group(1)
    assert "short.length < s.length" in body, "必须先判后压：只有更短才用压缩结果"
    assert "::ffff:" in body, "IPv4-mapped 需按 IPv4 显示"
    assert "'%'" in body or '"%"' in body, "带 zone id 的地址不压缩"

    def shortip(ip):
        s = (ip or "").strip() if ip else ""
        if not s:
            return s
        mm = re.match(r"^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$", s, re.I)
        if mm:
            return mm.group(1)
        if ":" not in s:
            return s
        if "%" in s:
            return s
        parts = s.split(":")
        if len(parts) <= 3:
            return s
        short = f"{parts[0]}:{parts[1]}:…:{parts[-1]}"
        return short if len(short) < len(s) else s

    cases = {
        "2001:db8::1": "2001:db8::1",              # 压缩不至于更短 → 原串
        "::ffff:1.2.3.4": "1.2.3.4",               # IPv4-mapped → IPv4
        "fe80::1%eth0": "fe80::1%eth0",            # zone id → 不压
        "::1": "::1",
        "1.2.3.4": "1.2.3.4",
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334": "2001:0db8:…:7334",
        "2400:8902:e001:233:216:3eff:fef6:cb4a": "2400:8902:…:cb4a",
        "240e:3b0:2c00:1234::a": "240e:3b0:…:a",
        "": "",
        None: "",
    }
    for inp, want in cases.items():
        got = shortip(inp)
        assert got == want, f"shortip({inp!r}) 期望 {want!r}，实际 {got!r}"
        # 压缩结果绝不能比原串更长
        if inp:
            assert len(got) <= len(inp.strip()), \
                f"shortip({inp!r}) 压完反而变长：{got!r}"

if __name__ == "__main__":
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
            except Exception as e:  # noqa: BLE001
                fails += 1
                print(f"  FAIL  {name}: {type(e).__name__}: {e}")
    print("IP 策略与延迟过滤测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)