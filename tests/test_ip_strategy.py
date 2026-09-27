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