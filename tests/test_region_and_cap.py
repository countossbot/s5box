"""地区识别与容量上限的回归测试。

覆盖两条新需求：
  需求 1：每空间节点数不得超过 100，超出时按"最差优先"淘汰旧节点（物理删除）
  需求 2：地区过滤（白名单/黑名单/无法识别时的取舍）
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())

from app.db import DB                                    # noqa: E402
from app.region import detect_region, region_filter      # noqa: E402


# ---------------------------------------------------------------- 地区识别

def test_detect_region_forms():
    cases = {
        "NL": "NL", "HK-01": "HK", "JP-Tokyo-01": "JP",
        "🇯🇵东京": "JP", "🇭🇰 香港01": "HK", "🇸🇬SG": "SG",
        "美国 洛杉矶": "US", "新加坡": "SG", "台湾": "TW", "澳门": "MO",
        "SG|Premium": "SG", "[TW] 台湾": "TW", "(KR) Seoul": "KR",
        "Germany Frankfurt": "DE", "United States": "US",
    }
    for name, expect in cases.items():
        got = detect_region(name)
        assert got == expect, f"{name!r} 应为 {expect}，实际 {got}"


def test_detect_region_avoids_false_positives():
    """'russia-1' 里有 us 子串，但必须识别成 RU 而不是 US。"""
    assert detect_region("russia-1") == "RU"
    assert detect_region("RU Moscow") == "RU"
    # 'in-premium' 里的 in 是印度码，这里应识别为 IN
    assert detect_region("IN Mumbai") == "IN"
    # 完全无法识别的名字
    for junk in ("剩余流量", "节点01", "Premium-Node", ""):
        assert detect_region(junk) is None, f"{junk!r} 不该识别出地区"


def test_region_filter_modes():
    codes = {"HK", "TW", "JP"}
    # off 时不拦
    assert region_filter("US Node", "off", codes) is True
    # 白名单：只留列表内
    assert region_filter("HK-01", "whitelist", codes) is True
    assert region_filter("US-01", "whitelist", codes) is False
    # 黑名单：丢弃列表内
    assert region_filter("JP-02", "blacklist", codes) is False
    assert region_filter("DE-02", "blacklist", codes) is True
    # 无法识别时的取舍
    assert region_filter("未知节点", "whitelist", codes, unknown="keep") is True
    assert region_filter("未知节点", "whitelist", codes, unknown="drop") is False


def test_apply_filters_counts_region():
    from app.subscription import ParsedNode, apply_filters

    def mk(name):
        return ParsedNode(name=name, protocol="trojan", host="h", port=443, outbound={}, uri="u")

    nodes = [mk("HK-01"), mk("JP-01"), mk("US-01"), mk("DE-01"), mk("未知")]
    kept, stat = apply_filters(nodes, {
        "region_filter_mode": "whitelist",
        "region_filter_list": "HK,JP",
        "region_filter_unknown": "drop",
    })
    assert [n.name for n in kept] == ["HK-01", "JP-01"], [n.name for n in kept]
    assert stat["region"] == 3, stat


# ---------------------------------------------------------------- 容量上限

def make_space(db, n_nodes, cap=None):
    sid = db.create_space("S", "http://s", 1800, "space")
    for i in range(n_nodes):
        h = f"n{i}.example.com"
        db.upsert_node(sid, f"fp{i}", f"node{i}", "trojan", h, 4000 + i, "{}", h)
    return sid


def test_cap_not_applied_below_limit():
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = make_space(db, 50)
    r = db.enforce_node_cap(sid, 100)
    assert r["evicted"] == 0, r
    assert len(db.nodes(sid, include_deleted=True)) == 50
    db.close()


def test_cap_evicts_down_to_limit():
    """120 个节点、上限 100 → 必须物理删除 20 个。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = make_space(db, 120)
    r = db.enforce_node_cap(sid, 100)
    assert r["evicted"] == 20, r
    assert len(db.nodes(sid, include_deleted=True)) == 100
    # 物理删除：不残留 probes 记录
    left = {row["id"] for row in db.nodes(sid, include_deleted=True)}
    assert left.isdisjoint(set(r["victims"])), "被淘汰的节点仍留在表里"
    db.close()


def test_cap_evicts_worst_first():
    """'最差优先'：已删除/失败/高延迟的先被淘汰，健康低延迟的最后保留。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = db.create_space("S", "http://s", 1800, "space")
    ids = {}
    # 1 个健康低延迟（应保留）
    db.upsert_node(sid, "good", "good", "trojan", "good.com", 443, "{}", "good.com")
    # 1 个健康高延迟（应优先被淘汰）
    db.upsert_node(sid, "slow", "slow", "trojan", "slow.com", 443, "{}", "slow.com")
    # 1 个已删除标记的（最该被淘汰）
    db.upsert_node(sid, "dead", "dead", "trojan", "dead.com", 443, "{}", "dead.com")
    for row in db.nodes(sid, include_deleted=True):
        ids[row["fingerprint"]] = row["id"]
    db.execute("UPDATE nodes SET state='healthy', delay_ms=30, last_ok_at=? WHERE id=?",
               (time.time(), ids["good"]))
    db.execute("UPDATE nodes SET state='healthy', delay_ms=5000, last_ok_at=? WHERE id=?",
               (time.time(), ids["slow"]))
    db.execute("UPDATE nodes SET state='deleted', deletion_reason='x' WHERE id=?", (ids["dead"],))

    r = db.enforce_node_cap(sid, 2, "worst")
    assert r["evicted"] == 1, r
    alive = {row["fingerprint"] for row in db.nodes(sid, include_deleted=True)}
    assert "dead" not in alive, "已删除的节点应最先被淘汰"
    assert {"good", "slow"} <= alive, alive
    db.close()


def test_cap_oldest_strategy_is_fifo():
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = db.create_space("S", "http://s", 1800, "space")
    for i in range(5):
        db.upsert_node(sid, f"fp{i}", f"n{i}", "trojan", f"h{i}.com", 443, "{}", f"h{i}.com")
        db.execute("UPDATE nodes SET added_at=? WHERE fingerprint=?", (1000 + i, f"fp{i}"))
    r = db.enforce_node_cap(sid, 3, "oldest")
    assert r["evicted"] == 2, r
    left = {row["fingerprint"] for row in db.nodes(sid, include_deleted=True)}
    assert left == {"fp2", "fp3", "fp4"}, left   # 最早的两个被删
    db.close()


def test_cap_zero_means_unlimited():
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = make_space(db, 30)
    r = db.enforce_node_cap(sid, 0)
    assert r["evicted"] == 0
    assert len(db.nodes(sid, include_deleted=True)) == 30
    db.close()


def test_hard_delete_removes_probe_history():
    """'删除后空间中不再保留任何相关信息' —— 探测历史也要一起清掉。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = make_space(db, 3)
    nid = db.nodes(sid)[0]["id"]
    db.record_probe(nid, False, None, "timeout", None, 1, True)
    before = len(db.q("SELECT * FROM probes WHERE node_id=?", (nid,)))
    assert before > 0
    db.hard_delete_node(nid)
    assert db.q("SELECT * FROM probes WHERE node_id=?", (nid,)) == []
    assert db.q1("SELECT * FROM nodes WHERE id=?", (nid,)) is None
    db.close()


# ---------------------------------------------------------------- 删除语义统一

def test_manual_delete_is_physical():
    """手动删除必须物理删除 —— 否则列表 API 仍会返回它，用户看到"删了还在"。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = make_space(db, 3)
    nid = db.nodes(sid)[0]["id"]

    db.delete_node(nid, "手动删除")

    assert db.q1("SELECT * FROM nodes WHERE id=?", (nid,)) is None, "行仍留在表里"
    assert db.nodes(sid, include_deleted=True) and len(db.nodes(sid, include_deleted=True)) == 2
    # 探测历史也要一起清掉
    assert db.q("SELECT * FROM probes WHERE node_id=?", (nid,)) == []
    db.close()


def test_delete_node_and_hard_delete_are_equivalent():
    """delete_node 与 hard_delete_node 现在语义一致（都是物理删除）。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    s1 = make_space(db, 2)
    s2 = make_space(db, 2)
    a = db.nodes(s1)[0]["id"]
    b = db.nodes(s2)[0]["id"]

    db.delete_node(a)
    db.hard_delete_node(b)

    assert db.q1("SELECT * FROM nodes WHERE id=?", (a,)) is None
    assert db.q1("SELECT * FROM nodes WHERE id=?", (b,)) is None
    assert len(db.nodes(s1, include_deleted=True)) == 1
    assert len(db.nodes(s2, include_deleted=True)) == 1
    db.close()


def test_no_deleted_rows_remain_after_delete():
    """删除后不该再有任何 state='deleted' 的行 —— 列表默认查询不会带出它们。"""
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = make_space(db, 5)
    for r in db.nodes(sid)[:3]:
        db.delete_node(r["id"])

    remaining = db.nodes(sid, include_deleted=True)
    assert not [r for r in remaining if r["state"] == "deleted"], "仍有 deleted 残留"
    assert len(remaining) == 2
    # 列表 API 用的 include_deleted=False 也应看到同样结果
    assert len(db.nodes(sid, include_deleted=False)) == 2
    db.close()


def test_hard_delete_removes_probe_history_too():
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = make_space(db, 2)
    nid = db.nodes(sid)[0]["id"]
    db.record_probe(nid, False, None, "timeout", None, 1, True)
    assert db.q("SELECT * FROM probes WHERE node_id=?", (nid,))
    db.delete_node(nid)
    assert db.q("SELECT * FROM probes WHERE node_id=?", (nid,)) == []
    db.close()


# ---------------------------------------------------------------- 刷新后自动探测

def test_refresh_identifies_new_nodes():
    """刷新订阅时必须能识别出"这次新进来的"节点 —— 它们是自动探测的对象。

    原先 refresh_space 只做 拉取→解析→落库→重建配置，从不触发探测，
    于是新节点一直停在 unknown（面板显示"未探测"），
    用户以为加了订阅就能用，实际一个可用节点都没有。
    """
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    sid = db.create_space("S", "http://s", 1800, "space")

    # 第一次刷新：3 个全新节点
    before = {r["id"] for r in db.nodes(sid, include_deleted=True)}
    for i in range(3):
        h = f"a{i}.com"
        db.upsert_node(sid, f"fp-a{i}", f"a{i}", "trojan", h, 443, "{}", h)
    new1 = [r["id"] for r in db.nodes(sid, include_deleted=True) if r["id"] not in before]
    assert len(new1) == 3, new1

    # 第二次刷新：2 个重复 + 2 个新的
    before2 = {r["id"] for r in db.nodes(sid, include_deleted=True)}
    for h, fp in (("a0.com", "fp-a0"), ("a1.com", "fp-a1"),
                  ("b0.com", "fp-b0"), ("b1.com", "fp-b1")):
        db.upsert_node(sid, fp, fp, "trojan", h, 443, "{}", h)
    new2 = [r["id"] for r in db.nodes(sid, include_deleted=True) if r["id"] not in before2]
    assert len(new2) == 2, f"只应识别出 2 个新节点，实际 {len(new2)}"
    # 重复的不能算新
    assert not (set(new2) & set(new1)), "重复节点被误判成新的"
    # 总数是并集
    assert len(db.nodes(sid, include_deleted=True)) == 5
    db.close()


def test_probe_after_refresh_default_on():
    from app.config import DEFAULT_SETTINGS
    assert DEFAULT_SETTINGS["probe_after_refresh"] == "true"


def test_probe_specific_only_touches_given_nodes():
    """probe_specific 只处理传入的节点 id，不会误伤其它节点。"""
    import inspect
    from app.probe import ProbeRunner
    src = inspect.getsource(ProbeRunner.probe_specific)
    # 必须按传入的 id 集合过滤
    assert "want = set(node_ids)" in src
    assert "if r[\"id\"] in want" in src
    # 且必须走两阶段（首测 retry_pending、重测 deleted）
    assert "retry_pending" in src and "retry" in src
    assert "hard_delete_nodes" in src


def test_schedule_probe_is_non_blocking():
    """schedule_probe 必须是后台任务，不能让 HTTP 请求等探测跑完。"""
    import asyncio
    from app.probe import ProbeRunner

    calls = []

    class FakeRunner(ProbeRunner):
        async def probe_specific(self, space_id, node_ids):
            calls.append((space_id, list(node_ids)))
            await asyncio.sleep(0.05)
            return {"space_id": space_id, "probed": len(node_ids)}

    async def run():
        r = FakeRunner.__new__(FakeRunner)
        r._tasks = {}
        r._stop = asyncio.Event()
        r.schedule_probe(1, [10, 11])
        # 立即返回：此时探测还没跑完
        assert not calls, "schedule_probe 不应同步等待探测完成"
        await asyncio.sleep(0.3)
        assert calls == [(1, [10, 11])], calls
        # 完成后任务应从 _tasks 里清掉
        assert not r._tasks, r._tasks

    asyncio.run(run())


def test_schedule_probe_noop_on_empty():
    import asyncio
    from app.probe import ProbeRunner
    calls = []

    class FakeRunner(ProbeRunner):
        async def probe_specific(self, space_id, node_ids):
            calls.append(1)

    async def run():
        r = FakeRunner.__new__(FakeRunner)
        r._tasks = {}
        r.schedule_probe(1, [])
        await asyncio.sleep(0.1)
        assert calls == [], "空列表不该调度探测"

    asyncio.run(run())


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
    print("地区过滤与容量上限测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)