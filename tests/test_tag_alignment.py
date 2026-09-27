"""节点 tag / 端口 / 路由三方对齐测试。

这是最隐蔽的一个 bug：sing-box 配置里 nN 的编号、inN 端口绑定的节点、
以及内存注册表里 Node.socks_port 三者必须指向同一个节点。
一旦错位，表现为"探测显示节点健康、走代理却全部失败"。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())

from app import registry as R          # noqa: E402
from app.db import DB                  # noqa: E402


def build_db(space_count=2):
    db = DB(os.path.join(tempfile.mkdtemp(), "t.db"))
    spaces = [db.create_space(f"S{i}", f"http://s{i}", 1800, "space") for i in range(space_count)]
    # 交错插入 + 混合状态，最大限度制造错位机会
    hosts = []
    for i in range(12):
        sid = spaces[i % space_count]
        h = f"node{i}.example.com"
        db.upsert_node(sid, f"fp{i}", f"n{i}", "trojan", h, 4000 + i, "{}", h)
        hosts.append((sid, h, 4000 + i))
    # 让一半节点处于各种状态
    for idx, (sid, h, p) in enumerate(hosts):
        state = ("healthy", "cooling", "unknown", "deleted")[idx % 4]
        db.execute("UPDATE nodes SET state=? WHERE host=?", (state, h))
    return db


def test_config_tags_match_tag_map():
    """配置生成时的 nN 顺序必须严格等于 tag_map 的编号顺序。"""
    db = build_db()
    for sp in db.spaces():
        rows = sorted(db.nodes(sp["id"], include_deleted=True), key=lambda r: r["id"])
        tag_of = R.tag_map(rows)
        # 模拟 rebuild_space_instance 的输出顺序
        payload = [(tag_of[r["id"]], r["host"]) for r in rows]
        for i, (tag, host) in enumerate(payload):
            assert tag == f"n{i}", f"第 {i} 个出站 tag 应为 n{i}，实际 {tag}"
            assert rows[i]["host"] == host
    db.close()


def test_registry_port_matches_node_index():
    """注册表里每个节点的 socks_port 必须等于 基端口 + 它的 nN 编号。"""
    db = build_db()
    base = 11080
    ports = {sp["id"]: base for sp in db.spaces()}
    reg = R.build_registry(db, ports)
    by_id = {}
    for sp in db.spaces():
        for r in db.nodes(sp["id"], include_deleted=True):
            by_id[r["id"]] = r["host"]
    checked = 0
    for space in reg.spaces():
        for node in space.nodes:
            expect_idx = int(node.outbound_tag.lstrip("n"))
            assert node.index == expect_idx, f"{node.name}: index {node.index} != tag {node.outbound_tag}"
            assert node.socks_port == ports[space.id] + expect_idx, \
                f"{node.name}: port {node.socks_port} 与 tag {node.outbound_tag} 不匹配"
            # 该节点在同空间里的 host 必须与 DB 一致（下标也一致）
            assert by_id[node.id] == node.host
            checked += 1
    assert checked > 0
    db.close()


def test_deleted_nodes_excluded_from_pool_but_keep_index():
    """已删节点不能进随机池，但仍然占用自己的编号（否则后面所有节点都会错位）。"""
    db = build_db()
    ports = {sp["id"]: 11080 for sp in db.spaces()}
    reg = R.build_registry(db, ports)
    for space in reg.spaces():
        all_rows = sorted(db.nodes(space.id, include_deleted=True), key=lambda r: r["id"])
        deleted_ids = {r["id"] for r in all_rows if r["state"] == "deleted"}
        pool_ids = {n.id for n in space.nodes}
        assert not (deleted_ids & pool_ids), "已删节点不应出现在随机池里"
        # 池里节点的编号必须与完整列表中的位置一致
        for i, r in enumerate(all_rows):
            if r["id"] in pool_ids:
                node = next(n for n in space.nodes if n.id == r["id"])
                assert node.index == i, f"编号偏移：{r['host']} 应为 n{i}，实际 {node.outbound_tag}"
    db.close()


def test_hard_delete_renumbers_and_registry_must_be_rebuilt():
    """物理删除节点后编号会前移；注册表若不重建就会与 sing-box 配置错位。

    这是"静默错误结果"类缺陷：探测/代理会连到错误的节点端口，
    不报错但结果全错。所以删除后必须 rebuild（probe.py 已这么做）。
    """
    db = build_db(space_count=1)
    sid = db.spaces()[0]["id"]
    ports = {sid: 11080}
    reg = R.build_registry(db, ports)
    snap = {n.id: (n.outbound_tag, n.socks_port) for sp in reg.spaces() for n in sp.nodes}

    # 物理删除中间某个节点
    victim = sorted(snap)[1]
    db.hard_delete_node(victim)

    tm_new = R.tag_map(db.nodes(sid, include_deleted=True))
    # 删除后若不重建，编号必然错位
    misaligned = [nid for nid in tm_new if snap.get(nid, (None,))[0] != tm_new[nid]]
    assert misaligned, "本用例的前提是删除会导致编号前移"

    # 重建之后必须完全对齐。
    # 注意：注册表只装"参与随机池"的节点（非 deleted/cooling 会被排除），
    # 所以只对出现在注册表里的节点做对齐断言。
    reg2 = R.build_registry(db, ports)
    by_id = {}
    for sp in reg2.spaces():
        for n in sp.nodes:
            by_id[n.id] = n
    assert by_id, "重建后注册表不该为空"
    for nid, node in by_id.items():
        tag = tm_new[nid]
        assert node.outbound_tag == tag, f"重建后错位：{nid} {node.outbound_tag} != {tag}"
        expect_port = ports[sid] + int(tag.lstrip("n"))
        assert node.socks_port == expect_port, f"{nid} 端口 {node.socks_port} != {expect_port}"
    db.close()


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
    print("tag 对齐测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)