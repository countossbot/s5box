"""代理模式（global / direct）的回归测试。

对照 tests/test_ip_strategy.py 的既有范式写：这是同一类"space 级覆盖 + 全局默认"
的开关，解析/迁移/三态/HTTP 四层都要盖到。
"""
import asyncio
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())

from app.config import DEFAULT_PROXY_MODE, DEFAULT_SETTINGS, VALID_PROXY_MODES  # noqa: E402
from app.db import DB                                                        # noqa: E402


def _fresh_db():
    return DB(os.path.join(tempfile.mkdtemp(), "t.db"))


def _mk_space_with_node(db, mode=None):
    """建一个带 1 个健康节点的空间，返回 (sid, node_id)。"""
    sid = db.create_space("S", "http://s", 1800, "space")
    if mode is not None:
        db.update_space(sid, proxy_mode=mode)
    h = "h0.com"
    db.upsert_node(sid, "fp0", "n0", "trojan", h, 443, "{}", h)
    nid = db.nodes(sid, include_deleted=True)[0]["id"]
    db.execute("UPDATE nodes SET state='healthy', delay_ms=100 WHERE id=?", (nid,))
    return sid, nid


# --- 常量与默认值

def test_proxy_mode_default_and_values():
    assert DEFAULT_SETTINGS["proxy_mode"] == "global"
    assert DEFAULT_PROXY_MODE in VALID_PROXY_MODES
    assert set(VALID_PROXY_MODES) == {"global", "direct"}


def test_singbox_reexports_valid_proxy_modes():
    """与 VALID_IP_STRATEGIES 同样保持单一来源，防止被复制成两份。"""
    from app import config, singbox
    assert singbox.VALID_PROXY_MODES is config.VALID_PROXY_MODES


# --- 解析优先级（space 覆盖 > 全局 > 默认）

def test_resolve_proxy_mode_priority():
    db = _fresh_db()
    try:
        sid, _ = _mk_space_with_node(db)

        # 1) 全局与 space 都设 -> space 赢
        db.set_setting("proxy_mode", "direct")
        db.update_space(sid, proxy_mode="global")
        assert db.resolve_proxy_mode(db.get_space(sid)) == "global"

        # 2) space 为 NULL -> 继承全局
        db.update_space(sid, proxy_mode=None)
        assert db.resolve_proxy_mode(db.get_space(sid)) == "direct"

        # 3) space 是脏值 -> 回退全局
        db.execute("UPDATE spaces SET proxy_mode='bogus' WHERE id=?", (sid,))
        assert db.resolve_proxy_mode(db.get_space(sid)) == "direct"

        # 4) 全局也脏 -> 兜底默认
        db.set_setting("proxy_mode", "nonsense")
        assert db.resolve_proxy_mode(db.get_space(sid)) == DEFAULT_PROXY_MODE

        # 5) 传 None（无 space）等价于继承全局
        db.set_setting("proxy_mode", "direct")
        assert db.resolve_proxy_mode(None) == "direct"
    finally:
        db.close()


def test_new_space_proxy_mode_is_null_meaning_inherit():
    db = _fresh_db()
    try:
        sid = db.create_space("s", "http://a/b", 1800, "space")
        assert db.get_space(sid)["proxy_mode"] is None
    finally:
        db.close()


def test_backward_compat_without_space_override():
    """不设 space 级覆盖时，结果等同于直接读全局设置。"""
    db = _fresh_db()
    try:
        sid, _ = _mk_space_with_node(db)
        for v in VALID_PROXY_MODES:
            db.set_setting("proxy_mode", v)
            assert db.resolve_proxy_mode(db.get_space(sid)) == v
        # 老库可能根本没这个键
        db.execute("DELETE FROM settings WHERE key='proxy_mode'")
        assert db.resolve_proxy_mode(db.get_space(sid)) == DEFAULT_PROXY_MODE
    finally:
        db.close()


# --- 老库迁移

def test_migrate_spaces_adds_proxy_mode_idempotent():
    path = os.path.join(tempfile.mkdtemp(), "old.db")
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE spaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1, refresh_interval INTEGER NOT NULL DEFAULT 1800,
      weight_mode TEXT NOT NULL DEFAULT 'space', node_limit INTEGER NOT NULL DEFAULT 0,
      last_refresh_at REAL, last_refresh_ok INTEGER, last_refresh_error TEXT,
      created_at REAL NOT NULL);
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    INSERT INTO spaces(name,url,created_at) VALUES('老空间','http://a/b',1.0);
    """)
    conn.commit()
    conn.close()

    db = DB(path)
    try:
        cols = [r["name"] for r in db.q("PRAGMA table_info(spaces)")]
        assert "proxy_mode" in cols
        assert "ip_strategy" in cols, "同一次迁移里两个列都该补上"
        assert db.spaces()[0]["proxy_mode"] is None, "老数据必须是 NULL（=继承）"
    finally:
        db.close()

    db2 = DB(path)
    try:
        cols2 = [r["name"] for r in db2.q("PRAGMA table_info(spaces)")]
        assert cols2.count("proxy_mode") == 1, "二次初始化不得重复 ALTER"
    finally:
        db2.close()


# --- registry：选点时的模式分流

def _registry_with(db, mode):
    """按 main/probe 的方式构造 Registry（proxy_modes 由调用方解析后传入）。"""
    from app import registry as R
    sid, _ = _mk_space_with_node(db, mode=mode)
    rows = db.spaces()
    modes = {sp["id"]: db.resolve_proxy_mode(sp) for sp in rows}
    reg = R.build_registry(db, {sid: 11080}, modes)
    return reg, sid


def test_pick_global_returns_node_with_port():
    db = _fresh_db()
    try:
        reg, _ = _registry_with(db, "global")
        p = reg.pick()
        assert p is not None
        assert p.mode == "global"
        assert p.space is not None and p.node is not None
        assert p.node_port == 11080 + p.index, "端口必须是 socks_port + 节点下标"
    finally:
        db.close()


def test_pick_direct_returns_none_space_and_node():
    """direct 空间不进随机池：结果是直连，且 space/node 为 None。"""
    db = _fresh_db()
    try:
        reg, _ = _registry_with(db, "direct")
        p = reg.pick()
        assert p is not None, "direct 也必须有结果，不能当成'没得选'"
        assert p.mode == "direct"
        assert p.space is None and p.node is None
        assert p.node_port is None
    finally:
        db.close()


def test_pick_direct_space_excluded_from_random_pool():
    """混合场景：direct 空间必须被排除，另一个空间照常被选中。"""
    db = _fresh_db()
    try:
        from app import registry as R
        s1, _ = _mk_space_with_node(db, mode="direct")
        s2, _ = _mk_space_with_node(db, mode="global")
        rows = db.spaces()
        modes = {sp["id"]: db.resolve_proxy_mode(sp) for sp in rows}
        reg = R.build_registry(db, {s1: 11080, s2: 11081}, modes)
        for _ in range(30):
            p = reg.pick()
            assert p.mode == "global"
            assert p.space.id == s2, "direct 空间不该被选中"
    finally:
        db.close()


def test_pick_global_falls_back_to_global_default():
    """space 没设 proxy_mode 时，全局设成 direct 也应当走直连。"""
    db = _fresh_db()
    try:
        reg, _ = _registry_with(db, None)
        assert reg.pick().mode == "global", "默认仍应是 global"
        db.set_setting("proxy_mode", "direct")
        reg2, _ = _registry_with(db, None)
        assert reg2.pick().mode == "direct"
    finally:
        db.close()


def test_pick_none_when_no_spaces():
    db = _fresh_db()
    try:
        from app import registry as R
        reg = R.build_registry(db, {}, {})
        assert reg.pick() is None
    finally:
        db.close()


# --- dispatcher：direct 时真的直连目标

def test_connect_upstream_direct_skips_singbox():
    """node_port=None 时必须直连「目标主机:端口」，而不是连本地 127.0.0.1。

    这条是该功能的核心断言：把 node_port 当 127.0.0.1 的端口去连，
    直连模式就会静默连到 sing-box（或直接连接失败）。
    """
    from unittest import mock
    from app.proxy import Dispatcher

    seen = {}

    async def fake_open(host, port):
        seen["host"], seen["port"] = host, port
        return "R", "W"

    async def run():
        d = Dispatcher.__new__(Dispatcher)
        with mock.patch("app.proxy.asyncio.open_connection", fake_open):
            return await d.connect_upstream(None, "example.com", 8443)

    r = asyncio.run(run())
    assert r == ("R", "W")
    assert seen == {"host": "example.com", "port": 8443}, seen


def test_connect_upstream_uses_loopback_for_node_port():
    """global 时连的是本地回环上的节点专属端口，并完成一次 SOCKS 握手。

    真起一个假 SOCKS 服务端（而不是 mock open_connection）：connect_upstream 的
    global 分支不止建连，还要发 no-auth 握手并读回响应，mock 掉连接就会漏测这段。
    """
    from app.proxy import Dispatcher

    async def run():
        seen = {}

        async def handler(reader, writer):
            seen["greeting"] = await reader.readexactly(3)
            writer.write(bytes([0x05, 0x00]))       # 同意 no-auth
            seen["request"] = await reader.readexactly(18)   # 4 + 1 + 11 + 2
            # CONNECT 成功：VER REP RSV ATYP=IPv4 + 4 字节地址 + 2 字节端口
            writer.write(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            d = Dispatcher.__new__(Dispatcher)
            await asyncio.wait_for(d.connect_upstream(port, "example.com", 443), timeout=5)
        finally:
            server.close()
            await server.wait_closed()
        return seen

    seen = asyncio.run(run())
    assert seen["greeting"] == bytes([0x05, 0x01, 0x00]), seen
    # 请求头：VER CMD CONNECT RSV ATYP=域名 + 长度 + example.com + 端口 443
    assert seen["request"][:4] == bytes([0x05, 0x01, 0x00, 0x03]), seen
    assert seen["request"][4] == 11, "域名长度"
    assert seen["request"][5:16] == b"example.com", seen
    assert seen["request"][16:18] == (443).to_bytes(2, "big"), seen


def test_log_tolerates_none_space_and_node():
    """direct 模式的日志不能因为 sp/node 为 None 而抛异常。"""
    from app.proxy import Dispatcher

    got = {}

    class _Logs:
        def add(self, **kw):
            got.update(kw)

    d = Dispatcher.__new__(Dispatcher)
    d.logs = _Logs()
    d._log("1.2.3.4", "SOCKS5", "example.com", 443, None, None, True, "direct")
    assert got["space_id"] is None and got["node_id"] is None
    assert got["node_name"] == "直连"
    assert got["target"] == "example.com:443"


# --- HTTP / API 层

def _http_client(db):
    from fastapi.testclient import TestClient
    from app import main as main_mod

    async def _noop(sid):
        return None

    class _FakeRunner:
        def rebuild(self):
            return None

    main_mod.STATE["db"] = db
    main_mod.STATE["runner"] = _FakeRunner()
    main_mod.STATE.setdefault("panel_token", "test-token")
    main_mod.rebuild_space_instance = _noop
    main_mod.refresh_space = _noop
    client = TestClient(main_mod.app)
    client.cookies.set("sw_token", main_mod.STATE["panel_token"])
    return client


def test_http_patch_proxy_mode_three_states():
    db = _fresh_db()
    try:
        sid, _ = _mk_space_with_node(db)
        client = _http_client(db)

        # 合法值（带空白）-> strip 后落库
        r = client.patch(f"/api/spaces/{sid}", json={"proxy_mode": "  direct  "})
        assert r.status_code == 200, r.text
        assert db.get_space(sid)["proxy_mode"] == "direct"

        # 空串 -> NULL（继承）
        r = client.patch(f"/api/spaces/{sid}", json={"proxy_mode": "   "})
        assert r.status_code == 200, r.text
        assert db.get_space(sid)["proxy_mode"] is None

        # 显式 null -> NULL（继承）
        db.update_space(sid, proxy_mode="direct")
        r = client.patch(f"/api/spaces/{sid}", json={"proxy_mode": None})
        assert r.status_code == 200, r.text
        assert db.get_space(sid)["proxy_mode"] is None

        # 缺省 key -> 已有值不变
        db.update_space(sid, proxy_mode="direct")
        r = client.patch(f"/api/spaces/{sid}", json={"name": "renamed"})
        assert r.status_code == 200, r.text
        assert db.get_space(sid)["proxy_mode"] == "direct"
    finally:
        db.close()


def test_http_patch_proxy_mode_illegal_rejected():
    db = _fresh_db()
    try:
        sid, _ = _mk_space_with_node(db)
        db.update_space(sid, proxy_mode="direct")
        client = _http_client(db)

        r = client.patch(f"/api/spaces/{sid}", json={"proxy_mode": "sometimes"})
        assert r.status_code == 400, r.text
        assert db.get_space(sid)["proxy_mode"] == "direct", "非法值不得覆盖已有值"

        for bad in (123, ["direct"], True, {"a": 1}):
            r = client.patch(f"/api/spaces/{sid}", json={"proxy_mode": bad})
            assert r.status_code == 400, f"{bad!r} -> {r.status_code}"
            assert db.get_space(sid)["proxy_mode"] == "direct"
    finally:
        db.close()


def test_settings_api_rejects_illegal_global_proxy_mode():
    """全局设置里的 proxy_mode 走同一套枚举校验。

    注意 put_settings 的既有约定是「软拒绝」：返回 200，但把非法值放进
    _rejected 且不落库（与 ip_strategy 一致），不是抛 400。
    """
    db = _fresh_db()
    try:
        client = _http_client(db)
        r = client.put("/api/settings", json={"proxy_mode": "sometimes"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert "proxy_mode" in body.get("_rejected", {}), body
        assert db.get_setting("proxy_mode", DEFAULT_PROXY_MODE) == DEFAULT_PROXY_MODE, \
            "被拒的非法值不得落库"
        assert body["proxy_mode"] == DEFAULT_PROXY_MODE, "回显的仍是生效值"

        r = client.put("/api/settings", json={"proxy_mode": "direct"})
        assert r.status_code == 200, r.text
        assert "_rejected" not in r.json(), r.json()
        assert db.get_setting("proxy_mode") == "direct"

        # 大小写不敏感（该端点统一走 str(v).strip().lower()）
        r = client.put("/api/settings", json={"proxy_mode": "  GLOBAL "})
        assert r.status_code == 200 and "_rejected" not in r.json(), r.text
        assert db.get_setting("proxy_mode") == "global"
    finally:
        db.close()
def test_create_space_applies_proxy_mode():
    """POST /api/spaces 也要认 proxy_mode（与 ip_strategy 同一条路径）。"""
    db = _fresh_db()
    try:
        client = _http_client(db)
        r = client.post("/api/spaces", json={
            "name": "新建", "url": "http://a/b", "proxy_mode": "direct"})
        assert r.status_code == 200, r.text
        sid = r.json()["id"]
        assert db.get_space(sid)["proxy_mode"] == "direct"
    finally:
        db.close()



def test_api_rejects_invalid_proxy_mode_direct_call():
    from fastapi import HTTPException
    from app.main import _apply_space_proxy_mode

    db = _fresh_db()
    try:
        sid, _ = _mk_space_with_node(db)
        rejected = False
        try:
            _apply_space_proxy_mode(db, sid, {"proxy_mode": "bogus"})
        except HTTPException as e:
            rejected = e.status_code == 400
        assert rejected, "非法 proxy_mode 未被拒绝"
        assert db.get_space(sid)["proxy_mode"] is None, "被拒后不得留脏值"
    finally:
        db.close()


# --- 前端：开关必须真的出现在 UI 与提交体里

def test_frontend_exposes_proxy_mode_control():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "app", "static", "app.js")
    src = open(path, encoding="utf-8").read()
    assert 'data-act="proxy_mode"' in src, "空间列表里应有代理模式下拉"
    assert "proxy_mode: get('proxy_mode')" in src, "编辑时必须把 proxy_mode 一起提交"
    assert "'proxy_mode'" in src, "全局设置里应有 proxy_mode 项"


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
    print("代理模式测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)
