"""设置迁移测试。

锁住一个真实踩过的升级问题：老库里存着"旧出厂默认值"时，
all_settings() 的"新默认打底 + 旧值覆盖"会让新默认值永远不生效，
升级后新功能看起来完全没工作（实际遇到：probe_url 和容量上限都被旧值盖住）。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())

from app import config                             # noqa: E402
from app.db import DB                              # noqa: E402


def fresh_db():
    return DB(os.path.join(tempfile.mkdtemp(), "t.db"))


def test_old_defaults_are_migrated():
    """老库里存的旧出厂值必须被迁到新默认值。"""
    db = fresh_db()
    db.set_setting("probe_url", "https://1.1.1.1/cdn-cgi/trace")
    db.set_setting("filter_max_nodes_per_space", "0")
    db.set_setting("failure_threshold", "3")
    # 模拟老库（还没有版本号）
    db.execute("DELETE FROM settings WHERE key='settings_schema_version'")

    r = db.migrate_settings()
    assert set(r["changed"]) >= {"probe_url", "filter_max_nodes_per_space", "failure_threshold"}, r

    s = db.all_settings()
    assert s["probe_url"] == config.DEFAULT_SETTINGS["probe_url"] == "https://httpbin.org/ip"
    assert s["filter_max_nodes_per_space"] == "100"
    assert s["failure_threshold"] == "1"
    db.close()


def test_user_modified_values_are_kept():
    """用户自己改过的值绝不能被迁移覆盖。"""
    db = fresh_db()
    db.set_setting("probe_url", "https://my-own-probe.example.com/ping")
    db.set_setting("filter_max_nodes_per_space", "250")     # 用户特意调大
    db.execute("DELETE FROM settings WHERE key='settings_schema_version'")

    r = db.migrate_settings()
    assert "probe_url" not in r["changed"], r
    assert "filter_max_nodes_per_space" not in r["changed"], r

    s = db.all_settings()
    assert s["probe_url"] == "https://my-own-probe.example.com/ping"
    assert s["filter_max_nodes_per_space"] == "250"
    db.close()


def test_new_keys_appear_without_touching_db():
    """老库里没有的新键（地区过滤等）应通过默认值直接生效。"""
    db = fresh_db()
    db.execute("DELETE FROM settings WHERE key='settings_schema_version'")
    db.migrate_settings()
    s = db.all_settings()
    assert s["region_filter_mode"] == "off"
    assert s["region_filter_list"]
    assert s["region_filter_unknown"] == "keep"
    assert s["probe_retry_failed_once"] == "true"
    db.close()


def test_migration_is_idempotent():
    db = fresh_db()
    db.set_setting("probe_url", "https://1.1.1.1/cdn-cgi/trace")
    db.execute("DELETE FROM settings WHERE key='settings_schema_version'")

    first = db.migrate_settings()
    assert first["changed"], first
    second = db.migrate_settings()
    assert second["changed"] == {}, f"第二次不该再改动：{second}"
    assert second["from"] == config.SETTINGS_SCHEMA_VERSION
    db.close()


def test_missing_key_uses_new_default():
    """老库压根没有这个键时，直接用新默认值，不该写库。"""
    db = fresh_db()
    db.execute("DELETE FROM settings WHERE key='settings_schema_version'")
    db.execute("DELETE FROM settings WHERE key='probe_url'")
    r = db.migrate_settings()
    assert "probe_url" not in r["changed"], r
    assert db.all_settings()["probe_url"] == "https://httpbin.org/ip"
    db.close()


def test_migration_marks_schema_version():
    db = fresh_db()
    db.execute("DELETE FROM settings WHERE key='settings_schema_version'")
    assert db.settings_schema_version() == 1
    db.migrate_settings()
    assert db.settings_schema_version() == config.SETTINGS_SCHEMA_VERSION
    db.close()


def test_capacity_cap_actually_takes_effect_after_migration():
    """端到端：迁移后容量上限真的开始生效。"""
    db = fresh_db()
    db.set_setting("filter_max_nodes_per_space", "0")     # 老库 = 无限
    db.execute("DELETE FROM settings WHERE key='settings_schema_version'")
    db.migrate_settings()

    cap = int(db.all_settings()["filter_max_nodes_per_space"])
    assert cap == 100

    sid = db.create_space("S", "http://s", 1800, "space")
    for i in range(120):
        h = f"h{i}.com"
        db.upsert_node(sid, f"fp{i}", f"n{i}", "trojan", h, 443, "{}", h)
    r = db.enforce_node_cap(sid, cap)
    assert r["evicted"] == 20, r
    assert len(db.nodes(sid, include_deleted=True)) == 100
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
    print("设置迁移测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)
