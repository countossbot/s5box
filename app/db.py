"""SQLite 存储层。stdlib sqlite3 + WAL，够用就不引 ORM。

只被调度器/API 写；代理分发器从不碰这里（它读 registry 的内存快照）。
"""
from __future__ import annotations

import logging
import sqlite3
import tempfile
import threading
import time
from pathlib import Path


from . import config

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS spaces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  refresh_interval INTEGER NOT NULL DEFAULT 1800,
  weight_mode TEXT NOT NULL DEFAULT 'space',
  node_limit INTEGER NOT NULL DEFAULT 0,
  last_refresh_at REAL,
  last_refresh_ok INTEGER,
  last_refresh_error TEXT,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  space_id INTEGER NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  outbound_json TEXT NOT NULL,   -- sing-box outbound 片段（含 secret，仅服务端可见）
  uri TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'unknown',  -- healthy|unknown|cooling|deleted
  delay_ms INTEGER,
  exit_ip TEXT,
  fail_count INTEGER NOT NULL DEFAULT 0,
  ok_count INTEGER NOT NULL DEFAULT 0,
  last_probe_at REAL,
  last_ok_at REAL,
  deletion_reason TEXT,
  added_at REAL NOT NULL,
  UNIQUE(space_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_nodes_space_state ON nodes(space_id, state);

CREATE TABLE IF NOT EXISTS probes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id INTEGER NOT NULL,
  ts REAL NOT NULL,
  ok INTEGER NOT NULL,
  delay_ms INTEGER,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_probes_ts ON probes(ts);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS conn_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  client TEXT,
  proto TEXT,
  target TEXT,
  space_id INTEGER,
  space_name TEXT,
  node_id INTEGER,
  node_name TEXT,
  ok INTEGER,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_connlog_ts ON conn_log(ts);
"""


class DB:
    def __init__(self, path=None):
        self.path = str(path or config.DB_PATH)
        # 卷没挂上时 /data 可能不存在或不可写：退到临时目录并明确告警，
        # 别让"忘了挂卷"变成容器起不来
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            fallback = Path(tempfile.gettempdir()) / "subswarm.db"
            logging.getLogger("subswarm").warning(
                "无法创建 %s，改用 %s（数据不会持久化！请挂载 /data 卷）", self.path, fallback)
            self.path = str(fallback)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    # --- 基础 ---
    def q(self, sql: str, args: Iterable = ()) -> list[sqlite3.Row]:
            return self._conn.execute(sql, tuple(args)).fetchall()

    def q1(self, sql: str, args: Iterable = ()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: Iterable = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(args))

    def execute(self, sql: str, args: Iterable = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, tuple(args))
            return cur.lastrowid or 0

    def close(self):
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
            self._conn.close()

    # --- settings ---
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.q1("SELECT value FROM settings WHERE key=?", (key,))
        return row["value"] if row else default

    def all_settings(self) -> dict[str, str]:
        out = dict(config.DEFAULT_SETTINGS)
        for r in self.q("SELECT key,value FROM settings"):
            out[r["key"]] = r["value"]
        return out

    # --- 设置迁移 ---
    def settings_schema_version(self) -> int:
        try:
            return int(self.get_setting("settings_schema_version", "1") or 1)
        except (TypeError, ValueError):
            return 1

    def migrate_settings(self) -> dict:
        """把老库里的"旧出厂默认值"升级成新默认值。

        为什么需要：all_settings() 是"新默认打底 + 旧库值覆盖"。
        如果老库里已经存了旧默认值（例如出厂的 probe_url、容量上限 0），
        它会一直盖住新默认值 —— 升级后新功能看起来完全没生效。
        真实踩过这个坑。

        只替换**恰好等于已知旧值**的项；用户手改过的值一律不动。
        幂等：跑第二次不会有任何变化。
        """
        current = self.settings_schema_version()
        if current >= config.SETTINGS_SCHEMA_VERSION:
            return {"from": current, "to": current, "changed": {}}

        changed: dict[str, dict[str, str]] = {}
        for key, pairs in config.SETTINGS_MIGRATIONS.items():
            row = self.q1("SELECT value FROM settings WHERE key=?", (key,))
            if row is None:
                continue                      # 库里没有 → 用新默认值即可
            value = row["value"]
            for old_val, new_val in pairs:
                if value == old_val:
                    self.set_setting(key, new_val)
                    changed[key] = {"from": value, "to": new_val}
                    break

        # 新增的键不需要写库：all_settings() 会用新默认值打底
        self.set_setting("settings_schema_version", config.SETTINGS_SCHEMA_VERSION)
        return {"from": current, "to": config.SETTINGS_SCHEMA_VERSION, "changed": changed}

    def set_setting(self, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    # --- spaces ---
    def create_space(self, name: str, url: str, refresh_interval: int, weight_mode: str) -> int:
        return self.execute(
            "INSERT INTO spaces(name,url,refresh_interval,weight_mode,created_at) VALUES(?,?,?,?,?)",
            (name, url, refresh_interval, weight_mode, time.time()),
        )

    def spaces(self) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM spaces ORDER BY id")

    def get_space(self, sid: int):
        return self.q1("SELECT * FROM spaces WHERE id=?", (sid,))

    def update_space(self, sid: int, **fields) -> None:
        allowed = {"name", "url", "enabled", "refresh_interval", "weight_mode", "node_limit",
                   "last_refresh_at", "last_refresh_ok", "last_refresh_error"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if not sets:
            return
        sql = "UPDATE spaces SET " + ",".join(f"{k}=?" for k in sets) + " WHERE id=?"
        self.execute(sql, (*sets.values(), sid))

    def delete_space(self, sid: int) -> None:
        self.execute("DELETE FROM nodes WHERE space_id=?", (sid,))
        self.execute("DELETE FROM spaces WHERE id=?", (sid,))

    # --- nodes ---
    def upsert_node(self, space_id: int, fp: str, name: str, protocol: str, host: str,
                    port: int, outbound_json: str, uri: str) -> None:
        """只插入新节点。已存在（含已删除）的不复活，避免删了又加反复抖动。"""
        self.execute(
            """INSERT INTO nodes(space_id,fingerprint,name,protocol,host,port,outbound_json,uri,state,added_at)
               VALUES(?,?,?,?,?,?,?,?,'unknown',?)
               ON CONFLICT(space_id,fingerprint) DO UPDATE SET name=excluded.name, uri=excluded.uri,
                 outbound_json=excluded.outbound_json""",
            (space_id, fp, name, protocol, host, port, outbound_json, uri, time.time()),
        )

    def nodes(self, space_id: int | None = None, include_deleted: bool = False) -> list[sqlite3.Row]:
        where, args = [], []
        if space_id is not None:
            where.append("space_id=?")
            args.append(space_id)
        if not include_deleted:
            where.append("state != 'deleted'")
        sql = "SELECT * FROM nodes"
        if where:
            sql += " WHERE " + " AND ".join(where)
        return self.q(sql + " ORDER BY space_id, id", args)

    def pool_nodes(self) -> list[sqlite3.Row]:
        """随机池：healthy + unknown（未探测的给一次机会），按延迟升序。"""
        return self.q(
            "SELECT * FROM nodes WHERE state IN ('healthy','unknown') "
            "ORDER BY space_id, (delay_ms IS NULL), delay_ms"
        )

    def retry_pending_nodes(self, space_id: int) -> list[sqlite3.Row]:
        """本轮失败、等待重测的节点（需求 3）。"""
        return self.q("SELECT * FROM nodes WHERE space_id=? AND state='retry_pending' ORDER BY id",
                      (space_id,))

    def record_probe(self, node_id: int, ok: bool, delay_ms: int | None, error: str | None,
                     exit_ip: str | None, failure_threshold: int, auto_delete: bool,
                     mark_failed_as: str = "deleted") -> str:
        """写入探测结果并推进状态机。返回新状态。

        mark_failed_as 决定"本轮失败"的落库方式（需求 3 的两阶段流程）：
          "retry_pending" —— 第一阶段失败：只标记待重测，绝不当场删除
          "deleted"       —— 重测仍失败：标记 deleted（随后会被物理删除）
          "cooling"       —— 旧行为：进入冷却，保留在池外
        """
        now = time.time()
        self.execute("INSERT INTO probes(node_id,ts,ok,delay_ms,error) VALUES(?,?,?,?,?)",
                     (node_id, now, 1 if ok else 0, delay_ms, error))
        row = self.q1("SELECT fail_count, state FROM nodes WHERE id=?", (node_id,))
        if row is None:
            return "gone"
        if ok:
            self.execute(
                """UPDATE nodes SET state='healthy', delay_ms=?, exit_ip=COALESCE(?,exit_ip),
                   fail_count=0, ok_count=ok_count+1, last_probe_at=?, last_ok_at=?, deletion_reason=NULL
                   WHERE id=?""",
                (delay_ms, exit_ip, now, now, node_id),
            )
            return "healthy"

        fails = (row["fail_count"] or 0) + 1
        if mark_failed_as == "retry_pending":
            # 需求 3：失败先跳过、继续后面的节点，等整轮跑完再统一重测
            self.execute(
                "UPDATE nodes SET state='retry_pending', fail_count=?, last_probe_at=?, delay_ms=NULL WHERE id=?",
                (fails, now, node_id),
            )
            return "retry_pending"
        if auto_delete and fails >= failure_threshold:
            self.execute(
                """UPDATE nodes SET state='deleted', fail_count=?, last_probe_at=?,
                   deletion_reason=? WHERE id=?""",
                (fails, now, f"探测连续失败 {fails} 次（阈值 {failure_threshold}）", node_id),
            )
            return "deleted"
        self.execute(
            "UPDATE nodes SET state='cooling', fail_count=?, last_probe_at=?, delay_ms=NULL WHERE id=?",
            (fails, now, node_id),
        )
        return "cooling"

    def revive_node(self, node_id: int) -> None:
        self.execute(
            "UPDATE nodes SET state='unknown', fail_count=0, delay_ms=NULL, deletion_reason=NULL WHERE id=?",
            (node_id,))

    def delete_node(self, node_id: int, reason: str = "手动删除") -> None:
        """删除节点 —— 物理删除，不留任何记录。

        原先这里只标记 state='deleted'，行仍留在表里；而列表 API 用
        include_deleted=True 查询，于是"删掉的节点还在 web 上显示，
        刷新也不消失"。现在与自动删除（hard_delete_nodes）统一为物理删除，
        满足"删除后空间中不再保留任何相关信息"。
        """
        self.hard_delete_node(node_id)

    def purge_probes(self, keep_seconds: int = 7 * 86400) -> None:
        self.execute("DELETE FROM probes WHERE ts < ?", (time.time() - keep_seconds,))

    # --- 容量上限（需求 1） ---
    def hard_delete_node(self, node_id: int) -> None:
        """物理删除节点及其探测历史。

        与 delete_node()（只标记 deleted、移出随机池）不同：
        容量淘汰和"重测仍失败"都是彻底清除，不留任何记录（需求 3）。
        """
        self.execute("DELETE FROM probes WHERE node_id=?", (node_id,))
        self.execute("DELETE FROM nodes WHERE id=?", (node_id,))

    def hard_delete_nodes(self, node_ids: list[int]) -> int:
        if not node_ids:
            return 0
        marks = ",".join("?" * len(node_ids))
        self.execute(f"DELETE FROM probes WHERE node_id IN ({marks})", node_ids)
        self.execute(f"DELETE FROM nodes WHERE id IN ({marks})", node_ids)
        return len(node_ids)

    def enforce_node_cap(self, space_id: int, cap: int, strategy: str = "worst") -> dict:
        """保证单个空间的节点数不超过 cap（需求 1）。

        订阅每次刷新都会返回一批全新节点，若不做限制会无限累积。
        超出时按 strategy 淘汰：
          worst  先淘汰"最差"的 —— 已删除/冷却的优先，其次高延迟，最后最久未成功
          oldest 纯 FIFO，按加入时间淘汰最早的
        都是**物理删除**，不留痕迹。
        """
        if cap <= 0:
            return {"space_id": space_id, "cap": cap, "evicted": 0, "kept": None}
        rows = self.nodes(space_id, include_deleted=True)
        total = len(rows)
        if total <= cap:
            return {"space_id": space_id, "cap": cap, "evicted": 0, "kept": total}

        need = total - cap
        if strategy == "oldest":
            rows.sort(key=lambda r: (r["added_at"] or 0, r["id"]))
        else:
            # 排序优先级（越靠前越该被淘汰）：
            #  1. state 权重：deleted(0) < cooling(1) < unknown(2) < healthy(3)
            #  2. 延迟：无延迟数据的排前面，有数据的按延迟降序（最慢先走）
            #  3. 最后成功时间：越久没成功的越先走
            state_rank = {"deleted": 0, "cooling": 1, "unknown": 2, "healthy": 3}
            rows.sort(key=lambda r: (
                state_rank.get(r["state"], 9),
                -(r["delay_ms"] if r["delay_ms"] is not None else 10 ** 9),
                r["last_ok_at"] or 0,
                r["added_at"] or 0,
                r["id"],
            ))
        victims = [r["id"] for r in rows[:need]]
        self.hard_delete_nodes(victims)
        return {"space_id": space_id, "cap": cap, "evicted": len(victims), "kept": cap,
                "victims": victims[:20]}

    # --- conn log ---
    def log_conn(self, **kw) -> None:
        self.execute(
            """INSERT INTO conn_log(ts,client,proto,target,space_id,space_name,node_id,node_name,ok,detail)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (time.time(), kw.get("client"), kw.get("proto"), kw.get("target"), kw.get("space_id"),
             kw.get("space_name"), kw.get("node_id"), kw.get("node_name"),
             1 if kw.get("ok") else 0, kw.get("detail")),
        )

    def recent_conns(self, limit: int = 200) -> list[sqlite3.Row]:
        return self.q("SELECT * FROM conn_log ORDER BY id DESC LIMIT ?", (limit,))
