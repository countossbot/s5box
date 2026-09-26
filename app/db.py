"""SQLite 存储层。stdlib sqlite3 + WAL，够用就不引 ORM。

只被调度器/API 写；代理分发器从不碰这里（它读 registry 的内存快照）。
"""
from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any, Iterable

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
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    # --- 基础 ---
    def q(self, sql: str, args: Iterable = ()) -> list[sqlite3.Row]:
        with self._lock:
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

    def record_probe(self, node_id: int, ok: bool, delay_ms: int | None, error: str | None,
                     exit_ip: str | None, failure_threshold: int, auto_delete: bool) -> str:
        """写入探测结果并推进状态机。返回新状态。"""
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
        self.execute("UPDATE nodes SET state='deleted', deletion_reason=? WHERE id=?", (reason, node_id))

    def purge_probes(self, keep_seconds: int = 7 * 86400) -> None:
        self.execute("DELETE FROM probes WHERE ts < ?", (time.time() - keep_seconds,))

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
