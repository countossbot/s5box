"""连接日志环形缓冲 + 随机选择分布统计。

分布直方图是验证"随机确实生效"的主要手段：如果某个空间占了 99%，说明池子配置有问题。
"""
from __future__ import annotations

import collections
import threading
import time


class LogBuffer:
    def __init__(self, db=None, maxlen: int = 2000):
        self.db = db
        self.buf: collections.deque = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self.persist = True

    def add(self, **kw) -> None:
        row = {
            "ts": time.time(),
            "client": kw.get("client"),
            "proto": kw.get("proto"),
            "target": kw.get("target"),
            "space_id": kw.get("space_id"),
            "space_name": kw.get("space_name"),
            "node_id": kw.get("node_id"),
            "node_name": kw.get("node_name"),
            "ok": bool(kw.get("ok")),
            "detail": kw.get("detail"),
        }
        with self._lock:
            self.buf.append(row)
        if self.persist and self.db is not None:
            try:
                self.db.log_conn(**row)
            except Exception:  # noqa: BLE001
                pass

    def recent(self, limit: int = 200) -> list[dict]:
        with self._lock:
            items = list(self.buf)[-limit:]
        items.reverse()      # 最新在前
        return items

    def distribution(self, last: int = 200) -> dict:
        with self._lock:
            items = list(self.buf)[-last:]
        by_space: collections.Counter = collections.Counter()
        by_node: collections.Counter = collections.Counter()
        ok = fail = 0
        for r in items:
            key = f'{r["space_id"]}:{r["space_name"]}'
            by_space[key] += 1
            if r["node_name"]:
                by_node[f'{r["space_id"]}/{r["node_name"]}'] += 1
            if r["ok"]:
                ok += 1
            else:
                fail += 1
        return {"sampled": len(items), "ok": ok, "fail": fail,
                "by_space": dict(by_space.most_common(20)),
                "by_node": dict(by_node.most_common(20))}
