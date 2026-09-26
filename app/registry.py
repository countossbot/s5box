"""内存注册表：节点池快照 + 层级随机选择。

关键约束：代理分发器只读这里的快照，永远不碰 SQLite；刷新时整体替换引用，读路径零锁。
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass, field

# SystemRandom = os.urandom 底层，并发下无共享状态
_rng = random.SystemRandom()


@dataclass
class Node:
    id: int
    space_id: int
    name: str
    protocol: str
    host: str
    port: int
    state: str
    outbound_tag: str = ""     # sing-box 里的 tag，如 n17


@dataclass
class Space:
    id: int
    name: str
    enabled: bool
    weight_mode: str
    socks_port: int
    nodes: list[Node] = field(default_factory=list)

    def available(self) -> list[Node]:
        """随机池：healthy + unknown。cooling/deleted 一律不参与。"""
        return [n for n in self.nodes if n.state in ("healthy", "unknown")]


@dataclass
class Pick:
    space: Space
    node: Node
    index: int      # 在该空间节点列表中的下标（= sing-box tag 里的编号）


class Registry:
    """整个节点池的内存快照。写方（调度器）调用 replace()，读方（分发器）调 pick()。"""

    def __init__(self) -> None:
        self._spaces: tuple[Space, ...] = ()     # 不可变元组，替换即原子

    def replace(self, spaces: list[Space]) -> None:
        self._spaces = tuple(spaces)

    def spaces(self) -> tuple[Space, ...]:
        return self._spaces

    def active(self) -> list[Space]:
        return [s for s in self._spaces if s.enabled and s.available()]

    def stats(self) -> dict:
        total = healthy = unknown = cooling = deleted = 0
        for s in self._spaces:
            for n in s.nodes:
                total += 1
                if n.state == "healthy":
                    healthy += 1
                elif n.state == "unknown":
                    unknown += 1
                elif n.state == "cooling":
                    cooling += 1
                else:
                    deleted += 1
        return {"spaces": len(self._spaces), "spaces_active": len(self.active()),
                "nodes": total, "healthy": healthy, "unknown": unknown,
                "cooling": cooling, "deleted": deleted}

    def pick(self) -> Pick | None:
        """层级随机：随机空间 → 该空间随机节点。

        默认"空间等权"（每个空间被选概率相同），可在空间上设 weight_mode='node'
        改成按健康节点数加权。整个过程无 await、无共享可变状态，并发安全。
        """
        spaces = self.active()
        if not spaces:
            return None
        weighted = [s for s in spaces if s.weight_mode == "node"]
        if weighted and len(weighted) != len(spaces):
            # 混合模式：等权空间和加权空间按各自的比例参与（这里简化为统一按池子大小加权）
            pool = [(s, len(s.available())) for s in spaces]
            total = sum(w for _, w in pool) or 1
            r = _rng.randrange(total)
            acc = 0
            for s, w in pool:
                acc += w
                if r < acc:
                    return self._pick_node(s)
            return self._pick_node(spaces[0])
        if weighted:
            return self._pick_weighted(spaces)
        # 空间等权：打乱后取第一个有可用节点的
        order = list(spaces)
        _rng.shuffle(order)
        for s in order:
            p = self._pick_node(s)
            if p:
                return p
        return None

    def _pick_weighted(self, spaces: list[Space]) -> Pick | None:
        pool = [(s, len(s.available())) for s in spaces]
        total = sum(w for _, w in pool)
        if total <= 0:
            return None
        r = _rng.randrange(total)
        acc = 0
        for s, w in pool:
            acc += w
            if r < acc:
                return self._pick_node(s)
        return self._pick_node(spaces[-1])

    def _pick_node(self, s: Space) -> Pick | None:
        avail = s.available()
        if not avail:
            return None
        node = avail[_rng.randrange(len(avail))]
        # tag 编号是节点在完整列表里的下标，不能用 avail 的下标
        return Pick(space=s, node=node, index=s.nodes.index(node))


def tag_map(all_rows) -> dict[int, str]:
    """节点 id → sing-box outbound tag 的唯一映射来源。

    配置生成（main.rebuild_space_instance）和内存注册表都必须用这一个函数，
    否则两边编号一旦不一致，随机选中的节点和实际使用的节点就会错位
    —— 表现为"探测可用但代理全部超时"。
    """
    return {r["id"]: f"n{i}" for i, r in enumerate(sorted(all_rows, key=lambda r: r["id"]))}


def build_registry(db, manager_ports: dict[int, int]) -> Registry:
    """从 SQLite 快照出内存注册表。传给 manager_ports: space_id -> sing-box socks 端口。"""
    reg = Registry()
    out: list[Space] = []
    for sp in db.spaces():
        # 仅参与随机池的节点（非 deleted），tag 编号由 tag_map 统一决定
        rows = db.nodes(sp["id"], include_deleted=False)
        tag_of = tag_map(db.nodes(sp["id"], include_deleted=True))
        nodes = []
        for r in rows:
            nodes.append(Node(id=r["id"], space_id=sp["id"], name=r["name"], protocol=r["protocol"],
                              host=r["host"], port=r["port"], state=r["state"],
                              outbound_tag=tag_of[r["id"]]))
        out.append(Space(id=sp["id"], name=sp["name"], enabled=bool(sp["enabled"]),
                         weight_mode=sp["weight_mode"], socks_port=manager_ports.get(sp["id"], 0),
                         nodes=nodes))
    reg.replace(out)
    return reg


def self_check() -> None:
    """池子排除 + 空间等权 + 加权模式的断言（不依赖 DB）。"""
    def mk(state="healthy", n=3):
        return [Node(id=i, space_id=0, name=f"x{i}", protocol="trojan", host="h", port=1, state=state)
                for i in range(n)]
    a = Space(1, "A", True, "space", 11080, mk("healthy", 100))
    b = Space(2, "B", True, "space", 11081, mk("healthy", 2))
    c = Space(3, "C", True, "space", 11082, mk("deleted", 50) + mk("cooling", 50))
    reg = Registry()
    reg.replace([a, b, c])

    assert reg.active() == [a, b], "全是 deleted/cooling 的空间不该进池子"
    counts = {1: 0, 2: 0}
    for _ in range(6000):
        p = reg.pick()
        assert p is not None
        counts[p.space.id] += 1
    # 空间等权：100 节点 vs 2 节点，两边都应该接近 50%
    assert 0.40 < counts[1] / 6000 < 0.60, f"空间等权被打破：{counts}"

    a.weight_mode = b.weight_mode = "node"
    counts = {1: 0, 2: 0}
    for _ in range(6000):
        counts[reg.pick().space.id] += 1
    assert counts[1] / 6000 > 0.90, f"加权模式应向大空间倾斜：{counts}"

    reg.replace([Space(9, "Z", True, "space", 11090, mk("deleted", 5))])
    assert reg.pick() is None, "无可用节点必须返回 None（不能抛异常）"
    assert reg.active() == []
    print("registry 自检通过")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    self_check()
