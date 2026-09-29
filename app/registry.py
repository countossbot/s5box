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
    index: int = 0             # 在空间节点列表中的序号（决定私有 socks 端口）
    socks_port: int = 0        # 该节点专属的本地 socks 入站端口


@dataclass
class Space:
    id: int
    name: str
    enabled: bool
    weight_mode: str
    proxy_mode: str = "global"   # global / direct，见 db.resolve_proxy_mode
    socks_port: int = 0
    nodes: list[Node] = field(default_factory=list)

    def available(self) -> list[Node]:
        """随机池：healthy + unknown。

        cooling / deleted / retry_pending 一律不参与：
        retry_pending 是"本轮失败、等待重测"的节点，不该在重测出结果前被选中。
        """
        return [n for n in self.nodes if n.state in ("healthy", "unknown")]


@dataclass(frozen=True)
class Pick:
    """一次选点结果。

    mode == "direct" 时 space/node 为 None —— 这不是"没选到"，而是"这次连接
    刻意不出节点"。区分二者很重要：调用方据此决定走节点还是本地直连。
    """
    mode: str                 # global / direct
    space: Space | None
    node: Node | None
    index: int = -1           # 在该空间节点列表中的下标（= sing-box tag 里的编号）
    node_port: int | None = None   # 该节点专属 socks 入站端口；direct 时为 None
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
        counts = {"healthy": 0, "unknown": 0, "cooling": 0, "deleted": 0, "retry_pending": 0}
        total = 0
        for s in self._spaces:
            for n in s.nodes:
                total += 1
                counts[n.state] = counts.get(n.state, 0) + 1
        return {"spaces": len(self._spaces), "spaces_active": len(self.active()),
                "nodes": total, **counts}

    def pick(self) -> Pick | None:
        """层级随机：随机空间 → 该空间随机节点。

        默认"空间等权"（每个空间被选概率相同），可在空间上设 weight_mode='node'
        改成按健康节点数加权。整个过程无 await、无共享可变状态，并发安全。

        代理模式在空间上：mode='direct' 的空间不参与随机，直接返回直连结果
        （space/node 为 None）。若所有空间都是 direct，结果仍是直连 —— 这是
        刻意的，模式是用户的显式选择，不该被"池子里没有可用节点"悄悄翻回走节点。
        """
        spaces = self.active()
        if not spaces:
            return None
        proxies = [s for s in spaces if s.proxy_mode != "direct"]
        if not proxies:
            return Pick(mode="direct", space=None, node=None)
        spaces = proxies
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
        index = s.nodes.index(node)
        return Pick(mode="global", space=s, node=node, index=index,
                    node_port=s.socks_port + index)


def tag_map(all_rows) -> dict[int, str]:
    """节点 id → sing-box outbound tag 的唯一映射来源。

    配置生成（main.rebuild_space_instance）和内存注册表都必须用这一个函数，
    否则两边编号一旦不一致，随机选中的节点和实际使用的节点就会错位
    —— 表现为"探测可用但代理全部超时"。
    """
    return {r["id"]: f"n{i}" for i, r in enumerate(sorted(all_rows, key=lambda r: r["id"]))}


def build_registry(db, manager_ports: dict[int, int],
                   proxy_modes: dict[int, str] | None = None) -> Registry:
    """从 SQLite 快照出内存注册表。

    manager_ports: space_id -> sing-box socks 端口
    proxy_modes:   space_id -> 已解析的代理模式（global/direct）；缺省全 global
    """
    proxy_modes = proxy_modes or {}
    reg = Registry()
    out: list[Space] = []
    for sp in db.spaces():
        sp = dict(sp)
        # proxy_mode 由调用方解析后传入（space 覆盖 > 全局默认），理由同 manager_ports：
        # 本模块刻意不依赖 db/config，只吃已算好的快照。缺省 global 保证向后兼容。
        sp["proxy_mode"] = proxy_modes.get(sp["id"], "global")
        # 仅参与随机池的节点（非 deleted），tag 编号由 tag_map 统一决定
        rows = db.nodes(sp["id"], include_deleted=False)
        tag_of = tag_map(db.nodes(sp["id"], include_deleted=True))
        nodes = []
        base_port = manager_ports.get(sp["id"], 0)
        for r in rows:
            tag = tag_of[r["id"]]
            idx = int(tag.lstrip("n") or 0)
            nodes.append(Node(id=r["id"], space_id=sp["id"], name=r["name"], protocol=r["protocol"],
                              host=r["host"], port=r["port"], state=r["state"],
                              outbound_tag=tag, index=idx,
                              socks_port=(base_port + idx if base_port else 0)))
        # proxy_mode 已在 build_registry 的入口解析好（space 覆盖 > 全局），
        # 这里只负责搬运，不在选点路径上再查一次 DB。
        out.append(Space(id=sp["id"], name=sp["name"], enabled=bool(sp["enabled"]),
                         weight_mode=sp["weight_mode"], proxy_mode=sp["proxy_mode"],
                         socks_port=manager_ports.get(sp["id"], 0),
                         nodes=nodes))
    reg.replace(out)
    return reg


def self_check() -> None:
    """池子排除 + 空间等权 + 加权模式的断言（不依赖 DB）。"""
    def mk(state="healthy", n=3):
        return [Node(id=i, space_id=0, name=f"x{i}", protocol="trojan", host="h", port=1, state=state)
                for i in range(n)]
    a = Space(1, "A", True, "space", socks_port=11080, nodes=mk("healthy", 100))
    b = Space(2, "B", True, "space", socks_port=11081, nodes=mk("healthy", 2))
    c = Space(3, "C", True, "space", socks_port=11082,
              nodes=mk("deleted", 50) + mk("cooling", 50))
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
    reg.replace([Space(9, "Z", True, "space", socks_port=11090,
                        nodes=mk("deleted", 5))])
    assert reg.active() == []
    print("registry 自检通过")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    self_check()
