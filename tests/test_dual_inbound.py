"""方案 B（每节点双入站）回归测试。

背景：过去一个空间只有一个 dns.strategy，探测一次只能真正拿到一族出口 IP。
方案 B 给每个节点加一个 v6 专用入站，两个入站各自在 route 里把解析族钉死，
于是同一节点能同时探到 v4 和 v6 两个出口 IP。

这里锁死三件事，都是最容易静默出错、出错了还"看起来正常"的：
  1. 每个存活节点确实生成了 v4/v6 两个入站，端口按 V6_PORT_OFFSET 对齐；
  2. 端口段不重叠 —— 含「节点数超过 V6_PORT_OFFSET」的极端情况，
     v6 段绝不能溢进相邻空间；
  3. 探测 URL 与入站按族配对（v4 用 v4 地址、v6 用 v6 地址）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import config as app_config  # noqa: E402
from app.probe import ProbeRunner  # noqa: E402
from app.singbox import SingBoxManager, SpaceInstance  # noqa: E402


def _mgr() -> SingBoxManager:
    """不启动任何进程，只要端口分配逻辑。"""
    m = SingBoxManager.__new__(SingBoxManager)
    m._instances = {}
    m._next_socks = 11080
    m._next_api = 21080
    m.workdir = Path("/tmp")
    m.note_socks_extent = lambda sid, block: None  # 不触发重建
    return m


def _node(i: int, kind: str = "socks") -> dict:
    """第 i 个节点的出站配置（下标即编号，保证生成出来的是 n{i}）。"""
    import json
    if kind == "socks":
        ob = {"type": "socks", "version": "5", "tag": "x",
              "server": "example.com", "server_port": 1080}
    else:
        ob = {}
    return {"outbound_json": json.dumps(ob)}


# ---------------------------------------------------------------- 入站生成


def test_每个存活节点都有v4和v6两个入站():
    si = SpaceInstance(1, Path("/tmp"), 11080, 19080)
    cfg = si.build_config([_node(0), _node(1)], "warn", "prefer_ipv4")
    tags = [i["tag"] for i in cfg["inbounds"]]
    assert tags == ["in0", "in1", "in0v6", "in1v6"], tags


def test_v6入站端口等于基准加偏移():
    """v6 入站端口 = socks_port + V6_PORT_OFFSET + i，且不和 v4 段撞。"""
    si = SpaceInstance(1, Path("/tmp"), 11080, 19080)
    off = SingBoxManager.V6_PORT_OFFSET
    cfg = si.build_config([_node(0), _node(1), _node(2)], "warn", "prefer_ipv4")
    ports = {i["tag"]: i["listen_port"] for i in cfg["inbounds"]}
    assert ports["in0"] == 11080 and ports["in1"] == 11081 and ports["in2"] == 11082, ports
    assert ports["in0v6"] == 11080 + off, ports
    assert ports["in1v6"] == 11081 + off, ports
    assert ports["in2v6"] == 11082 + off, ports
    # 也验证实例方法（探测侧就是用它取端口的）
    assert si.node_v6_port(2) == 11082 + off


def test_被跳过的脏节点不留下孤儿v6入站():
    """半截配置（缺 type/server）整条跳过，不能只生成 v4 或只生成 v6。"""
    si = SpaceInstance(1, Path("/tmp"), 11080, 19080)
    cfg = si.build_config([_node(0), _node(1, kind="bad"), _node(2)], "warn", "prefer_ipv4")
    tags = [i["tag"] for i in cfg["inbounds"]]
    assert tags == ["in0", "in2", "in0v6", "in2v6"], tags


def test_两个入站各自用resolve动作钉死解析族():
    """这是方案 B 的核心：v4 入站强制 ipv4_only、v6 入站强制 ipv6_only。

    必须用 action=resolve 的 strategy —— 1.14.2 的 route rule 不接受
    domain_strategy 字段（实测报 unknown field），inbounds[].domain_strategy
    也已在 1.13 移除。写错字段名 sing-box 会直接 check 失败。
    """
    si = SpaceInstance(1, Path("/tmp"), 11080, 19080)
    cfg = si.build_config([_node(0)], "warn", "prefer_ipv4")
    resolves = [r for r in cfg["route"]["rules"] if r.get("action") == "resolve"]
    assert {"inbound": ["in0"], "action": "resolve", "strategy": "ipv4_only"} in resolves, resolves
    assert {"inbound": ["in0v6"], "action": "resolve", "strategy": "ipv6_only"} in resolves, resolves
    # 全局 dns.strategy 仍然保留（作为未匹配流量的兜底），不受影响
    assert cfg["dns"]["strategy"] == "prefer_ipv4"


def test_两个入站都转发到同一个出站():
    """v4/v6 入站必须走同一个 outbound，否则"同一节点两族出口"不成立。"""
    si = SpaceInstance(1, Path("/tmp"), 11080, 19080)
    cfg = si.build_config([_node(0)], "warn", "prefer_ipv4")
    fwd = [r for r in cfg["route"]["rules"] if "outbound" in r]
    assert {"inbound": ["in0"], "outbound": "n0"} in fwd, fwd
    assert {"inbound": ["in0v6"], "outbound": "n0"} in fwd, fwd


# ---------------------------------------------------------------- 端口不重叠


def _reserved(si):
    """某空间「预留」的总区间 [lo, hi]（闭）。

    真源是 _occupied()：它按 socks_port + socks_block - 1 算到哪，
    别的空间就被挡在哪儿。注意 socks_block 是**含 v6 偏移的总跨度**，
    而不是单段的长度 —— 这点搞错就会误判"不重叠"。
    """
    return si.socks_port, si.socks_port + si.socks_block - 1


def test_同一空间的v4段和v6段不重叠():
    """同一空间内部：v6 段起点必须在 v4 段末尾之后。"""
    m = _mgr()
    si = m.instance(1)
    n = 10
    si.build_config([_node(i) for i in range(n)], "warn", "prefer_ipv4")
    v4lo, v4hi = si.socks_port, si.socks_port + n - 1          # v4 实际用到哪
    v6lo, v6hi = si.node_v6_port(0), si.node_v6_port(n - 1)    # v6 实际用到哪
    assert v6lo > v4hi, f"v6 段侵入 v4 段：v4=({v4lo},{v4hi}) v6=({v6lo},{v6hi})"
    # 两段都必须在自己的预留区间内（否则会溢到别的空间）
    lo, hi = _reserved(si)
    assert lo <= v4lo and v6hi <= hi, f"越出预留区间 ({lo},{hi})"


def test_多空间的v4与v6段两两不重叠():
    """多个空间的预留区间两两不重叠（这是端口分配的硬不变量）。"""
    m = _mgr()
    sis = []
    for i in range(1, 6):
        si = m.instance(i)
        si.build_config([_node(j) for j in range(20)], "warn", "prefer_ipv4")
        sis.append(si)
    spans = [_reserved(si) for si in sis]
    for a in range(len(spans)):
        for b in range(a + 1, len(spans)):
            (alo, ahi), (blo, bhi) = spans[a], spans[b]
            assert ahi < blo or bhi < alo, f"重叠：({alo},{ahi}) vs ({blo},{bhi})"
    # 再把两段（视作独立占用）也两两比一遍，覆盖"socks_block 算错"这类错误
    segs = []
    for si in sis:
        n = 20
        segs.append((si.socks_port, si.socks_port + n - 1))
        segs.append((si.node_v6_port(0), si.node_v6_port(n - 1)))
    for a in range(len(segs)):
        for b in range(a + 1, len(segs)):
            (alo, ahi), (blo, bhi) = segs[a], segs[b]
            assert ahi < blo or bhi < alo, f"段重叠：({alo},{ahi}) vs ({blo},{bhi})"


def test_节点数超过偏移量时v6段不溢出到别的空间():
    """极端情况：节点数 > V6_PORT_OFFSET，v6 段会越过初始块。

    这时 socks_block 必须按需扩容到 V6_PORT_OFFSET + max(used) + 1，
    且下一个空间拿到的起始端口必须在这个扩容后的段之后 ——
    否则两个空间的端口会交叠，连 A 的端口实际走到 B 的节点。
    """
    off = SingBoxManager.V6_PORT_OFFSET
    m = _mgr()
    a = m.instance(1)
    n_a = off + 8                      # 故意超过偏移量
    a.build_config([_node(i) for i in range(n_a)], "warn", "prefer_ipv4")
    b = m.instance(2)

    # A 的 v6 段最后一个端口就是它实际占用的最后一个端口
    a_v6_last = a.node_v6_port(n_a - 1)
    assert a_v6_last == a.socks_port + off + n_a - 1
    # 块必须扩容到能容纳 v6 段
    assert a.socks_block == off + n_a, (a.socks_block, off + n_a)
    # B 的起点必须在 A 的预留区间之后
    assert b.socks_port > a_v6_last, \
        f"B 起点 {b.socks_port} 落在 A 的 v6 段末尾 {a_v6_last} 之内"
    assert b.socks_port > _reserved(a)[1]


def test_扩容登记的是含v6偏移的总跨度():
    """note_socks_extent 收到的块大小必须已含 V6_PORT_OFFSET，
    否则 _occupied 算出来的占用区间会漏掉 v6 段，别的空间就能抢这段端口。"""
    seen = []
    m = _mgr()
    m.note_socks_extent = lambda sid, block: seen.append((sid, block))
    si = m.instance(7)
    si.build_config([_node(i) for i in range(3)], "warn", "prefer_ipv4")
    # 块必须扩到覆盖 v6 段：256 + 3 = 259（初始 512 更大，所以不触发登记）
    assert si.socks_block >= SingBoxManager.V6_PORT_OFFSET + 3
    # 节点数超过初始块时才真的登记扩容
    seen.clear()
    big = m.instance(8)
    n_big = SingBoxManager.SOCKS_BLOCK + 5
    big.build_config([_node(i) for i in range(n_big)], "warn", "prefer_ipv4")
    assert seen, "大节点数时扩容没有被登记"
    assert seen[-1][1] == SingBoxManager.V6_PORT_OFFSET + n_big, seen
    assert big.socks_block == SingBoxManager.V6_PORT_OFFSET + n_big


# ---------------------------------------------------------------- URL 按族配对


def test_按族挑出口ip查询地址():
    st = {"exit_ip_url_v4": "https://api-ipv4.ip.sb/ip",
          "exit_ip_url_v6": "https://api-ipv6.ip.sb/ip",
          "exit_ip_url": "https://api.ipify.org"}
    assert ProbeRunner.family_url(st, "ipv4") == "https://api-ipv4.ip.sb/ip"
    assert ProbeRunner.family_url(st, "ipv6") == "https://api-ipv6.ip.sb/ip"


def test_没有分族配置时回退到旧exit_ip_url():
    """老库/老配置向后兼容：只有旧的 exit_ip_url 也要能用。"""
    st = {"exit_ip_url": "https://api.ipify.org"}
    assert ProbeRunner.family_url(st, "ipv4") == "https://api.ipify.org"
    assert ProbeRunner.family_url(st, "ipv6") == "https://api.ipify.org"


def test_出厂默认的两个族地址():
    """默认配置里两个分族地址必须存在，且互不相同（否则方案 B 白做）。"""
    v4 = app_config.DEFAULT_SETTINGS["exit_ip_url_v4"]
    v6 = app_config.DEFAULT_SETTINGS["exit_ip_url_v6"]
    assert v4 == "https://api-ipv4.ip.sb/ip", v4
    assert v6 == "https://api-ipv6.ip.sb/ip", v6
    assert v4 != v6
    # 旧的单值配置必须保留，供未分族的调用方兜底
    assert "exit_ip_url" in app_config.DEFAULT_SETTINGS


# ---------------------------------------------------------------- 双族结果落地


def test_两族都探到时期望各自入站端口():
    """端到端的小验证：两族都成功时，ip_v4/ip_v6 都要带回来。"""
    import asyncio
    from types import SimpleNamespace

    pr = ProbeRunner.__new__(ProbeRunner)
    calls = []

    async def fake_family_available(fam):
        return True

    async def fake_probe_one(space_id, tag, url, timeout_ms, fallback_urls=None,
                             want_ip=False, family=None, port=None):
        calls.append((family, port, url))
        ip = "1.2.3.4" if family == "ipv4" else "2001:db8::1"
        return True, 10, None, ip

    pr.family_available = fake_family_available
    pr.probe_one = fake_probe_one
    pr.reg = SimpleNamespace(spaces=lambda: [SimpleNamespace(
        id=1, nodes=[SimpleNamespace(outbound_tag="n0", socks_port=11080,
                                     socks_port_v6=11080 + 256)])])
    st = {"exit_ip_url_v4": "https://api-ipv4.ip.sb/ip",
          "exit_ip_url_v6": "https://api-ipv6.ip.sb/ip"}

    out = asyncio.run(pr.probe_node_both_families(
        1, "n0", "http://probe", 5000, "prefer_ipv4", True, None, st=st))
    # 主族成功 → used_family 是 v4，且两族 IP 都该带回来（方案 B 的意义）
    assert out[0] is True and out[4] == "ipv4", out
    assert out[5] == "1.2.3.4" and out[6] == "2001:db8::1", out
    # 两族各走各自入站端口与 URL
    assert calls == [
        ("ipv4", 11080, "https://api-ipv4.ip.sb/ip"),
        ("ipv6", 11080 + 256, "https://api-ipv6.ip.sb/ip"),
    ], calls


def test_补探另一族失败不影响成功结论():
    """主族成功、补探另一族失败时：仍然 ok、used_family 仍是主族，
    只是另一族 IP 记 None。绝不能因为补探失败把好节点判坏。"""
    import asyncio
    from types import SimpleNamespace

    pr = ProbeRunner.__new__(ProbeRunner)

    async def fake_family_available(fam):
        return True

    async def fake_probe_one(space_id, tag, url, timeout_ms, fallback_urls=None,
                             want_ip=False, family=None, port=None):
        if family == "ipv4":
            return True, 10, None, "1.2.3.4"
        return False, None, "v6 不通", None

    pr.family_available = fake_family_available
    pr.probe_one = fake_probe_one
    pr.reg = SimpleNamespace(spaces=lambda: [SimpleNamespace(
        id=1, nodes=[SimpleNamespace(outbound_tag="n0", socks_port=11080,
                                     socks_port_v6=11080 + 256)])])
    st = {"exit_ip_url_v4": "https://api-ipv4.ip.sb/ip",
          "exit_ip_url_v6": "https://api-ipv6.ip.sb/ip"}
    out = asyncio.run(pr.probe_node_both_families(
        1, "n0", "http://probe", 5000, "prefer_ipv4", True, None, st=st))
    assert out[0] is True, "补探失败不能改变 ok"
    assert out[4] == "ipv4" and out[5] == "1.2.3.4", out
    assert out[6] is None, out


def test_不取IP时不做多余请求():
    """want_ip=False（只要延迟）时不补探另一族。"""
    import asyncio
    from types import SimpleNamespace

    pr = ProbeRunner.__new__(ProbeRunner)
    calls = []

    async def fake_family_available(fam):
        return True

    async def fake_probe_one(space_id, tag, url, timeout_ms, fallback_urls=None,
                             want_ip=False, family=None, port=None):
        calls.append(family)
        return True, 10, None, None

    pr.family_available = fake_family_available
    pr.probe_one = fake_probe_one
    pr.reg = SimpleNamespace(spaces=lambda: [SimpleNamespace(
        id=1, nodes=[SimpleNamespace(outbound_tag="n0", socks_port=11080,
                                     socks_port_v6=11080 + 256)])])
    out = asyncio.run(pr.probe_node_both_families(
        1, "n0", "http://probe", 5000, "prefer_ipv4", False, None))
    assert out[0] is True
    assert calls == ["ipv4"], calls


def test_prefer策略下两族分别走各自入站端口与URL():
    """v4 失败 → 必须继续 v6，且 v6 用 v6 端口 + v6 URL。"""
    import asyncio
    from types import SimpleNamespace

    pr = ProbeRunner.__new__(ProbeRunner)
    calls = []

    async def fake_family_available(fam):
        return True

    async def fake_probe_one(space_id, tag, url, timeout_ms, fallback_urls=None,
                             want_ip=False, family=None, port=None):
        calls.append((family, port, url))
        if family == "ipv4":
            return False, None, "v4 不通", None
        return True, 20, None, "2001:db8::1"

    pr.family_available = fake_family_available
    pr.probe_one = fake_probe_one
    pr.reg = SimpleNamespace(spaces=lambda: [SimpleNamespace(
        id=1, nodes=[SimpleNamespace(outbound_tag="n0", socks_port=11080,
                                     socks_port_v6=11080 + 256)])])
    st = {"exit_ip_url_v4": "https://api-ipv4.ip.sb/ip",
          "exit_ip_url_v6": "https://api-ipv6.ip.sb/ip"}

    out = asyncio.run(pr.probe_node_both_families(
        1, "n0", "http://probe", 5000, "prefer_ipv4", True, None, st=st))
    assert out[0] is True and out[4] == "ipv6", out
    assert out[6] == "2001:db8::1", out
    assert calls == [
        ("ipv4", 11080, "https://api-ipv4.ip.sb/ip"),
        ("ipv6", 11080 + 256, "https://api-ipv6.ip.sb/ip"),
    ], calls
