"""端口分配回归测试。

历史 bug：SingBoxManager 每建一个空间只把端口游标 +1，而每个空间要给
「第 i 个节点」分配 socks_port + i。于是第二个空间的基础端口落在第一个
空间的节点端口区间内 —— 连 A 空间的端口实际会走到 B 空间的节点，
而且面板显示完全正常，极难排查。

这里锁死「每个空间独占一个不重叠的端口块」这个不变量。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.singbox import SingBoxManager, SpaceInstance  # noqa: E402


def _mgr() -> SingBoxManager:
    """不启动任何进程，只要端口分配逻辑。"""
    m = SingBoxManager.__new__(SingBoxManager)
    m._instances = {}
    m._next_socks = 11080
    m._next_api = 21080
    m.workdir = Path("/tmp")
    return m


def test_每个空间的基础端口互不重叠():
    m = _mgr()
    bases = [m.instance(i).socks_port for i in (1, 2, 3, 4, 5)]
    assert len(set(bases)) == len(bases), f"基础端口重复：{bases}"


def test_端口块之间留有整块间距():
    """关键：空间 A 的节点端口 [base, base+BLOCK-1] 不能侵入空间 B。"""
    m = _mgr()
    block = SingBoxManager.SOCKS_BLOCK
    bases = [m.instance(i).socks_port for i in (1, 2, 3)]
    for lo, hi in zip(bases, bases[1:]):
        assert hi >= lo + block, (
            f"块间距不足：{lo} -> {hi}，需要至少 {block}；"
            f"A 空间节点端口会溢出到 B 空间")


def test_满节点时仍不越界():
    """每个空间塞满 BLOCK-1 个节点（最大下标 BLOCK-1）仍不得越界。"""
    m = _mgr()
    block = SingBoxManager.SOCKS_BLOCK
    a, b = m.instance(1).socks_port, m.instance(2).socks_port
    assert a + (block - 1) < b, "空间1 的最后一个节点端口侵入了空间2"


def test_instance_幂等():
    """同一 space_id 反复取必须返回同一实例，否则端口会不断被消耗。"""
    m = _mgr()
    a = m.instance(42)
    assert m.instance(42) is a
    assert len(m._instances) == 1


def test_节点数超初始块时自动扩容而不是报错():
    """cap<=0（不限量）是合法配置，节点数无上限；越界必须扩容而非让空间起不来。"""
    inst = SpaceInstance(1, Path("/tmp"), 11080, 21080)
    n = SingBoxManager.SOCKS_BLOCK + 5
    nodes = [{"outbound_json": '{"type":"socks","server":"1.1.1.1","server_port":1080}'}
             for _ in range(n)]
    inst.build_config(nodes)                      # 不应抛异常
    assert inst.socks_block >= n, "块未随节点数扩容"


def test_扩容后的空间会被后续空间避让():
    m = _mgr()
    a = m.instance(1)
    n = SingBoxManager.SOCKS_BLOCK + 5
    a.build_config([{"outbound_json": '{"type":"socks","server":"1.1.1.1","server_port":1080}'}
                    for _ in range(n)])
    m.note_socks_extent(1, a.socks_block)         # 模拟 build_config 的登记
    b = m.instance(2)
    assert b.socks_port > a.socks_port + a.socks_block - 1, (
        f"A 扩容到 {a.socks_block} 后 B 仍压上来：A={a.socks_port} B={b.socks_port}")


def test_api_端口不得落进自身socks块():
    """回归：clash_api 端口曾经落进同一个空间的 socks 区间。

    历史 bug：instance() 里 _alloc_socks_base() 与 _alloc_api_port() 作为构造
    参数从左到右分别求值，而 _instances[space_id] = inst 发生在两者之后。
    于是 _alloc_api_port() 查询 _occupied() 时看不到刚选定的 socks 块，当
    API 基数恰好在 socks 区间附近时（默认 base=12000，第二空间 socks 从
    12001 起），api 端口就等于自己 socks 块的首个端口，sing-box 启动即
    FATAL: bind: address already in use。

    这里把两处基数设成会触发该错位的值，锁死「同一空间内 api 端口与
    socks 块互不相交」这一不变量。
    """
    m = SingBoxManager.__new__(SingBoxManager)
    m._instances = {}
    m._next_socks = 11080
    m._next_api = 12000          # 与默认 SINGBOX_API_PORT_BASE 一致
    m.workdir = Path("/tmp")

    block = SingBoxManager.SOCKS_BLOCK
    for sid in (32, 34, 36):
        inst = m.instance(sid)
        lo, hi = inst.socks_port, inst.socks_port + block - 1
        assert not (lo <= inst.api_port <= hi), (
            f"空间 {sid}: api_port={inst.api_port} 落进自身 socks 块 "
            f"[{lo}, {hi}]，sing-box 将因端口占用启动失败")


def test_多空间下_api端口全局唯一():
    """api 端口同样不能跨空间重复。"""
    m = SingBoxManager.__new__(SingBoxManager)
    m._instances = {}
    m._next_socks = 11080
    m._next_api = 12000
    m.workdir = Path("/tmp")

    apis = [m.instance(i).api_port for i in range(1, 8)]
    assert len(set(apis)) == len(apis), f"api 端口重复：{apis}"


def _run_standalone() -> int:
    """CI 以 `python tests/xxx.py` 方式直接执行本文件，需要显式入口。"""
    import traceback

    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} 通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_standalone())
