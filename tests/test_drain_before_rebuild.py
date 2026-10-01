"""重建实例前必须排空在途长连接。

历史 bug（真机现象）：grok2api 走本代理请求 LLM，流式输出（SSE）进行到一半
连接被断开，客户端看到 HTTP 200 但流戛然而止。

根因：SingBoxManager.apply() 旧实现是 stop → write_config → start。
stop 会 killpg 掉 sing-box 进程组，该实例上所有活跃 TCP 连接（包括正在被
读取的 LLM 长流）被立即终止。订阅刷新默认每 1800 秒、节点探测每 300 秒就
会触发一次重建，所以撞上几乎是必然。

修复：重建前先等活跃连接自然结束（最多 DRAIN_GRACE 秒）再重启。

这里锁住三件事：
  1) 有活跃连接时，apply() 会等待而不是立即 stop；
  2) 排空有上限，超时后仍然重启（不能因为长连接永不退出而卡死刷新）；
  3) 没有活跃连接时不额外等待。
"""
import asyncio
import time

from app.singbox import SingBoxManager


class _FakeInst:
    """记录 stop/start 调用次序的假实例。"""

    def __init__(self, space_id, socks_port=11080):
        self.space_id = space_id
        self.socks_port = socks_port
        self.alive = True
        self.desired = True
        self.calls: list[str] = []

    async def stop(self):
        self.calls.append("stop")
        self.alive = False

    async def start(self):
        self.calls.append("start")
        self.alive = True

    def write_config(self, nodes, ip_strategy="prefer_ipv4"):
        self.calls.append("write_config")


class _FakeDispatcher:
    """用 active_by_port 模拟在途连接。"""

    def __init__(self, counts=None):
        self.active_by_port = counts or {}


def _make_manager(inst, dispatcher, grace=0.2, poll=0.05):
    m = SingBoxManager.__new__(SingBoxManager)
    m._instances = {inst.space_id: inst}
    m._dispatcher = dispatcher
    m._rebuild_cb = None
    m.SOCKS_BLOCK = 512
    m.DRAIN_GRACE = grace
    m.DRAIN_POLL = poll
    return m


def test_waits_for_active_conn_then_restarts():
    """有活跃连接时，stop 必须发生在连接释放之后。"""
    inst = _FakeInst(1)
    disp = _FakeDispatcher({11080: 1})
    m = _make_manager(inst, disp, grace=2.0, poll=0.02)

    async def release_later():
        await asyncio.sleep(0.15)
        disp.active_by_port.pop(11080, None)

    async def run():
        t = asyncio.create_task(release_later())
        await m.apply(1, nodes=[{"tag": "n1"}])
        await t

    t0 = time.monotonic()
    asyncio.run(run())
    elapsed = time.monotonic() - t0

    # 必须真的等过（连接不是立刻释放的）
    assert elapsed >= 0.12, f"未等待在途连接，耗时仅 {elapsed:.3f}s"
    # 顺序锁定：先 stop（旧实例下线），再 write_config + start
    assert inst.calls == ["stop", "write_config", "start"], inst.calls


def test_drain_timeout_still_restarts():
    """连接一直不释放时，到上限后仍要重启，不能永久卡住刷新。"""
    inst = _FakeInst(1)
    disp = _FakeDispatcher({11080: 3})  # 永不释放
    m = _make_manager(inst, disp, grace=0.15, poll=0.02)

    t0 = time.monotonic()
    asyncio.run(m.apply(1, nodes=[{"tag": "n1"}]))
    elapsed = time.monotonic() - t0

    assert elapsed < 1.0, f"排空超时未生效，耗时 {elapsed:.2f}s"
    assert "stop" in inst.calls and "start" in inst.calls, inst.calls


def test_no_active_conn_restarts_immediately():
    """没有在途连接时不该有任何额外等待。"""
    inst = _FakeInst(1)
    disp = _FakeDispatcher({})
    m = _make_manager(inst, disp, grace=5.0, poll=0.05)

    t0 = time.monotonic()
    asyncio.run(m.apply(1, nodes=[{"tag": "n1"}]))
    elapsed = time.monotonic() - t0

    assert elapsed < 0.5, f"空载时仍在等待：{elapsed:.2f}s"
    assert inst.calls == ["stop", "write_config", "start"], inst.calls


def test_count_active_scopes_to_instance_port_block():
    """只统计落在本实例端口段内的连接，不能把别的空间的算进来。"""
    inst = _FakeInst(1, socks_port=11080)
    disp = _FakeDispatcher({11080: 1, 11081: 2, 11592: 9, 12000: 5})
    m = _make_manager(inst, disp)

    # 段内：11080..11591 → 1 + 2 = 3；11592 属于下一个空间的起始端口段
    assert m._count_active(1) == 3


def test_no_dispatcher_degrades_gracefully():
    """没注入 dispatcher（CLI/测试场景）时按 0 处理，退化为直接重启。"""
    inst = _FakeInst(1)
    m = _make_manager(inst, None, grace=5.0)

    assert m._count_active(1) == 0
    t0 = time.monotonic()
    asyncio.run(m.apply(1, nodes=[{"tag": "n1"}]))
    assert time.monotonic() - t0 < 0.5
