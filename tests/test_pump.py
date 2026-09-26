"""pump 回归测试：分包写入不能丢、半关闭不能截断尾巴。

这两个都是真机上踩出来的 bug，必须锁住：
  1) 客户端分多次写（TLS 多 record）时，数据必须全部转发到上游；
  2) 客户端半关闭后，上游回传的响应必须完整到达客户端（不能变成 0 字节）。
"""
import asyncio
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.proxy import Dispatcher  # noqa: E402


class FakeStats:
    def __init__(self):
        self.bytes_up = 0
        self.bytes_down = 0


def make_dispatcher():
    d = Dispatcher.__new__(Dispatcher)   # 不走 __init__，只测 pump
    d.stats = FakeStats()
    return d


async def scenario(chunks, upstream_reply):
    """用 socketpair 造出「客户端两端」，pump 对接一个会回显的上游。"""
    d = make_dispatcher()
    got_upstream = []

    async def fake_upstream(reader, writer):
        buf = b""
        while True:
            data = await reader.read(65536)
            if not data:
                break
            buf += data
        got_upstream.append(buf)
        if upstream_reply:
            writer.write(upstream_reply)
            await writer.drain()
        writer.close()

    up_server = await asyncio.start_server(fake_upstream, "127.0.0.1", 0)
    up_port = up_server.sockets[0].getsockname()[1]

    # 客户端侧：a 给 pump，b 给测试代码，用来喂数据和收响应
    a, b = socket.socketpair()
    a.setblocking(False)
    b.setblocking(False)
    cli_reader, cli_writer = await asyncio.open_connection(sock=a)
    peer_reader, peer_writer = await asyncio.open_connection(sock=b)

    up_reader, up_writer = await asyncio.open_connection("127.0.0.1", up_port)
    pump = asyncio.create_task(d.pump(cli_reader, cli_writer, up_reader, up_writer))

    for c in chunks:
        peer_writer.write(c)
        await peer_writer.drain()
        await asyncio.sleep(0.02)

    # 半关闭：只关写方向，读方向继续等着收上游响应
    peer_writer.write_eof()

    back = b""
    try:
        while True:
            piece = await asyncio.wait_for(peer_reader.read(65536), timeout=5)
            if not piece:
                break
            back += piece
    except asyncio.TimeoutError:
        pass

    pump.cancel()
    up_server.close()
    await up_server.wait_closed()
    for w in (peer_writer, cli_writer, up_writer):
        try:
            w.close()
        except Exception:  # noqa: BLE001
            pass
    return (got_upstream[0] if got_upstream else b""), back, d.stats


def test_split_writes_and_half_close_reply():
    async def run():
        up, back, stats = await scenario([b"AAA", b"BBB", b"CCC"], b"REPLY-XYZ")
        assert up == b"AAABBBCCC", f"分包数据丢失：上游只收到 {up!r}"
        assert back == b"REPLY-XYZ", f"半关闭后响应被截断：客户端只收到 {back!r}"
        assert stats.bytes_up == 9, stats.bytes_up
        assert stats.bytes_down == 9, stats.bytes_down
    asyncio.run(run())


def test_large_payload_not_truncated():
    async def run():
        big = b"x" * (256 * 1024)
        chunks = [big[i:i + 8192] for i in range(0, len(big), 8192)]
        up, back, _ = await scenario(chunks, b"OK")
        assert up == big, f"大负载被截断：收到 {len(up)} 字节，期望 {len(big)}"
        assert back == b"OK"
    asyncio.run(run())


def test_no_data_is_forwarded_as_empty_not_lost():
    async def run():
        up, back, _ = await scenario([b""], b"EMPTY-OK")
        assert up == b"", up
        assert back == b"EMPTY-OK", back
    asyncio.run(run())


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
    print("泵送测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)
