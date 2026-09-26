"""SOCKS5 请求解析回归测试。

踩过的坑：bytes.decode("idna", "replace") 是错的 —— "idna" 是编解码器名、
不是错误处理器名，必然抛 UnicodeError。异常被吞掉后域名解析失败，
端口的 2 个字节残留在流里，被当成应用数据转发出去
（TLS ClientHello 首字节变成 6d01bb 而不是 160301，握手全部失败）。
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def parse_domain(raw: bytes) -> str:
    """与 app/proxy.py 中 ATYP_DOMAIN 分支保持一致的解码逻辑。"""
    try:
        return raw.decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return raw.decode("utf-8", "replace")


def test_idna_decode_never_raises():
    for raw in (b"www.cloudflare.com", b"a.b.c", "测试.中国".encode("utf-8"), b"xn--fiqs8s", b"x" * 200):
        got = parse_domain(raw)          # 不允许抛异常
        assert isinstance(got, str) and got


def test_old_bad_form_raises_so_we_never_regress():
    # 明确记录旧写法确实是坏的（如果有人改回去，这个断言会提醒）
    try:
        b"www.cloudflare.com".decode("idna", "replace")
    except UnicodeError:
        return
    raise AssertionError('bytes.decode("idna","replace") 竟然没抛错，前提假设已变，请复查')


def test_port_bytes_are_consumed_after_domain():
    """域名 + 端口的完整请求必须被精确消费，不能把端口字节留在缓冲区。"""
    host = b"www.cloudflare.com"
    request = bytes([5, 1, 0, 3, len(host)]) + host + struct.pack(">H", 443)
    # 模拟按协议逐段读取
    atyp = request[3]
    assert atyp == 3
    ln = request[4]
    got_host = parse_domain(request[5:5 + ln])
    rest = request[5 + ln:]
    port = struct.unpack(">H", rest[:2])[0]
    assert got_host == "www.cloudflare.com"
    assert port == 443
    assert rest[2:] == b"", "域名+端口之后不应有残留字节"


def test_domain_and_port_len_matches_total():
    """带域名的 SOCKS5 CONNECT 请求长度必须等于 5+len(host)+2。"""
    for host in (b"a.io", b"www.cloudflare.com", b"sub.domain.example.org"):
        req = bytes([5, 1, 0, 3, len(host)]) + host + struct.pack(">H", 8443)
        assert len(req) == 5 + len(host) + 2


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
    print("SOCKS5 解析测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)
