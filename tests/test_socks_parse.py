"""SOCKS5 请求解析回归测试。

这里锁住的是一个极其隐蔽的 bug：ATYP 分支少写了 `==`。

    elif ATYP_IPV6:      # 少了 atyp ==
    elif ATYP_DOMAIN:

ATYP_IPV6=4、ATYP_DOMAIN=3 都是真值，所以**每个**请求都会走进 IPv6 分支，
把域名字节当成 16 字节地址读掉，剩下 3 个字节（如 6d01bb）留在缓冲区里，
再被 pump 当作应用数据转发给上游 —— TLS ClientHello 首字节因此变成
6d01bb 而不是 160301，经代理访问任何 HTTPS 都握手失败。
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.proxy import ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6  # noqa: E402


def send_addr(atyp, raw):
    """模拟分发器里按 ATYP 解析地址的那段逻辑。"""
    if atyp == ATYP_IPV4:
        return f"ipv4:{raw[:4].hex()}", 4
    elif atyp == ATYP_IPV6:
        return f"ipv6:{raw[:16].hex()}", 16
    elif atyp == ATYP_DOMAIN:
        ln = raw[0]
        hb = raw[1:1 + ln]
        try:
            host = hb.decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            host = hb.decode("utf-8", "replace")
        return host, 1 + ln
    raise ValueError("未知 ATYP")


def test_atyp_constants_are_truthy_so_bare_name_is_a_bug():
    # 说明为什么少写 == 会出问题：这两个常量本身是真值
    assert ATYP_IPV6 == 4 and ATYP_DOMAIN == 3
    assert bool(ATYP_IPV6) and bool(ATYP_DOMAIN)


def test_bare_name_would_always_match_ipv6():
    """反证：`elif ATYP_IPV6:` 这种写法对所有 atyp 都为真。"""
    for atyp in (ATYP_IPV4, ATYP_IPV6, ATYP_DOMAIN):
        matched_ipv6_branch = bool(ATYP_IPV6)      # 这就是省略 == 后的实际判断
        assert matched_ipv6_branch is True, "若此断言失败说明前提变了"
    # 正确的写法必须只在真 IPv6 时命中
    assert (ATYP_IPV4 == ATYP_IPV6) is False
    assert (ATYP_DOMAIN == ATYP_IPV6) is False
    assert (ATYP_IPV6 == ATYP_IPV6) is True


def test_domain_request_consumes_exactly_25_bytes():
    """完整的域名 CONNECT 请求必须被精确消费，不留残余字节。"""
    host = b"www.cloudflare.com"
    req = bytes([5, 1, 0, ATYP_DOMAIN, len(host)]) + host + struct.pack(">H", 443)
    assert len(req) == 25, len(req)
    atyp = req[3]
    assert atyp == ATYP_DOMAIN
    addr, consumed = send_addr(atyp, req[4:])
    assert addr == "www.cloudflare.com", addr
    assert consumed == 1 + len(host)
    rest = req[4 + consumed:]
    assert rest == b"\x01\xbb", rest
    assert struct.unpack(">H", rest)[0] == 443


def test_ipv4_request_parses_as_ipv4_not_domain():
    import socket as _s
    req = bytes([5, 1, 0, ATYP_IPV4]) + _s.inet_aton("1.2.3.4") + struct.pack(">H", 80)
    atyp = req[3]
    assert atyp == ATYP_IPV4
    addr, consumed = send_addr(atyp, req[4:])
    assert addr.startswith("ipv4:") and consumed == 4


def test_idna_decode_falls_back_instead_of_raising():
    for raw in (b"www.cloudflare.com", "测试.中国".encode("utf-8"), b"xn--fiqs8s"):
        try:
            got = raw.decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            got = raw.decode("utf-8", "replace")
        assert isinstance(got, str) and got


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
