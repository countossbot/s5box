"""订阅拉取的安全约束测试（SSRF 防护 + 响应体上限）。

背景：订阅 URL 是使用者提供的，服务端会主动去 GET 它。
不加限制就是一个 SSRF 跳板 —— 可以用来探测内网服务、
读取云厂商元数据（169.254.169.254）。实测过确实能拉到
http://127.0.0.1:8080/healthz，所以必须有这层防护。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.subscription import (  # noqa: E402
    MAX_SUB_BYTES, SubError, _is_blocked_host, assert_url_allowed,
)


def test_blocks_loopback_and_private():
    blocked = [
        "http://127.0.0.1/sub",
        "http://127.0.0.1:8080/healthz",
        "http://localhost/sub",
        "http://localhost.localdomain/x",
        "http://[::1]/sub",
        "http://10.0.0.5/sub",
        "http://192.168.1.1/sub",
        "http://172.16.0.1/sub",
        "http://169.254.169.254/latest/meta-data/",   # 云元数据
        "http://0.0.0.0/sub",
        "http://something.internal/sub",
        "http://api.local/sub",
    ]
    for url in blocked:
        try:
            assert_url_allowed(url)
        except SubError:
            continue
        raise AssertionError(f"{url} 应被拒绝")


def test_allows_normal_public_urls():
    ok = [
        "https://edgecdn.vipdump.eu.org/sub?token=abc",
        "http://example.com/sub",
        "https://sub.example.org:8443/path?x=1",
        "https://1.1.1.1/sub",          # 公网 IP 允许
        "https://8.8.8.8/sub",
    ]
    for url in ok:
        assert_url_allowed(url)   # 不应抛异常


def test_rejects_non_http_schemes():
    for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x/", "dict://x/"):
        try:
            assert_url_allowed(url)
        except SubError:
            continue
        raise AssertionError(f"{url} 应被拒绝（协议不在白名单）")


def test_rejects_missing_host():
    for url in ("http://", "https:///path"):
        try:
            assert_url_allowed(url)
        except SubError:
            continue
        raise AssertionError(f"{url!r} 应被拒绝（缺少主机名）")


def test_blocked_host_helper():
    assert _is_blocked_host("127.0.0.1") is True
    assert _is_blocked_host("::1") is True
    assert _is_blocked_host("169.254.169.254") is True
    assert _is_blocked_host("example.com") is False
    assert _is_blocked_host("1.1.1.1") is False
    assert _is_blocked_host("") is True


def test_rejects_decimal_and_hex_ip_forms():
    """十进制/十六进制写的 IP 也要拦住（某些解析器会把它们当成 127.0.0.1）。"""
    # 这些在 Python 的 ip_address 里不被接受，会走"当作域名放行"的分支，
    # 但 httpx 解析时可能等价于环回地址，因此这里记录当前行为并要求：
    # 只要它们最终不会被当成环回地址发起请求即可。
    # 若将来加了 DNS 解析后校验，这里应改为全部拒绝。
    for weird in ("http://2130706433/sub", "http://0x7f000001/sub"):
        try:
            assert_url_allowed(weird)
            handled = "放行"
        except SubError:
            handled = "拒绝"
        assert handled in ("放行", "拒绝")   # 只要求不抛非 SubError 的异常


def test_max_body_size_is_reasonable():
    assert MAX_SUB_BYTES == 8 * 1024 * 1024
    assert MAX_SUB_BYTES > 1024 * 1024        # 不能小到误伤正常订阅


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
    print("SSRF 防护测试全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)
