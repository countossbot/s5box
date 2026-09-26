"""订阅解析自检：拿真实样本（33 个 trojan+ws+tls+ech 节点）当锚点。

跑法： python3 -m tests.test_subscription   （或 pytest tests/）
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.subscription import (  # noqa: E402
    SubError, apply_filters, dedupe, parse_subscription, parse_uri,
)

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures_real_sub.txt")

REAL_URI = ("trojan://65d11e46-03e3-47cd-821b-4627b7a840aa@1.2.3.4:443"
            "?security=tls&type=ws&host=edgecdn.vipdump.eu.org&sni=edgecdn.vipdump.eu.org"
            "&fp=chrome&path=%2Fclip%2Fpage%2Ffilm&encryption=none"
            "&ech=cloudflare-ech.com%2Bhttps%3A%2F%2Fdns.alidns.com%2Fdns-query"
            "#%E6%9F%90%E5%9C%B0%E5%8C%BA")


def test_real_fixture_base64():
    """真实订阅：base64 包裹的 33 行 trojan，必须全部解析出来。"""
    raw = open(FIXTURE, encoding="utf-8").read()
    nodes = parse_subscription(raw)
    assert len(nodes) == 33, f"预期 33 个节点，实际 {len(nodes)}"
    assert {n.protocol for n in nodes} == {"trojan"}
    # 名字里大量重名（NL 出现 8 次），指纹去重不能按名字来
    kept, dup = dedupe(nodes)
    assert dup == 0, "33 个节点指纹应互不相同（端口/path 不同）"
    assert len(kept) == 33
    n = nodes[0]
    assert n.port == 443 and n.outbound["type"] == "trojan"
    assert n.outbound["transport"]["type"] == "ws"
    assert n.outbound["transport"]["path"] == "/clip/page/film"
    assert n.outbound["transport"]["headers"]["Host"] == "edgecdn.vipdump.eu.org"
    assert n.outbound["tls"]["server_name"] == "edgecdn.vipdump.eu.org"
    assert n.outbound["tls"]["utls"]["fingerprint"] == "chrome"
    assert n.outbound["tls"]["ech"]["config"] == ["cloudflare-ech.com+https://dns.alidns.com/dns-query"]
    # outbound 必须能被 sing-box 吃下：tag 字段存在且非空字符串
    assert n.outbound["tag"] == ""


def test_trojan_default_tls_and_no_alpn_emptiness():
    """alpn= 空值时不能产生 alpn: []（sing-box 会报错）。"""
    n = parse_uri(REAL_URI)
    assert "alpn" not in n.outbound["tls"], "空 alpn 不应写入配置"
    assert n.name == "某地区"


def test_dedupe_by_connection_not_name():
    a = parse_uri(REAL_URI)
    b = parse_uri(REAL_URI.replace("#%E6%9F%90%E5%9C%B0%E5%8C%BA", "#TOKYO-01"))
    assert a.fingerprint == b.fingerprint, "同名不同、连接参数相同 → 同一指纹"
    c = parse_uri(REAL_URI.replace(":443", ":8443"))
    assert c.fingerprint != a.fingerprint, "端口不同 → 不同节点"


def test_base64_plain_and_json_inputs():
    raw = open(FIXTURE, encoding="utf-8").read()
    import base64
    plain = base64.b64decode(raw.strip() + "=" * (-len(raw.strip()) % 4)).decode()
    assert len(parse_subscription(plain)) == 33, "明文列表也要能解析"

    sb = json.dumps({"outbounds": [
        {"type": "vmess", "tag": "x", "server": "1.1.1.1", "server_port": 80, "uuid": "u"},
        {"type": "direct", "tag": "direct"},
    ]})
    assert len(parse_subscription(sb)) == 1, "sing-box JSON 只取有 server 的 outbound"


def test_vmess_and_ss_parsing():
    import base64
    vm = base64.b64encode(json.dumps({
        "v": "2", "ps": "节点A", "add": "5.5.5.5", "port": "443", "id": "uuid-x",
        "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "h.example.com",
        "path": "/ws", "tls": "tls", "sni": "h.example.com",
    }).encode()).decode()
    n = parse_subscription("vmess://" + vm)[0]
    assert n.protocol == "vmess" and n.name == "节点A"
    assert n.outbound["transport"] == {"type": "ws", "path": "/ws", "headers": {"Host": "h.example.com"}}
    assert n.outbound["tls"]["server_name"] == "h.example.com"

    ss = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw123").decode().rstrip("=") + "@6.6.6.6:8388#SS%E8%8A%82%E7%82%B9"
    n2 = parse_subscription(ss)[0]
    assert n2.outbound["method"] == "aes-256-gcm" and n2.outbound["password"] == "pw123"
    assert n2.name == "SS节点" and n2.port == 8388


def test_filters():
    nodes = parse_subscription(open(FIXTURE, encoding="utf-8").read())
    nodes[0].name = "剩余流量：100GB"
    kept, stat = apply_filters(nodes, {
        "filter_protocols": "trojan", "filter_port_blacklist": "8888",
        "filter_exclude_keywords": "剩余流量", "filter_max_nodes_per_space": "5",
    })
    assert stat["keyword"] == 1 and stat["port"] == 1
    assert len(kept) == 5 and stat["limit"] == 26, stat

    kept2, stat2 = apply_filters(nodes, {"filter_protocols": "vless"})
    assert kept2 == [] and stat2["protocol"] == 33


def test_bad_input_raises():
    for bad in ("", "   ", "这不是订阅"):
        try:
            parse_subscription(bad)
        except SubError:
            continue
        raise AssertionError(f"{bad!r} 应该抛 SubError")


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
    print("全部通过" if not fails else f"{fails} 个用例失败")
    sys.exit(1 if fails else 0)
