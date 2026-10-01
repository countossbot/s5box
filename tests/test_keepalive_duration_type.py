"""出站长连接保活字段必须是 duration 字符串，不能是数字。

真实事故：给节点出站加 tcp_keep_alive 时写成了数字 30，sing-box 1.14.2
直接 FATAL 拒绝整个配置：

  decode config at /data/work/space-1.json:
  outbounds[0].tcp_keep_alive: json: cannot unmarshal number into
  Go struct field ...AbstractDialerOptions.tcp_keep_alive of type string

后果是实例完全起不来（不是降级，是启动失败），空间内所有节点不可用。

sing-box 这两个字段的类型是 duration（Go time.Duration 的字符串形式，
如 "30s"、"1m"）。这里锁住：生成出来的值必须是带单位后缀的字符串。
"""
import json
import tempfile
from pathlib import Path

from app.singbox import SpaceInstance

_NODE = {
    "outbound_json": json.dumps({
        "type": "vless",
        "server": "1.2.3.4",
        "server_port": 443,
        "uuid": "11111111-1111-1111-1111-111111111111",
    })
}


def _build():
    with tempfile.TemporaryDirectory() as td:
        inst = SpaceInstance(1, Path(td), 11080, 12080)
        return inst.build_config([_NODE])


def test_keepalive_is_duration_string_not_number():
    """核心回归：必须是 '30s' 这类字符串，数字会让 sing-box 起不来。"""
    cfg = _build()
    node_outs = [o for o in cfg["outbounds"] if o.get("type") != "direct"]
    assert node_outs, "应当生成至少一个节点出站"

    for ob in node_outs:
        ka = ob.get("tcp_keep_alive")
        assert isinstance(ka, str), (
            f"tcp_keep_alive 必须是 duration 字符串，实际是 "
            f"{type(ka).__name__}({ka!r}) —— 数字会导致 sing-box FATAL")
        # 必须带单位，否则 sing-box 解析不出时长
        assert ka.endswith(("s", "m", "h")), f"缺少时间单位：{ka!r}"
        assert ka == "30s"

        ki = ob.get("tcp_keep_alive_interval")
        assert isinstance(ki, str) and ki.endswith(("s", "m", "h")), ki


def test_direct_outbound_not_polluted():
    """direct 出站不该被塞入保活字段（它不接受这些 dialer 选项）。"""
    cfg = _build()
    for ob in cfg["outbounds"]:
        if ob.get("type") == "direct":
            assert "tcp_keep_alive" not in ob
            assert "tcp_keep_alive_interval" not in ob
