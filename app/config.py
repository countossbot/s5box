"""全局配置：环境变量只用于"启动时不能变"的东西，可调参数一律进 SQLite settings 表。"""
import os
import secrets
from pathlib import Path

# --- 不可运行时变更（进程/端口绑定） ---
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "subswarm.db"
SINGBOX_BIN = os.getenv("SINGBOX_BIN", "/usr/local/bin/sing-box")
SINGBOX_API_PORT_BASE = int(os.getenv("SINGBOX_API_PORT_BASE", "12000"))

PANEL_PORT = int(os.getenv("PANEL_PORT", "8080"))
SOCKS_PORT = int(os.getenv("SOCKS_PORT", "1080"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "1081"))
BIND_ADDR = os.getenv("BIND_ADDR", "0.0.0.0")

# 面板口令：未设置则随机生成并打到日志（绝不无密码裸奔）
PANEL_USER = os.getenv("PANEL_USER", "admin")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD") or secrets.token_urlsafe(12)
PANEL_PASSWORD_GENERATED = not bool(os.getenv("PANEL_PASSWORD"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# --- 可调参数的出厂默认（会被 settings 表覆盖） ---
DEFAULT_SETTINGS = {
    # 探测
    "probe_interval": "300",        # 秒，一轮全量探测的间隔
    "probe_timeout": "5",           # 秒，单节点探测超时
    # 探测目标。旧键 probe_url 保留作向后兼容：未配置分族 URL 时回退到它。
    # 双栈探测必须按族拆开 —— v4 域名只有 A 记录、v6 域名只有 AAAA 记录，
    # 经同一条 socks 入站请求时，代理必须走对应族才能通，从而拿到该族出口 IP。
    # 不再用双入站/V6_PORT_OFFSET（方案 B 已回退）。
    "probe_url": "https://httpbin.org/ip",
    "probe_url_v4": "https://api-ipv4.ip.sb/ip",
    "probe_url_v6": "https://api-ipv6.ip.sb/ip",
    # 取出口 IP 的备用请求：当探测 URL 的响应体里解析不出 IP（例如用
    # generate_204 这种只返回状态码的地址）时，单独再发一次请求问"我是谁"。
    # 旧 exit_ip_url 仍可用；分族键 probe_exit_ip_v4/v6 优先。
    "exit_ip_url": "https://api.ipify.org",
    "probe_exit_ip_v4": "https://api-ipv4.ip.sb/ip",
    "probe_exit_ip_v6": "https://api-ipv6.ip.sb/ip",
    "probe_exit_ip_from_body": "true",   # 从响应体里解析 origin/ip 作为出口 IP
    "probe_fallback_urls": "",           # 默认不回退；需要时自己填
    "probe_round_budget": "600",     # 单空间单轮探测总时限（秒），防止节点过多时把自己卡死
    # IP 策略（决定 sing-box 解析域名时偏好哪一栈）
    #   prefer_ipv4 优先解析 IPv4，不通再试 IPv6
    #   prefer_ipv6 优先解析 IPv6，不通再试 IPv4
    #   ipv4_only   只用 IPv4
    #   ipv6_only   只用 IPv6
    # prefer_* 时探测会测两族（顺序由本值决定）：先成功的一族作为 used_family，
    # 但两族出口 IP 都会分别落到 exit_ip_v4 / exit_ip_v6。
    "ip_strategy": "prefer_ipv4",
    "probe_concurrency_per_space": "1",   # 空间内串行（需求要求）
    # 失败处理（需求 3）：一轮里失败的节点先标记 pending_retry，
    # 全轮跑完后只对这一批重测一次；仍失败才彻底删除。
    "probe_retry_failed_once": "true",
    # 订阅刷新（新增/手动更新）后自动探测新节点 —— 默认开启。
    # 否则新节点会一直停在 unknown（面板显示"未探测"），
    # 用户以为加了订阅就能用，实际没有一个可用节点。
    "probe_after_refresh": "true",
    "failure_threshold": "1",       # 连续失败 N 次 → 自动删除；1=重测失败即删
    "auto_delete": "true",
    # 订阅
    "default_refresh_interval": "1800",   # 秒
    "subscription_ua": "subswarm/1.0",
    # 随机
    "weight_mode": "space",         # space=空间等权 | node=节点数加权
    "max_connections": "512",
    "connect_retry": "1",           # 握手失败换空间重试次数
    # 过滤器
    "filter_protocols": "trojan,vless,vmess,ss,ssr,hysteria2,tuic,http,socks",
    "filter_port_blacklist": "",
    "filter_exclude_keywords": "过期,官网,剩余,流量,邀请,加群,订阅,机场,测速,试用,直连,广告,群组,t.me,telegram",
    "filter_max_delay_ms": "0",     # 0 = 关闭
    # 每个空间的节点容量上限（需求 1）：默认 100，超出时按"最差优先"淘汰旧节点。
    "filter_max_nodes_per_space": "100",
    "node_cap_evict_strategy": "worst",   # worst=先淘汰失败/最慢/最久未成功的 | oldest=纯 FIFO
    # 地区过滤（需求 2）。列表为空 = 不启用；match 都基于节点名里识别出的地区码。
    "region_filter_mode": "off",          # off | whitelist | blacklist
    "region_filter_list": "HK,TW,JP,SG,US,KR,MO",
    "region_filter_unknown": "keep",      # keep=无法识别地区时保留 | drop=丢弃
}

FILTER_KEY = "filters"  # settings 里存 JSON 的子键前缀（预留）

# --- 设置迁移 ---
# 每次改动"某个设置的出厂默认值"就在这里加一条，否则老库里的旧值会一直压住新默认值，
# 升级后新功能看起来"没生效"（真实踩过：probe_url 和容量上限都被旧值盖住了）。
VALID_IP_STRATEGIES = ("prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only")

SETTINGS_SCHEMA_VERSION = 4

# 键 -> [(旧值, 新值), ...]，只有当前值**恰好等于**旧值时才替换，
# 用户自己改过的值不会被覆盖。
SETTINGS_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "probe_url": [
        ("http://www.gstatic.com/generate_204", "https://httpbin.org/ip"),
        ("https://1.1.1.1/cdn-cgi/trace", "https://httpbin.org/ip"),
        ("http://cp.cloudflare.com/generate_204", "https://httpbin.org/ip"),
    ],
    "filter_max_nodes_per_space": [("0", "100")],
    # v2 新增：老库里没有这些键，由 all_settings() 的默认值打底自动补齐，
    # 但如果老库存在同名的旧默认值，也一并迁过来
    "failure_threshold": [("3", "1")],
    "probe_fallback_urls": [
        ("http://cp.cloudflare.com/generate_204,http://www.gstatic.com/generate_204", ""),
    ],
    # v4 新增：probe_url_v4/v6、probe_exit_ip_v4/v6。新键在老库里不存在，
    # all_settings() 会用默认值打底，不需要迁移条目。
}
