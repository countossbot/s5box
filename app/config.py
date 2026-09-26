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
    # 探测目标。国内/受限网络里 gstatic 常被墙，首选 Cloudflare 的 204 端点。
    "probe_url": "https://1.1.1.1/cdn-cgi/trace",
    "probe_fallback_urls": "http://cp.cloudflare.com/generate_204,http://www.gstatic.com/generate_204",
    "probe_round_budget": "600",     # 单空间单轮探测总时限（秒），防止节点过多时把自己卡死
    "probe_concurrency_per_space": "1",   # 空间内串行（需求要求）
    "failure_threshold": "3",       # 连续失败 N 次 → 自动删除
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
    "filter_max_nodes_per_space": "0",  # 0 = 无限
}

FILTER_KEY = "filters"  # settings 里存 JSON 的子键前缀（预留）
