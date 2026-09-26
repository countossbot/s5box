"""地区识别：从节点名里解析出地区码，供地区过滤使用。

节点名千奇百怪，实测常见形式：
    "NL"  "HK-01"  "🇯🇵东京"  "美国 洛杉矶"  "SG|Premium"  "[TW] 台湾"
所以识别顺序是：国旗 emoji → 方括号内的码 → 独立出现的 2 位国家码 → 中文地区名。
匹配用词边界，避免 "US" 命中 "Russia" 这种误判。
"""
from __future__ import annotations

import re

# --- 国旗 emoji → 地区码（由两个 regional indicator 组成） ---
_FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


def _flag_to_code(s: str) -> str | None:
    if len(s) != 2:
        return None
    a, b = ord(s[0]), ord(s[1])
    if not (0x1F1E6 <= a <= 0x1F1FF and 0x1F1E6 <= b <= 0x1F1FF):
        return None
    return chr(a - 0x1F1E6 + ord("A")) + chr(b - 0x1F1E6 + ord("A"))


# --- 常见地区：中文/英文别名 → 标准码 ---
ALIASES: dict[str, str] = {
    # 大中华
    "香港": "HK", "hongkong": "HK", "hong kong": "HK", "hk": "HK", "港": "HK",
    "台湾": "TW", "taiwan": "TW", "tw": "TW", "台": "TW", "台北": "TW",
    "澳门": "MO", "macao": "MO", "macau": "MO", "mo": "MO",
    "中国": "CN", "china": "CN", "cn": "CN", "国内": "CN", "回国": "CN",
    # 东亚
    "日本": "JP", "japan": "JP", "jp": "JP", "东京": "JP", "大阪": "JP", "日": "JP",
    "韩国": "KR", "korea": "KR", "kr": "KR", "首尔": "KR", "韩": "KR",
    # 东南亚
    "新加坡": "SG", "singapore": "SG", "sg": "SG", "狮城": "SG",
    "马来西亚": "MY", "malaysia": "MY", "my": "MY", "马来": "MY",
    "泰国": "TH", "thailand": "TH", "th": "TH", "曼谷": "TH",
    "越南": "VN", "vietnam": "VN", "vn": "VN",
    "菲律宾": "PH", "philippines": "PH", "ph": "PH",
    "印尼": "ID", "indonesia": "ID", "id": "ID",
    "柬埔寨": "KH", "cambodia": "KH",
    # 南亚 / 中亚
    "印度": "IN", "india": "IN", "in": "IN", "孟买": "IN",
    "巴基斯坦": "PK", "pakistan": "PK", "pk": "PK",
    "哈萨克": "KZ", "kazakhstan": "KZ", "kz": "KZ",
    "乌兹别克": "UZ", "uzbekistan": "UZ", "uz": "UZ",
    # 北美
    "美国": "US", "united states": "US", "usa": "US", "us": "US", "洛杉矶": "US",
    "西雅图": "US", "达拉斯": "US", "圣何塞": "US", "凤凰城": "US", "美": "US",
    "加拿大": "CA", "canada": "CA", "ca": "CA",
    "墨西哥": "MX", "mexico": "MX",
    # 欧洲
    "英国": "GB", "uk": "GB", "united kingdom": "GB", "gb": "GB", "伦敦": "GB",
    "德国": "DE", "germany": "DE", "de": "DE", "法兰克福": "DE", "德": "DE",
    "法国": "FR", "france": "FR", "fr": "FR", "巴黎": "FR",
    "荷兰": "NL", "netherlands": "NL", "nl": "NL", "阿姆斯特丹": "NL", "荷": "NL",
    "俄罗斯": "RU", "russia": "RU", "ru": "RU", "莫斯科": "RU", "俄": "RU",
    "意大利": "IT", "italy": "IT",
    "西班牙": "ES", "spain": "ES",
    "瑞典": "SE", "sweden": "SE",
    "瑞士": "CH", "switzerland": "CH",
    "挪威": "NO", "norway": "NO",
    "芬兰": "FI", "finland": "FI", "fi": "FI",
    "丹麦": "DK", "denmark": "DK",
    "波兰": "PL", "poland": "PL", "pl": "PL",
    "爱尔兰": "IE", "ireland": "IE",
    "奥地利": "AT", "austria": "AT",
    "比利时": "BE", "belgium": "BE",
    "捷克": "CZ", "czech": "CZ",
    "匈牙利": "HU", "hungary": "HU",
    "罗马尼亚": "RO", "romania": "RO",
    "乌克兰": "UA", "ukraine": "UA", "ua": "UA",
    "土耳其": "TR", "turkey": "TR", "tr": "TR", "伊斯坦布尔": "TR",
    "立陶宛": "LT", "lithuania": "LT",
    "拉脱维亚": "LV", "latvia": "LV", "lv": "LV",
    "爱沙尼亚": "EE", "estonia": "EE",
    "保加利亚": "BG", "bulgaria": "BG",
    "塞尔维亚": "RS", "serbia": "RS",
    "希腊": "GR", "greece": "GR",
    "葡萄牙": "PT", "portugal": "PT",
    "卢森堡": "LU", "luxembourg": "LU",
    "摩尔多瓦": "MD", "moldova": "MD",
    # 中东 / 非洲
    "以色列": "IL", "israel": "IL",
    "阿联酋": "AE", "uae": "AE", "迪拜": "AE",
    "沙特": "SA", "saudi": "SA",
    "南非": "ZA", "south africa": "ZA",
    "埃及": "EG", "egypt": "EG",
    "尼日利亚": "NG", "nigeria": "NG",
    # 大洋洲 / 南美
    "澳大利亚": "AU", "australia": "AU", "au": "AU", "悉尼": "AU",
    "新西兰": "NZ", "new zealand": "NZ",
    "巴西": "BR", "brazil": "BR", "br": "BR",
    "阿根廷": "AR", "argentina": "AR",
    "智利": "CL", "chile": "CL",
    "哥伦比亚": "CO", "colombia": "CO",
    "秘鲁": "PE", "peru": "PE",
}

# 两字母码里这些不是国家码，避免误判
_NOT_COUNTRY = {
    "IP", "WS", "TCP", "UDP", "TLS", "SS", "SSR", "VM", "CD", "VL", "TR2",
    "PRO", "VIP", "PLUS", "NEW", "OLD", "HK2", "TEST", "FREE", "EDGE",
}

# 优先匹配长别名，避免 "hong kong" 被 "hk" 抢走、或 "us" 命中 "russia"
_SORTED_ALIASES = sorted(ALIASES.items(), key=lambda kv: -len(kv[0]))

# 独立出现的两字母国家码：前后不能紧邻字母数字
_CODE_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2})(?![A-Za-z0-9])")
_BRACKET_RE = re.compile(r"[\[\(【（]\s*([A-Za-z]{2})\s*[\]\)】）]")
_VALID_CODES = {v for v in ALIASES.values()} | {"KH", "PK", "AE", "SA", "ZA", "EG", "NG", "MX", "IL", "RS", "GR", "PT", "LU", "MD", "AT", "BE", "CZ", "HU", "RO", "DK", "NO", "CH", "IT", "ES", "SE", "IE", "BG", "EE", "LT", "HR", "SI", "SK", "BY", "GE", "AM", "AZ", "MN", "NP", "LK", "BD", "MM", "LA", "BN", "PG", "GU", "PR", "CL", "PE", "AR", "CO", "VE", "EC", "UY", "PY", "BO", "CR", "PA", "GT", "DO", "CU", "JM", "TT", "BS", "BB"}


def detect_region(name: str) -> str | None:
    """从节点名里识别地区码。识别不出来返回 None。"""
    if not name:
        return None
    raw = name.strip()

    # 1) 国旗 emoji 最可靠
    for m in _FLAG_RE.finditer(raw):
        code = _flag_to_code(m.group(0))
        if code:
            return code

    # 2) 方括号里的两字母码，如 [HK] (JP)
    for m in _BRACKET_RE.finditer(raw):
        code = m.group(1).upper()
        if code in _VALID_CODES:
            return code

    low = raw.lower()

    # 3) 中文/英文别名（长别名优先）
    for alias, code in _SORTED_ALIASES:
        if alias.isascii():
            # 英文别名要求词边界，避免 "in" 命中 "singapore" 之类
            if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", low):
                return code
        else:
            if alias in raw:
                return code

    # 4) 独立出现的两字母码
    for m in _CODE_RE.finditer(raw):
        code = m.group(1).upper()
        if code in _VALID_CODES and code not in _NOT_COUNTRY:
            return code
    return None


def region_filter(name: str, mode: str, codes: set[str], unknown: str = "keep") -> bool:
    """返回 True = 保留该节点。

    mode: off 不启用 | whitelist 只保留 codes 里的 | blacklist 丢弃 codes 里的
    unknown: 识别不出地区时 keep 还是 drop
    """
    if mode == "off" or not codes:
        return True
    region = detect_region(name)
    if region is None:
        return unknown == "keep"
    if mode == "whitelist":
        return region in codes
    if mode == "blacklist":
        return region not in codes
    return True
