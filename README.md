# s5box

一个 Docker 容器，管理**多个订阅空间**，对外提供 **SOCKS5 + HTTP 代理**，并带 Web 管理面板。

核心行为：

- **每个订阅链接是一个独立空间**，空间之间完全隔离（每个空间一个独立的 sing-box 进程）。
- **每条新建连接 → 随机挑一个空间 → 在该空间随机挑一个节点**，全部用 `os.urandom` 级别的随机源。
- **空间内按顺序探测**节点可用性（串行），**跨空间并行**。
- **探测失败自动删除**（默认连续 3 次）＋ 一套**自动过滤**规则。
- 支持高并发，连接数上限可调。

镜像：`ghcr.io/countossbot/s5box:latest`（同时支持 `linux/amd64` 与 `linux/arm64`）。

---

## 1. 快速开始

```bash
# 拉镜像（公开包无需登录；私有包需 docker login ghcr.io）
docker pull ghcr.io/countossbot/s5box:latest

docker run -d --name s5box \
  -p 1080:1080 -p 1081:1081 -p 8080:8080 \
  -e PANEL_PASSWORD='你自己设一个强口令' \
  -v "$PWD/s5box-data:/data" \
  --restart unless-stopped \
  ghcr.io/countossbot/s5box:latest
```

或者用 compose：

```bash
cp docker-compose.example.yml docker-compose.yml
# 改 image 和 PANEL_PASSWORD
docker compose up -d
```

打开 `http://<主机>:8080`，用 `admin` / 你设的口令登录，在「订阅空间」里把你的订阅链接粘进去。

### 客户端怎么连

| 协议 | 地址 |
|---|---|
| SOCKS5 | `<主机>:1080` |
| HTTP / HTTPS 代理 | `<主机>:1081` |

```bash
curl -x socks5h://用户:口令@主机:1080 https://api.ipify.org
curl -x http://用户:口令@主机:1081 https://api.ipify.org
```

> 代理认证默认关闭。在面板「设置 → 随机与代理」里把 `proxy_auth_b64` 填上
> `base64("user:pass")`（`echo -n 'u:p' | base64`）就会开启，两个协议同时生效。

---

## 2. 架构

```
┌──────────────────────── container: s5box ────────────────────────┐
│                                                                   │
│  fastapi :8080 面板+API         sing-box 实例（每空间一个进程）      │
│   ├ 订阅拉取 / 解析 / 过滤       空间①  节点n0 → 127.0.0.1:11080    │
│   ├ 后台调度（刷新 + 探测）      空间①  节点n1 → 127.0.0.1:11081    │
│   └ 代理分发器 :1080 / :1081 ──▶ 空间②  节点n0 → 127.0.0.1:12080 …  │
│        随机选中哪个节点，就只连它专属的那个入站端口                  │
└───────────────────────────────────────────────────────────────────┘
```

**为什么一个空间一个 sing-box 进程**：空间之间互不影响（A 空间的坏节点不会拖累 B）；
面板停用/删除空间可以直接杀进程，不必全量 reload 掐断所有在途连接；探测并发天然隔离。
代价是每空间约十几 MB 常驻内存，`[ponytail]` 对「几个到几十个空间」这个量级是最省事的正确解。

**怎么保证"选中的节点"就是"实际使用的节点"**：每个节点在 sing-box 里配一个**独立的
socks 入站**（端口 = 该空间基端口 + 节点序号），并用 `route.rules` 把 `inN` 的流量
**强制**导向 `nN`。分发器随机选中哪个节点，就直接连它专属的端口 —— 选路是物理确定的，
不依赖任何隐式机制。（试过用 SOCKS5 用户名传 outbound tag，sing-box 不支持。）

**为什么代理分发器不自己实现协议栈**：trojan / vless / vmess / ss / hysteria2 / tuic 的
出站全部交给 sing-box。分发器只做两件事：随机选点、把客户端流泵到被选空间的本地 socks 入站。
所以"支持新协议"几乎零成本，而且不会因为自己写错 TLS/WS 握手而误判节点。

### 目录

```
app/
  main.py          FastAPI 入口、生命周期（含资源释放）、全部 REST API
  config.py        环境变量 + 可调参数出厂默认
  db.py            SQLite 存储（stdlib sqlite3，WAL）
  subscription.py  拉取 / 解析（base64·明文·Clash YAML·sing-box JSON）/ 去重 / 过滤
  singbox.py       每空间配置生成 + 子进程管理 + Clash API 控制
  registry.py      内存节点池快照 + 层级随机选择
  probe.py         探测调度（空间内串行，跨空间并行）
  proxy.py         SOCKS5 + HTTP 服务端
  logbuf.py        连接日志环形缓冲 + 分布统计
  static/          面板单页（原生 HTML/CSS/JS，无构建步骤）
tests/
  test_subscription.py   用真实订阅样本做解析/去重/过滤断言
  fixtures_real_sub.txt  真实样本（base64 的 33 个 trojan+ws+tls+ech 节点）
```

---

## 3. 随机选择（需求核心）

```
每条新建连接 →  随机挑空间（等权） →  在该空间的健康节点里随机挑一个  →  整条连接固定用这个节点
```

- **每次新建 TCP 连接重掷**。第 1 个请求可能走空间①/节点7，第 2 个走空间②/节点19。
- **空间等权**（默认）：空间 A 有 100 个节点、空间 B 只有 2 个，两边被选中概率都是 50%。
  在空间的 `weight_mode` 改成 `node` 则改为按健康节点数加权（大空间占绝对多数）。
- **随机源是 `random.SystemRandom`**（底层 `os.urandom`），并发下没有共享可变状态。
- **读路径零锁**：节点池是内存里的不可变元组，刷新时整体替换引用；分发器从不查 SQLite。
- **连接内固定**：一个 SOCKS5 连接握手时选一次，之后不再换——否则下载和 WebSocket 会中途断。
- 池子里只有 `healthy` 和 `unknown`（未探测的给一次机会），`cooling`/`deleted` 永不参与。
- 握手失败会自动换一个空间重试（`connect_retry`，默认 1 次）。

**怎么验证随机真的生效**：面板「概览」页有「随机选择分布」柱状图，统计最近 200 次连接
命中了哪个空间、哪个节点。如果某个空间占 99%，说明池子配置有问题。

---

## 4. 探测与自动删除

**空间内串行**（需求原文"按顺序探测"）：同一空间同时只有 1 个探测在跑，按 id 顺序过，
`unknown`/`cooling` 的节点优先排队。
**跨空间并行**：3 个空间 = 3 路同时探。否则 5 个空间 × 33 节点 × 3s 超时，一轮要 8 分钟，池子早就腐烂了。

探测是**真实可用性验证**，不是 TCP 探活：通过该空间的 sing-box 发一次真实 HTTP 请求
（默认 `http://www.gstatic.com/generate_204`），量延迟，并顺带查出口 IP。
这些节点是 trojan+ws+tls，TCP 能连上不代表握手能成功。

状态机：

```
unknown ──成功──▶ healthy ──成功──▶ healthy（刷新延迟）
   │                │
   └─失败─▶ cooling ─┴─失败累计 ≥ failure_threshold ──▶ deleted（自动删除，记录原因）
```

被删节点**不物理删除**，只移出随机池，面板能看到删除原因和时间，也能一键复活。
订阅刷新时相同指纹不会复活已删节点，避免"删了又加"反复抖动。

### 自动过滤规则

| 规则 | 设置键 | 默认 |
|---|---|---|
| 协议白名单 | `filter_protocols` | trojan,vless,vmess,ss,ssr,hysteria2,tuic,http,socks |
| 端口黑名单 | `filter_port_blacklist` | 空 |
| 名称关键词排除 | `filter_exclude_keywords` | 过期,官网,剩余,流量,邀请,加群… |
| 延迟上限 | `filter_max_delay_ms` | 0（关闭） |
| 每空间节点数上限 | `filter_max_nodes_per_space` | 0（无限） |
| 去重 | 强制 | 按连接参数指纹，**不按节点名** |

> 去重为什么不能用节点名：真实订阅里 33 个节点名大量重复（`NL` 出现 8 次），
> 按名字去重会砍掉 2/3 的可用节点。指纹用 `协议|服务器|端口|path|sni|host` 等连接参数。

---

## 5. 面板

| 页 | 能做什么 |
|---|---|
| 概览 | 空间/节点/健康数、活跃连接、流量、sing-box 版本、**随机分布柱状图**、各空间实例状态 |
| 订阅空间 | 增删改、启停、手动刷新、刷新间隔、权重模式、批量导入 |
| 节点 | 按空间/状态/关键词筛选、按延迟排序、单节点探测/删除/复活、批量操作、一键全量探测 |
| 连接日志 | 最近 200 条：每次连接命中的空间+节点+结果，用来验证随机 |
| 设置 | 探测参数、随机与代理参数、过滤规则，全部热生效 |

所有可调参数都存在 SQLite 的 `settings` 表里，改完即时生效（探测参数下一轮生效）。

---

## 6. 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PANEL_USER` / `PANEL_PASSWORD` | `admin` / **随机生成** | 面板登录。不设密码会随机生成并打印到 `docker logs`，绝不明文裸奔 |
| `PANEL_PORT` | `8080` | 面板端口 |
| `SOCKS_PORT` | `1080` | SOCKS5 端口 |
| `HTTP_PORT` | `1081` | HTTP 代理端口 |
| `BIND_ADDR` | `0.0.0.0` | 监听地址（要只给内网就设 `127.0.0.1`） |
| `DATA_DIR` | `/data` | SQLite 与 sing-box 工作目录，必须挂卷 |
| `LOG_LEVEL` | `INFO` | 排查问题用 `DEBUG` |
| `SINGBOX_BIN` | `/usr/local/bin/sing-box` | 内核路径 |
| `SINGBOX_VERSION` | `1.14.2`（构建参数） | 需 ≥1.14 才支持 `ech` 字段 |
| `SINGBOX_DNS_SERVER` | 空（用系统 DNS） | 指定 sing-box 上游 DNS，如 `223.5.5.5`。**默认不要硬编码公共 DNS**：容器所在网络可能连不上，会导致全部探测失败 |

sing-box 的私有 socks 端口全部绑在容器内 `127.0.0.1`，不会暴露到宿主机。

---

## 7. REST API

面板用的就是这套 API，HTTP Basic 认证（或登录后带 cookie）。

```
GET    /api/overview                     总览（含随机分布统计）
GET    /api/spaces                       空间列表（含各状态节点计数）
POST   /api/spaces                       {url, name?, refresh_interval?}
POST   /api/spaces/bulk                  {urls: "每行一个"}
PATCH  /api/spaces/{id}                  {name?,url?,enabled?,refresh_interval?,weight_mode?,node_limit?}
DELETE /api/spaces/{id}                  删空间（连带节点记录与 sing-box 实例）
POST   /api/spaces/{id}/refresh          手动刷新单个空间
POST   /api/refresh-all                  刷新全部

GET    /api/nodes?space_id=&state=&q=    节点列表
POST   /api/nodes/{id}/probe             立即探测单个节点
POST   /api/nodes/{id}/delete            移出随机池
POST   /api/nodes/{id}/revive            复活
POST   /api/nodes/bulk                   {ids:[], action: delete|revive|probe}

POST   /api/probe/run?space_id=          立即探测（不带参数=全部空间）
GET    /api/settings                     读设置
PUT    /api/settings                     写设置（热生效）
GET    /api/logs?limit=200               连接日志
GET    /api/logs/distribution?last=500   随机分布统计
GET    /healthz                          健康检查
```

---

## 8. 构建（GitHub Actions）

两个架构**分别在原生 runner 上构建**，最后合并成一个多架构 manifest：

```
test   → ubuntu-latest          语法检查 + 解析/随机测试（不占构建资源）
build  → ubuntu-24.04     (amd64)  ┐ 各自构建、各自 push by digest
          ubuntu-24.04-arm (arm64)  ┘
merge  → docker buildx imagetools create  → ghcr.io/countossbot/s5box:latest
```

**为什么不用一次构建两个平台**：`--platform linux/amd64,linux/arm64` 会让 arm64 走 QEMU 模拟，
pip 安装和二进制校验慢十倍以上。用原生 arm runner 既快又省资源。
每个架构单独设 `cache-to: type=gha,mode=max`，二次构建基本只跑变更层。
`provenance: false` / `sbom: false` 是为了减小 manifest 体积。

触发：push 到 `main`、打 `v*` tag、或手动 `workflow_dispatch`。

### 使用别的仓库/镜像源

国内直连 Docker Hub 常常失败，可以改基础镜像源：

```bash
docker build --build-arg BASE_IMAGE=docker.m.daocloud.io/library/debian:bookworm-slim -t s5box .
```

CI 里也支持：把 `Dockerfile` 第 4 行的默认值改掉即可（`ARG BASE_IMAGE`）。

---

## 9. 本地开发

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python tests/test_subscription.py    # 订阅解析（含真实样本）
python tests/test_pump.py            # 双向泵：分包不丢 / 大负载 / 半关闭
python tests/test_tag_alignment.py   # tag ↔ 端口 ↔ 节点 三方对齐
python tests/test_socks_parse.py     # SOCKS5 请求解析
python app/registry.py               # 随机选择自检（空间等权 / 加权 / 池子排除）
DATA_DIR=./data SINGBOX_BIN=./sing-box python3 -m app.main
```

---

## 10. 排错

| 症状 | 原因 / 处理 |
|---|---|
| 面板打不开 | `docker logs s5box` 找面板密码；确认 8080 映射了 |
| 节点全是「未探测」 | 探测还没跑完（等一轮）或在设置里点「立即全量探测」 |
| 节点全被删了 | 探测目标被墙或超时太短。改 `probe_url`（比如 `https://www.cloudflare.com/cdn-cgi/trace`）或调大 `probe_timeout`、关掉 `auto_delete`，然后在节点页批量复活 |
| 代理返回 503 / 无可用节点 | 随机池是空的：所有节点处于 `cooling`/`deleted`，去节点页看状态和删除原因 |
| 日志里 `sing-box 启动失败` | 空间配置有问题，看容器日志里 sing-box 的输出；通常是订阅里某种协议的字段没解析对 |
| 出口 IP 全是同一个 | 说明这些节点其实是同一个中转，属订阅本身的问题，不是随机没生效（看分布柱状图确认） |
| 想抓具体某次连接的选点 | `LOG_LEVEL=DEBUG`，或看「连接日志」页 |
| 提示「该空间已有一轮探测在跑」 | 节点太多导致一轮跑太久。调小 `probe_round_budget`（默认 600s），或调大 `probe_interval` |
| 探测全部失败但节点其实能用 | 探测目标被墙。换 `probe_url`（默认 Cloudflare 204），或设 `SINGBOX_DNS_SERVER` 指定可达的 DNS |

### 资源占用

- 空闲：面板 + 分发器约 60–90 MB；每个空间实例再加约 15 MB。
- **每个节点会多一个 socks 入站**，入站本身开销很小，但节点很多时（数百个）
  配置文件与句柄数会上升；几百节点量级建议用 `filter_max_nodes_per_space` 收敛。
- 3 个空间、100 个节点时实测常在 120–180 MB 区间。
- 连接内存：每条连接双向各 64KB 缓冲，上限由 `max_connections` 控制（默认 512）。

---

## 11. 明确没做的部分

| 功能 | 原因 |
|---|---|
| SOCKS5 `UDP ASSOCIATE` | 要额外做 UDP-over-stream 编解码；不支持时明确返回 `0x07 Command not supported`，不假装支持 |
| `BIND` | 同上，返回 `0x07` |
| Clash 兼容的 `/proxies` 外部控制 API | 面板已覆盖需求 |
| 多租户 / 多用户 | 单人自用场景 |
| 每个目标地址重掷节点 | 会破坏长连接；当前是「每条连接重掷」 |

需要其中任何一项时告诉我，都能加。
