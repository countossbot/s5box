"""s5box 主程序：FastAPI 面板 + 生命周期 + 资源释放。

生命周期顺序（AGENTS.md 要求）：
  启动：DB → 空间配置 → sing-box 子进程 → 注册表 → 代理服务 → 探测循环
  关闭：停止接新连接 → 等在途连接 → 杀 sing-box 子进程 → 关 DB → 清临时文件
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import logging
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path
from fastapi import Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, registry as reg_mod
from .db import DB
from .logbuf import LogBuffer
from .probe import ProbeRunner
from .proxy import ConnStats, Dispatcher, ProxyServers
from .singbox import SingBoxManager
from . import subscription as sub

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("subswarm")

STATE: dict = {}


# ------------------------------------------------------------------ 认证

def _check_auth(request: Request) -> bool:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            dec = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return False
        u, _, p = dec.partition(":")
        return hmac.compare_digest(u, config.PANEL_USER) and hmac.compare_digest(p, config.PANEL_PASSWORD)
    cookie = request.cookies.get("sw_token", "")
    if cookie:
        return hmac.compare_digest(cookie, STATE.get("panel_token", ""))
    return False


# ------------------------------------------------------------------ 业务动作

async def refresh_space(space_id: int, reload_instance: bool = True) -> dict:
    """拉取订阅 → 解析 → 过滤 → 落库 → 重建 sing-box 配置。"""
    db: DB = STATE["db"]
    sp = db.get_space(space_id)
    if sp is None:
        return {"space_id": space_id, "error": "空间不存在"}
    st = db.all_settings()
    try:
        text = await sub.fetch(sp["url"], st.get("subscription_ua", "subswarm/1.0"))
        nodes = sub.parse_subscription(text)
        nodes, dup = sub.dedupe(nodes)
        kept, fstat = sub.apply_filters(nodes, st)
        for n in kept:
            db.upsert_node(space_id, n.fingerprint, n.name, n.protocol, n.host, n.port,
                           __import__("json").dumps(n.outbound, ensure_ascii=False), n.uri)
        db.update_space(space_id, last_refresh_at=time.time(), last_refresh_ok=1, last_refresh_error=None)
        result = {"space_id": space_id, "ok": True, "parsed": len(nodes), "deduped": dup,
                  "accepted": len(kept), "filtered": fstat}
    except Exception as e:  # noqa: BLE001
        db.update_space(space_id, last_refresh_at=time.time(), last_refresh_ok=0, last_refresh_error=str(e)[:400])
        log.warning("空间 %s 刷新失败：%s", space_id, e)
        result = {"space_id": space_id, "ok": False, "error": str(e)[:400]}

    if reload_instance:
        await rebuild_space_instance(space_id)
    STATE["runner"].rebuild()
    return result


async def rebuild_space_instance(space_id: int) -> None:
    """按当前 DB 内容重建该空间的 sing-box 配置与进程。"""
    db: DB = STATE["db"]
    mgr: SingBoxManager = STATE["manager"]
    sp = db.get_space(space_id)
    if sp is None:
        await mgr.stop_space(space_id, cleanup=True)
        return
    if not sp["enabled"]:
        await mgr.stop_space(space_id)
        return
    rows = db.nodes(space_id, include_deleted=False)
    rows = sorted(rows, key=lambda r: (0 if r["state"] in ("healthy", "unknown") else 1, r["id"]))
    # tag 编号必须和 registry 里的 outbound_tag 一致：按完整（含 deleted）列表顺序编号
    all_rows = db.nodes(space_id, include_deleted=True)
    ordered = sorted(all_rows, key=lambda r: r["id"])
    tag_of = {r["id"]: f"n{i}" for i, r in enumerate(ordered)}
    payload = []
    for r in rows:
        ob = __import__("json").loads(r["outbound_json"])
        ob["tag"] = tag_of[r["id"]]
        payload.append({"id": r["id"], "outbound_json": __import__("json").dumps(ob, ensure_ascii=False)})
    try:
        await mgr.apply(space_id, payload, start=True)
    except Exception as e:  # noqa: BLE001
        log.error("空间 %s sing-box 重建失败：%s", space_id, e)
        db.update_space(space_id, last_refresh_error=f"sing-box 启动失败：{e}"[:400])


async def refresh_all() -> list[dict]:
    db: DB = STATE["db"]
    return list(await asyncio.gather(*[refresh_space(s["id"]) for s in db.spaces()]))


async def startup() -> None:
    db = DB()
    STATE["db"] = db
    # 卷挂错（把 /data 挂成了文件）也不能让容器起不来
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError, OSError) as e:
        log.warning("无法创建数据目录 %s（%s），改用系统临时目录；数据不会持久化！",
                    config.DATA_DIR, e)
        config.DATA_DIR = Path(tempfile.gettempdir()) / "s5box"
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    manager = SingBoxManager(config.DATA_DIR / "work")
    STATE["manager"] = manager
    STATE["reg"] = reg_mod.Registry()
    STATE["stats"] = ConnStats()
    STATE["logs"] = LogBuffer(db)
    STATE["panel_token"] = secrets.token_urlsafe(24)

    from .proxy import Dispatcher
    dispatcher = Dispatcher(STATE["reg"], STATE["logs"], STATE["stats"])
    STATE["dispatcher"] = dispatcher

    if config.PANEL_PASSWORD_GENERATED:
        log.warning("=" * 62)
        log.warning("未设置 PANEL_PASSWORD，本次随机生成：")
        log.warning("  用户名 %s   密码 %s", config.PANEL_USER, config.PANEL_PASSWORD)
        log.warning("生产环境请显式设置 PANEL_PASSWORD 环境变量。")
        log.warning("=" * 62)

    # 先把 runner 放进 STATE —— refresh_space() 会在里面读 STATE["runner"]，顺序不能倒
    runner = ProbeRunner(db, manager, STATE["reg"])
    STATE["runner"] = runner

    # 启动时把每个启用空间都拉一遍并起进程（单个空间失败不能拖垮整个容器）
    for sp in db.spaces():
        try:
            if sp["enabled"]:
                await refresh_space(sp["id"])
        except Exception as e:  # noqa: BLE001
            log.error("空间 %s 启动失败（不影响其他空间）：%s", sp["id"], e)
    runner.rebuild()

    servers = ProxyServers(dispatcher, db)
    await servers.start(config.BIND_ADDR, config.SOCKS_PORT, config.HTTP_PORT)
    STATE["servers"] = servers

    await runner.start_loop()

    STATE["refresh_task"] = asyncio.create_task(_refresh_loop())
    STATE["started_at"] = time.time()
    log.info("subswarm 就绪：面板 http://%s:%s  |  SOCKS5 :%s  |  HTTP :%s",
             config.BIND_ADDR, config.PANEL_PORT, config.SOCKS_PORT, config.HTTP_PORT)


async def _refresh_loop() -> None:
    """订阅定时刷新。每个空间按自己的 refresh_interval 判断。"""
    try:
        while True:
            await asyncio.sleep(60)
            db: DB = STATE["db"]
            now = time.time()
            for sp in db.spaces():
                if not sp["enabled"]:
                    continue
                last = sp["last_refresh_at"] or 0
                if now - last >= (sp["refresh_interval"] or 1800):
                    try:
                        await refresh_space(sp["id"])
                    except Exception as e:  # noqa: BLE001
                        log.warning("定时刷新空间 %s 失败：%s", sp["id"], e)
    except asyncio.CancelledError:
        raise


async def shutdown() -> None:
    log.info("正在关闭 subswarm …")
    # 1) 停后台循环
    for key in ("refresh_task",):
        t = STATE.get(key)
        if t and not t.done():
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
    # 2) 探测调度器
    runner = STATE.get("runner")
    if runner:
        with contextlib.suppress(Exception):
            await runner.stop()
    # 3) 代理：停止接受新连接
    servers = STATE.get("servers")
    if servers:
        with contextlib.suppress(Exception):
            await servers.stop()
    # 4) 等在途连接结束（最多 5 秒）
    stats: ConnStats = STATE.get("stats")
    if stats:
        for _ in range(50):
            if stats.active <= 0:
                break
            await asyncio.sleep(0.1)
    # 5) sing-box 子进程（先子进程，后句柄）
    manager = STATE.get("manager")
    if manager:
        with contextlib.suppress(Exception):
            await manager.stop_all()
    # 6) 临时文件
    for inst in list(getattr(manager, "_instances", {}).values()):
        inst.cleanup_files()
    work = config.DATA_DIR / "work"
    if work.exists():
        for p in work.glob("*.tmp"):
            with contextlib.suppress(OSError):
                p.unlink()
    # 7) 数据库最后关
    db: DB = STATE.get("db")
    if db:
        with contextlib.suppress(Exception):
            db.close()
    log.info("subswarm 已关闭，资源已释放")


# ------------------------------------------------------------------ FastAPI

app = FastAPI(title="subswarm", docs_url=None, redoc_url=None)
STATIC = Path(__file__).parent / "static"


@app.on_event("startup")
async def _on_startup():
    await startup()


@app.on_event("shutdown")
async def _on_shutdown():
    await shutdown()


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    p = request.url.path
    if p.startswith("/api/login") or p == "/healthz":
        return await call_next(request)
    if p.startswith("/api/") or p in ("/", "/index.html"):
        if not _check_auth(request):
            if p.startswith("/api/"):
                return JSONResponse({"error": "unauthorized"}, status_code=401,
                                    headers={"WWW-Authenticate": 'Basic realm="subswarm"'})
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="subswarm"'})
    return await call_next(request)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "uptime": int(time.time() - STATE.get("started_at", time.time()))}


@app.post("/api/login")
async def login(request: Request):
    body = await request.json()
    if body.get("user") == config.PANEL_USER and body.get("password") == config.PANEL_PASSWORD:
        resp = JSONResponse({"ok": True})
        resp.set_cookie("sw_token", STATE["panel_token"], httponly=True, samesite="lax")
        return resp
    raise HTTPException(401, "用户名或密码错误")


def A(name):
    return STATE["dispatcher"]


# ---------- 概览 ----------
@app.get("/api/overview")
async def overview():
    db: DB = STATE["db"]
    reg: reg_mod.Registry = STATE["reg"]
    stats: ConnStats = STATE["stats"]
    mgr: SingBoxManager = STATE["manager"]
    st = db.all_settings()
    runners = [{"space_id": s["id"], "name": s["name"], "socks_port": mgr._instances[s["id"]].socks_port,
                "alive": mgr._instances[s["id"]].alive if s["id"] in mgr._instances else False}
               for s in db.spaces()]
    return {
        "version": "1.0.0",
        "singbox": await mgr.version(),
        "uptime": int(time.time() - STATE.get("started_at", time.time())),
        "registry": reg.stats(),
        "proxy": {"socks_port": config.SOCKS_PORT, "http_port": config.HTTP_PORT,
                  "active": stats.active, "total": stats.total,
                  "bytes_up": stats.bytes_up, "bytes_down": stats.bytes_down, "errors": stats.errors,
                  "auth": bool(st.get("proxy_auth_b64"))},
        "random": {"weight_mode": st.get("weight_mode", "space"),
                   "distribution": STATE["logs"].distribution(200)},
        "probe": {"last_round_at": STATE["runner"].last_round_at if STATE.get("runner") else None,
                  "running": STATE["runner"].round_running if STATE.get("runner") else False,
                  "interval": st.get("probe_interval")},
        "instances": runners,
    }


# ---------- 空间 ----------
@app.get("/api/spaces")
async def list_spaces():
    db: DB = STATE["db"]
    mgr: SingBoxManager = STATE["manager"]
    out = []
    for s in db.spaces():
        nodes = db.nodes(s["id"], include_deleted=True)
        cnt = {"total": len(nodes), "healthy": 0, "unknown": 0, "cooling": 0, "deleted": 0}
        for n in nodes:
            cnt[n["state"]] = cnt.get(n["state"], 0) + 1
        inst = mgr._instances.get(s["id"])
        out.append({**dict(s), "counts": cnt,
                    "socks_port": inst.socks_port if inst else None,
                    "singbox_alive": bool(inst and inst.alive)})
    return out


@app.post("/api/spaces")
async def create_space(payload: dict = Body(...)):
    db: DB = STATE["db"]
    url = (payload.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "订阅链接必须以 http(s):// 开头")
    name = (payload.get("name") or "").strip()
    if not name:
        n = len(db.spaces()) + 1
        name = sub.space_default_name(url, n)
    sid = db.create_space(name, url, int(payload.get("refresh_interval") or 1800),
                          payload.get("weight_mode") or db.get_setting("weight_mode", "space"))
    if payload.get("node_limit"):
        db.update_space(sid, node_limit=int(payload["node_limit"]))
    res = await refresh_space(sid)
    return {"id": sid, "refresh": res}


@app.post("/api/spaces/bulk")
async def bulk_create(payload: dict = Body(...)):
    urls = [u.strip() for u in (payload.get("urls") or "").splitlines() if u.strip()]
    out = []
    for i, u in enumerate(urls, 1):
        if not u.startswith(("http://", "https://")):
            out.append({"url": u, "error": "不是合法链接"})
            continue
        db: DB = STATE["db"]
        sid = db.create_space(payload.get("name_prefix") and f"{payload['name_prefix']}-{i}"
                              or sub.space_default_name(u, len(db.spaces()) + 1), u, 1800,
                              db.get_setting("weight_mode", "space"))
        out.append({"id": sid, "url": u, "refresh": await refresh_space(sid)})
    return out


@app.patch("/api/spaces/{sid}")
async def patch_space(sid: int, payload: dict = Body(...)):
    db: DB = STATE["db"]
    if db.get_space(sid) is None:
        raise HTTPException(404, "空间不存在")
    fields = {}
    for k in ("name", "url", "enabled", "refresh_interval", "weight_mode", "node_limit"):
        if k in payload:
            fields[k] = payload[k]
    if "enabled" in fields:
        fields["enabled"] = 1 if fields["enabled"] else 0
    db.update_space(sid, **fields)
    if any(k in payload for k in ("url", "enabled")):
        await refresh_space(sid)
    else:
        await rebuild_space_instance(sid)
    STATE["runner"].rebuild()
    return {"ok": True}


@app.delete("/api/spaces/{sid}")
async def delete_space(sid: int):
    db: DB = STATE["db"]
    mgr: SingBoxManager = STATE["manager"]
    await mgr.stop_space(sid, cleanup=True)
    db.delete_space(sid)
    STATE["runner"].rebuild()
    return {"ok": True}


@app.post("/api/spaces/{sid}/refresh")
async def do_refresh(sid: int):
    return await refresh_space(sid)


@app.post("/api/refresh-all")
async def do_refresh_all():
    return await refresh_all()


# ---------- 节点 ----------
@app.get("/api/nodes")
async def list_nodes(space_id: int | None = None, state: str | None = None,
                     q: str | None = None, limit: int = 1000):
    db: DB = STATE["db"]
    rows = db.nodes(space_id, include_deleted=True)
    out = []
    for r in rows:
        if state and state != "all" and r["state"] != state:
            continue
        if q and q.lower() not in f'{r["name"]} {r["host"]} {r["protocol"]}'.lower():
            continue
        out.append({k: r[k] for k in ("id", "space_id", "name", "protocol", "host", "port", "state",
                                      "delay_ms", "exit_ip", "fail_count", "ok_count",
                                      "last_probe_at", "last_ok_at", "deletion_reason", "added_at")})
    out.sort(key=lambda x: (x["delay_ms"] is None, x["delay_ms"] or 0, x["id"]))
    return out[:limit]


@app.post("/api/nodes/{nid}/probe")
async def probe_node(nid: int):
    db: DB = STATE["db"]
    row = db.q1("SELECT * FROM nodes WHERE id=?", (nid,))
    if row is None:
        raise HTTPException(404, "节点不存在")
    reg: reg_mod.Registry = STATE["reg"]
    idx = None
    for s in reg.spaces():
        if s.id == row["space_id"]:
            for n in s.nodes:
                if n.id == nid:
                    idx = int(n.outbound_tag.lstrip("n"))
    if idx is None:
        raise HTTPException(400, "节点不在当前空间快照中，请先刷新")
    st = db.all_settings()
    runner: ProbeRunner = STATE["runner"]
    ok, delay, err = await runner.probe_one(row["space_id"], f"n{idx}",
                                            st.get("probe_url"), int(float(st.get("probe_timeout", "5")) * 1000))
    exit_ip = None
    if ok:
        exit_ip = await runner.fetch_exit_ip(STATE["manager"].instance(row["space_id"]).socks_port)
    new_state = db.record_probe(nid, ok, delay, err, exit_ip,
                                int(st.get("failure_threshold", "3")),
                                st.get("auto_delete", "true").lower() == "true")
    STATE["runner"].rebuild()
    return {"ok": ok, "delay_ms": delay, "error": err, "exit_ip": exit_ip, "state": new_state}


@app.post("/api/nodes/{nid}/delete")
async def delete_node(nid: int):
    STATE["db"].delete_node(nid)
    STATE["runner"].rebuild()
    return {"ok": True}


@app.post("/api/nodes/{nid}/revive")
async def revive_node(nid: int):
    STATE["db"].revive_node(nid)
    await rebuild_space_instance(STATE["db"].q1("SELECT space_id FROM nodes WHERE id=?", (nid,))["space_id"])
    STATE["runner"].rebuild()
    return {"ok": True}


@app.post("/api/nodes/bulk")
async def bulk_nodes(payload: dict = Body(...)):
    db: DB = STATE["db"]
    ids = payload.get("ids") or []
    action = payload.get("action")
    for nid in ids:
        if action == "delete":
            db.delete_node(nid, "批量删除")
        elif action == "revive":
            db.revive_node(nid)
        elif action == "probe":
            pass
    if action == "probe" and ids:
        for sid in {db.q1("SELECT space_id FROM nodes WHERE id=?", (i,))["space_id"] for i in ids}:
            await STATE["runner"].probe_space(sid)
    else:
        for sid in {db.q1("SELECT space_id FROM nodes WHERE id=?", (i,))["space_id"] for i in ids}:
            await rebuild_space_instance(sid)
    STATE["runner"].rebuild()
    return {"ok": True, "count": len(ids)}


# ---------- 探测 / 设置 / 日志 ----------
@app.post("/api/probe/run")
async def probe_run(space_id: int | None = None):
    runner: ProbeRunner = STATE["runner"]
    return await runner.probe_all(space_id)


@app.get("/api/settings")
async def get_settings():
    return STATE["db"].all_settings()


@app.put("/api/settings")
async def put_settings(payload: dict = Body(...)):
    db: DB = STATE["db"]
    allowed = set(config.DEFAULT_SETTINGS) | {"proxy_auth_b64"}
    for k, v in payload.items():
        if k in allowed:
            db.set_setting(k, v)
    return db.all_settings()


@app.get("/api/logs")
async def get_logs(limit: int = 200, source: str = "both"):
    if source == "db":
        rows = STATE["db"].recent_conns(limit)
        return [dict(r) for r in rows]
    return STATE["logs"].recent(limit)


@app.get("/api/logs/distribution")
async def get_dist(last: int = 500):
    return STATE["logs"].distribution(last)


if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

    @app.get("/")
    async def index():
        return FileResponse(str(STATIC / "index.html"))


def main() -> None:
    import uvicorn
    uvicorn.run(app, host=config.BIND_ADDR, port=config.PANEL_PORT, log_level=config.LOG_LEVEL.lower(),
                access_log=False)


if __name__ == "__main__":
    main()
