"""VPN Checker — FastAPI main application."""

import asyncio
import logging
import secrets

from fastapi import FastAPI, Request, Form, HTTPException, Header
from fastapi.responses import RedirectResponse, PlainTextResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, func, delete

from database import (
    create_db_and_tables,
    engine,
    Subscription,
    ProxyResult,
    Settings,
    TestUrl,
    Node,
    NodeProxyResult,
)
from auth import (
    hash_password,
    verify_password,
    create_session_token,
    get_current_user,
    SESSION_COOKIE,
)
from subs_manager import fetch_and_parse_subscriptions
from tester import run_full_test, test_status
from speed_tester import run_speed_test
from proxy_parsers import replace_proxy_remark
from scheduler import start_scheduler, scheduler_status
from log_buffer import log_buffer, setup_log_buffer

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("vpn_checker")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="VPN Checker", version="2.0.0")
templates = Jinja2Templates(directory="templates")

# ---------------------------------------------------------------------------
# All default subscription URLs — GitVerse + conversation history
# ---------------------------------------------------------------------------
DEFAULT_SUBSCRIPTIONS = [
    # === GitVerse RUVIPIEN/russian-white-bolt (v2ray format, auto-updated every 3h) ===
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Goida_Config_3_b4689a.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Goida_Config_1_f7c635.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Goida_Config_26_9d0474.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Sevcator_VLESS_ffd7b3.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Kort_VLESS_Clean_fa7d47.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Kort_Trojan_Clean_f30cdf.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Kort_VMess_Clean_94367a.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Kort_SS_Clean_2a8980.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/OpenRay_All_Proxies_39ce9f.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Bypass_Config_7_d33b54.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Vify_VLESS_7f9765.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Yitong_V2Ray_11218f.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/BLACK_VLESS_RUS_11add6.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/BLACK_SS_All_316a8b.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/VLESS_Reality_White_3eac2d.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/V2RayRoot_VLESS_feed6f.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/WhitePrime_Available_e52883.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/WhitePrime_Available_WL_35806c.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/WhitePrime_Available_ST_7ad618.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/WhitePrime_WL_ST_587e43.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Xray_Mix_URI_c4598b.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/SilentGhost_Blacklist_676750.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Roosterkid_V2Ray_2e2cfa.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Pawdroid_Free_Servers_6d71e8.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/MahsaNet_Xray_Final_1f5ce9.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/AlexanderY_Sub_All_946555.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/AlexanderY_VLESS_9c1e9a.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/AlexanderY_VLESS_Warp_d9ad39.txt",
    "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/AlexanderY_EdikRU_ae94d8.txt",
    # === Russian community (GitHub) ===
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/Whitelist.txt",
    "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/Whitelist%20%E2%84%962.txt",
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/refs/heads/main/configs/available",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    # === Iranian aggregators (VLESS Reality focused) ===
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/vless",
    "https://raw.githubusercontent.com/Bardiafa/Free-V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    # === Mixed protocol aggregators (GitHub) ===
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    # === CDN subscription ===
    "https://etoneya.a9fm.site/1",
]


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def on_startup():
    setup_log_buffer()
    create_db_and_tables()
    # Seed default settings if empty
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        if not settings:
            settings = Settings(
                admin_pass_hash=hash_password("admin"),
                ping_threshold_ms=1000,
                webhook_secret_path="secret-distrib",
                concurrent_checks_limit=50,
                schedule_interval_minutes=0,
                webhook_max_proxies=0,
                http_timeout_s=10,
                speed_test_top_n=0,
                node_api_token=secrets.token_hex(16),
                node_check_top_n=50,
            )
            session.add(settings)

            # Default strict URL tests for Russia (DPI bypass)
            default_urls = [
                ("https://www.instagram.com/favicon.ico", 200, 100),
                ("https://x.com/favicon.ico", 200, 100),
                ("https://www.youtube.com/generate_204", 204, 0),
                ("https://chatgpt.com/favicon.ico", 200, 100),
                ("https://rutracker.org/favicon.ico", 200, 100),
            ]
            for i, (url, status, min_b) in enumerate(default_urls, start=1):
                tu = TestUrl(url=url, expect_status=status, min_body_bytes=min_b, position=i)
                session.add(tu)

            # Default subscriptions
            for sub_url in DEFAULT_SUBSCRIPTIONS:
                session.add(Subscription(url=sub_url))

            session.commit()
            logger.info("Created default settings, test URLs, and subscriptions")

    start_scheduler()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _require_login(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


# ---------------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, password: str = Form(...)):
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
    if settings and verify_password(password, settings.admin_pass_hash):
        token = create_session_token("admin")
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, max_age=86400)
        return resp
    return templates.TemplateResponse(request, "login.html", {"error": "Wrong password"}, status_code=401)


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ---------------------------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        sub_count = session.exec(select(func.count(Subscription.id))).one()
        proxy_count = session.exec(select(func.count(ProxyResult.id))).one()
        test_url_count = session.exec(select(func.count(TestUrl.id))).one()
        node_count = session.exec(select(func.count(Node.id))).one()
        settings = session.exec(select(Settings)).first()

    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "sub_count": sub_count,
        "proxy_count": proxy_count,
        "test_url_count": test_url_count,
        "node_count": node_count,
        "settings": settings,
        "test_status": test_status,
    })


# ---------------------------------------------------------------------------
# SUBSCRIPTIONS
# ---------------------------------------------------------------------------
@app.get("/subscriptions", response_class=HTMLResponse)
async def subscriptions_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        subs = session.exec(select(Subscription).order_by(Subscription.id.desc())).all()
    return templates.TemplateResponse(request, "subscriptions.html", {
        "user": user,
        "subs": subs,
    })


@app.post("/subscriptions/add")
async def add_subscription(request: Request, url: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    url = url.strip()
    if url:
        with Session(engine) as session:
            existing = session.exec(select(Subscription).where(Subscription.url == url)).first()
            if not existing:
                sub = Subscription(url=url)
                session.add(sub)
                session.commit()
    return RedirectResponse("/subscriptions", status_code=302)


@app.post("/subscriptions/delete/{sub_id}")
async def delete_subscription(request: Request, sub_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        sub = session.get(Subscription, sub_id)
        if sub:
            session.delete(sub)
            session.commit()
    return RedirectResponse("/subscriptions", status_code=302)


# ---------------------------------------------------------------------------
# TEST URLS
# ---------------------------------------------------------------------------
@app.get("/test-urls", response_class=HTMLResponse)
async def test_urls_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        urls = session.exec(select(TestUrl).order_by(TestUrl.position, TestUrl.id)).all()
    return templates.TemplateResponse(request, "test_urls.html", {
        "user": user,
        "test_urls": urls,
    })


@app.post("/test-urls/add")
async def add_test_url(
    request: Request,
    url: str = Form(...),
    expect_status: int = Form(200),
    min_body_bytes: int = Form(100),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    url = url.strip()
    if url:
        with Session(engine) as session:
            existing = session.exec(select(TestUrl).where(TestUrl.url == url)).first()
            if not existing:
                max_pos = session.exec(select(func.max(TestUrl.position))).one()
                pos = (max_pos or 0) + 1
                tu = TestUrl(
                    url=url,
                    expect_status=expect_status,
                    min_body_bytes=max(0, min_body_bytes),
                    position=pos,
                )
                session.add(tu)
                session.commit()
    return RedirectResponse("/test-urls", status_code=302)


@app.post("/test-urls/delete/{url_id}")
async def delete_test_url(request: Request, url_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        tu = session.get(TestUrl, url_id)
        if tu:
            session.delete(tu)
            session.commit()
    return RedirectResponse("/test-urls", status_code=302)


# ---------------------------------------------------------------------------
# SETTINGS
# ---------------------------------------------------------------------------
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
    return templates.TemplateResponse(request, "settings.html", {
        "user": user,
        "settings": settings,
        "saved": False,
    })


@app.post("/settings", response_class=HTMLResponse)
async def settings_save(
    request: Request,
    ping_threshold_ms: int = Form(...),
    concurrent_checks_limit: int = Form(...),
    webhook_secret_path: str = Form(...),
    schedule_interval_minutes: int = Form(0),
    webhook_max_proxies: int = Form(0),
    http_timeout_s: int = Form(10),
    speed_test_top_n: int = Form(0),
    node_check_top_n: int = Form(50),
    global_sub_min_nodes: int = Form(1),
    global_sub_top_n: int = Form(50),
    new_password: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        if settings:
            settings.ping_threshold_ms = ping_threshold_ms
            settings.concurrent_checks_limit = concurrent_checks_limit
            settings.webhook_secret_path = webhook_secret_path.strip().strip("/")
            settings.schedule_interval_minutes = max(0, schedule_interval_minutes)
            settings.webhook_max_proxies = max(0, webhook_max_proxies)
            settings.http_timeout_s = max(1, http_timeout_s)
            settings.speed_test_top_n = max(0, speed_test_top_n)
            settings.node_check_top_n = max(1, node_check_top_n)
            settings.global_sub_min_nodes = max(1, global_sub_min_nodes)
            settings.global_sub_top_n = max(0, global_sub_top_n)
            if new_password.strip():
                settings.admin_pass_hash = hash_password(new_password.strip())
            session.add(settings)
            session.commit()
            session.refresh(settings)
    return templates.TemplateResponse(request, "settings.html", {
        "user": user,
        "settings": settings,
        "saved": True,
    })


@app.post("/settings/regenerate-node-token")
async def regenerate_node_token(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        if settings:
            settings.node_api_token = secrets.token_hex(16)
            session.add(settings)
            session.commit()
    return RedirectResponse("/settings", status_code=302)


# ---------------------------------------------------------------------------
# VALID PROXIES page
# ---------------------------------------------------------------------------
@app.get("/proxies", response_class=HTMLResponse)
async def proxies_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        proxies = session.exec(
            select(ProxyResult).order_by(
                ProxyResult.speed_score.desc(),
                ProxyResult.tests_passed.desc(),
                ProxyResult.ping_ms,
            )
        ).all()
    return templates.TemplateResponse(request, "proxies.html", {
        "user": user,
        "proxies": proxies,
    })


# ---------------------------------------------------------------------------
# LOGS page
# ---------------------------------------------------------------------------
@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "logs.html", {"user": user})


@app.get("/api/logs")
async def api_logs(after_id: int = 0):
    entries = log_buffer.get_since(after_id)
    return {"entries": entries}


# ---------------------------------------------------------------------------
# NODES management page
# ---------------------------------------------------------------------------
@app.get("/nodes", response_class=HTMLResponse)
async def nodes_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        nodes = session.exec(select(Node).order_by(Node.id)).all()
        settings = session.exec(select(Settings)).first()
    return templates.TemplateResponse(request, "nodes.html", {
        "user": user,
        "nodes": nodes,
        "settings": settings,
    })


@app.post("/nodes/delete/{node_id}")
async def delete_node(request: Request, node_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        node = session.get(Node, node_id)
        if node:
            session.exec(delete(NodeProxyResult).where(NodeProxyResult.node_id == node_id))
            session.delete(node)
            session.commit()
    return RedirectResponse("/nodes", status_code=302)


# ---------------------------------------------------------------------------
# NODE API — Bearer Token Auth
# ---------------------------------------------------------------------------
def _verify_node_token(authorization: str | None) -> bool:
    if not authorization or not authorization.startswith("Bearer "):
        return False
    token = authorization[7:]
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        return settings and settings.node_api_token and token == settings.node_api_token


@app.post("/api/node/register")
async def node_register(request: Request, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    name = body.get("name", "unnamed")
    region = body.get("region", "unknown")

    client_ip = request.client.host if request.client else ""

    with Session(engine) as session:
        # Check if node with same name exists
        existing = session.exec(select(Node).where(Node.name == name)).first()
        if existing:
            existing.ip = client_ip
            existing.region = region
            existing.is_online = True
            from datetime import datetime, timezone
            existing.last_heartbeat = datetime.now(timezone.utc).isoformat()
            session.add(existing)
            session.commit()
            return {"status": "updated", "node_id": existing.id}
        else:
            from datetime import datetime, timezone
            node = Node(
                name=name,
                region=region,
                ip=client_ip,
                is_online=True,
                last_heartbeat=datetime.now(timezone.utc).isoformat(),
            )
            session.add(node)
            session.commit()
            session.refresh(node)
            return {"status": "registered", "node_id": node.id}


@app.get("/api/node/config")
async def node_get_config(authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        test_urls = session.exec(select(TestUrl).order_by(TestUrl.position)).all()

    return {
        "ping_threshold_ms": settings.ping_threshold_ms if settings else 1000,
        "http_timeout_s": settings.http_timeout_s if settings else 10,
        "concurrent_checks_limit": settings.concurrent_checks_limit if settings else 50,
        "speed_test_top_n": settings.speed_test_top_n if settings else 0,
        "test_urls": [
            {"url": t.url, "expect_status": t.expect_status, "min_body_bytes": t.min_body_bytes}
            for t in test_urls
        ],
    }


@app.get("/api/node/proxies")
async def node_get_proxies(top: int = 50, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        limit = min(top, settings.node_check_top_n if settings else 50)
        proxies = session.exec(
            select(ProxyResult)
            .order_by(ProxyResult.speed_score.desc(), ProxyResult.tests_passed.desc(), ProxyResult.ping_ms)
            .limit(limit)
        ).all()

    return {"proxies": [p.raw_url for p in proxies]}


@app.post("/api/node/results")
async def node_post_results(request: Request, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    node_id = body.get("node_id")
    results = body.get("results", [])

    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    with Session(engine) as session:
        node = session.get(Node, node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")

        # Clear old results for this node
        session.exec(delete(NodeProxyResult).where(NodeProxyResult.node_id == node_id))

        passed = 0
        for r in results:
            npr = NodeProxyResult(
                node_id=node_id,
                raw_url=r.get("raw_url", ""),
                ping_ms=r.get("ping_ms", 0),
                tests_passed=r.get("tests_passed", 0),
                tests_total=r.get("tests_total", 0),
                download_speed_kbps=r.get("download_speed_kbps", 0),
                upload_speed_kbps=r.get("upload_speed_kbps", 0),
                speed_score=r.get("speed_score", 0.0),
                last_tested=now,
            )
            session.add(npr)
            if r.get("tests_passed", 0) > 0:
                passed += 1

        node.proxies_checked = len(results)
        node.proxies_passed = passed
        node.last_heartbeat = now
        node.is_online = True
        session.add(node)
        session.commit()

    logger.info(f"Node {node_id} reported {len(results)} results ({passed} passed)")
    return {"status": "ok", "accepted": len(results)}


@app.post("/api/node/heartbeat")
async def node_heartbeat(request: Request, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    node_id = body.get("node_id")
    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")

    from datetime import datetime, timezone
    with Session(engine) as session:
        node = session.get(Node, node_id)
        if node:
            node.last_heartbeat = datetime.now(timezone.utc).isoformat()
            node.is_online = True
            session.add(node)
            session.commit()

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# RUN TEST
# ---------------------------------------------------------------------------
@app.post("/run-test")
async def run_test(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    if test_status["running"]:
        return RedirectResponse("/", status_code=302)

    asyncio.create_task(_background_test())
    return RedirectResponse("/", status_code=302)


async def _background_test():
    """Background task for running the full test pipeline."""
    try:
        test_status["current_phase"] = "fetching"
        test_status["running"] = True
        proxy_links = await fetch_and_parse_subscriptions()
        if proxy_links:
            await run_full_test(proxy_links)
            # Run speed test if configured
            await run_speed_test(test_status)
            test_status["current_phase"] = "done"
            test_status["running"] = False
        else:
            test_status["current_phase"] = "done"
            test_status["running"] = False
            logger.warning("No proxy links found from subscriptions")
    except Exception as e:
        logger.error(f"Test pipeline error: {e}", exc_info=True)
        test_status["running"] = False
        test_status["current_phase"] = "error"


# ---------------------------------------------------------------------------
# TEST STATUS API (for AJAX polling)
# ---------------------------------------------------------------------------
@app.get("/api/test-status")
async def api_test_status():
    return {
        **test_status,
        "scheduler": scheduler_status,
    }


# ---------------------------------------------------------------------------
# WEBHOOK — Public proxy distribution (master)
# ---------------------------------------------------------------------------
@app.get("/{secret_path:path}")
async def webhook_output(secret_path: str):
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        if not settings:
            raise HTTPException(status_code=404)

        # Node-specific webhook: {webhook_secret_path}/node/{node_id}
        node_prefix = f"{settings.webhook_secret_path}/node/"
        if secret_path.startswith(node_prefix):
            try:
                node_id = int(secret_path[len(node_prefix):])
            except ValueError:
                raise HTTPException(status_code=404)

            node = session.get(Node, node_id)
            if not node:
                raise HTTPException(status_code=404)

            proxies = session.exec(
                select(NodeProxyResult)
                .where(NodeProxyResult.node_id == node_id)
                .order_by(NodeProxyResult.speed_score.desc(), NodeProxyResult.tests_passed.desc(), NodeProxyResult.ping_ms)
            ).all()

            if settings.webhook_max_proxies > 0:
                proxies = proxies[:settings.webhook_max_proxies]

            lines = []
            for i, p in enumerate(proxies, start=1):
                renamed = replace_proxy_remark(p.raw_url, str(i))
                lines.append(renamed)
            return PlainTextResponse("\n".join(lines), media_type="text/plain; charset=utf-8")

        # Global Consensus Webhook: {webhook_secret_path}/global
        global_prefix = f"{settings.webhook_secret_path}/global"
        if secret_path == global_prefix:
            from collections import defaultdict
            
            # Dictionary to accumulate stats: link -> {"passes": 0, "speed_scores": []}
            stats = defaultdict(lambda: {"passes": 0, "speed_scores": []})
            
            # Master results
            master_results = session.exec(select(ProxyResult)).all()
            for p in master_results:
                link = p.raw_url
                stats[link]["passes"] += 1
                stats[link]["speed_scores"].append(p.speed_score)
                
            # Node results (only consider as passed if tests_passed > 0)
            node_results = session.exec(select(NodeProxyResult)).all()
            for np in node_results:
                if np.tests_passed > 0:  # Valid local pass for that node
                    link = np.raw_url
                    stats[link]["passes"] += 1
                    stats[link]["speed_scores"].append(np.speed_score)
            
            # Compute consensus
            consensus_list = []
            for link, data in stats.items():
                if data["passes"] >= settings.global_sub_min_nodes:
                    avg_speed = sum(data["speed_scores"]) / len(data["speed_scores"])
                    consensus_list.append({
                        "link": link,
                        "passes": data["passes"],
                        "avg_speed": avg_speed
                    })
            
            # Sort by passes (desc), then speed (desc)
            consensus_list.sort(key=lambda x: (x["passes"], x["avg_speed"]), reverse=True)
            
            # Limit
            top_n = settings.global_sub_top_n
            if top_n > 0:
                consensus_list = consensus_list[:top_n]
                
            lines = []
            for i, p in enumerate(consensus_list, start=1):
                renamed = replace_proxy_remark(p["link"], f"GLOBAL-{i}-P{p['passes']}")
                lines.append(renamed)
            return PlainTextResponse("\n".join(lines), media_type="text/plain; charset=utf-8")

        # Main webhook
        if secret_path != settings.webhook_secret_path:
            raise HTTPException(status_code=404)

        query = select(ProxyResult).order_by(
            ProxyResult.speed_score.desc(),
            ProxyResult.tests_passed.desc(),
            ProxyResult.ping_ms,
        )
        if settings.webhook_max_proxies > 0:
            query = query.limit(settings.webhook_max_proxies)
        proxies = session.exec(query).all()

    lines = []
    for i, p in enumerate(proxies, start=1):
        renamed = replace_proxy_remark(p.raw_url, str(i))
        lines.append(renamed)

    text = "\n".join(lines)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# Run with uvicorn
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
