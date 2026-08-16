"""VPN Checker — FastAPI main application (Manager-only mode).

The master panel does NOT run any proxy tests. It serves as a manager:
- Fetches subscriptions and stores raw proxy URLs
- Distributes raw proxies to worker nodes for testing
- Aggregates results from nodes
- Serves webhook with best proxies from node results
"""

import copy

class TokenAuthMiddleware:
    def __init__(self, asgi_app, token_field: str):
        self.asgi_app = asgi_app
        self.token_field = token_field

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.asgi_app(scope, receive, send)

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode()
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

        with Session(engine) as session:
            s = session.exec(select(Settings)).first()
            expected_token = getattr(s, self.token_field, "") if s else ""

        if not expected_token or token != expected_token:
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"text/plain")],
            })
            await send({
                "type": "http.response.body",
                "body": b"Unauthorized",
            })
            return

        return await self.asgi_app(scope, receive, send)

import asyncio
import json
import logging
import secrets
import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request, Form, HTTPException, Header, BackgroundTasks, Query
from fastapi.responses import RedirectResponse, PlainTextResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select, func, delete
from sqlalchemy import text, or_

import database
from database import (
    create_db_and_tables,
    engine,
    Subscription,
    RawProxy,
    Settings,
    TestUrl,
    Node,
    NodeProxyResult,
    RatingGroup,
    NodeRatingLink,
)
from auth import (
    hash_password,
    verify_password,
    create_session_token,
    get_current_user,
    SESSION_COOKIE,
)
from subs_manager import fetch_and_parse_subscriptions
from scheduler import start_scheduler, scheduler_status
from log_buffer import log_buffer, setup_log_buffer
from proxy_parsers import replace_proxy_remark, get_proxy_identity

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
app = FastAPI(title="VPN Checker", version="3.0.0")

try:
    from starlette.routing import Mount
    from mcp_server import mcp_ro, mcp_admin

    mcp_ro_app = mcp_ro.http_app(transport="sse")
    auth_ro_app = TokenAuthMiddleware(mcp_ro_app, "mcp_read_token")
    
    mcp_admin_app = mcp_admin.http_app(transport="sse")
    auth_admin_app = TokenAuthMiddleware(mcp_admin_app, "mcp_admin_token")
    
    app.router.routes.insert(0, Mount("/mcp/admin", auth_admin_app))
    app.router.routes.insert(0, Mount("/mcp/read", auth_ro_app))
    logger.info("Mounted MCP endpoints: /mcp/read, /mcp/admin")
except ImportError as e:
    logger.warning(f"Failed to mount MCP servers: {e}")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

from i18n import translations

def t(request: Request, key: str, **kwargs):
    lang = request.cookies.get("lang", "en")
    if lang not in translations:
        lang = "en"
    
    default_text = kwargs.pop("default", key)
    text = translations[lang].get(key, default_text)
    
    if kwargs:
        text = text.format(**kwargs)
    return text

templates.env.globals["t"] = t

# Global fetch status (replaces test_status)
fetch_status = {
    "running": False,
    "current_phase": "idle",  # idle | fetching | saving | done | error
    "total_subs": 0,
    "fetched_proxies": 0,
    "last_fetch_at": None,
}

# ---------------------------------------------------------------------------
# All default subscription URLs
# ---------------------------------------------------------------------------
DEFAULT_SUBSCRIPTIONS = [
    # === GitVerse RUVIPIEN/russian-white-bolt ===
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
    # === Iranian aggregators ===
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/vless",
    "https://raw.githubusercontent.com/Bardiafa/Free-V2ray-Config/main/Splitted-By-Protocol/vless.txt",
    # === Mixed protocol aggregators ===
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

    # Clean up stale node results from previous runs
    with Session(engine) as session:
        cleanup_stats = _cleanup_stale_node_data(session)
        if any(v for k, v in cleanup_stats.items() if k != "online_ids" and v > 0):
            logger.info(
                f"Startup cleanup: stale_marked={cleanup_stats['stale_marked']} "
                f"orphan_npr={cleanup_stats['orphan_npr_deleted']} "
                f"online_nodes={len(cleanup_stats['online_ids'])}"
            )

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
                ban_duration_hours=168,

                ban_after_n_failures=3,
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
        raw_proxy_count = session.exec(select(func.count(RawProxy.id))).one()
        test_url_count = session.exec(select(func.count(TestUrl.id))).one()
        node_count = session.exec(select(func.count(Node.id))).one()
        settings = session.exec(select(Settings)).first()

        # Count valid proxies from all nodes (unique by raw_url where tests_passed > 0)
        valid_proxy_count = session.exec(
            select(func.count(func.distinct(NodeProxyResult.raw_url)))
            .where(NodeProxyResult.tests_passed > 0)
        ).one()

    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "sub_count": sub_count,
        "raw_proxy_count": raw_proxy_count,
        "valid_proxy_count": valid_proxy_count,
        "test_url_count": test_url_count,
        "node_count": node_count,
        "settings": settings,
        "fetch_status": fetch_status,
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


@app.post("/subscriptions/toggle/{sub_id}")
async def toggle_subscription(request: Request, sub_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    with Session(engine) as session:
        sub = session.get(Subscription, sub_id)
        if sub:
            sub.is_enabled = not sub.is_enabled
            session.add(sub)
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
        # Parse enabled_protocols JSON for template rendering
        enabled_protocols = {
            "vless": True,
            "vmess": True,
            "trojan": True,
            "ss": True,
            "hy2": True,
            "hysteria2": True,
        }
        if settings and settings.enabled_protocols:
            try:
                enabled_protocols = json.loads(settings.enabled_protocols)
            except Exception:
                pass
    return templates.TemplateResponse(request, "settings.html", {
        "user": user,
        "settings": settings,
        "saved": False,
        "enabled_protocols": enabled_protocols,
    })


@app.post("/settings", response_class=HTMLResponse)
async def settings_save(
    request: Request,
    ping_threshold_ms: int = Form(...),
    concurrent_checks_limit: int = Form(...),
    webhook_secret_path: str = Form(...),
    schedule_interval_minutes: int = Form(0),
    http_timeout_s: int = Form(10),
    speed_test_top_n: int = Form(0),
    node_check_top_n: int = Form(50),
    global_sub_top_n: int = Form(50),
    ban_duration_hours: int = Form(168),

    ban_after_n_failures: int = Form(3),
    good_proxy_retention_cycles: int = Form(3),
    chunk_size: int = Form(0),

    # Protocol filter checkboxes
    proto_vless: int = Form(0),
    proto_vmess: int = Form(0),
    proto_trojan: int = Form(0),
    proto_ss: int = Form(0),
    proto_hy2: int = Form(0),
    proto_hysteria2: int = Form(0),

    # Geo check toggle
    geo_check_enabled: int = Form(0),

    new_password: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    # Build enabled_protocols JSON
    enabled_protocols = {
        "vless": bool(proto_vless),
        "vmess": bool(proto_vmess),
        "trojan": bool(proto_trojan),
        "ss": bool(proto_ss),
        "hy2": bool(proto_hy2),
        "hysteria2": bool(proto_hysteria2),
    }
    enabled_protocols_json = json.dumps(enabled_protocols)

    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        if settings:
            settings.ping_threshold_ms = ping_threshold_ms
            settings.concurrent_checks_limit = concurrent_checks_limit
            settings.webhook_secret_path = webhook_secret_path.strip().strip("/")
            settings.schedule_interval_minutes = max(0, schedule_interval_minutes)
            settings.http_timeout_s = max(1, http_timeout_s)
            settings.speed_test_top_n = max(0, speed_test_top_n)
            settings.node_check_top_n = max(0, node_check_top_n)
            settings.global_sub_top_n = max(0, global_sub_top_n)

            settings.ban_duration_hours = max(0, ban_duration_hours)
            settings.ban_after_n_failures = max(1, ban_after_n_failures)
            settings.good_proxy_retention_cycles = max(0, good_proxy_retention_cycles)
            settings.chunk_size = max(0, chunk_size)
            settings.enabled_protocols = enabled_protocols_json
            settings.geo_check_enabled = bool(geo_check_enabled)

            if new_password.strip():
                settings.admin_pass_hash = hash_password(new_password.strip())
            session.add(settings)
            session.commit()
            session.refresh(settings)

    # Re-parse for template rendering
    return templates.TemplateResponse(request, "settings.html", {
        "user": user,
        "settings": settings,
        "saved": True,
        "enabled_protocols": enabled_protocols,
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
# RATINGS GROUPS
# ---------------------------------------------------------------------------
@app.get("/ratings", response_class=HTMLResponse)
async def ratings_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        ratings = session.exec(select(RatingGroup).order_by(RatingGroup.id)).all()
        nodes = session.exec(select(Node).order_by(Node.id)).all()
        
        # Build mapping: rating_group_id -> list of node_ids
        links = session.exec(select(NodeRatingLink)).all()
        rating_nodes_map = defaultdict(list)
        for link in links:
            rating_nodes_map[link.rating_group_id].append(link.node_id)
            
    return templates.TemplateResponse(request, "ratings.html", {
        "user": user,
        "ratings": ratings,
        "nodes": nodes,
        "rating_nodes_map": dict(rating_nodes_map),
    })

@app.post("/ratings/add")
async def add_rating(
    request: Request,
    name: str = Form(...),
    webhook_path: str = Form(...),
    max_proxies: int = Form(0),
    min_dl_kbps: int = Form(0),
    min_ul_kbps: int = Form(0),
    rename_prefix: str = Form(""),
    consensus_only: int = Form(0),
    geo_top_n: int = Form(1),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        rg = RatingGroup(
            name=name.strip(),
            webhook_path=webhook_path.strip().strip("/"),
            max_proxies=max(0, max_proxies),
            min_dl_kbps=max(0, min_dl_kbps),
            min_ul_kbps=max(0, min_ul_kbps),
            rename_prefix=rename_prefix.strip(),
            consensus_only=bool(consensus_only),
            geo_top_n=max(1, geo_top_n)
        )
        session.add(rg)
        try:
            session.commit()
        except Exception as e:
            logger.error(f"Error adding rating: {e}")
            session.rollback()

    return RedirectResponse("/ratings", status_code=302)

@app.post("/ratings/edit/{rating_id}")
async def edit_rating(
    request: Request,
    rating_id: int,
    name: str = Form(...),
    webhook_path: str = Form(...),
    max_proxies: int = Form(0),
    min_dl_kbps: int = Form(0),
    min_ul_kbps: int = Form(0),
    rename_prefix: str = Form(""),
    consensus_only: int = Form(0),
    geo_top_n: int = Form(1),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        rg = session.get(RatingGroup, rating_id)
        if rg:
            rg.name = name.strip()
            rg.webhook_path = webhook_path.strip().strip("/")
            rg.max_proxies = max(0, max_proxies)
            rg.min_dl_kbps = max(0, min_dl_kbps)
            rg.min_ul_kbps = max(0, min_ul_kbps)
            rg.rename_prefix = rename_prefix.strip()
            rg.consensus_only = bool(consensus_only)
            rg.geo_top_n = max(1, geo_top_n)
            session.add(rg)
            try:
                session.commit()
            except Exception as e:
                logger.error(f"Error editing rating: {e}")
                session.rollback()

    return RedirectResponse("/ratings", status_code=302)

@app.post("/ratings/delete/{rating_id}")
async def delete_rating(request: Request, rating_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        rg = session.get(RatingGroup, rating_id)
        if rg:
            session.exec(delete(NodeRatingLink).where(NodeRatingLink.rating_group_id == rating_id))
            session.delete(rg)
            session.commit()

    return RedirectResponse("/ratings", status_code=302)

@app.post("/ratings/{rating_id}/add-node/{node_id}")
async def add_node_to_rating(request: Request, rating_id: int, node_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        existing = session.exec(select(NodeRatingLink).where(
            NodeRatingLink.rating_group_id == rating_id,
            NodeRatingLink.node_id == node_id
        )).first()
        if not existing:
            link = NodeRatingLink(rating_group_id=rating_id, node_id=node_id)
            session.add(link)
            try:
                session.commit()
            except Exception:
                session.rollback()

    return RedirectResponse("/ratings", status_code=302)

@app.post("/ratings/{rating_id}/remove-node/{node_id}")
async def remove_node_from_rating(request: Request, rating_id: int, node_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        link = session.exec(select(NodeRatingLink).where(
            NodeRatingLink.rating_group_id == rating_id,
            NodeRatingLink.node_id == node_id
        )).first()
        if link:
            session.delete(link)
            session.commit()

    return RedirectResponse("/ratings", status_code=302)

@app.get("/ratings/{rating_id}/proxies", response_class=HTMLResponse)
async def rating_proxies_partial(request: Request, rating_id: int):
    user = get_current_user(request)
    if not user:
        return PlainTextResponse("Unauthorized", status_code=401)

    with Session(engine) as session:
        group = session.get(RatingGroup, rating_id)
        if not group:
            return PlainTextResponse("Rating group not found", status_code=404)
            
        settings = session.exec(select(Settings)).first()

        cleanup_stats = _cleanup_stale_node_data(session)
        online_ids = set(cleanup_stats.get("online_ids", []))
        
        links = session.exec(select(NodeRatingLink).where(NodeRatingLink.rating_group_id == rating_id)).all()
        linked_node_ids = {link.node_id for link in links}
        target_node_ids = online_ids & linked_node_ids
        
        if not target_node_ids:
            return templates.TemplateResponse(request, "proxy_table.html", {"proxies": []})
            
        all_results = session.exec(
            select(NodeProxyResult)
            .where(NodeProxyResult.tests_passed > 0)
            .where(NodeProxyResult.node_id.in_(target_node_ids))
        ).all()
        
    aggregated = {}
    for r in all_results:
        pid = get_proxy_identity(r.raw_url)
        if pid not in aggregated:
            aggregated[pid] = {"node_best": {}, "tests_total": r.tests_total}
        agg = aggregated[pid]
        nid = r.node_id
        if nid not in agg["node_best"] or r.speed_score > agg["node_best"][nid].speed_score:
            agg["node_best"][nid] = r
        agg["tests_total"] = max(agg["tests_total"], r.tests_total)

    proxy_list = []
    for pid, agg in aggregated.items():
        nc = len(agg["node_best"])
        if nc == 0:
            continue
            
        if group.consensus_only and nc < len(target_node_ids):
            continue
            
        best_rows = list(agg["node_best"].values())
        sum_scores = sum(r.speed_score for r in best_rows)
        sum_dl = sum(r.download_speed_kbps for r in best_rows)
        sum_ul = sum(r.upload_speed_kbps for r in best_rows)
        
        avg_dl = sum_dl // nc
        avg_ul = sum_ul // nc
        
        if group.min_dl_kbps > 0 and avg_dl < group.min_dl_kbps: continue
        if group.min_ul_kbps > 0 and avg_ul < group.min_ul_kbps: continue

        best_ping = min(r.ping_ms for r in best_rows)
        best_row = max(best_rows, key=lambda r: r.speed_score)

        proxy_list.append({
            "pid": pid,
            "raw_url": best_row.raw_url,
            "node_count": nc,
            "avg_speed_score": round(sum_scores / nc, 1),
            "avg_tests_passed": sum(r.tests_passed for r in best_rows) // nc,
            "tests_total": max(r.tests_total for r in best_rows),
            "best_ping_ms": best_ping,
            "avg_dl_kbps": avg_dl,
            "avg_ul_kbps": avg_ul,
            "last_tested": max(r.last_tested for r in best_rows),
            "country_name": getattr(best_row, "country_name", "") or "",
        })

    if settings.geo_check_enabled:
        geo_top_n = max(1, group.geo_top_n or 1)
        country_proxies = {}
        for p in proxy_list:
            country = p["country_name"].strip()
            if not country or country.lower() == "unknown" or country.lower() == "украина":
                continue
            if country not in country_proxies:
                country_proxies[country] = []
            country_proxies[country].append(p)
            
        deduped_list = []
        for country, proxies in country_proxies.items():
            proxies.sort(key=lambda x: x["avg_speed_score"], reverse=True)
            deduped_list.extend(proxies[:geo_top_n])
        proxy_list = deduped_list
        
    proxy_list.sort(key=lambda x: (-x["node_count"], -x["avg_speed_score"]))
    
    if group.max_proxies > 0:
        proxy_list = proxy_list[:group.max_proxies]

    return templates.TemplateResponse(request, "proxy_table.html", {"proxies": proxy_list})

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


# ---------------------------------------------------------------------------
# DEBUG: NodeProxyResult summary
# ---------------------------------------------------------------------------
@app.get("/api/debug/npr-summary")
async def api_debug_npr_summary():
    """Diagnostic: show NPR state, online nodes, and per-node row counts."""
    with Session(engine) as session:
        all_nodes = session.exec(select(Node)).all()
        npr_total = session.exec(select(func.count(NodeProxyResult.id))).one()
        npr_passing = session.exec(
            select(func.count(NodeProxyResult.id))
            .where(NodeProxyResult.tests_passed > 0)
        ).one()

        # Per-node NPR counts
        node_npr_counts = {}
        for node in all_nodes:
            count = session.exec(
                select(func.count(NodeProxyResult.id))
                .where(NodeProxyResult.node_id == node.id)
            ).one()
            node_npr_counts[node.id] = {
                "name": node.name,
                "is_online": node.is_online,
                "last_heartbeat": node.last_heartbeat,
                "npr_count": count,
            }

        # Node IDs in NPR that aren't in nodes table
        existing_ids = {n.id for n in all_nodes}
        npr_node_ids = session.exec(
            select(NodeProxyResult.node_id).distinct()
        ).all()
        orphan_ids = []
        for row in npr_node_ids:
            nid = row[0] if isinstance(row, tuple) else row
            try:
                nid = int(nid)
            except (TypeError, ValueError):
                continue
            if nid not in existing_ids:
                orphan_ids.append(nid)

    return {
        "nodes_total": len(all_nodes),
        "nodes_online": sum(1 for n in all_nodes if n.is_online),
        "npr_total": npr_total,
        "npr_passing": npr_passing,
        "per_node": node_npr_counts,
        "orphan_node_ids_in_npr": orphan_ids,
    }


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


@app.post("/api/node/{node_id}/force-test")
async def force_node_test(request: Request, node_id: int):
    """Trigger a manual test run on a specific node."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    with Session(engine) as session:
        node = session.get(Node, node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        node.force_test = True
        # Reset counters for the new test run
        node.proxies_checked = 0
        node.proxies_passed = 0
        session.add(node)
        session.commit()
    return {"status": "ok"}


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
        existing = session.exec(select(Node).where(Node.name == name)).first()
        if existing:
            # Anti-duplicate: if another instance is still online and testing, reject
            stale_threshold = datetime.now(timezone.utc) - timedelta(seconds=60)
            try:
                hb = datetime.fromisoformat(existing.last_heartbeat) if existing.last_heartbeat else None
            except (ValueError, TypeError):
                hb = None
            is_recent = hb is not None and hb >= stale_threshold

            # Anti-duplicate: block registration if another instance is still alive.
            # is_recent = heartbeat within last 60 seconds.
            # We block ALL duplicates, not just those in "testing" state —
            # an idle node still means a live original that shouldn't be replaced.
            if existing.is_online and is_recent:
                logger.warning(f"Node '{name}' (id={existing.id}) is already active (status={existing.status}). "
                               f"Rejecting duplicate registration from {client_ip}.")
                return {"status": "already_active", "node_id": existing.id}

            existing.ip = client_ip
            existing.region = region
            existing.is_online = True
            existing.last_heartbeat = datetime.now(timezone.utc).isoformat()

            # Reset results from previous worker instance to prevent
            # stale counters on restart
            session.exec(
                delete(NodeProxyResult).where(
                    NodeProxyResult.node_id == existing.id
                )
            )
            existing.proxies_checked = 0
            existing.proxies_passed = 0
            existing.testing_generation_id = ""

            session.add(existing)
            session.commit()
            return {"status": "updated", "node_id": existing.id}
        else:
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
async def node_get_config(authorization: str = Header(None), node_id: int = Query(default=0)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    force_test = False
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        test_urls = session.exec(select(TestUrl).order_by(TestUrl.position)).all()
        if node_id > 0:
            node = session.get(Node, node_id)
            if node:
                force_test = node.force_test

    return {
        "ping_threshold_ms": settings.ping_threshold_ms if settings else 1000,
        "http_timeout_s": settings.http_timeout_s if settings else 10,
        "concurrent_checks_limit": settings.concurrent_checks_limit if settings else 50,
        "speed_test_top_n": settings.speed_test_top_n if settings else 0,
        "schedule_interval_minutes": settings.schedule_interval_minutes if settings else 0,
        "chunk_size": settings.chunk_size if settings and settings.chunk_size else 0,
        "generation_id": database.generation_id,
        "force_test": force_test,
        "test_urls": [
            {"url": t.url, "expect_status": t.expect_status, "min_body_bytes": t.min_body_bytes}
            for t in test_urls
        ],
        "geo_check_enabled": settings.geo_check_enabled if settings else False,
        "speed_test_dl_url": "/api/speedtest/download",
    }


@app.get("/api/node/proxies")
async def node_get_proxies(
    authorization: str = Header(None),
    offset: int = Query(default=0),
    limit: int = Query(default=0),
    full: bool = Query(default=False),
):
    """Serve raw fetched proxies to workers for testing with optional pagination and protocol filtering."""
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    # Protocol prefix map
    PROTOCOL_MAP = {
        "vless": "vless://",
        "vmess": "vmess://",
        "trojan": "trojan://",
        "ss": "ss://",
        "hy2": "hy2://",
        "hysteria2": "hysteria2://",
    }

    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()

        # Parse enabled_protocols from settings
        enabled_protocols = {}
        if settings and settings.enabled_protocols:
            try:
                enabled_protocols = json.loads(settings.enabled_protocols)
            except Exception:
                enabled_protocols = {}

        # Build protocol filter conditions (if any protocols are disabled)
        conditions = []
        for proto, prefix in PROTOCOL_MAP.items():
            if enabled_protocols.get(proto, True):
                conditions.append(RawProxy.raw_url.like(f"{prefix}%"))

        # When full=True: ignore offset/limit, fetch everything.
        # effective_limit stays 0 → no LIMIT clause.
        effective_limit = 0
        if not full:
            if limit > 0:
                effective_limit = limit
            elif settings and settings.chunk_size > 0:
                effective_limit = settings.chunk_size
            elif settings and settings.node_check_top_n > 0:
                effective_limit = settings.node_check_top_n

        # Get total count with same filters
        count_query = select(func.count(RawProxy.id))
        if conditions:
            count_query = count_query.where(or_(*conditions))
        total = session.exec(count_query).one()

        # Build main query with filters, ordering, offset, limit
        query = select(RawProxy).order_by(RawProxy.id)
        if conditions:
            query = query.where(or_(*conditions))
        if not full and offset > 0:
            query = query.offset(offset)
        if effective_limit > 0:
            query = query.limit(effective_limit)

        raw_proxies = session.exec(query).all()

    raw_urls = sorted([p.raw_url for p in raw_proxies])

    # In full mode: run_id = md5(generation_id) only (no offset, since chunking is now on worker)
    # In paginated mode: run_id = md5(generation_id:offset) (legacy, kept for existing workers)
    if full:
        run_id_str = f"{database.generation_id}"
    else:
        run_id_str = f"{database.generation_id}:{offset}"
    run_id = hashlib.md5(run_id_str.encode("utf-8")).hexdigest() if raw_urls else "empty"

    # Calculate if there are more results (paginated mode only)
    has_more = (offset + len(raw_urls)) < total if total > 0 else False

    response = {
        "run_id": run_id,
        "proxies": raw_urls,
        "offset": 0 if full else offset,
        "total": total,
        "has_more": False if full else has_more,
    }

    # In full mode: always return chunk_size so worker can slice locally
    if full and settings:
        response["chunk_size"] = settings.chunk_size if settings.chunk_size else 0

    return response


@app.post("/api/node/results")
async def node_post_results(request: Request, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    node_id = body.get("node_id")
    results = body.get("results", [])
    is_partial = body.get("is_partial", False)
    generation_id = body.get("generation_id", "")

    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")

    now = datetime.now(timezone.utc).isoformat()
    chunk_urls = [r.get("raw_url", "") for r in results]

    with Session(engine) as session:
        node = session.get(Node, node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")

        # Detect generation change: wipe ALL old results for this node
        # before accepting data from the new generation.
        # This prevents stale rows from previous fetch cycles from
        # inflating proxies_checked/proxies_passed counters.
        if generation_id and generation_id != node.testing_generation_id:
            logger.info(
                f"Node {node_id}: generation changed "
                f"('{node.testing_generation_id}' -> '{generation_id}'), "
                f"wiping all old results."
            )
            session.exec(
                delete(NodeProxyResult).where(
                    NodeProxyResult.node_id == node_id
                )
            )
            node.testing_generation_id = generation_id
            node.proxies_checked = 0
            node.proxies_passed = 0
            # Force full clear even for this chunk — old data is gone
            is_partial = False

        # Clear old results: if partial, only delete for proxies in this chunk
        if is_partial and chunk_urls:
            session.exec(
                delete(NodeProxyResult).where(
                    NodeProxyResult.node_id == node_id,
                    NodeProxyResult.raw_url.in_(chunk_urls)
                )
            )
        else:
            # Full replacement: clear all results for this node
            session.exec(delete(NodeProxyResult).where(NodeProxyResult.node_id == node_id))

        passed = 0
        failed_urls = []
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
                country_name=r.get("country_name", ""),
            )
            session.add(npr)
            if r.get("tests_passed", 0) > 0:
                passed += 1
            else:
                failed_urls.append(r.get("raw_url", ""))

        # Recalculate counters from DB — correctly accumulates across partial chunks
        total_checked = session.exec(
            select(func.count()).select_from(NodeProxyResult).where(
                NodeProxyResult.node_id == node_id
            )
        ).one()
        total_passed = session.exec(
            select(func.count()).select_from(NodeProxyResult).where(
                NodeProxyResult.node_id == node_id,
                NodeProxyResult.tests_passed > 0
            )
        ).one()
        node.proxies_checked = total_checked
        node.proxies_passed = total_passed
        node.last_heartbeat = now
        node.is_online = True
        # Mark node idle when full result set is reported (testing cycle complete)
        if not is_partial:
            node.status = "idle"
            node.total_chunks = 0
            node.current_chunk = 0
        session.add(node)
        session.commit()

    logger.info(f"Node {node_id} reported {len(results)} results ({passed} passed), is_partial={is_partial}")

    # Evaluate bans across all nodes (optionally limit to chunk_urls)
    background_tasks.add_task(_evaluate_bans, chunk_urls if is_partial else None)

    return {"status": "ok", "accepted": len(results)}


def _evaluate_bans(raw_urls: list[str] | None = None):
    """Evaluate ban status for all proxies based on cross-node consensus.

    Args:
        raw_urls: Optional list to limit evaluation to specific proxies (for chunked mode).
                  If None, evaluates all tested proxies.

    Rules:
    - A proxy is considered 'failed' only if it failed on ALL connected workers
    - If it passed on at least one worker → reset consecutive_failures to 0
    - Ban only after N consecutive failures (ban_after_n_failures setting)
    """
    try:
        with Session(engine) as session:
            settings = session.exec(select(Settings)).first()
            if not settings or settings.ban_duration_hours <= 0:
                return  # Bans disabled

            ban_threshold = settings.ban_after_n_failures or 3
            ban_duration = settings.ban_duration_hours

            # Get all online nodes that have reported results
            nodes = session.exec(select(Node).where(Node.is_online == True)).all()
            if not nodes:
                return

            node_ids = [n.id for n in nodes]

            # Get all NodeProxyResults grouped by raw_url
            all_results = session.exec(select(NodeProxyResult)).all()
            
            # Build per-proxy result map: raw_url -> {node_id: tests_passed}
            proxy_node_results = defaultdict(dict)
            for r in all_results:
                if r.node_id in node_ids:
                    proxy_node_results[r.raw_url][r.node_id] = r.tests_passed

            # Get all raw proxies that were tested (have results from at least one node)
            tested_urls = set(proxy_node_results.keys())
            if not tested_urls:
                return

            # If raw_urls provided (chunked mode), intersect with tested_urls
            if raw_urls:
                tested_urls = tested_urls & set(raw_urls)
                if not tested_urls:
                    return

            # Evaluate each tested proxy
            banned_count = 0
            reset_count = 0
            now_iso = datetime.now(timezone.utc).isoformat()

            # Load tested RawProxies in chunks to avoid SQLite limits
            tested_urls_list = list(tested_urls)
            raw_proxy_map = {}
            for i in range(0, len(tested_urls_list), 900):
                chunk = tested_urls_list[i:i+900]
                chunk_rps = session.exec(select(RawProxy).where(RawProxy.raw_url.in_(chunk))).all()
                for rp in chunk_rps:
                    raw_proxy_map[rp.raw_url] = rp

            for raw_url in tested_urls:
                rp = raw_proxy_map.get(raw_url)
                if not rp:
                    continue

                node_results = proxy_node_results[raw_url]
                
                # Check if proxy passed on at least one worker
                passed_on_any = any(tp > 0 for tp in node_results.values())

                if passed_on_any:
                    # Passed on at least one node → reset failures, unban if banned
                    if rp.consecutive_failures > 0:
                        rp.consecutive_failures = 0
                        rp.banned_until = None
                        reset_count += 1
                else:
                    # Failed on all nodes that tested it
                    # Only count as failure if tested on ALL connected nodes
                    tested_on_all = all(nid in node_results for nid in node_ids)
                    if tested_on_all:
                        rp.consecutive_failures += 1
                        if rp.consecutive_failures >= ban_threshold:
                            ban_until = (datetime.now(timezone.utc) + timedelta(hours=ban_duration)).isoformat()
                            rp.banned_until = ban_until
                            banned_count += 1

                session.add(rp)

            session.commit()

            if banned_count > 0:
                logger.info(f"Banned {banned_count} proxies (failed {ban_threshold}+ times on all {len(node_ids)} nodes, ban={ban_duration}h)")
            if reset_count > 0:
                logger.info(f"Reset {reset_count} proxy failure counters (passed on at least one node)")

    except Exception as e:
        logger.error(f"Error evaluating bans: {e}", exc_info=True)

# ---------------------------------------------------------------------------
# Shared cleanup: remove stale NodeProxyResult rows from offline/orphan nodes
# ---------------------------------------------------------------------------
def _cleanup_stale_node_data(session) -> dict:
    """Delete NodeProxyResult rows belonging to offline or non-existent nodes.

    Uses datetime.fromisoformat() to safely compare ISO timestamps
    (avoids edge cases with differing microsecond / timezone precision).

    Returns a dict with cleanup statistics for logging.
    """
    stale_threshold_dt = datetime.now(timezone.utc) - timedelta(minutes=30)
    stats = {
        "stale_marked": 0,
        "orphan_npr_deleted": 0,
        "online_ids": [],
    }

    all_nodes = session.exec(select(Node)).all()

    # Step 1: Mark nodes as offline if no heartbeat in last 5 minutes
    for node in all_nodes:
        if not node.is_online:
            continue
        if not node.last_heartbeat:
            node.is_online = False
            node.status = "idle"
            node.total_chunks = 0
            node.current_chunk = 0
            stats["stale_marked"] += 1
            logger.info(
                f"Marked node {node.id} ({node.name}) as offline (last_heartbeat=NULL)"
            )
            continue
        try:
            hb = datetime.fromisoformat(node.last_heartbeat)
            if hb < stale_threshold_dt:
                node.is_online = False
                node.status = "idle"
                node.total_chunks = 0
                node.current_chunk = 0
                stats["stale_marked"] += 1
                logger.info(
                    f"Marked node {node.id} ({node.name}) as offline "
                    f"(last_heartbeat={node.last_heartbeat})"
                )
        except (ValueError, TypeError):
            node.is_online = False
            node.status = "idle"
            node.total_chunks = 0
            node.current_chunk = 0
            stats["stale_marked"] += 1
            logger.warning(
                f"Marked node {node.id} ({node.name}) as offline "
                f"(malformed last_heartbeat={node.last_heartbeat!r})"
            )

    if stats["stale_marked"] > 0:
        session.commit()

    # Step 2: Delete NPR rows from node_ids not present in nodes table at all (orphan cleanup)
    all_node_ids_raw = session.exec(select(Node.id)).all()
    all_node_ids = {int(row[0]) if isinstance(row, tuple) else int(row) for row in all_node_ids_raw}
    orphan_rows = session.exec(
        select(NodeProxyResult.node_id).distinct()
    ).all()
    orphan_ids: list[int] = []
    for row in orphan_rows:
        nid = row[0] if isinstance(row, tuple) else row
        try:
            nid = int(nid)
        except (TypeError, ValueError):
            continue
        if nid not in all_node_ids:
            orphan_ids.append(nid)

    if orphan_ids:
        result = session.exec(
            delete(NodeProxyResult).where(NodeProxyResult.node_id.in_(orphan_ids))
        )
        session.commit()
        stats["orphan_npr_deleted"] = result.rowcount if hasattr(result, "rowcount") else 0
        logger.info(
            f"Cleaned up NodeProxyResult rows from {len(orphan_ids)} "
            f"orphan node_ids (node no longer exists)"
        )

    # Collect remaining online node IDs (fresh query)
    online_rows = session.exec(select(Node.id).where(Node.is_online == True)).all()
    stats["online_ids"] = [
        int(row[0]) if isinstance(row, tuple) else int(row)
        for row in online_rows
    ]

    return stats


@app.post("/api/node/heartbeat")
async def node_heartbeat(request: Request, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    node_id = body.get("node_id")
    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")

    with Session(engine) as session:
        node = session.get(Node, node_id)
        if node:
            node.last_heartbeat = datetime.now(timezone.utc).isoformat()
            node.is_online = True
            session.add(node)
            session.commit()

    return {"status": "ok"}


@app.post("/api/node/logs")
async def node_logs(request: Request, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    node_id = body.get("node_id")
    logs = body.get("logs", [])
    
    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")
        
    with Session(engine) as session:
        node = session.get(Node, node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        node_name = node.name

    for log in logs:
        entry = {
            "timestamp": log.get("timestamp"),
            "level": log.get("level", "INFO"),
            "logger": f"worker:{node_name}",
            "message": log.get("message", "")
        }
        log_buffer.append(entry)
        
    return {"status": "ok", "received": len(logs)}


# ---------------------------------------------------------------------------
# NODE STATUS — worker reports testing progress
# ---------------------------------------------------------------------------
@app.post("/api/node/status")
async def node_update_status(request: Request, authorization: str = Header(None)):
    """Worker reports: idle/testing, current_chunk/total_chunks, generation_id."""
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    node_id = body.get("node_id")
    status = body.get("status", "idle")
    current_chunk = body.get("current_chunk", 0)
    total_chunks = body.get("total_chunks", 0)
    testing_gen_id = body.get("generation_id", "")

    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")

    now = datetime.now(timezone.utc).isoformat()
    with Session(engine) as session:
        node = session.get(Node, node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        node.status = status
        node.current_chunk = current_chunk
        node.total_chunks = total_chunks
        node.testing_generation_id = testing_gen_id
        # Reset force_test flag when node starts testing
        if status == "testing" and node.force_test:
            node.force_test = False
        node.last_heartbeat = now
        node.is_online = True
        session.add(node)
        session.commit()

    logger.debug(f"Node {node_id} status: {status}, chunk {current_chunk}/{total_chunks}")
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# NODE STATE — worker fetches its own state on startup (crash recovery)
# ---------------------------------------------------------------------------
@app.get("/api/node/state")
async def node_get_state(node_id: int = Query(...), authorization: str = Header(None)):
    """Worker fetches its saved state to resume after crash."""
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    with Session(engine) as session:
        node = session.get(Node, node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        settings = session.exec(select(Settings)).first()
        return {
            "status": node.status,
            "current_chunk": node.current_chunk,
            "total_chunks": node.total_chunks,
            "testing_generation_id": node.testing_generation_id,
            "chunk_size": settings.chunk_size if settings else 0,
        }


# ---------------------------------------------------------------------------
# Speed test download endpoint (self-hosted fallback for restricted nodes)
# ---------------------------------------------------------------------------
_SPEEDTEST_BLOB_SIZE = 10 * 1024 * 1024  # 10 MB
_speedtest_blob: bytes | None = None


def _get_speedtest_blob() -> bytes:
    """Lazily generate and cache a 10 MB random blob for speed testing."""
    global _speedtest_blob
    if _speedtest_blob is None:
        import os as _os
        _speedtest_blob = _os.urandom(_SPEEDTEST_BLOB_SIZE)
    return _speedtest_blob


@app.get("/api/speedtest/download")
async def speedtest_download():
    """Serve a 10 MB binary blob for speed testing.

    Nodes behind restricted networks (e.g. MTS whitelist) can use this
    endpoint as a reliable fallback when external speed test servers
    are unreachable.  No auth required — only random bytes are served.
    """
    blob = _get_speedtest_blob()
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(len(blob)),
            "Accept-Ranges": "bytes",
            "Cache-Control": "no-cache",
        },
    )


# ---------------------------------------------------------------------------
# FETCH SUBSCRIPTIONS (replaces run-test)
_background_tasks = set()

@app.post("/fetch-subs")
async def fetch_subs(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    if fetch_status["running"]:
        return RedirectResponse("/", status_code=302)

    # Set status BEFORE scheduling the task so the redirect renders with correct state
    fetch_status["running"] = True
    fetch_status["current_phase"] = "starting"

    task = asyncio.create_task(_background_fetch())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return RedirectResponse("/", status_code=302)


async def _background_fetch():
    try:
        fetch_status["current_phase"] = "fetching"
        fetch_status["fetched_proxies"] = 0

        with Session(engine) as session:
            fetch_status["total_subs"] = session.exec(select(func.count(Subscription.id))).one()

        # Get good proxies from previous tests (tests_passed > 0)
        with Session(engine) as session:
            results = session.exec(
                select(NodeProxyResult.raw_url)
                .where(NodeProxyResult.tests_passed > 0)
                .distinct()
            ).all()

            # Handle both tuple and scalar results from SQLModel
            good_proxies = []
            for row in results:
                url = row[0] if isinstance(row, tuple) else row
                if url:
                    good_proxies.append(str(url))
            logger.info(f"Found {len(good_proxies)} good proxies from previous tests")

            # Read retention settings and existing RawProxy retention state
            settings = session.exec(select(Settings)).first()
            retention_limit = settings.good_proxy_retention_cycles if settings else 3

            # Parse enabled_protocols for filtering
            enabled_protocols = None
            if settings and settings.enabled_protocols:
                try:
                    enabled_protocols = json.loads(settings.enabled_protocols)
                except Exception:
                    pass

            if retention_limit > 0:
                existing_rp = session.exec(select(RawProxy)).all()
                old_retention: dict[str, int] = {}
                for rp in existing_rp:
                    key = rp.raw_url.split("#", 1)[0]
                    old_retention[key] = rp.retention_cycles
            else:
                old_retention = {}

        # Pass session to update last_config_count
        with Session(engine) as session:
            proxy_links = await fetch_and_parse_subscriptions(session, enabled_protocols)
            # Compare by identity key (URL minus #remark)
            new_keys = {url.split("#", 1)[0] for url in proxy_links}

            # Build final proxy set with retention tracking
            # key → (full_url, retention_cycles)
            final_proxies: dict[str, tuple[str, int]] = {}

            # 1. Fresh subscriptions: retention_cycles = 0 (reset)
            for url in proxy_links:
                key = url.split("#", 1)[0]
                final_proxies[key] = (url, 0)

            # 2. Good proxies NOT in fresh subscriptions: increment retention
            if retention_limit > 0:
                added_count = 0
                expired_count = 0
                for p in good_proxies:
                    key = p.split("#", 1)[0]
                    if key not in final_proxies:
                        prev = old_retention.get(key, 0)
                        new_cycles = prev + 1
                        if new_cycles <= retention_limit:
                            final_proxies[key] = (p, new_cycles)
                            added_count += 1
                        else:
                            expired_count += 1
                if added_count > 0:
                    logger.info(f"Retained {added_count} good proxies "
                                f"(not in subscriptions, within {retention_limit}-cycle limit)")
                if expired_count > 0:
                    logger.info(f"Expired {expired_count} proxies "
                                f"(exceeded {retention_limit}-cycle retention limit)")
            else:
                logger.info("Proxy retention disabled (good_proxy_retention_cycles=0)")

            fetch_status["current_phase"] = "saving"
            fetch_status["fetched_proxies"] = len(final_proxies)

            # Store raw proxies with retention_cycles
            if final_proxies:
                # Update generation_id BEFORE commit - ensures no race condition where
                # workers see new proxies with old generation_id
                database.generation_id = str(uuid.uuid4())
                logger.info(f"Background fetch: updated generation_id={database.generation_id}")

                session.exec(delete(RawProxy))
                for key, (url, cycles) in final_proxies.items():
                    if isinstance(url, str) and len(url) > 10 and url.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://')):
                        session.add(RawProxy(raw_url=url, retention_cycles=cycles))
                session.commit()

        fetch_status["current_phase"] = "done"
        fetch_status["last_fetch_at"] = datetime.now(timezone.utc).isoformat()
        logger.info(f"Subscription fetch complete: {len(final_proxies)} unique proxies stored for workers")

    except Exception as e:
        logger.error(f"Fetch pipeline error: {e}", exc_info=True)
        fetch_status["current_phase"] = "error"
    finally:
        fetch_status["running"] = False


# ---------------------------------------------------------------------------
# FETCH STATUS API (for AJAX polling)
# ---------------------------------------------------------------------------
@app.get("/api/fetch-status")
async def api_fetch_status():
    return {
        **fetch_status,
        "scheduler": scheduler_status,
    }


# ---------------------------------------------------------------------------
# WEBHOOK — Public proxy distribution (from node results)
# ---------------------------------------------------------------------------
def _compute_webhook_averages(
    results: list[NodeProxyResult],
) -> dict[str, dict]:
    """Aggregate per proxy identity: best result per node_id, then compute averages.

    Returns dict: identity_key -> {"raw_url": str, "avg_dl": int, "avg_ul": int, "avg_score": float,
                                    "node_ids": list, "country_name": str}
    """
    grouped: dict[str, dict] = {}
    for r in results:
        if r.tests_passed <= 0:
            continue
        pid = get_proxy_identity(r.raw_url)
        if pid not in grouped:
            grouped[pid] = {"node_best": {}, "total": r.tests_total}
        agg = grouped[pid]
        nid = r.node_id
        if nid not in agg["node_best"] or r.speed_score > agg["node_best"][nid].speed_score:
            agg["node_best"][nid] = r

    out = {}
    for pid, agg in grouped.items():
        nc = len(agg["node_best"])
        if nc == 0:
            continue
        rows = list(agg["node_best"].values())
        node_ids = list(agg["node_best"].keys())
        best_row = max(rows, key=lambda r: r.speed_score)
        # Pick country_name from the best-scoring row (most reliable result)
        country = getattr(best_row, "country_name", "") or ""
        out[pid] = {
            "raw_url": best_row.raw_url,
            "avg_dl": sum(r.download_speed_kbps for r in rows) // nc,
            "avg_ul": sum(r.upload_speed_kbps for r in rows) // nc,
            "avg_score": round(sum(r.speed_score for r in rows) / nc, 1),
            "node_ids": node_ids,
            "country_name": country,
        }
    return out


@app.get("/{secret_path:path}")
async def webhook_output(secret_path: str):
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        if not settings:
            raise HTTPException(status_code=404)
        
        # Check if secret_path matches a RatingGroup or the global fallback webhook
        group = session.exec(select(RatingGroup).where(RatingGroup.webhook_path == secret_path)).first()
        is_global = False
        if not group:
            if secret_path == settings.webhook_secret_path:
                is_global = True
            else:
                raise HTTPException(status_code=404)
        
        # Cleanup stale node data (marks offline nodes, deletes orphan results)
        cleanup_stats = _cleanup_stale_node_data(session)
        
        # RE-LOAD settings/group after cleanup
        settings = session.exec(select(Settings)).first()
        if not is_global:
            group = session.get(RatingGroup, group.id)
            if not group:
                raise HTTPException(status_code=404)
        
        online_ids = cleanup_stats.get("online_ids", [])
        if not online_ids:
            logger.warning("Webhook: no online nodes, returning empty list")
            return PlainTextResponse("", media_type="text/plain; charset=utf-8")
        
        online_ids_set = set(online_ids)

        if not is_global:
            # Get linked nodes for this group
            links = session.exec(select(NodeRatingLink).where(NodeRatingLink.rating_group_id == group.id)).all()
            linked_node_ids = {link.node_id for link in links}
            # Intersect with online_ids
            target_node_ids = online_ids_set & linked_node_ids
        else:
            target_node_ids = online_ids_set

        if not target_node_ids:
            logger.warning(f"Webhook {secret_path}: no target online nodes, returning empty list")
            return PlainTextResponse("", media_type="text/plain; charset=utf-8")
        
        # Load results only from target nodes where tests_passed > 0
        all_results = session.exec(
            select(NodeProxyResult)
            .where(NodeProxyResult.tests_passed > 0)
            .where(NodeProxyResult.node_id.in_(target_node_ids))
        ).all()
        
        # Aggregate: best result per (identity, node_id), then compute averages
        avg_data = _compute_webhook_averages(all_results)
        
        # Determine filtering parameters
        if is_global:
            consensus_only = settings.webhook_consensus_only
            min_dl = settings.webhook_min_dl_kbps or 0
            min_ul = settings.webhook_min_ul_kbps or 0
            geo_top_n = max(1, settings.webhook_geo_top_n or 1)
            top_n = settings.webhook_max_proxies or 0
            prefix = (settings.webhook_rename_prefix or "").strip()
        else:
            consensus_only = group.consensus_only
            min_dl = group.min_dl_kbps or 0
            min_ul = group.min_ul_kbps or 0
            geo_top_n = max(1, group.geo_top_n or 1)
            top_n = group.max_proxies or 0
            prefix = (group.rename_prefix or "").strip()

        # Consensus-only filter
        if consensus_only:
            consensus_threshold = len(target_node_ids)
            if consensus_threshold > 0:
                consensus_data = {}
                for pid, d in avg_data.items():
                    if len(d["node_ids"]) >= consensus_threshold:
                        consensus_data[pid] = d
                avg_data = consensus_data
        
        # Apply speed filters BEFORE sorting and limiting
        filtered_data = {}
        for pid, d in avg_data.items():
            if (min_dl == 0 or d["avg_dl"] >= min_dl) and (min_ul == 0 or d["avg_ul"] >= min_ul):
                filtered_data[pid] = d
        
        # Geo-check deduplication: if enabled globally, deduplicate based on geo_top_n
        geo_enabled = settings.geo_check_enabled
        if geo_enabled:
            country_proxies: dict[str, list[tuple[str, dict]]] = {}
            for pid, d in filtered_data.items():
                country = d.get("country_name", "").strip()
                if not country or country.lower() == "unknown":
                    continue
                if country.lower() == "украина":
                    continue
                if country not in country_proxies:
                    country_proxies[country] = []
                country_proxies[country].append((pid, d))
            
            deduped_data = {}
            for country, proxies in country_proxies.items():
                proxies.sort(key=lambda x: x[1]["avg_score"], reverse=True)
                for pid, d in proxies[:geo_top_n]:
                    deduped_data[pid] = d
            
            filtered_data = deduped_data
        
        # Sort: node_count (desc) → avg_score (desc)
        sorted_pids = sorted(
            filtered_data.keys(),
            key=lambda pid: (len(filtered_data[pid]["node_ids"]), filtered_data[pid]["avg_score"]),
            reverse=True,
        )
        
        # Limit to top-N
        if top_n > 0:
            sorted_pids = sorted_pids[:top_n]
        
        # Build output lines with appropriate naming
        lines = []
        if geo_enabled:
            country_counters: dict[str, int] = {}
            for pid in sorted_pids:
                url = filtered_data[pid]["raw_url"]
                country = filtered_data[pid].get("country_name", "").strip()
                if country:
                    country_counters[country] = country_counters.get(country, 0) + 1
                    idx = country_counters[country]
                    if geo_top_n > 1:
                        remark = f"{country} {idx}"
                    else:
                        remark = country
                    url = replace_proxy_remark(url, remark)
                else:
                    continue
                lines.append(url)
        else:
            for i, pid in enumerate(sorted_pids, start=1):
                url = filtered_data[pid]["raw_url"]
                if prefix:
                    url = replace_proxy_remark(url, f"{prefix} - {i}")
                lines.append(url)
        
        return PlainTextResponse("\n".join(lines), media_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# Run with uvicorn
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
