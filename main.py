"""VPN Checker — FastAPI main application (Manager-only mode).

The master panel does NOT run any proxy tests. It serves as a manager:
- Fetches subscriptions and stores raw proxy URLs
- Distributes raw proxies to worker nodes for testing
- Aggregates results from nodes
- Serves webhook with best proxies from node results
"""

import asyncio
import logging
import secrets
import hashlib
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request, Form, HTTPException, Header, BackgroundTasks
from fastapi.responses import RedirectResponse, PlainTextResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select, func, delete

from database import (
    create_db_and_tables,
    engine,
    Subscription,
    RawProxy,
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
                f"offline_npr={cleanup_stats['offline_npr_deleted']} "
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
    global_sub_top_n: int = Form(50),
    webhook_min_dl_kbps: int = Form(0),
    webhook_min_ul_kbps: int = Form(0),
    webhook_rename_prefix: str = Form(""),
    ban_duration_hours: int = Form(168),

    ban_after_n_failures: int = Form(3),
    good_proxy_retention_cycles: int = Form(3),
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
            settings.node_check_top_n = max(0, node_check_top_n)
            settings.global_sub_top_n = max(0, global_sub_top_n)
            settings.webhook_min_dl_kbps = max(0, webhook_min_dl_kbps)
            settings.webhook_min_ul_kbps = max(0, webhook_min_ul_kbps)
            settings.webhook_rename_prefix = webhook_rename_prefix.strip()

            settings.ban_duration_hours = max(0, ban_duration_hours)
            settings.ban_after_n_failures = max(1, ban_after_n_failures)
            settings.good_proxy_retention_cycles = max(0, good_proxy_retention_cycles)
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
# VALID PROXIES page (aggregated from all nodes)
# ---------------------------------------------------------------------------
@app.post("/proxies/clear-rating")
async def clear_rating(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        session.exec(delete(NodeProxyResult))
        session.exec(delete(Node))
        session.commit()

    logger.info("Rating cleared: all NodeProxyResult and Node rows deleted")
    return RedirectResponse("/proxies", status_code=302)


@app.get("/proxies", response_class=HTMLResponse)
async def proxies_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    with Session(engine) as session:
        # --- Run stale data cleanup ---
        cleanup_stats = _cleanup_stale_node_data(session)
        logger.info(
            f"/proxies cleanup: stale_marked={cleanup_stats['stale_marked']} "
            f"offline_npr={cleanup_stats['offline_npr_deleted']} "
            f"orphan_npr={cleanup_stats['orphan_npr_deleted']} "
            f"online={len(cleanup_stats['online_ids'])}"
        )

        online_ids = cleanup_stats["online_ids"]
        online_node_ids_set = set(online_ids)

        # --- Fetch results ONLY from online nodes (SQL-side filter) ---
        if online_node_ids_set:
            all_results = session.exec(
                select(NodeProxyResult)
                .where(NodeProxyResult.tests_passed > 0)
                .where(NodeProxyResult.node_id.in_(online_node_ids_set))
            ).all()
        else:
            all_results = []

    # --- Aggregate per proxy identity with per-node semantics ---
    # Instead of summing tests_passed/tests_total across all nodes
    # (which creates inflated, confusing numbers like 66/80 for 2 nodes),
    # we compute averages per node: avg_tests_passed = total / node_count
    aggregated: dict[str, dict] = {}
    for r in all_results:
        pid = get_proxy_identity(r.raw_url)
        if pid not in aggregated:
            aggregated[pid] = {
                "raw_url": r.raw_url,
                "node_count": 0,
                "sum_tests_passed": 0,
                "tests_total": r.tests_total,  # same for all nodes, take first
                "best_ping_ms": r.ping_ms,
                "dl_sum": 0,
                "ul_sum": 0,
                "max_speed_score": 0.0,
                "last_tested": r.last_tested,
            }
        agg = aggregated[pid]
        agg["node_count"] += 1
        agg["sum_tests_passed"] += r.tests_passed
        agg["tests_total"] = max(agg["tests_total"], r.tests_total)
        agg["best_ping_ms"] = min(agg["best_ping_ms"], r.ping_ms)
        agg["dl_sum"] += r.download_speed_kbps
        agg["ul_sum"] += r.upload_speed_kbps
        agg["max_speed_score"] = max(agg["max_speed_score"], r.speed_score)
        if r.last_tested > agg["last_tested"]:
            agg["last_tested"] = r.last_tested

    # Build final list with computed averages
    proxy_list: list[dict] = []
    for agg in aggregated.values():
        nc = agg["node_count"]
        proxy_list.append({
            "raw_url": agg["raw_url"],
            "node_count": nc,
            "avg_tests_passed": agg["sum_tests_passed"] // nc if nc else 0,
            "tests_total": agg["tests_total"],
            "best_ping_ms": agg["best_ping_ms"],
            "avg_dl_kbps": agg["dl_sum"] // nc if nc else 0,
            "avg_ul_kbps": agg["ul_sum"] // nc if nc else 0,
            "max_speed_score": agg["max_speed_score"],
            "last_tested": agg["last_tested"],
        })

    # Sort: most nodes -> highest speed -> lowest ping
    proxy_list.sort(
        key=lambda x: (-x["node_count"], -x["max_speed_score"], x["best_ping_ms"])
    )

    return templates.TemplateResponse(request, "proxies.html", {
        "user": user,
        "proxies": proxy_list,
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
            existing.ip = client_ip
            existing.region = region
            existing.is_online = True
            existing.last_heartbeat = datetime.now(timezone.utc).isoformat()
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
        "schedule_interval_minutes": settings.schedule_interval_minutes if settings else 0,
        "test_urls": [
            {"url": t.url, "expect_status": t.expect_status, "min_body_bytes": t.min_body_bytes}
            for t in test_urls
        ],
    }


@app.get("/api/node/proxies")
async def node_get_proxies(authorization: str = Header(None)):
    """Serve raw fetched proxies to workers for testing."""
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        limit = settings.node_check_top_n if settings and settings.node_check_top_n > 0 else 0
        query = select(RawProxy).order_by(RawProxy.id)
        if limit > 0:
            query = query.limit(limit)
        raw_proxies = session.exec(query).all()

    raw_urls = sorted([p.raw_url for p in raw_proxies])
    run_id = hashlib.md5("".join(raw_urls).encode("utf-8")).hexdigest() if raw_urls else "empty"

    return {
        "run_id": run_id,
        "proxies": raw_urls
    }


@app.post("/api/node/results")
async def node_post_results(request: Request, background_tasks: BackgroundTasks, authorization: str = Header(None)):
    if not _verify_node_token(authorization):
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await request.json()
    node_id = body.get("node_id")
    results = body.get("results", [])

    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")

    now = datetime.now(timezone.utc).isoformat()

    with Session(engine) as session:
        node = session.get(Node, node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")

        # Clear old results for this node
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
            )
            session.add(npr)
            if r.get("tests_passed", 0) > 0:
                passed += 1
            else:
                failed_urls.append(r.get("raw_url", ""))

        node.proxies_checked = body.get("checked_count", len(results))
        node.proxies_passed = passed
        node.last_heartbeat = now
        node.is_online = True
        session.add(node)
        session.commit()

    logger.info(f"Node {node_id} reported {len(results)} results ({passed} passed)")

    # Evaluate bans across all nodes
    background_tasks.add_task(_evaluate_bans)

    return {"status": "ok", "accepted": len(results)}


def _evaluate_bans():
    """Evaluate ban status for all proxies based on cross-node consensus.
    
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
    from datetime import datetime, timezone, timedelta

    stale_threshold_dt = datetime.now(timezone.utc) - timedelta(minutes=5)
    stats = {
        "stale_marked": 0,
        "offline_npr_deleted": 0,
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
            stats["stale_marked"] += 1
            logger.info(
                f"Marked node {node.id} ({node.name}) as offline (last_heartbeat=NULL)"
            )
            continue
        try:
            hb = datetime.fromisoformat(node.last_heartbeat)
            if hb < stale_threshold_dt:
                node.is_online = False
                stats["stale_marked"] += 1
                logger.info(
                    f"Marked node {node.id} ({node.name}) as offline "
                    f"(last_heartbeat={node.last_heartbeat})"
                )
        except (ValueError, TypeError):
            node.is_online = False
            stats["stale_marked"] += 1
            logger.warning(
                f"Marked node {node.id} ({node.name}) as offline "
                f"(malformed last_heartbeat={node.last_heartbeat!r})"
            )

    if stats["stale_marked"] > 0:
        session.commit()

    # Step 2: Delete NPR rows from offline nodes
    offline_ids = [n.id for n in all_nodes if not n.is_online]
    if offline_ids:
        result = session.exec(
            delete(NodeProxyResult).where(NodeProxyResult.node_id.in_(offline_ids))
        )
        session.commit()
        stats["offline_npr_deleted"] = result.rowcount if hasattr(result, "rowcount") else 0

    # Step 3: Delete NPR rows from node_ids not present in nodes table at all
    all_node_ids = {n.id for n in all_nodes}
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

    # Collect remaining online node IDs
    stats["online_ids"] = [n.id for n in all_nodes if n.is_online]

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
# FETCH SUBSCRIPTIONS (replaces run-test)
_background_tasks = set()

@app.post("/fetch-subs")
async def fetch_subs(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    if fetch_status["running"]:
        return RedirectResponse("/", status_code=302)

    task = asyncio.create_task(_background_fetch())
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return RedirectResponse("/", status_code=302)


async def _background_fetch():
    """Background task: fetch subscriptions and store raw proxies.
    Also preserves 'good' proxies that passed previous tests but disappeared from sources,
    subject to good_proxy_retention_cycles limit."""
    try:
        fetch_status["running"] = True
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
            proxy_links = await fetch_and_parse_subscriptions(session)
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
                session.exec(delete(RawProxy))
                for key, (url, cycles) in final_proxies.items():
                    if isinstance(url, str) and len(url) > 10 and url.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://')):
                        session.add(RawProxy(raw_url=url, retention_cycles=cycles))
                session.commit()

        fetch_status["current_phase"] = "done"
        fetch_status["running"] = False
        fetch_status["last_fetch_at"] = datetime.now(timezone.utc).isoformat()
        logger.info(f"Subscription fetch complete: {len(final_proxies)} unique proxies stored for workers")

    except Exception as e:
        logger.error(f"Fetch pipeline error: {e}", exc_info=True)
        fetch_status["running"] = False
        fetch_status["current_phase"] = "error"


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
def _apply_webhook_filters(proxy_urls: list[str], speeds: dict, settings) -> list[str]:
    """Filter proxies by min speed thresholds and optionally rename them.
    
    Args:
        proxy_urls: list of raw_url strings (already sorted)
        speeds: dict mapping raw_url -> {"dl": int, "ul": int} (best values)
        settings: Settings object with webhook_min_dl_kbps, webhook_min_ul_kbps, webhook_rename_prefix
    Returns:
        list of final proxy URL strings
    """
    min_dl = settings.webhook_min_dl_kbps or 0
    min_ul = settings.webhook_min_ul_kbps or 0
    prefix = (settings.webhook_rename_prefix or "").strip()

    filtered = []
    for url in proxy_urls:
        sp = speeds.get(url, {"dl": 0, "ul": 0})
        if min_dl > 0 and sp["dl"] < min_dl:
            continue
        if min_ul > 0 and sp["ul"] < min_ul:
            continue
        filtered.append(url)

    # Rename if prefix is set
    if prefix:
        renamed = []
        for i, url in enumerate(filtered, start=1):
            renamed.append(replace_proxy_remark(url, f"{prefix} - {i}"))
        return renamed

    return filtered


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
                .where(NodeProxyResult.tests_passed > 0)
                .order_by(NodeProxyResult.speed_score.desc(), NodeProxyResult.tests_passed.desc(), NodeProxyResult.ping_ms)
            ).all()

            if settings.webhook_max_proxies > 0:
                proxies = proxies[:settings.webhook_max_proxies]

            urls = [p.raw_url for p in proxies]
            speeds = {p.raw_url: {"dl": p.download_speed_kbps, "ul": p.upload_speed_kbps} for p in proxies}
            lines = _apply_webhook_filters(urls, speeds, settings)
            return PlainTextResponse("\n".join(lines), media_type="text/plain; charset=utf-8")

        # Global Consensus Webhook: {webhook_secret_path}/global
        global_prefix = f"{settings.webhook_secret_path}/global"
        if secret_path == global_prefix:
            # Aggregate all node results
            stats = defaultdict(lambda: {"passes": 0, "speed_scores": [], "dl_max": 0, "ul_max": 0, "link": ""})

            node_results = session.exec(select(NodeProxyResult)).all()
            for np_r in node_results:
                if np_r.tests_passed > 0:
                    pid = get_proxy_identity(np_r.raw_url)
                    stats[pid]["link"] = np_r.raw_url  # Keep the latest
                    stats[pid]["passes"] += 1
                    stats[pid]["speed_scores"].append(np_r.speed_score)
                    stats[pid]["dl_max"] = max(stats[pid]["dl_max"], np_r.download_speed_kbps)
                    stats[pid]["ul_max"] = max(stats[pid]["ul_max"], np_r.upload_speed_kbps)

            consensus_list = []
            for pid, data in stats.items():
                avg_speed = sum(data["speed_scores"]) / len(data["speed_scores"]) if data["speed_scores"] else 0
                consensus_list.append({
                    "link": data["link"],
                    "passes": data["passes"],
                    "avg_speed": avg_speed,
                    "dl": data["dl_max"],
                    "ul": data["ul_max"],
                })
            
            consensus_list.sort(key=lambda x: (x["passes"], x["avg_speed"]), reverse=True)

            top_n = settings.global_sub_top_n
            if top_n > 0:
                consensus_list = consensus_list[:top_n]

            urls = [p["link"] for p in consensus_list]
            speeds = {p["link"]: {"dl": p["dl"], "ul": p["ul"]} for p in consensus_list}
            lines = _apply_webhook_filters(urls, speeds, settings)
            return PlainTextResponse("\n".join(lines), media_type="text/plain; charset=utf-8")

        # Main webhook — best proxies across all nodes
        if secret_path != settings.webhook_secret_path:
            raise HTTPException(status_code=404)

        # Aggregate across nodes: pick best result per proxy
        all_results = session.exec(
            select(NodeProxyResult)
            .where(NodeProxyResult.tests_passed > 0)
        ).all()

        best_by_url = {}
        for r in all_results:
            pid = get_proxy_identity(r.raw_url)
            if pid not in best_by_url or r.speed_score > best_by_url[pid].speed_score:
                best_by_url[pid] = r

        proxies = sorted(
            best_by_url.values(),
            key=lambda x: (-x.speed_score, -x.tests_passed, x.ping_ms)
        )

        if settings.webhook_max_proxies > 0:
            proxies = proxies[:settings.webhook_max_proxies]

    urls = [p.raw_url for p in proxies]
    speeds = {p.raw_url: {"dl": p.download_speed_kbps, "ul": p.upload_speed_kbps} for p in proxies}
    lines = _apply_webhook_filters(urls, speeds, settings)

    text = "\n".join(lines)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")


# ---------------------------------------------------------------------------
# Run with uvicorn
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
