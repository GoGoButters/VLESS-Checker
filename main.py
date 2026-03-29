"""VPN Checker — FastAPI main application."""

import asyncio
import logging

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, PlainTextResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, func

from database import (
    create_db_and_tables,
    engine,
    Subscription,
    ProxyResult,
    Settings,
    TestUrl,
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
from proxy_parsers import replace_proxy_remark
from scheduler import start_scheduler, scheduler_status

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
app = FastAPI(title="VPN Checker", version="1.0.0")
templates = Jinja2Templates(directory="templates")


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def on_startup():
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

            # Default subscriptions (Mix, VLESS, Hysteria2)
            default_subs = [
                "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
                "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/mix",
                "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/vless",
                "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria2",
            ]
            for sub_url in default_subs:
                session.add(Subscription(url=sub_url))
                
            session.commit()
            logger.info("Created default settings, test URLs, and subscriptions")
    # Start the scheduler background loop
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
        settings = session.exec(select(Settings)).first()

    return templates.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "sub_count": sub_count,
        "proxy_count": proxy_count,
        "test_url_count": test_url_count,
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
# TEST URLS — manage the URLs used to validate proxies
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
                # Assign next position
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
            select(ProxyResult).order_by(ProxyResult.tests_passed.desc(), ProxyResult.ping_ms)
        ).all()
    return templates.TemplateResponse(request, "proxies.html", {
        "user": user,
        "proxies": proxies,
    })


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

    # Launch test in background
    asyncio.create_task(_background_test())
    return RedirectResponse("/", status_code=302)


async def _background_test():
    """Background task for running the full test pipeline."""
    try:
        test_status["current_phase"] = "fetching"
        test_status["running"] = True
        vless_links = await fetch_and_parse_subscriptions()
        if vless_links:
            await run_full_test(vless_links)
        else:
            test_status["current_phase"] = "done"
            test_status["running"] = False
            logger.warning("No VLESS links found from subscriptions")
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
# WEBHOOK — Public proxy distribution
# Proxies sorted by tests_passed DESC, ping_ms ASC
# Configs renamed to sequential numbers: 1, 2, 3, ...
# ---------------------------------------------------------------------------
@app.get("/{secret_path:path}")
async def webhook_output(secret_path: str):
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        if not settings or secret_path != settings.webhook_secret_path:
            raise HTTPException(status_code=404)
        query = select(ProxyResult).order_by(
            ProxyResult.tests_passed.desc(),
            ProxyResult.ping_ms,
        )
        if settings.webhook_max_proxies > 0:
            query = query.limit(settings.webhook_max_proxies)
        proxies = session.exec(query).all()

    # Rename configs: replace remark with sequential numbers
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
