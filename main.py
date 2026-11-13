"""VPN Checker — manager panel.

The panel tests nothing itself. Each rating group is a pipeline: the group's
sources are fetched on its schedule, its pool goes to its worker nodes, and
their results form the group's webhook.

Handlers that touch SQLite are plain ``def`` (run in the threadpool) or hand
their work to ``run_in_threadpool`` — the single uvicorn process must never
block its event loop.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, text
from sqlmodel import select
from starlette.concurrency import run_in_threadpool

import db_maintenance
import node_api
import pipeline
import rating
from auth import SESSION_COOKIE, SESSION_MAX_AGE, create_session_token, get_current_user, hash_password, verify_password
from database import (
    Session,
    DB_PATH, PROTOCOLS, GroupSource, Node, NodeRatingLink, RatingGroup, Settings,
    Subscription, TestUrl, create_db_and_tables, effective_generation, engine, utcnow,
)
from i18n import translations
from log_buffer import log_buffer, setup_log_buffer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("vpn_checker")

RESERVED_PATHS = {"", "login", "logout", "subscriptions", "test-urls", "settings", "ratings", "logs", "nodes",
                  "api", "mcp", "static", "fetch-subs", "favicon.ico", "robots.txt"}
WEBHOOK_PATH_RE = re.compile(r"^[A-Za-z0-9._~-]{1,100}$")
PROTOCOL_LABELS = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "ss": "Shadowsocks",
                   "hy2": "Hysteria2 (hy2://)", "hysteria2": "Hysteria2 (hysteria2://)", "tuic": "TUIC",
                   "hysteria": "Hysteria v1", "anytls": "AnyTLS", "socks": "SOCKS5"}

DEFAULT_SUBSCRIPTIONS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
]
DEFAULT_TEST_URLS = [
    ("https://www.gstatic.com/generate_204", 204, 0),
    ("https://www.google.com", 200, 1000),
    ("https://www.youtube.com/generate_204", 204, 0),
]


# ---------------------------------------------------------------------------
# startup / shutdown
# ---------------------------------------------------------------------------
def _seed_defaults() -> None:
    with Session(engine) as s:
        if s.exec(select(Settings)).first():
            return
        s.add(Settings(admin_pass_hash=hash_password("admin"), node_api_token=secrets.token_hex(16)))
        for i, (url, status, min_b) in enumerate(DEFAULT_TEST_URLS):
            s.add(TestUrl(url=url, expect_status=status, min_body_bytes=min_b, position=i))
        subs = [Subscription(url=u) for u in DEFAULT_SUBSCRIPTIONS]
        s.add_all(subs)
        group = RatingGroup(name="default", webhook_path=secrets.token_urlsafe(12), schedule_interval_minutes=360)
        s.add(group)
        s.flush()
        for sub in subs:
            s.add(GroupSource(group_id=group.id, subscription_id=sub.id))
        s.commit()
        logger.warning("First start: created settings (password 'admin' — change it), "
                       "default test URLs, sources and a 'default' rating group")


@asynccontextmanager
async def lifespan(_: FastAPI):
    setup_log_buffer()
    await run_in_threadpool(create_db_and_tables)
    await run_in_threadpool(_seed_defaults)
    # VACUUM / index hygiene off the request path; the app serves meanwhile.
    maintenance = asyncio.create_task(asyncio.to_thread(db_maintenance.run_maintenance, DB_PATH))
    scheduler = asyncio.create_task(pipeline.scheduler_loop())
    try:
        yield
    finally:
        scheduler.cancel()
        maintenance.cancel()


app = FastAPI(title="VPN Checker", version="4.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def t(request: Request, key: str, **kwargs) -> str:
    lang = request.cookies.get("lang", "en")
    table = translations.get(lang) or translations["en"]
    default = kwargs.pop("default", None)
    value = table.get(key) or translations["en"].get(key) or default or key
    return value.format(**kwargs) if kwargs else value


templates.env.globals["t"] = t


class _LoginRequired(Exception):
    pass


@app.exception_handler(_LoginRequired)
async def _login_redirect(request: Request, exc: _LoginRequired):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Unauthorized"}, status_code=401)
    return RedirectResponse("/login", status_code=302)


def _user(request: Request) -> str:
    user = get_current_user(request)
    if not user:
        raise _LoginRequired()
    return user


def _page(request: Request, name: str, ctx: dict, status_code: int = 200):
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def _int(form, key: str, default: int = 0, lo: int | None = None, hi: int | None = None) -> int:
    try:
        v = int(str(form.get(key, default)).strip() or default)
    except ValueError:
        v = default
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


# ---------------------------------------------------------------------------
# MCP (token-protected SSE apps)
# ---------------------------------------------------------------------------
class TokenAuthMiddleware:
    def __init__(self, asgi_app, token_field: str):
        self.asgi_app = asgi_app
        self.token_field = token_field
        self._token: str | None = None
        self._at = 0.0

    def _load(self) -> str:
        with Session(engine) as s:
            st = s.exec(select(Settings)).first()
            return (getattr(st, self.token_field, "") if st else "") or ""

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.asgi_app(scope, receive, send)
        if self._token is None or time.monotonic() - self._at > 60:
            self._token, self._at = await run_in_threadpool(self._load), time.monotonic()
        auth = dict(scope.get("headers", [])).get(b"authorization", b"").decode()
        if not self._token or not secrets.compare_digest(auth, f"Bearer {self._token}"):
            await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return
        if scope["type"] == "http" and scope.get("method") == "HEAD":
            # Clients probe the SSE endpoint with HEAD; fastmcp's SSE transport
            # then tries to answer twice ("response already completed").
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"text/event-stream")]})
            await send({"type": "http.response.body", "body": b""})
            return
        return await self.asgi_app(scope, receive, send)


try:
    from starlette.routing import Mount

    from mcp_server import mcp_admin, mcp_ro

    app.router.routes.insert(0, Mount("/mcp/admin", TokenAuthMiddleware(mcp_admin.http_app(transport="sse"), "mcp_admin_token")))
    app.router.routes.insert(0, Mount("/mcp/read", TokenAuthMiddleware(mcp_ro.http_app(transport="sse"), "mcp_read_token")))
except ImportError as e:
    logger.warning(f"MCP endpoints disabled: {e}")

app.include_router(node_api.router)


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse("/", status_code=302)
    return _page(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, password: str = Form(...)):
    with Session(engine) as s:
        st = s.exec(select(Settings)).first()
    if st and verify_password(password, st.admin_pass_hash):
        resp = RedirectResponse("/", status_code=302)
        resp.set_cookie(SESSION_COOKIE, create_session_token("admin"), httponly=True, samesite="lax",
                        max_age=SESSION_MAX_AGE)
        return resp
    time.sleep(1)  # slows down guessing (runs in the threadpool)
    return _page(request, "login.html", {"error": "Wrong password"}, status_code=401)


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------
def _group_overview(s: Session) -> list[dict]:
    groups = s.exec(select(RatingGroup).order_by(RatingGroup.id)).all()
    links = s.exec(select(NodeRatingLink.rating_group_id, Node.name, Node.is_online)
                   .join(Node, Node.id == NodeRatingLink.node_id)).all()
    nodes_by_group: dict[int, list] = {}
    for gid, name, online in links:
        nodes_by_group.setdefault(gid, []).append({"name": name, "online": online})
    src_counts = dict(s.exec(select(GroupSource.group_id, func.count(GroupSource.id))
                             .group_by(GroupSource.group_id)).all())
    out = []
    for g in groups:
        nxt = pipeline.next_fetch_at(g)
        out.append({
            "group": g, "nodes": nodes_by_group.get(g.id, []), "sources": src_counts.get(g.id, 0),
            "valid": len(rating.get_rating(g.id)),
            "next_fetch": nxt.isoformat() if nxt else "",
        })
    return out


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = _user(request)
    with Session(engine) as s:
        groups = _group_overview(s)
        ctx = {
            "user": user, "groups": groups,
            "sub_count": s.exec(select(func.count(Subscription.id))).one(),
            "test_url_count": s.exec(select(func.count(TestUrl.id))).one(),
            "node_count": s.exec(select(func.count(Node.id))).one(),
            "node_online": s.exec(select(func.count(Node.id)).where(Node.is_online == True)).one(),  # noqa: E712
            "pool_total": sum(g["group"].pool_size for g in groups),
            "valid_total": sum(g["valid"] for g in groups),
            "pipeline": pipeline.status,
        }
    return _page(request, "dashboard.html", ctx)


@app.post("/fetch-subs")
def fetch_all(request: Request):
    _user(request)
    with Session(engine) as s:
        gids = [g for (g,) in s.exec(text("SELECT id FROM rating_groups")).all()]
    pipeline.request_cycle(gids, fetch=True)
    return RedirectResponse(request.headers.get("referer") or "/", status_code=302)


@app.get("/api/fetch-status")
def api_fetch_status(request: Request):
    _user(request)
    with Session(engine) as s:
        groups = [{"id": g.id, "name": g.name, "pool_size": g.pool_size, "last_fetch_at": g.last_fetch_at,
                   "last_fetch_status": g.last_fetch_status,
                   "next_fetch_at": (pipeline.next_fetch_at(g).isoformat() if pipeline.next_fetch_at(g) else None)}
                  for g in s.exec(select(RatingGroup).order_by(RatingGroup.id)).all()]
    return {**pipeline.status, "groups": groups}


# ---------------------------------------------------------------------------
# subscriptions (global source catalog)
# ---------------------------------------------------------------------------
@app.get("/subscriptions", response_class=HTMLResponse)
def subscriptions_page(request: Request):
    user = _user(request)
    with Session(engine) as s:
        subs = s.exec(select(Subscription).order_by(Subscription.id.desc())).all()
        groups = {g.id: g.name for g in s.exec(select(RatingGroup)).all()}
        usage: dict[int, list[dict]] = {}
        for gs in s.exec(select(GroupSource)).all():
            usage.setdefault(gs.subscription_id, []).append(
                {"name": groups.get(gs.group_id, "?"), "skipped": gs.stats_disabled})
    return _page(request, "subscriptions.html", {"user": user, "subs": subs, "usage": usage})


@app.post("/subscriptions/add")
def add_subscription(request: Request, url: str = Form(...)):
    _user(request)
    urls = [u.strip() for u in re.split(r"[\s]+", url) if u.strip().startswith(("http://", "https://"))]
    with Session(engine) as s:
        for u in urls:
            if s.exec(select(Subscription).where(Subscription.url == u)).first():
                continue
            sub = Subscription(url=u)
            s.add(sub)
            s.flush()
            pipeline.add_source_to_auto_groups(s, sub.id)
        s.commit()
    return RedirectResponse("/subscriptions", status_code=302)


@app.post("/subscriptions/delete/{sub_id}")
def delete_subscription(request: Request, sub_id: int):
    _user(request)
    with Session(engine) as s:
        sub = s.get(Subscription, sub_id)
        if sub:
            gids = [g for (g,) in s.exec(text("SELECT group_id FROM group_sources WHERE subscription_id=:s")
                                         .bindparams(s=sub_id)).all()]
            pipeline.delete_source_data(s, sub_id)
            s.delete(sub)
            s.commit()
            pipeline.request_cycle(gids, fetch=False)
    return RedirectResponse("/subscriptions", status_code=302)


@app.post("/subscriptions/toggle/{sub_id}")
def toggle_subscription(request: Request, sub_id: int):
    _user(request)
    with Session(engine) as s:
        sub = s.get(Subscription, sub_id)
        if sub:
            sub.is_enabled = not sub.is_enabled
            s.add(sub)
            s.commit()
            gids = [g for (g,) in s.exec(text("SELECT group_id FROM group_sources WHERE subscription_id=:s")
                                         .bindparams(s=sub_id)).all()]
            pipeline.request_cycle(gids, fetch=False)
    return RedirectResponse("/subscriptions", status_code=302)


# ---------------------------------------------------------------------------
# test URLs (shared by all groups)
# ---------------------------------------------------------------------------
@app.get("/test-urls", response_class=HTMLResponse)
def test_urls_page(request: Request):
    user = _user(request)
    with Session(engine) as s:
        urls = s.exec(select(TestUrl).order_by(TestUrl.position, TestUrl.id)).all()
    return _page(request, "test_urls.html", {"user": user, "test_urls": urls})


@app.post("/test-urls/add")
def add_test_url(request: Request, url: str = Form(...), expect_status: int = Form(200),
                 min_body_bytes: int = Form(100)):
    _user(request)
    url = url.strip()
    if url.startswith(("http://", "https://")):
        with Session(engine) as s:
            if not s.exec(select(TestUrl).where(TestUrl.url == url)).first():
                pos = (s.exec(select(func.max(TestUrl.position))).one() or 0) + 1
                s.add(TestUrl(url=url, expect_status=expect_status, min_body_bytes=max(0, min_body_bytes), position=pos))
                s.commit()
    return RedirectResponse("/test-urls", status_code=302)


@app.post("/test-urls/delete/{url_id}")
def delete_test_url(request: Request, url_id: int):
    _user(request)
    with Session(engine) as s:
        tu = s.get(TestUrl, url_id)
        if tu:
            s.delete(tu)
            s.commit()
    return RedirectResponse("/test-urls", status_code=302)


# ---------------------------------------------------------------------------
# settings (panel-wide only; pipeline settings live in each rating group)
# ---------------------------------------------------------------------------
@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = _user(request)
    with Session(engine) as s:
        st = s.exec(select(Settings)).first()
    return _page(request, "settings.html", {"user": user, "settings": st, "saved": request.query_params.get("saved")})


@app.post("/settings")
def settings_save(request: Request, node_log_level: str = Form("info"), new_password: str = Form("")):
    _user(request)
    with Session(engine) as s:
        st = s.exec(select(Settings)).first()
        if node_log_level in ("debug", "info", "warning", "error", "off"):
            st.node_log_level = node_log_level
        if new_password.strip():
            st.admin_pass_hash = hash_password(new_password.strip())
        s.add(st)
        s.commit()
    return RedirectResponse("/settings?saved=1", status_code=302)


@app.post("/settings/regenerate-{which}")
def regenerate_token(request: Request, which: str):
    _user(request)
    field = {"node-token": "node_api_token", "mcp-read-token": "mcp_read_token",
             "mcp-admin-token": "mcp_admin_token"}.get(which)
    if not field:
        raise HTTPException(status_code=404)
    with Session(engine) as s:
        st = s.exec(select(Settings)).first()
        setattr(st, field, secrets.token_hex(16) if field == "node_api_token" else secrets.token_urlsafe(32))
        s.add(st)
        s.commit()
    node_api.invalidate_token_cache()
    return RedirectResponse("/settings", status_code=302)


# ---------------------------------------------------------------------------
# rating groups
# ---------------------------------------------------------------------------
def _group_payload(g: RatingGroup, source_ids: list[int]) -> dict:
    """Everything the edit form needs, as JSON for the page script."""
    data = g.model_dump(exclude={"generation_id", "generation_at", "last_fetch_status", "created_at"})
    data["protocols"] = g.protocols()
    data["source_ids"] = source_ids
    return data


@app.get("/ratings", response_class=HTMLResponse)
def ratings_page(request: Request):
    user = _user(request)
    with Session(engine) as s:
        groups = s.exec(select(RatingGroup).order_by(RatingGroup.id)).all()
        nodes = s.exec(select(Node).order_by(Node.id)).all()
        subs = s.exec(select(Subscription).order_by(Subscription.id)).all()
        rating_nodes: dict[int, list[int]] = {}
        for link in s.exec(select(NodeRatingLink)).all():
            rating_nodes.setdefault(link.rating_group_id, []).append(link.node_id)
        group_sources: dict[int, dict[int, GroupSource]] = {}
        for gs in s.exec(select(GroupSource)).all():
            group_sources.setdefault(gs.group_id, {})[gs.subscription_id] = gs
        cards = []
        for g in groups:
            nxt = pipeline.next_fetch_at(g)
            selected = group_sources.get(g.id, {})
            cards.append({
                "group": g,
                "payload": _group_payload(g, sorted(selected)),
                "sources_selected": len(selected),
                "sources_skipped": sum(1 for gs in selected.values() if gs.stats_disabled),
                "valid": len(rating.get_rating(g.id)),
                "next_fetch": nxt.isoformat() if nxt else "",
            })
    return _page(request, "ratings.html", {
        "user": user, "cards": cards, "nodes": nodes, "subs": subs, "rating_nodes_map": rating_nodes,
        "protocol_labels": PROTOCOL_LABELS, "error": request.query_params.get("error"),
        "new_group_defaults": _group_payload(RatingGroup(), [sub.id for sub in subs]),
    })


def _read_group_form(form) -> tuple[dict, set[int]]:
    data = {
        "name": str(form.get("name", "")).strip()[:100],
        "webhook_path": str(form.get("webhook_path", "")).strip().strip("/"),
        "max_proxies": _int(form, "max_proxies", 0, 0),
        "min_dl_kbps": _int(form, "min_dl_kbps", 0, 0),
        "min_ul_kbps": _int(form, "min_ul_kbps", 0, 0),
        "rename_prefix": str(form.get("rename_prefix", "")).strip()[:100],
        "consensus_only": form.get("consensus_only") == "1",
        "geo_check_enabled": form.get("geo_check_enabled") == "1",
        "geo_top_n": _int(form, "geo_top_n", 1, 1, 1000),
        "excluded_countries": ", ".join(c.strip() for c in str(form.get("excluded_countries", "")).split(",") if c.strip()),
        "auto_add_new_sources": form.get("auto_add_new_sources") == "1",
        "enabled_protocols": json.dumps({p: form.get(f"proto_{p}") == "1" for p in PROTOCOLS}),
        "schedule_interval_minutes": _int(form, "schedule_interval_minutes", 0, 0, 10080),
        "good_proxy_retention_cycles": _int(form, "good_proxy_retention_cycles", 3, 0, 100),
        "ban_duration_hours": _int(form, "ban_duration_hours", 168, 0, 8760),
        "ban_after_n_failures": _int(form, "ban_after_n_failures", 3, 1, 100),
        "ping_threshold_ms": _int(form, "ping_threshold_ms", 1000, 50, 10000),
        "concurrent_checks_limit": _int(form, "concurrent_checks_limit", 50, 1, 500),
        "http_timeout_s": _int(form, "http_timeout_s", 10, 1, 60),
        "speed_test_top_n": _int(form, "speed_test_top_n", 0, 0, 50000),
        "chunk_size": _int(form, "chunk_size", 0, 0, 10000),
    }
    source_ids = {int(v) for v in form.getlist("source_ids") if str(v).isdigit()}
    return data, source_ids


def _save_group(gid: int | None, data: dict, source_ids: set[int]) -> str | None:
    """Create/update a group. Returns an error message or None."""
    path = data["webhook_path"]
    if not data["name"]:
        return "Name is required"
    if not WEBHOOK_PATH_RE.match(path) or path.split("/")[0].lower() in RESERVED_PATHS:
        return f"Webhook path '{path}' is invalid or reserved (allowed: letters, digits, . _ ~ -)"
    with Session(engine) as s:
        clash = s.exec(select(RatingGroup).where(RatingGroup.webhook_path == path)).first()
        if clash and clash.id != gid:
            return f"Webhook path '{path}' is used by group '{clash.name}'"
        group = s.get(RatingGroup, gid) if gid else RatingGroup()
        if gid and not group:
            return "Group not found"
        old_protocols = group.enabled_protocols
        for k, v in data.items():
            setattr(group, k, v)
        s.add(group)
        s.flush()
        valid_ids = {i for (i,) in s.exec(text("SELECT id FROM subscriptions")).all()}
        sources_changed = pipeline.set_group_sources(s, group.id, source_ids & valid_ids)
        s.commit()
        new_id = group.id
    rating.invalidate(new_id)
    _invalidate_paths()
    if not gid:
        pipeline.request_cycle([new_id], fetch=True)
    elif sources_changed or old_protocols != data["enabled_protocols"]:
        pipeline.request_cycle([new_id], fetch=False)
    return None


@app.post("/ratings/save")
async def ratings_save(request: Request):
    _user(request)
    form = await request.form()
    gid = _int(form, "rating_id", 0, 0) or None
    data, source_ids = _read_group_form(form)
    error = await run_in_threadpool(_save_group, gid, data, source_ids)
    if error:
        from urllib.parse import quote
        return RedirectResponse(f"/ratings?error={quote(error)}", status_code=302)
    return RedirectResponse("/ratings", status_code=302)


@app.post("/ratings/delete/{rating_id}")
def delete_rating(request: Request, rating_id: int):
    _user(request)
    with Session(engine) as s:
        group = s.get(RatingGroup, rating_id)
        if group:
            pipeline.delete_group_data(s, rating_id)
            s.delete(group)
            s.commit()
    rating.invalidate(rating_id)
    _invalidate_paths()
    return RedirectResponse("/ratings", status_code=302)


@app.post("/ratings/{rating_id}/fetch")
def fetch_rating(request: Request, rating_id: int):
    _user(request)
    pipeline.request_cycle([rating_id], fetch=True)
    return RedirectResponse(request.headers.get("referer") or "/ratings", status_code=302)


@app.post("/ratings/{rating_id}/add-node/{node_id}")
def add_node_to_rating(request: Request, rating_id: int, node_id: int):
    _user(request)
    with Session(engine) as s:
        if s.get(RatingGroup, rating_id) and s.get(Node, node_id):
            pipeline.link_node(s, rating_id, node_id)
            s.commit()
    rating.invalidate(rating_id)
    return RedirectResponse("/ratings", status_code=302)


@app.post("/ratings/{rating_id}/remove-node/{node_id}")
def remove_node_from_rating(request: Request, rating_id: int, node_id: int):
    _user(request)
    with Session(engine) as s:
        pipeline.unlink_node(s, rating_id, node_id)
        s.commit()
    rating.invalidate(rating_id)
    return RedirectResponse("/ratings", status_code=302)


@app.get("/ratings/{rating_id}/proxies", response_class=HTMLResponse)
def rating_proxies_partial(request: Request, rating_id: int):
    _user(request)
    return _page(request, "proxy_table.html", {"proxies": rating.get_rating(rating_id)})


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------
@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request):
    return _page(request, "logs.html", {"user": _user(request)})


@app.get("/api/logs")
def api_logs(request: Request, after_id: int = 0):
    _user(request)
    return {"entries": log_buffer.get_since(after_id)}


# ---------------------------------------------------------------------------
# nodes
# ---------------------------------------------------------------------------
def _node_group_stats(s: Session) -> dict[int, list[dict]]:
    now = utcnow()
    rows = s.exec(text(
        "SELECT st.node_id, st.group_id, g.name, st.status, st.current_chunk, st.total_chunks, "
        " st.completed_generation, st.run_seq, g.generation_id, g.pool_size, "
        " COALESCE(x.passed, 0), COALESCE(x.banned, 0), COALESCE(x.tested_gen, 0) "
        "FROM node_group_state st JOIN rating_groups g ON g.id = st.group_id "
        "JOIN node_rating_links l ON l.node_id = st.node_id AND l.rating_group_id = st.group_id "
        "LEFT JOIN (SELECT s.group_id, s.node_id, SUM(s.tests_passed > 0 AND s.ping_ms > 0) passed, "
        "  SUM(s.banned_until IS NOT NULL AND s.banned_until > :now) banned, "
        "  SUM(s.generation_id = g2.generation_id || '.' || st2.run_seq) tested_gen "
        "  FROM group_node_proxies s JOIN rating_groups g2 ON g2.id = s.group_id "
        "  JOIN node_group_state st2 ON st2.group_id = s.group_id AND st2.node_id = s.node_id "
        "  GROUP BY s.group_id, s.node_id) x ON x.group_id = st.group_id AND x.node_id = st.node_id "
        "ORDER BY st.group_id").bindparams(now=now)).all()
    out: dict[int, list[dict]] = {}
    for (nid, gid, name, status, cur, total, completed, run_seq, gen, pool, passed, banned, tested) in rows:
        eff = effective_generation(gen, run_seq)
        out.setdefault(nid, []).append({
            "group_id": gid, "name": name, "status": status, "current_chunk": cur, "total_chunks": total,
            "done": bool(eff) and completed == eff, "pool": pool, "passed": passed, "banned": banned,
            "tested": tested,
        })
    return out


@app.get("/nodes", response_class=HTMLResponse)
def nodes_page(request: Request):
    user = _user(request)
    with Session(engine) as s:
        nodes = s.exec(select(Node).order_by(Node.id)).all()
        settings = s.exec(select(Settings)).first()
        stats = _node_group_stats(s)
    return _page(request, "nodes.html", {"user": user, "nodes": nodes, "settings": settings, "stats": stats})


@app.post("/nodes/delete/{node_id}")
def delete_node(request: Request, node_id: int):
    _user(request)
    with Session(engine) as s:
        node = s.get(Node, node_id)
        if node:
            pipeline.delete_node_data(s, node_id)
            s.delete(node)
            s.commit()
    rating.invalidate_all()
    return RedirectResponse("/nodes", status_code=302)


@app.post("/api/node/{node_id}/force-test")
def force_node_test(request: Request, node_id: int):
    """Re-test everything of every group of the node, without refetching sources."""
    _user(request)
    with Session(engine) as s:
        if not s.get(Node, node_id):
            raise HTTPException(status_code=404, detail="Node not found")
        s.exec(text("UPDATE node_group_state SET run_seq = run_seq + 1 WHERE node_id = :n").bindparams(n=node_id))
        s.commit()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# speed test blob (fallback download target for nodes in restricted networks)
# ---------------------------------------------------------------------------
_SPEEDTEST_BLOB = os.urandom(10 * 1024 * 1024)


@app.get(node_api.SPEEDTEST_PATH)
async def speedtest_download():
    return Response(_SPEEDTEST_BLOB, media_type="application/octet-stream",
                    headers={"Cache-Control": "no-cache", "Content-Encoding": "identity"})


# ---------------------------------------------------------------------------
# webhooks — must stay the last route
# ---------------------------------------------------------------------------
_paths: dict = {"map": {}, "at": 0.0}


def _invalidate_paths() -> None:
    _paths["at"] = 0.0


def _webhook(path: str) -> str | None:
    if time.monotonic() - _paths["at"] > 60:
        with Session(engine) as s:
            _paths["map"] = {g.webhook_path: g.id for g in s.exec(select(RatingGroup)).all()}
        _paths["at"] = time.monotonic()
    gid = _paths["map"].get(path)
    if gid is None:
        return None
    with Session(engine) as s:
        group = s.get(RatingGroup, gid)
    return rating.webhook_text(group) if group else None


@app.get("/{secret_path:path}")
def webhook_output(secret_path: str):
    body = _webhook(secret_path)
    if body is None:
        raise HTTPException(status_code=404)
    return PlainTextResponse(body, media_type="text/plain; charset=utf-8")
