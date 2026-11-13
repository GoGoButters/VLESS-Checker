"""Worker node API.

v2 (jobs): a node asks which of its groups need testing, pulls the remaining
proxies of one group, posts results per chunk and finally reports idle.
"Remaining" excludes what the node already tested in the current generation,
so a restarted node simply continues where it stopped.

v1 (legacy) endpoints map an old worker onto its first group so it keeps
working until it is updated.

All handlers are plain ``def``: FastAPI runs them in the threadpool, so SQLite
never blocks the event loop.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import zlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlmodel import select

import rating
from database import (
    Session,
    Node, NodeGroupState, NodeRatingLink, RatingGroup, Settings, TestUrl, effective_generation, engine, utcnow,
)
from log_buffer import log_buffer
from proxy_parsers import get_proxy_identity, proxy_key

logger = logging.getLogger("vpn_checker.node_api")
router = APIRouter()

DUPLICATE_WINDOW = timedelta(seconds=90)
MAX_RESULTS_PER_POST = 5000
SPEEDTEST_PATH = "/api/speedtest/download"

_token_cache: dict = {"value": None, "at": 0.0}


def invalidate_token_cache() -> None:
    _token_cache["value"] = None


def _expected_token() -> str:
    if _token_cache["value"] is None or time.monotonic() - _token_cache["at"] > 60:
        with Session(engine) as s:
            st = s.exec(select(Settings)).first()
        _token_cache.update(value=(st.node_api_token if st else "") or "", at=time.monotonic())
    return _token_cache["value"]


def _auth(authorization: str | None) -> None:
    expected = _expected_token()
    if not expected or not authorization or authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Invalid token")




def _touch(s: Session, node_id: int) -> Node:
    node = s.get(Node, node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    node.last_heartbeat = utcnow()
    if not node.is_online:
        node.is_online = True
        rating.invalidate_all()
    s.add(node)
    return node


def _test_urls(s: Session) -> list[dict]:
    return [{"url": t.url, "expect_status": t.expect_status, "min_body_bytes": t.min_body_bytes}
            for t in s.exec(select(TestUrl).order_by(TestUrl.position, TestUrl.id)).all()]


def _state(s: Session, gid: int, nid: int) -> NodeGroupState:
    st = s.exec(select(NodeGroupState).where(NodeGroupState.group_id == gid,
                                            NodeGroupState.node_id == nid)).first()
    if st is None:
        st = NodeGroupState(group_id=gid, node_id=nid, updated_at=utcnow())
        s.add(st)
        s.flush()
    return st


def _group_for_node(s: Session, gid: int, nid: int) -> RatingGroup:
    linked = s.exec(select(NodeRatingLink).where(NodeRatingLink.rating_group_id == gid,
                                                NodeRatingLink.node_id == nid)).first()
    group = s.get(RatingGroup, gid) if linked else None
    if group is None:
        raise HTTPException(status_code=404, detail="Group not assigned to this node")
    return group


def _job(group: RatingGroup, st: NodeGroupState) -> dict:
    gen = effective_generation(group.generation_id, st.run_seq)
    return {
        "group_id": group.id,
        "name": group.name,
        "generation": gen,
        "due": bool(gen) and st.completed_generation != gen,
        "ping_threshold_ms": group.ping_threshold_ms,
        "http_timeout_s": group.http_timeout_s,
        "concurrent_checks_limit": group.concurrent_checks_limit,
        "speed_test_top_n": group.speed_test_top_n,
        "chunk_size": group.chunk_size,
        "geo_check_enabled": group.geo_check_enabled,
    }


# Pool minus the node's active bans and what it already tested in `gen`, plus
# its own retained proxies that left the pool.
_REMAINING_SQL = (
    "SELECT p.raw_url FROM group_proxies p WHERE p.group_id = :g AND NOT EXISTS ("
    " SELECT 1 FROM group_node_proxies s WHERE s.group_id = :g AND s.node_id = :n AND s.key = p.key"
    " AND ((s.banned_until IS NOT NULL AND s.banned_until > :now) OR s.generation_id = :gen)) "
    "UNION ALL "
    "SELECT s.raw_url FROM group_node_proxies s WHERE s.group_id = :g AND s.node_id = :n"
    " AND s.retention_cycles > 0 AND s.generation_id != :gen"
    " AND NOT (s.banned_until IS NOT NULL AND s.banned_until > :now)"
    " AND NOT EXISTS (SELECT 1 FROM group_proxies p WHERE p.group_id = :g AND p.key = s.key)"
)
# At most this many proxy lists are streamed at once (each holds a read cursor).
_list_slots = threading.BoundedSemaphore(2)


def _has_remaining(s: Session, gid: int, nid: int, gen: str) -> bool:
    return s.exec(text(f"SELECT 1 FROM ({_REMAINING_SQL}) LIMIT 1")
                  .bindparams(g=gid, n=nid, now=utcnow(), gen=gen)).first() is not None


def _stream_list(request: Request, head: dict, count_key: str, gid: int, nid: int, gen: str) -> StreamingResponse:
    """JSON object whose "proxies" array is streamed from a DB cursor (gzip on
    the fly): memory stays O(batch) instead of ~25 MB per 50k-link list."""
    gz = "gzip" in request.headers.get("accept-encoding", "")
    prefix = json.dumps(head, ensure_ascii=False, separators=(",", ":"))[:-1] + ',"proxies":['

    def body():
        comp = zlib.compressobj(5, zlib.DEFLATED, 31) if gz else None
        out = (lambda b: comp.compress(b)) if comp else (lambda b: b)
        with _list_slots, engine.connect() as c:
            yield out(prefix.encode())
            res = c.execute(text(_REMAINING_SQL), {"g": gid, "n": nid, "now": utcnow(), "gen": gen})
            n = 0
            while rows := res.fetchmany(2000):
                parts = []
                for (url,) in rows:
                    parts.append(("," if n else "") + json.dumps(url, ensure_ascii=False))
                    n += 1
                chunk = out("".join(parts).encode())
                if chunk:
                    yield chunk
            yield out(f'],"{count_key}":{n}}}'.encode())
        if comp:
            yield comp.flush()

    headers = {"Content-Encoding": "gzip", "Vary": "Accept-Encoding"} if gz else {}
    return StreamingResponse(body(), media_type="application/json", headers=headers)


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------
_UPSERT_PASSED = """
INSERT INTO group_node_proxies (group_id, node_id, key, raw_url, ident, ping_ms, tests_passed, tests_total,
  download_speed_kbps, upload_speed_kbps, speed_score, country_name, last_tested, last_passed, generation_id,
  consecutive_failures, banned_until, retention_cycles)
VALUES (:g, :n, :key, :url, :ident, :ping, :passed, :total, :dl, :ul, :score, :country, :now, :now, :gen,
  0, NULL, :retention)
ON CONFLICT (group_id, node_id, key) DO UPDATE SET raw_url = excluded.raw_url, ident = excluded.ident,
  ping_ms = excluded.ping_ms, tests_passed = excluded.tests_passed, tests_total = excluded.tests_total,
  download_speed_kbps = excluded.download_speed_kbps, upload_speed_kbps = excluded.upload_speed_kbps,
  speed_score = excluded.speed_score, country_name = excluded.country_name, last_tested = excluded.last_tested,
  last_passed = excluded.last_passed, generation_id = excluded.generation_id, consecutive_failures = 0,
  banned_until = NULL, retention_cycles = excluded.retention_cycles
"""
# Failure: count it; at the threshold ban the proxy for this node and give it
# a fresh set of attempts after the ban (owner's per-node ban rule).
_UPSERT_FAILED = """
INSERT INTO group_node_proxies (group_id, node_id, key, raw_url, ident, ping_ms, tests_passed, tests_total,
  download_speed_kbps, upload_speed_kbps, speed_score, country_name, last_tested, last_passed, generation_id,
  consecutive_failures, banned_until, retention_cycles)
VALUES (:g, :n, :key, :url, '', :ping, :passed, :total, 0, 0, 0, '', :now, '', :gen,
  CASE WHEN :ban IS NOT NULL AND 1 >= :thr THEN 0 ELSE 1 END,
  CASE WHEN :ban IS NOT NULL AND 1 >= :thr THEN :ban END, 0)
ON CONFLICT (group_id, node_id, key) DO UPDATE SET raw_url = excluded.raw_url, ping_ms = excluded.ping_ms,
  tests_passed = excluded.tests_passed, tests_total = excluded.tests_total, download_speed_kbps = 0,
  upload_speed_kbps = 0, speed_score = 0, last_tested = excluded.last_tested,
  generation_id = excluded.generation_id,
  consecutive_failures = CASE WHEN :ban IS NOT NULL AND consecutive_failures + 1 >= :thr THEN 0
                              ELSE consecutive_failures + 1 END,
  banned_until = CASE WHEN :ban IS NOT NULL AND consecutive_failures + 1 >= :thr THEN :ban
                      ELSE banned_until END
"""


def _num(v, cast=int, default=0):
    try:
        return cast(v)
    except (TypeError, ValueError):
        return default


def store_results(gid: int, nid: int, generation: str, results: list[dict]) -> dict:
    """Upsert one chunk of results + ban/retention state. Returns counters."""
    with Session(engine) as s:
        group = _group_for_node(s, gid, nid)
        _touch(s, nid)
        st = _state(s, gid, nid)
        current = effective_generation(group.generation_id, st.run_seq)
        st.status, st.testing_generation, st.updated_at = "testing", generation, utcnow()
        s.add(st)
        retention = max(0, group.good_proxy_retention_cycles)
        ban_hours = group.ban_duration_hours
        threshold = max(1, group.ban_after_n_failures)
        s.commit()

    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    ban_until = (now_dt + timedelta(hours=ban_hours)).isoformat() if ban_hours > 0 else None
    ok_rows, bad_rows = [], []
    seen = set()
    for r in results[:MAX_RESULTS_PER_POST]:
        url = str(r.get("raw_url") or "").strip()
        if not url:
            continue
        key = proxy_key(url)
        if key in seen:
            continue
        seen.add(key)
        ping, passed = _num(r.get("ping_ms")), _num(r.get("tests_passed"))
        row = {"g": gid, "n": nid, "key": key, "url": url, "ping": ping, "passed": passed,
               "total": _num(r.get("tests_total")), "now": now, "gen": generation}
        if ping > 0 and passed > 0:
            row.update(ident=get_proxy_identity(url), dl=_num(r.get("download_speed_kbps")),
                       ul=_num(r.get("upload_speed_kbps")), score=_num(r.get("speed_score"), float, 0.0),
                       country=str(r.get("country_name") or "")[:64], retention=retention)
            ok_rows.append(row)
        else:
            row.update(ban=ban_until, thr=threshold)
            bad_rows.append(row)
    with engine.begin() as c:
        if ok_rows:
            c.exec_driver_sql(_UPSERT_PASSED, ok_rows)
        if bad_rows:
            c.exec_driver_sql(_UPSERT_FAILED, bad_rows)
    if ok_rows:
        rating.invalidate(gid)
    return {"accepted": len(ok_rows) + len(bad_rows), "passed": len(ok_rows),
            "generation": current, "stale": generation != current}


def set_status(gid: int, nid: int, generation: str, status: str, current_chunk: int, total_chunks: int) -> dict:
    with Session(engine) as s:
        group = _group_for_node(s, gid, nid)
        _touch(s, nid)
        st = _state(s, gid, nid)
        current = effective_generation(group.generation_id, st.run_seq)
        st.status = "testing" if status == "testing" else "idle"
        st.testing_generation = generation
        st.current_chunk, st.total_chunks = max(0, current_chunk), max(0, total_chunks)
        st.updated_at = utcnow()
        if st.status == "idle" and generation and generation == current:
            st.completed_generation, st.completed_at = generation, st.updated_at
        s.add(st)
        s.commit()
    return {"status": "ok", "generation": current}


# ---------------------------------------------------------------------------
# v2 endpoints
# ---------------------------------------------------------------------------
@router.post("/api/node/register")
def node_register(request: Request, payload: dict = Body(default={}), authorization: str = Header(None)):
    _auth(authorization)
    data = payload
    name = str(data.get("name") or "unnamed")[:100]
    region = str(data.get("region") or "")[:100]
    instance = str(data.get("instance_id") or "")[:64]
    protocol = 2 if data.get("protocol") == 2 else 1
    ip = request.client.host if request.client else ""
    with Session(engine) as s:
        node = s.exec(select(Node).where(Node.name == name)).first()
        if node:
            try:
                hb = datetime.fromisoformat(node.last_heartbeat) if node.last_heartbeat else None
            except ValueError:
                hb = None
            alive = node.is_online and hb is not None and datetime.now(timezone.utc) - hb < DUPLICATE_WINDOW
            # Same instance re-registering (e.g. after a panel restart) is fine;
            # another live instance with the same name is a duplicate.
            if alive and (not instance or instance != node.instance_id):
                logger.warning(f"Node '{name}' (id={node.id}) already active; rejected duplicate from {ip}")
                return {"status": "already_active", "node_id": node.id}
            node.region, node.ip, node.instance_id, node.protocol = region, ip, instance, protocol
            node.is_online, node.last_heartbeat = True, utcnow()
            s.add(node)
            s.commit()
            rating.invalidate_all()
            return {"status": "updated", "node_id": node.id}
        node = Node(name=name, region=region, ip=ip, instance_id=instance, protocol=protocol,
                    is_online=True, last_heartbeat=utcnow())
        s.add(node)
        s.commit()
        s.refresh(node)
        logger.info(f"Registered new node '{name}' (id={node.id}) from {ip}")
        return {"status": "registered", "node_id": node.id}


@router.post("/api/node/heartbeat")
def node_heartbeat(payload: dict = Body(default={}), authorization: str = Header(None)):
    _auth(authorization)
    nid = _num(payload.get("node_id"))
    with Session(engine) as s:
        _touch(s, nid)
        s.commit()
    return {"status": "ok"}


@router.post("/api/node/logs")
def node_logs(payload: dict = Body(default={}), authorization: str = Header(None)):
    _auth(authorization)
    data = payload
    nid = _num(data.get("node_id"))
    with Session(engine) as s:
        node = s.get(Node, nid)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        name = node.name
    logs = data.get("logs") or []
    for entry in logs[-1000:]:
        if isinstance(entry, dict):
            log_buffer.append({"timestamp": entry.get("timestamp"), "level": entry.get("level", "INFO"),
                               "logger": f"worker:{name}", "message": str(entry.get("message", ""))[:4000]})
    return {"status": "ok", "received": len(logs)}


@router.get("/api/node/jobs")
def node_jobs(node_id: int = Query(...), authorization: str = Header(None)):
    _auth(authorization)
    with Session(engine) as s:
        _touch(s, node_id)
        settings = s.exec(select(Settings)).first()
        groups = s.exec(
            select(RatingGroup).join(NodeRatingLink, NodeRatingLink.rating_group_id == RatingGroup.id)
            .where(NodeRatingLink.node_id == node_id).order_by(RatingGroup.id)
        ).all()
        jobs = [_job(g, _state(s, g.id, node_id)) for g in groups]
        test_urls = _test_urls(s)
        s.commit()
    return {"node_log_level": (settings.node_log_level if settings else "info") or "info",
            "test_urls": test_urls, "speed_test_dl_url": SPEEDTEST_PATH, "jobs": jobs}


@router.get("/api/node/groups/{gid}/proxies")
def node_group_proxies(request: Request, gid: int, node_id: int = Query(...), authorization: str = Header(None)):
    _auth(authorization)
    with Session(engine) as s:
        group = _group_for_node(s, gid, node_id)
        st = _state(s, gid, node_id)
        gen = effective_generation(group.generation_id, st.run_seq)
        has_work = bool(gen) and _has_remaining(s, gid, node_id, gen)
        if gen and not has_work and st.completed_generation != gen:
            st.status, st.completed_generation, st.completed_at = "idle", gen, utcnow()
            s.add(st)
        s.commit()
        pool_total = group.pool_size
    head = {"generation": gen, "pool_total": pool_total}
    if not has_work:
        return {**head, "proxies": [], "remaining": 0}
    return _stream_list(request, head, "remaining", gid, node_id, gen)


@router.post("/api/node/groups/{gid}/results")
def node_group_results(gid: int, payload: dict = Body(default={}), authorization: str = Header(None)):
    _auth(authorization)
    data = payload
    nid = _num(data.get("node_id"))
    results = data.get("results") or []
    if not isinstance(results, list):
        raise HTTPException(status_code=400, detail="results must be a list")
    if len(results) > MAX_RESULTS_PER_POST:
        raise HTTPException(status_code=413, detail=f"at most {MAX_RESULTS_PER_POST} results per request")
    out = store_results(gid, nid, str(data.get("generation") or ""), [r for r in results if isinstance(r, dict)])
    logger.info(f"Node {nid} → group {gid}: {out['accepted']} results ({out['passed']} passed)"
                + (" [stale generation]" if out["stale"] else ""))
    return out


@router.post("/api/node/groups/{gid}/status")
def node_group_status(gid: int, payload: dict = Body(default={}), authorization: str = Header(None)):
    _auth(authorization)
    d = payload
    return set_status(gid, _num(d.get("node_id")), str(d.get("generation") or ""), str(d.get("status") or "idle"),
                      _num(d.get("current_chunk")), _num(d.get("total_chunks")))


# ---------------------------------------------------------------------------
# v1 compatibility (workers that predate the jobs API)
# ---------------------------------------------------------------------------
def _legacy_group(s: Session, nid: int) -> tuple[RatingGroup | None, NodeGroupState | None]:
    group = s.exec(
        select(RatingGroup).join(NodeRatingLink, NodeRatingLink.rating_group_id == RatingGroup.id)
        .where(NodeRatingLink.node_id == nid).order_by(RatingGroup.id)
    ).first()
    return (group, _state(s, group.id, nid)) if group else (None, None)


@router.get("/api/node/config")
def legacy_config(node_id: int = Query(default=0), authorization: str = Header(None)):
    _auth(authorization)
    with Session(engine) as s:
        if node_id and s.get(Node, node_id):
            _touch(s, node_id)
        settings = s.exec(select(Settings)).first()
        group, st = _legacy_group(s, node_id) if node_id else (None, None)
        test_urls = _test_urls(s)
        s.commit()
        g = group or RatingGroup()
        gen = effective_generation(group.generation_id, st.run_seq) if group else ""
    return {
        "ping_threshold_ms": g.ping_threshold_ms, "http_timeout_s": g.http_timeout_s,
        "concurrent_checks_limit": g.concurrent_checks_limit, "speed_test_top_n": g.speed_test_top_n,
        "schedule_interval_minutes": g.schedule_interval_minutes, "chunk_size": g.chunk_size,
        "generation_id": gen, "force_test": False, "test_urls": test_urls,
        "geo_check_enabled": g.geo_check_enabled, "speed_test_dl_url": SPEEDTEST_PATH,
        "node_log_level": (settings.node_log_level if settings else "info") or "info",
    }


@router.get("/api/node/state")
def legacy_state(node_id: int = Query(...), authorization: str = Header(None)):
    _auth(authorization)
    with Session(engine) as s:
        group, st = _legacy_group(s, node_id)
        s.commit()
        if not group:
            return {"status": "idle", "current_chunk": 0, "total_chunks": 0, "testing_generation_id": "", "chunk_size": 0}
        gen = effective_generation(group.generation_id, st.run_seq)
        done = st.completed_generation == gen
        return {"status": "idle" if done else "new", "current_chunk": 0, "total_chunks": 1 if done else 0,
                "testing_generation_id": gen if done else "", "chunk_size": group.chunk_size}


@router.get("/api/node/proxies")
def legacy_proxies(request: Request, node_id: int = Query(default=0), authorization: str = Header(None)):
    _auth(authorization)
    with Session(engine) as s:
        group, st = _legacy_group(s, node_id) if node_id else (None, None)
        gen = effective_generation(group.generation_id, st.run_seq) if group else ""
        has_work = bool(gen) and _has_remaining(s, group.id, node_id, gen)
        s.commit()
    if not has_work:
        return {"run_id": "empty", "proxies": [], "offset": 0, "total": 0, "has_more": False,
                "chunk_size": group.chunk_size if group else 0}
    head = {"run_id": hashlib.md5(gen.encode()).hexdigest(), "offset": 0, "has_more": False,
            "chunk_size": group.chunk_size}
    return _stream_list(request, head, "total", group.id, node_id, gen)


@router.post("/api/node/results")
def legacy_results(payload: dict = Body(default={}), authorization: str = Header(None)):
    _auth(authorization)
    data = payload
    nid = _num(data.get("node_id"))
    with Session(engine) as s:
        group, _ = _legacy_group(s, nid)
        s.commit()
    if not group:
        return {"status": "ok", "accepted": 0}
    results = [r for r in (data.get("results") or []) if isinstance(r, dict)]
    out = store_results(group.id, nid, str(data.get("generation_id") or ""), results)
    logger.info(f"Legacy node {nid} → group {group.id}: {out['accepted']} results ({out['passed']} passed)")
    return {"status": "ok", "accepted": out["accepted"]}


@router.post("/api/node/status")
def legacy_status(payload: dict = Body(default={}), authorization: str = Header(None)):
    _auth(authorization)
    d = payload
    nid = _num(d.get("node_id"))
    with Session(engine) as s:
        group, _ = _legacy_group(s, nid)
        s.commit()
    if not group:
        return {"status": "ok"}
    cur, total = _num(d.get("current_chunk")), _num(d.get("total_chunks"))
    status = str(d.get("status") or "idle")
    # v1 reports "idle" both at the start (no proxies) and at the end of a run
    return set_status(group.id, nid, str(d.get("generation_id") or ""), status, cur, total)
