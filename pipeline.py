"""Per-group pipeline: fetch sources → build the group pool → new generation.

All of it is blocking SQLite/HTTP work executed in one worker thread (cycles
are serialized by ``_cycle_lock``), never on the event loop. State that has to
survive a restart — generation, last fetch time — lives in the database.
"""
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlmodel import select

import rating
import sources
from database import (
    Session,
    GroupSource, GroupSourceStat, Node, NodeGroupState, NodeRatingLink, RatingGroup,
    SourceSnapshot, Subscription, engine, utcnow,
)

logger = logging.getLogger("vpn_checker.pipeline")

TICK_S = float(os.environ.get("VPN_PIPELINE_TICK_S", "15"))
SOURCE_STATS_KEEP = 10      # samples kept per (group, source)
SOURCE_STATS_WINDOW = 5     # zero live proxies in this many samples → skip the source
NODE_OFFLINE_AFTER = timedelta(minutes=5)
BATCH = 2000

_cycle_lock = threading.Lock()
_requests_lock = threading.Lock()
_requests: dict[int, bool] = {}   # group_id → fetch sources (True) or rebuild from snapshots (False)

status = {"running": False, "phase": "idle", "group": "", "last_cycle_at": None, "last_error": ""}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# requests from the UI / MCP
# ---------------------------------------------------------------------------
def request_cycle(group_ids: list[int], fetch: bool = True) -> None:
    """Queue groups for the next tick. fetch=False rebuilds from snapshots only
    (after a change of sources / protocol filter — no network needed)."""
    with _requests_lock:
        for gid in group_ids:
            _requests[gid] = _requests.get(gid, False) or fetch


def _take_requests() -> dict[int, bool]:
    with _requests_lock:
        out = dict(_requests)
        _requests.clear()
        return out


def next_fetch_at(group: RatingGroup) -> datetime | None:
    if group.schedule_interval_minutes <= 0:
        return None
    last = _parse(group.last_fetch_at)
    return (last + timedelta(minutes=group.schedule_interval_minutes)) if last else _now()


def _due_groups() -> dict[int, bool]:
    now = _now()
    due: dict[int, bool] = {}
    with Session(engine) as s:
        for g in s.exec(select(RatingGroup)).all():
            nxt = next_fetch_at(g)
            if nxt is not None and nxt <= now:
                due[g.id] = True
    return due


# ---------------------------------------------------------------------------
# cycle
# ---------------------------------------------------------------------------
def run_cycle(work: dict[int, bool]) -> None:
    """Fetch the sources the groups need (once each), then rebuild every group."""
    if not work or not _cycle_lock.acquire(blocking=False):
        if work:
            request_cycle([g for g, f in work.items() if f], fetch=True)
            request_cycle([g for g, f in work.items() if not f], fetch=False)
        return
    status.update(running=True, phase="fetching", group="", last_error="")
    t0 = time.monotonic()
    try:
        with Session(engine) as s:
            rows = s.exec(
                select(Subscription.id, Subscription.url, GroupSource.group_id, SourceSnapshot.subscription_id)
                .join(GroupSource, GroupSource.subscription_id == Subscription.id)
                .outerjoin(SourceSnapshot, SourceSnapshot.subscription_id == Subscription.id)
                .where(GroupSource.group_id.in_(list(work)), Subscription.is_enabled == True)  # noqa: E712
            ).all()
            # Sources of fetching groups, plus never-fetched ones of rebuilding groups
            to_fetch = {sid: url for sid, url, gid, snap in rows if work.get(gid) or snap is None}
        fetched = sources.fetch_many(list(to_fetch.items()))
        _store_fetch_results(fetched)

        status["phase"] = "building"
        for gid in sorted(work):
            try:
                rebuild_group(gid, fetched_now=work[gid])
            except Exception as e:  # one broken group must not stop the others
                logger.error(f"Group {gid}: rebuild failed: {e}", exc_info=True)
                status["last_error"] = f"group {gid}: {e}"
                _mark_failed(gid, str(e))
        logger.info(f"Cycle for groups {sorted(work)} finished in {time.monotonic() - t0:.1f}s")
    except Exception as e:
        logger.error(f"Pipeline cycle failed: {e}", exc_info=True)
        status["last_error"] = str(e)
    finally:
        status.update(running=False, phase="idle", group="", last_cycle_at=utcnow())
        _cycle_lock.release()


def _mark_failed(gid: int, error: str) -> None:
    """Count a failed rebuild as an attempt, so the schedule does not retry it every tick."""
    try:
        with Session(engine) as s:
            group = s.get(RatingGroup, gid)
            if group:
                group.last_fetch_at = utcnow()
                group.last_fetch_status = f"error: {error}"[:300]
                s.add(group)
                s.commit()
    except Exception as e:
        logger.error(f"Group {gid}: could not record the failure: {e}")


def _store_fetch_results(fetched: dict[int, tuple[list[str] | None, str]]) -> None:
    now = utcnow()
    with Session(engine) as s:
        for sid, (links, err) in fetched.items():
            sub = s.get(Subscription, sid)
            if not sub:
                continue
            sub.last_fetch_at = now
            sub.last_fetch_ok = links is not None
            sub.last_error = err
            if links is not None:
                sub.last_config_count = len(links)
                snap = s.get(SourceSnapshot, sid) or SourceSnapshot(subscription_id=sid)
                snap.links = sources.pack_links(links)
                snap.count = len(links)
                snap.signature = sources.source_signature(links)
                snap.fetched_at = now
                s.add(snap)
            else:
                logger.warning(f"Source {sid} kept its previous snapshot: {err}")
            s.add(sub)
        s.commit()


def _decide_source(gs: GroupSource, samples: list[tuple[int, int]], signature: str) -> str:
    """skip / reenable / disable / test — dead-source autoskip of one group."""
    if gs.stats_disabled:
        return "skip" if signature and signature == gs.disabled_signature else "reenable"
    if len(samples) >= SOURCE_STATS_WINDOW and sum(a for _, a in samples[:SOURCE_STATS_WINDOW]) == 0:
        return "disable"
    return "test"


def rebuild_group(gid: int, fetched_now: bool = True) -> None:
    t0 = time.monotonic()
    with Session(engine) as s:
        group = s.get(RatingGroup, gid)
        if not group:
            return
        status["group"] = group.name
        protocols = group.protocols()
        prev_generation = group.generation_id

        # What the group's nodes saw in the previous generation (for source stats):
        # only meaningful once at least one node completed that generation.
        completed = s.exec(
            select(NodeGroupState.id).where(
                NodeGroupState.group_id == gid,
                NodeGroupState.completed_generation.like(f"{prev_generation}.%"),
            )
        ).first() if prev_generation else None
        tested, alive = set(), set()
        if completed:
            for key, ok in s.exec(text(
                "SELECT key, MAX(tests_passed > 0 AND ping_ms > 0) FROM group_node_proxies "
                "WHERE group_id = :g AND last_tested != '' GROUP BY key"
            ).bindparams(g=gid)).all():
                tested.add(key)
                if ok:
                    alive.add(key)

        rows = s.exec(
            select(GroupSource, Subscription.is_enabled)
            .join(Subscription, Subscription.id == GroupSource.subscription_id)
            .where(GroupSource.group_id == gid)
        ).all()
        stats: dict[int, list[tuple[int, int]]] = {}
        for st in s.exec(
            select(GroupSourceStat).where(GroupSourceStat.group_id == gid).order_by(GroupSourceStat.id.desc())
        ).all():
            bucket = stats.setdefault(st.subscription_id, [])
            if len(bucket) < SOURCE_STATS_KEEP:
                bucket.append((st.tested, st.alive))

        pool: dict[str, str] = {}
        skipped = 0
        for gs, enabled in rows:
            if not enabled:
                continue
            snap = s.get(SourceSnapshot, gs.subscription_id)
            if snap is None:
                continue  # never fetched successfully: nothing to add, keep its autoskip state
            links = sources.filter_protocols(sources.unpack_links(snap.links), protocols)
            signature = sources.source_signature(links)
            decision = _decide_source(gs, stats.get(gs.subscription_id, []), signature)
            if decision == "reenable":
                gs.stats_disabled, gs.disabled_signature, gs.disabled_at = False, "", ""
                s.exec(text("DELETE FROM group_source_stats WHERE group_id=:g AND subscription_id=:s")
                       .bindparams(g=gid, s=gs.subscription_id))
                s.add(gs)
                logger.info(f"[{group.name}] source {gs.subscription_id}: config set changed — back in tests")
            elif decision == "disable":
                gs.stats_disabled, gs.disabled_signature, gs.disabled_at = True, signature, utcnow()
                s.add(gs)
                logger.info(f"[{group.name}] source {gs.subscription_id}: 0 alive in "
                            f"{SOURCE_STATS_WINDOW} runs — tests paused until its config set changes")
            if decision in ("skip", "disable"):
                skipped += 1
                continue
            keys = sources.dedup(links)
            if completed and fetched_now and keys:
                src_tested = keys.keys() & tested
                if src_tested:
                    s.add(GroupSourceStat(group_id=gid, subscription_id=gs.subscription_id,
                                          generation_id=prev_generation, tested=len(src_tested),
                                          alive=len(src_tested & alive)))
            for k, u in keys.items():
                pool.setdefault(k, u)

        # Trim per-source stats history
        s.exec(text(
            "DELETE FROM group_source_stats WHERE group_id = :g AND id NOT IN ("
            " SELECT id FROM (SELECT id, ROW_NUMBER() OVER (PARTITION BY subscription_id ORDER BY id DESC) rn"
            " FROM group_source_stats WHERE group_id = :g) WHERE rn <= :keep)"
        ).bindparams(g=gid, keep=SOURCE_STATS_KEEP))
        s.commit()

    added, removed = _apply_pool(gid, pool)
    pruned = _decay_and_prune(gid)

    with Session(engine) as s:
        group = s.get(RatingGroup, gid)
        group.generation_id = uuid.uuid4().hex
        group.generation_at = utcnow()
        if fetched_now:
            group.last_fetch_at = group.generation_at
        group.pool_size = len(pool)
        group.last_fetch_status = (
            f"pool {len(pool)} (+{added}/-{removed}), {skipped} sources skipped"
            + ("" if fetched_now else ", rebuilt from snapshots")
        )
        s.add(group)
        s.commit()
        name = group.name
    rating.invalidate(gid)
    logger.info(f"[{name}] pool {len(pool)} (+{added}/-{removed}), pruned {pruned} node rows, "
                f"{skipped} sources skipped, {time.monotonic() - t0:.1f}s")


def _apply_pool(gid: int, pool: dict[str, str]) -> tuple[int, int]:
    """Bring group_proxies to exactly `pool` with small batched transactions."""
    with engine.connect() as c:
        existing = {k: i for i, k in c.exec_driver_sql(
            "SELECT id, key FROM group_proxies WHERE group_id = ?", (gid,)).all()}
    gone = [i for k, i in existing.items() if k not in pool]
    new = [(gid, k, u) for k, u in pool.items() if k not in existing]
    for i in range(0, len(gone), BATCH):
        with engine.begin() as c:
            c.exec_driver_sql(
                f"DELETE FROM group_proxies WHERE id IN ({','.join('?' * len(gone[i:i + BATCH]))})",
                tuple(gone[i:i + BATCH]))
    for i in range(0, len(new), BATCH):
        with engine.begin() as c:
            c.exec_driver_sql(
                "INSERT OR IGNORE INTO group_proxies(group_id, key, raw_url) VALUES (?, ?, ?)", new[i:i + BATCH])
    return len(new), len(gone)


def _decay_and_prune(gid: int) -> int:
    """One retention cycle passes; drop node rows nobody needs any more."""
    now = utcnow()
    with engine.begin() as c:
        c.exec_driver_sql(
            "UPDATE group_node_proxies SET retention_cycles = retention_cycles - 1 "
            "WHERE group_id = ? AND retention_cycles > 0", (gid,))
    pruned = 0
    while True:
        with engine.begin() as c:
            n = c.exec_driver_sql(
                "DELETE FROM group_node_proxies WHERE id IN ("
                " SELECT s.id FROM group_node_proxies s WHERE s.group_id = ? AND s.retention_cycles <= 0"
                " AND NOT (s.banned_until IS NOT NULL AND s.banned_until > ?)"
                " AND NOT EXISTS (SELECT 1 FROM group_proxies p WHERE p.group_id = s.group_id AND p.key = s.key)"
                " LIMIT ?)", (gid, now, BATCH)).rowcount or 0
        pruned += n
        if n < BATCH:
            return pruned


# ---------------------------------------------------------------------------
# maintenance
# ---------------------------------------------------------------------------
def mark_offline_nodes() -> list[int]:
    """Nodes silent for NODE_OFFLINE_AFTER go offline (and out of ratings)."""
    limit = _now() - NODE_OFFLINE_AFTER
    changed = []
    with Session(engine) as s:
        for node in s.exec(select(Node).where(Node.is_online == True)).all():  # noqa: E712
            hb = _parse(node.last_heartbeat)
            if hb is None or hb < limit:
                node.is_online = False
                s.add(node)
                changed.append(node.id)
        if changed:
            s.exec(text(
                f"UPDATE node_group_state SET status='idle' WHERE node_id IN ({','.join(map(str, changed))})"))
            s.commit()
            logger.info(f"Nodes went offline: {changed}")
    if changed:
        rating.invalidate_all()
    return changed


def hourly_maintenance() -> None:
    now = utcnow()
    with engine.begin() as c:
        c.exec_driver_sql(
            "UPDATE group_node_proxies SET banned_until = NULL "
            "WHERE banned_until IS NOT NULL AND banned_until <= ?", (now,))
        # Orphans of deleted groups / nodes / sources (normally removed with them)
        c.exec_driver_sql("DELETE FROM group_proxies WHERE group_id NOT IN (SELECT id FROM rating_groups)")
        for table in ("group_node_proxies", "node_group_state"):
            c.exec_driver_sql(
                f"DELETE FROM {table} WHERE NOT EXISTS (SELECT 1 FROM node_rating_links l "
                f"WHERE l.rating_group_id = {table}.group_id AND l.node_id = {table}.node_id)")
        c.exec_driver_sql(
            "DELETE FROM group_sources WHERE subscription_id NOT IN (SELECT id FROM subscriptions) "
            "OR group_id NOT IN (SELECT id FROM rating_groups)")
        c.exec_driver_sql(
            "DELETE FROM source_snapshots WHERE subscription_id NOT IN (SELECT id FROM subscriptions)")
    with engine.connect() as c:
        c.exec_driver_sql("PRAGMA wal_checkpoint(PASSIVE)")
        c.exec_driver_sql("PRAGMA optimize")


async def scheduler_loop() -> None:
    logger.info("Pipeline scheduler started")
    last_hourly = 0.0
    while True:
        try:
            await asyncio.to_thread(mark_offline_nodes)
            if time.monotonic() - last_hourly > 3600:
                await asyncio.to_thread(hourly_maintenance)
                last_hourly = time.monotonic()
            work = await asyncio.to_thread(_due_groups)
            for gid, fetch in _take_requests().items():
                work[gid] = work.get(gid, False) or fetch
            if work:
                await asyncio.to_thread(run_cycle, work)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Scheduler tick failed: {e}", exc_info=True)
        await asyncio.sleep(TICK_S)


# ---------------------------------------------------------------------------
# cascades
# ---------------------------------------------------------------------------
def delete_group_data(s: Session, gid: int) -> None:
    for table in ("group_proxies", "group_node_proxies", "node_group_state", "group_sources", "group_source_stats"):
        s.exec(text(f"DELETE FROM {table} WHERE group_id = :g").bindparams(g=gid))
    s.exec(text("DELETE FROM node_rating_links WHERE rating_group_id = :g").bindparams(g=gid))


def delete_node_data(s: Session, nid: int) -> None:
    for table in ("group_node_proxies", "node_group_state"):
        s.exec(text(f"DELETE FROM {table} WHERE node_id = :n").bindparams(n=nid))
    s.exec(text("DELETE FROM node_rating_links WHERE node_id = :n").bindparams(n=nid))


def unlink_node(s: Session, gid: int, nid: int) -> None:
    for table in ("group_node_proxies", "node_group_state"):
        s.exec(text(f"DELETE FROM {table} WHERE group_id = :g AND node_id = :n").bindparams(g=gid, n=nid))
    s.exec(text("DELETE FROM node_rating_links WHERE rating_group_id = :g AND node_id = :n").bindparams(g=gid, n=nid))


def link_node(s: Session, gid: int, nid: int) -> None:
    if not s.exec(select(NodeRatingLink).where(NodeRatingLink.rating_group_id == gid,
                                              NodeRatingLink.node_id == nid)).first():
        s.add(NodeRatingLink(rating_group_id=gid, node_id=nid))
    if not s.exec(select(NodeGroupState).where(NodeGroupState.group_id == gid,
                                              NodeGroupState.node_id == nid)).first():
        s.add(NodeGroupState(group_id=gid, node_id=nid, updated_at=utcnow()))


def delete_source_data(s: Session, sid: int) -> None:
    for table in ("group_sources", "group_source_stats"):
        s.exec(text(f"DELETE FROM {table} WHERE subscription_id = :s").bindparams(s=sid))
    s.exec(text("DELETE FROM source_snapshots WHERE subscription_id = :s").bindparams(s=sid))


def add_source_to_auto_groups(s: Session, sid: int) -> list[int]:
    gids = [g.id for g in s.exec(select(RatingGroup).where(RatingGroup.auto_add_new_sources == True)).all()]  # noqa: E712
    for gid in gids:
        if not s.exec(select(GroupSource).where(GroupSource.group_id == gid, GroupSource.subscription_id == sid)).first():
            s.add(GroupSource(group_id=gid, subscription_id=sid))
    return gids


def set_group_sources(s: Session, gid: int, source_ids: set[int]) -> bool:
    """Make the group's selection exactly `source_ids`. True if it changed."""
    current = {gs.subscription_id: gs for gs in s.exec(select(GroupSource).where(GroupSource.group_id == gid)).all()}
    changed = False
    for sid, gs in current.items():
        if sid not in source_ids:
            s.delete(gs)
            changed = True
    for sid in source_ids - current.keys():
        s.add(GroupSource(group_id=gid, subscription_id=sid))
        changed = True
    return changed
