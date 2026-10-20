"""Scheduler — periodically fetches subscriptions and stores raw proxies for workers.

The whole fetch pipeline is synchronous SQLite/HTTP work and is executed via
``asyncio.to_thread`` so it never blocks the FastAPI event loop. Bulk writes into
``raw_proxies`` are batched with per-batch commits: a single 66k-row transaction
used to hold the write lock for 30-70s and produced ``database is locked`` on
workers.
"""

import asyncio
import json
import logging
import threading
import uuid
from datetime import datetime, timezone, timedelta

from sqlmodel import Session, select

from database import (
    DATABASE_URL,
    Settings,
    RawProxy,
    NodeProxyResult,
    engine,
)
from subs_manager import fetch_and_parse_subscriptions_sync
from db_maintenance import connect as raw_connect, cleanup_orphan_results

logger = logging.getLogger("vpn_checker.scheduler")

# Global scheduler state (read by dashboard)
scheduler_status = {
    "enabled": False,
    "interval_minutes": 0,
    "next_run_at": None,       # ISO string or None
    "last_run_at": None,       # ISO string or None
}

_scheduler_task: asyncio.Task | None = None
_cycle_running = False
# Serialises raw_proxies rebuilds: the scheduled cycle and the manual "Fetch
# subs" button both call store_raw_proxies and would otherwise interleave their
# batched DELETE/INSERT, leaving a mixed set behind.
_raw_proxies_lock = threading.Lock()

DB_FILE = DATABASE_URL.replace("sqlite:///", "").replace("./", "")
DELETE_BATCH = 5000
INSERT_BATCH = 2000
PROXY_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://")


def _read_interval() -> int:
    """Read schedule_interval_minutes from DB (0 = disabled)."""
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        return settings.schedule_interval_minutes if settings else 0


def load_state() -> tuple[list[str], int, dict | None, dict[str, int]]:
    """Read good proxies, retention limit, protocol filter and retention state."""
    with Session(engine) as session:
        good_results = session.exec(
            select(NodeProxyResult.raw_url)
            .where(NodeProxyResult.tests_passed > 0)
            .distinct()
        ).all()

        good_proxies = []
        for row in good_results:
            url = row[0] if isinstance(row, tuple) else row
            if url:
                good_proxies.append(str(url))
        logger.info(f"Scheduler: found {len(good_proxies)} good proxies from previous tests")

        settings = session.exec(select(Settings)).first()
        retention_limit = settings.good_proxy_retention_cycles if settings else 3

        enabled_protocols = None
        if settings and settings.enabled_protocols:
            try:
                enabled_protocols = json.loads(settings.enabled_protocols)
            except Exception:
                pass

        if retention_limit > 0:
            retention_rows = session.exec(
                select(RawProxy.raw_url, RawProxy.retention_cycles)
            ).all()
            old_retention: dict[str, int] = {}
            for raw_url, cycles in retention_rows:
                old_retention[raw_url.split("#", 1)[0]] = cycles
        else:
            old_retention = {}

    return good_proxies, retention_limit, enabled_protocols, old_retention


def build_final_proxies(
    proxy_links: list[str],
    good_proxies: list[str],
    retention_limit: int,
    old_retention: dict[str, int],
) -> dict[str, tuple[str, int]]:
    """Merge fresh subscription links with retained good proxies.

    Returns key -> (full_url, retention_cycles).
    """
    final_proxies: dict[str, tuple[str, int]] = {}

    # 1. Fresh subscriptions: retention_cycles = 0 (reset)
    for url in proxy_links:
        final_proxies[url.split("#", 1)[0]] = (url, 0)

    # 2. Good proxies NOT in fresh subscriptions: increment retention
    if retention_limit > 0:
        added_count = 0
        expired_count = 0
        for p in good_proxies:
            key = p.split("#", 1)[0]
            if key not in final_proxies:
                new_cycles = old_retention.get(key, 0) + 1
                if new_cycles <= retention_limit:
                    final_proxies[key] = (p, new_cycles)
                    added_count += 1
                else:
                    expired_count += 1
        if added_count > 0:
            logger.info(f"Scheduler: retained {added_count} good proxies "
                        f"(not in subscriptions, within {retention_limit}-cycle limit)")
        if expired_count > 0:
            logger.info(f"Scheduler: expired {expired_count} proxies "
                        f"(exceeded {retention_limit}-cycle retention limit)")
    else:
        logger.info("Scheduler: proxy retention disabled (good_proxy_retention_cycles=0)")

    return final_proxies


def store_raw_proxies(final_proxies: dict[str, tuple[str, int]]) -> int:
    """Replace raw_proxies contents in small batches and drop orphaned results.

    Serialised by ``_raw_proxies_lock`` so a scheduled cycle and a manual fetch
    can never interleave their batched DELETE/INSERT.

    Uses a dedicated autocommit connection so every batch is its own short
    transaction (small WAL, no 30-second write lock). Returns the number of
    proxies stored.

    The rebuild is intentionally not atomic: a worker polling mid-rebuild sees a
    partial list but still the OLD generation_id, and its results are discarded
    when the generation is bumped afterwards — correctness is preserved without
    holding a long write lock.
    """
    with _raw_proxies_lock:
        return _rebuild_raw_proxies(final_proxies)


def _rebuild_raw_proxies(final_proxies: dict[str, tuple[str, int]]) -> int:
    rows = [
        (url, cycles)
        for url, cycles in final_proxies.values()
        if isinstance(url, str) and len(url) > 10 and url.startswith(PROXY_PREFIXES)
    ]
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = raw_connect(DB_FILE)
    try:
        # 1. Clear the old set in batches.
        while True:
            cur = conn.execute(
                "DELETE FROM raw_proxies WHERE id IN ("
                "  SELECT id FROM raw_proxies LIMIT ?)",
                (DELETE_BATCH,),
            )
            if not (cur.rowcount or 0):
                break

        # 2. Insert the new set in batches.
        for i in range(0, len(rows), INSERT_BATCH):
            conn.executemany(
                "INSERT OR IGNORE INTO raw_proxies "
                "(raw_url, fetched_at, consecutive_failures, retention_cycles, banned_until) "
                "VALUES (?, ?, 0, ?, NULL)",
                [(url, now_iso, cycles) for url, cycles in rows[i:i + INSERT_BATCH]],
            )

        # 3. Prophylaxis: drop results for proxies that just disappeared, so
        #    node_proxy_results can never grow into 90% orphans again.
        cleanup_orphan_results(conn)

        # 4. Compact the WAL without holding the DB for a long TRUNCATE.
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except Exception:
            pass
    finally:
        conn.close()

    return len(rows)


def _run_cycle_sync() -> None:
    """Run one fetch cycle. Blocking — always called via asyncio.to_thread."""
    global _cycle_running
    if _cycle_running:
        logger.warning("Scheduler: previous cycle still running, skipping this tick")
        return
    _cycle_running = True
    try:
        good_proxies, retention_limit, enabled_protocols, old_retention = load_state()

        # Blocking HTTP fetch (parallel) — runs inside this worker thread.
        with Session(engine) as session:
            proxy_links = fetch_and_parse_subscriptions_sync(session, enabled_protocols)

        final_proxies = build_final_proxies(
            proxy_links, good_proxies, retention_limit, old_retention
        )

        if not final_proxies:
            logger.warning("Scheduler: no proxy links found from subscriptions")
            return

        stored = store_raw_proxies(final_proxies)
        logger.info(f"Scheduler: stored {stored} proxies for workers")

        # Update generation_id to signal new cycle to nodes
        import database
        database.generation_id = str(uuid.uuid4())
        logger.info(f"Scheduler: updated generation_id={database.generation_id}")
    finally:
        _cycle_running = False


async def _scheduler_loop():
    """Main scheduler loop — runs forever, sleeps between fetch cycles."""
    logger.info("Scheduler loop started")
    while True:
        try:
            interval = await asyncio.to_thread(_read_interval)
            scheduler_status["interval_minutes"] = interval

            if interval <= 0:
                scheduler_status["enabled"] = False
                scheduler_status["next_run_at"] = None
                await asyncio.sleep(30)
                continue

            scheduler_status["enabled"] = True
            next_run = datetime.now(timezone.utc) + timedelta(minutes=interval)
            scheduler_status["next_run_at"] = next_run.isoformat()

            # Sleep until next run (in 30-second chunks to pick up setting changes)
            while True:
                now = datetime.now(timezone.utc)
                if now >= next_run:
                    break
                new_interval = await asyncio.to_thread(_read_interval)
                if new_interval != interval:
                    interval = new_interval
                    scheduler_status["interval_minutes"] = interval
                    if interval <= 0:
                        scheduler_status["enabled"] = False
                        scheduler_status["next_run_at"] = None
                        break
                    next_run = datetime.now(timezone.utc) + timedelta(minutes=interval)
                    scheduler_status["next_run_at"] = next_run.isoformat()
                await asyncio.sleep(min(30, max(1, (next_run - now).total_seconds())))

            if interval <= 0:
                continue

            # Run the fetch pipeline off the event loop: the panel keeps serving
            # HTTP and worker heartbeats for the entire cycle.
            logger.info("Scheduler: starting scheduled subscription fetch")
            await asyncio.to_thread(_run_cycle_sync)
            scheduler_status["last_run_at"] = datetime.now(timezone.utc).isoformat()

        except asyncio.CancelledError:
            logger.info("Scheduler loop cancelled")
            break
        except Exception as e:
            logger.error(f"Scheduler error: {e}", exc_info=True)
            await asyncio.sleep(60)


def start_scheduler():
    """Start the scheduler background task. Safe to call multiple times."""
    global _scheduler_task
    if _scheduler_task is not None and not _scheduler_task.done():
        return
    _scheduler_task = asyncio.create_task(_scheduler_loop())
    logger.info("Scheduler task created")


def stop_scheduler():
    """Cancel the scheduler background task."""
    global _scheduler_task
    if _scheduler_task is not None and not _scheduler_task.done():
        _scheduler_task.cancel()
        logger.info("Scheduler task cancelled")
