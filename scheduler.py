"""Scheduler — periodically fetches subscriptions and stores raw proxies for workers."""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from sqlmodel import Session, select, delete

from database import Settings, Subscription, RawProxy, NodeProxyResult, engine
from subs_manager import fetch_and_parse_subscriptions

logger = logging.getLogger("vpn_checker.scheduler")

# Global scheduler state (read by dashboard)
scheduler_status = {
    "enabled": False,
    "interval_minutes": 0,
    "next_run_at": None,       # ISO string or None
    "last_run_at": None,       # ISO string or None
}

_scheduler_task: asyncio.Task | None = None


def _read_interval() -> int:
    """Read schedule_interval_minutes from DB (0 = disabled)."""
    with Session(engine) as session:
        settings = session.exec(select(Settings)).first()
        return settings.schedule_interval_minutes if settings else 0


async def _scheduler_loop():
    """Main scheduler loop — runs forever, sleeps between fetch cycles."""
    logger.info("Scheduler loop started")
    while True:
        try:
            interval = _read_interval()
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
                new_interval = _read_interval()
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

            # Run the fetch pipeline
            logger.info("Scheduler: starting scheduled subscription fetch")

            # Get good proxies from previous tests (tests_passed >0)
            with Session(engine) as session:
                good_results = session.exec(
                    select(NodeProxyResult.raw_url)
                    .where(NodeProxyResult.tests_passed >0)
                    .distinct()
                ).all()

                # Handle both tuple and scalar results from SQLModel
                good_proxies = []
                for row in good_results:
                    url = row[0] if isinstance(row, tuple) else row
                    if url:
                        good_proxies.append(str(url))
                logger.info(f"Scheduler: found {len(good_proxies)} good proxies from previous tests")

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

            # Pass session to update last_config_count and skip disabled
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
                        logger.info(f"Scheduler: retained {added_count} good proxies "
                                    f"(not in subscriptions, within {retention_limit}-cycle limit)")
                    if expired_count > 0:
                        logger.info(f"Scheduler: expired {expired_count} proxies "
                                    f"(exceeded {retention_limit}-cycle retention limit)")
                else:
                    logger.info("Scheduler: proxy retention disabled (good_proxy_retention_cycles=0)")

                if final_proxies:
                    session.exec(delete(RawProxy))
                    # Filter out any non-string or single-char entries
                    for key, (url, cycles) in final_proxies.items():
                        if isinstance(url, str) and len(url) > 10 and url.startswith(('vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://', 'hysteria2://')):
                            session.add(RawProxy(raw_url=url, retention_cycles=cycles))
                    session.commit()
                    logger.info(f"Scheduler: stored {len(final_proxies)} proxies for workers")
                else:
                    logger.warning("Scheduler: no proxy links found from subscriptions")

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
