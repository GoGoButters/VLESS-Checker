"""Scheduler — periodically fetches subscriptions and stores raw proxies for workers."""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from sqlmodel import Session, select, delete

from database import Settings, Subscription, RawProxy, engine
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

            proxy_links = await fetch_and_parse_subscriptions()
            if proxy_links:
                with Session(engine) as session:
                    session.exec(delete(RawProxy))
                    for url in proxy_links:
                        session.add(RawProxy(raw_url=url))
                    session.commit()
                logger.info(f"Scheduler: fetched {len(proxy_links)} proxies for workers")
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
