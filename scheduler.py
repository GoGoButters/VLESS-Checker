"""Scheduler — runs the full test pipeline on a configurable interval."""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from sqlmodel import Session, select

from database import Settings, engine
from subs_manager import fetch_and_parse_subscriptions
from tester import run_full_test, test_status

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
    """Main scheduler loop — runs forever, sleeps between test cycles."""
    logger.info("Scheduler loop started")
    while True:
        try:
            interval = _read_interval()
            scheduler_status["interval_minutes"] = interval

            if interval <= 0:
                scheduler_status["enabled"] = False
                scheduler_status["next_run_at"] = None
                # Check again in 30 seconds whether user enabled it
                await asyncio.sleep(30)
                continue

            scheduler_status["enabled"] = True
            next_run = datetime.now(timezone.utc) + timedelta(minutes=interval)
            scheduler_status["next_run_at"] = next_run.isoformat()

            # Sleep until next run (in 60-second chunks so we can pick up setting changes)
            while True:
                now = datetime.now(timezone.utc)
                if now >= next_run:
                    break
                # Re-read interval to detect changes
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

            # If interval became 0 while waiting, loop back to the top
            if interval <= 0:
                continue

            # Skip if a test is already running (e.g. manual trigger)
            if test_status.get("running"):
                logger.info("Scheduler: test already running, skipping this cycle")
                continue

            # Run the test pipeline
            logger.info("Scheduler: starting scheduled test")
            test_status["current_phase"] = "fetching"
            test_status["running"] = True

            vless_links = await fetch_and_parse_subscriptions()
            if vless_links:
                await run_full_test(vless_links)
            else:
                test_status["current_phase"] = "done"
                test_status["running"] = False
                logger.warning("Scheduler: no VLESS links found")

            scheduler_status["last_run_at"] = datetime.now(timezone.utc).isoformat()

        except asyncio.CancelledError:
            logger.info("Scheduler loop cancelled")
            break
        except Exception as e:
            logger.error(f"Scheduler error: {e}", exc_info=True)
            test_status["running"] = False
            test_status["current_phase"] = "error"
            await asyncio.sleep(60)  # backoff on error


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
