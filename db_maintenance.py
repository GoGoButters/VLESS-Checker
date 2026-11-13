"""SQLite housekeeping for VPN Checker (stdlib only).

Runs in the background after startup and as a CLI (`python3 db_maintenance.py`):
VACUUM when free pages are a large share of the file, then PRAGMA optimize and
a WAL checkpoint. Orphan rows are removed by the pipeline as it goes.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time

logger = logging.getLogger("vpn_checker.db_maintenance")

DB_PATH = os.environ.get("VPN_DB_PATH", "data/vpn_checker.db")
VACUUM_MIN_FREE_BYTES = 32 * 1024 * 1024
VACUUM_MIN_FREE_RATIO = 0.25


def run_maintenance(path: str = DB_PATH) -> dict:
    if not os.path.exists(path):
        return {}
    t0 = time.time()
    conn = sqlite3.connect(path, timeout=60.0, isolation_level=None)
    try:
        conn.execute("PRAGMA busy_timeout=60000")
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
        free = conn.execute("PRAGMA freelist_count").fetchone()[0] * page_size
        total = pages * page_size
        vacuumed = False
        if free >= VACUUM_MIN_FREE_BYTES and total and free / total >= VACUUM_MIN_FREE_RATIO:
            logger.info(f"VACUUM: {free / 1048576:.0f} of {total / 1048576:.0f} MB are free pages")
            conn.execute("VACUUM")
            vacuumed = True
        conn.execute("PRAGMA optimize")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    result = {"size_mb": round(os.path.getsize(path) / 1048576, 1), "vacuumed": vacuumed,
              "seconds": round(time.time() - t0, 1)}
    logger.info(f"DB maintenance: {result}")
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    run_maintenance()
