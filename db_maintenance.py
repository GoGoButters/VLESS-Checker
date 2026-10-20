"""One-shot SQLite maintenance for VPN Checker.

Deliberately stdlib-only (no SQLModel/FastAPI imports) so it can be unit-tested
in isolation and executed inside the container without booting the app:

    python3 db_maintenance.py

What it does, in order:
  1. Drop duplicate indexes left behind by older builds (ix_npr_raw_url /
     ix_npr_node_id when the canonical ORM index already exists).
  2. Delete orphan rows from node_proxy_results — rows whose raw_url is no longer
     present in raw_proxies (the ~90% garbage observed in production) or whose
     node_id no longer exists. Batched commits keep the WAL small and avoid
     holding a long write-lock that starves workers.
  3. VACUUM when the file carries a lot of free pages (once, after the cleanup).
  4. PRAGMA optimize + WAL truncate.

The whole thing is idempotent: a clean DB is a fast no-op.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time

logger = logging.getLogger("vpn_checker.db_maintenance")

DB_PATH = os.environ.get("VPN_DB_PATH", "data/vpn_checker.db")
BATCH = 5000
VACUUM_MIN_FREE_BYTES = 100 * 1024 * 1024  # 100 MB of free pages
VACUUM_MIN_FREE_RATIO = 0.10               # ...or >10% of the file


def connect(path: str) -> sqlite3.Connection:
    # isolation_level=None => autocommit: each batched DELETE is its own
    # transaction (small WAL) and VACUUM is allowed outside a transaction.
    conn = sqlite3.connect(path, timeout=60.0, isolation_level=None)
    conn.execute("PRAGMA busy_timeout=60000")
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def _index_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", (name,)
    ).fetchone()
    return row is not None


def cleanup_orphan_results(conn: sqlite3.Connection, batch: int = BATCH) -> dict:
    """Delete node_proxy_results rows whose raw_url or node_id no longer exist.

    Uses NOT EXISTS (NULL-safe, unlike NOT IN) and LIMIT batches so the write
    lock is held for a few ms at a time instead of minutes.
    """
    stats = {"orphan_raw_url": 0, "orphan_node_id": 0}
    if not _table_exists(conn, "node_proxy_results"):
        return stats

    if _table_exists(conn, "raw_proxies"):
        while True:
            cur = conn.execute(
                "DELETE FROM node_proxy_results WHERE id IN ("
                "  SELECT npr.id FROM node_proxy_results npr "
                "  WHERE NOT EXISTS ("
                "    SELECT 1 FROM raw_proxies rp WHERE rp.raw_url = npr.raw_url"
                "  ) LIMIT ?)",
                (batch,),
            )
            n = cur.rowcount or 0
            stats["orphan_raw_url"] += n
            if n < batch:
                break

    if _table_exists(conn, "nodes"):
        while True:
            cur = conn.execute(
                "DELETE FROM node_proxy_results WHERE id IN ("
                "  SELECT npr.id FROM node_proxy_results npr "
                "  WHERE NOT EXISTS ("
                "    SELECT 1 FROM nodes n WHERE n.id = npr.node_id"
                "  ) LIMIT ?)",
                (batch,),
            )
            n = cur.rowcount or 0
            stats["orphan_node_id"] += n
            if n < batch:
                break

    return stats


def drop_duplicate_indexes(conn: sqlite3.Connection) -> list[str]:
    """Drop duplicate single-column indexes when the canonical one exists."""
    dropped: list[str] = []
    for dup, canonical in (
        ("ix_npr_raw_url", "ix_node_proxy_results_raw_url"),
        ("ix_npr_node_id", "ix_node_proxy_results_node_id"),
    ):
        if _index_exists(conn, dup) and _index_exists(conn, canonical):
            conn.execute(f"DROP INDEX IF EXISTS {dup}")
            dropped.append(dup)
    return dropped


def vacuum_if_needed(conn: sqlite3.Connection, path: str) -> bool:
    """VACUUM only when free pages are a significant share of the file."""
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]
    free_bytes = page_size * freelist
    try:
        db_bytes = os.path.getsize(path)
    except OSError:
        db_bytes = 0

    if free_bytes < VACUUM_MIN_FREE_BYTES and (
        db_bytes == 0 or free_bytes < db_bytes * VACUUM_MIN_FREE_RATIO
    ):
        logger.info(f"VACUUM skipped (free pages: {free_bytes / 1048576:.1f} MB)")
        return False

    logger.info(f"VACUUM starting (free pages: {free_bytes / 1048576:.1f} MB)")
    t0 = time.time()
    try:
        conn.execute("VACUUM")
    except Exception as e:
        # e.g. a live app holds the write lock, or the disk is too full for the
        # temp copy. The orphan cleanup already committed, so this is not fatal.
        logger.warning(f"VACUUM failed after {time.time() - t0:.1f}s: {e}")
        return False
    logger.info(f"VACUUM finished in {time.time() - t0:.1f}s")
    return True


def run_maintenance(db_path: str | None = None) -> dict:
    """Run the full maintenance pass. Idempotent; safe to call on every startup."""
    path = db_path or DB_PATH
    if not os.path.exists(path):
        logger.info(f"DB maintenance skipped: {path} not found")
        return {}

    size_before = os.path.getsize(path)
    t0 = time.time()
    result: dict = {"path": path, "size_before_mb": round(size_before / 1048576, 1)}
    logger.info(f"DB maintenance started on {path} ({size_before / 1048576:.1f} MB)")

    conn = connect(path)
    try:
        dropped = drop_duplicate_indexes(conn)
        result["dropped_indexes"] = dropped
        if dropped:
            logger.info(f"Dropped duplicate indexes: {', '.join(dropped)}")

        stats = cleanup_orphan_results(conn)
        result.update(stats)
        if stats["orphan_raw_url"] or stats["orphan_node_id"]:
            logger.info(
                f"Deleted orphan node_proxy_results: "
                f"{stats['orphan_raw_url']} by raw_url, "
                f"{stats['orphan_node_id']} by node_id"
            )

        result["vacuumed"] = vacuum_if_needed(conn, path)

        for pragma in ("PRAGMA optimize", "PRAGMA wal_checkpoint(TRUNCATE)"):
            try:
                conn.execute(pragma)
            except Exception as e:  # pragma: no cover - best effort
                logger.warning(f"{pragma} failed: {e}")
    finally:
        conn.close()

    size_after = os.path.getsize(path)
    result["size_after_mb"] = round(size_after / 1048576, 1)
    logger.info(
        f"DB maintenance finished in {time.time() - t0:.1f}s: "
        f"{result['size_before_mb']} MB -> {result['size_after_mb']} MB"
    )
    return result


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    run_maintenance()
