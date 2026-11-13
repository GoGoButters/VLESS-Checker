"""Schema migrations for VPN Checker (stdlib sqlite3, idempotent).

v1 → v2: one global pipeline (raw_proxies / node_proxy_results /
node_proxy_state) becomes per-group pipelines. Each existing group inherits the
global settings, all sources, the current proxy pool, the results and the
per-node ban/retention state of its nodes. A backup of the v1 file is taken
first (``<db>.pre-v2``).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone

from sqlmodel import SQLModel

from proxy_parsers import get_proxy_identity, proxy_key

logger = logging.getLogger("vpn_checker.migrations")

SCHEMA_VERSION = 2
LEGACY_TABLES = (
    "raw_proxies", "node_proxy_results", "node_proxy_state",
    "subscription_test_stats", "proxy_results", "valid_proxies",
)
# Columns of v1 tables that v2 no longer uses.
LEGACY_COLUMNS = {
    "settings": (
        "ping_threshold_ms", "webhook_secret_path", "concurrent_checks_limit",
        "schedule_interval_minutes", "webhook_max_proxies", "http_timeout_s",
        "speed_test_top_n", "node_check_top_n", "global_sub_min_nodes", "global_sub_top_n",
        "webhook_min_dl_kbps", "webhook_min_ul_kbps", "webhook_rename_prefix",
        "webhook_consensus_only", "ban_duration_hours", "ban_after_n_failures",
        "good_proxy_retention_cycles", "enabled_protocols", "chunk_size",
        "geo_check_enabled", "webhook_geo_top_n",
    ),
    "subscriptions": ("stats_disabled", "disabled_signature", "disabled_at"),
    "nodes": (
        "proxies_checked", "proxies_passed", "status", "current_chunk",
        "total_chunks", "testing_generation_id", "force_test",
    ),
}
# Groups migrated from v1 keep their output unchanged: the v1 webhook always
# dropped this country in geo mode.
V1_EXCLUDED_COUNTRIES = "Украина"
NEW_PROTOCOLS_OFF_ON_MIGRATION = ("tuic", "hysteria", "anytls", "socks")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tables(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(conn, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _sql_type(col) -> str:
    name = type(col.type).__name__.lower()
    if "int" in name or "bool" in name:
        return "INTEGER"
    if "float" in name or "real" in name or "numeric" in name:
        return "REAL"
    if "binary" in name or "blob" in name:
        return "BLOB"
    return "TEXT"


def _sql_default(col) -> str:
    default = getattr(col.default, "arg", None)
    if callable(default) or default is None:
        return "NULL" if col.nullable else ("0" if _sql_type(col) in ("INTEGER", "REAL") else "''")
    if isinstance(default, bool):
        return "1" if default else "0"
    if isinstance(default, (int, float)):
        return str(default)
    return "'" + str(default).replace("'", "''") + "'"


def ensure_columns(conn) -> list[str]:
    """Add every model column missing from an existing table."""
    added = []
    existing_tables = _tables(conn)
    for table in SQLModel.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        have = _columns(conn, table.name)
        for col in table.columns:
            if col.name in have:
                continue
            conn.execute(
                f"ALTER TABLE {table.name} ADD COLUMN {col.name} {_sql_type(col)} DEFAULT {_sql_default(col)}"
            )
            added.append(f"{table.name}.{col.name}")
    return added


def prepare_legacy(path: str) -> None:
    """Back up a v1 database before anything touches its schema."""
    if not os.path.exists(path):
        return
    conn = sqlite3.connect(path, timeout=60)
    try:
        legacy = "raw_proxies" in _tables(conn) and "group_proxies" not in _tables(conn)
        if not legacy:
            return
        backup = path + ".pre-v2"
        if os.path.exists(backup):
            return
        t0 = time.time()
        dst = sqlite3.connect(backup)
        with dst:
            conn.backup(dst)
        dst.close()
        logger.info(f"Backed up v1 database to {backup} in {time.time() - t0:.1f}s")
    finally:
        conn.close()


def migrate(path: str) -> None:
    conn = sqlite3.connect(path, timeout=60, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=60000")
        conn.execute("BEGIN IMMEDIATE")
        added = ensure_columns(conn)
        if added:
            logger.info(f"Added columns: {', '.join(added)}")
        version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        version = int(version[0]) if version else 0
        migrated_v1 = False
        if version < 2 and "raw_proxies" in _tables(conn):
            _migrate_v1_to_v2(conn)
            migrated_v1 = True
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )
        conn.execute("COMMIT")
        if migrated_v1:
            _drop_legacy(conn)
            t0 = time.time()
            conn.execute("VACUUM")
            logger.info(f"VACUUM after v2 migration took {time.time() - t0:.1f}s")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def _migrate_v1_to_v2(conn) -> None:
    t0 = time.time()
    tables = _tables(conn)
    s = conn.execute("SELECT * FROM settings LIMIT 1").fetchone()
    s = dict(s) if s else {}

    protocols = {}
    try:
        protocols = json.loads(s.get("enabled_protocols") or "{}")
    except ValueError:
        pass
    for p in NEW_PROTOCOLS_OFF_ON_MIGRATION:
        protocols.setdefault(p, False)

    node_ids = {r[0] for r in conn.execute("SELECT id FROM nodes")}
    group_ids = [r[0] for r in conn.execute("SELECT id FROM rating_groups ORDER BY id")]
    sub_rows = [dict(r) for r in conn.execute("SELECT * FROM subscriptions")]

    # Links to nodes/groups that no longer exist
    dropped = conn.execute(
        "DELETE FROM node_rating_links WHERE node_id NOT IN (SELECT id FROM nodes) "
        "OR rating_group_id NOT IN (SELECT id FROM rating_groups)"
    ).rowcount
    if dropped:
        logger.info(f"Removed {dropped} dangling node↔group links")

    now = _now()
    for gid in group_ids:
        conn.execute(
            "UPDATE rating_groups SET schedule_interval_minutes=?, good_proxy_retention_cycles=?, "
            "ban_duration_hours=?, ban_after_n_failures=?, ping_threshold_ms=?, "
            "concurrent_checks_limit=?, http_timeout_s=?, speed_test_top_n=?, chunk_size=?, "
            "enabled_protocols=?, auto_add_new_sources=1, excluded_countries=?, "
            "generation_id=?, generation_at=?, last_fetch_at=?, last_fetch_status=? WHERE id=?",
            (
                int(s.get("schedule_interval_minutes") or 0),
                int(s.get("good_proxy_retention_cycles") if s.get("good_proxy_retention_cycles") is not None else 3),
                int(s.get("ban_duration_hours") if s.get("ban_duration_hours") is not None else 168),
                int(s.get("ban_after_n_failures") or 3),
                int(s.get("ping_threshold_ms") or 1000),
                int(s.get("concurrent_checks_limit") or 50),
                int(s.get("http_timeout_s") or 10),
                int(s.get("speed_test_top_n") or 0),
                int(s.get("chunk_size") or 0),
                json.dumps(protocols),
                V1_EXCLUDED_COUNTRIES,
                # last_fetch_at empty: fetch right after start to fill source snapshots
                uuid.uuid4().hex, now, "", "migrated from v1", gid,
            ),
        )
        for sub in sub_rows:
            conn.execute(
                "INSERT OR IGNORE INTO group_sources(group_id, subscription_id, stats_disabled, "
                "disabled_signature, disabled_at) VALUES(?,?,?,?,?)",
                (gid, sub["id"], int(sub.get("stats_disabled") or 0),
                 sub.get("disabled_signature") or "", sub.get("disabled_at") or ""),
            )
        if "subscription_test_stats" in tables:
            conn.execute(
                "INSERT INTO group_source_stats(group_id, subscription_id, generation_id, checked_at, tested, alive) "
                "SELECT ?, subscription_id, generation_id, checked_at, tested, alive "
                "FROM subscription_test_stats ORDER BY id",
                (gid,),
            )

    # Proxy pool: the current raw_proxies set belongs to every group
    pool: dict[str, str] = {}
    for (url,) in conn.execute("SELECT raw_url FROM raw_proxies"):
        if url:
            pool.setdefault(proxy_key(url), url)
    for gid in group_ids:
        conn.executemany(
            "INSERT OR IGNORE INTO group_proxies(group_id, key, raw_url) VALUES(?,?,?)",
            [(gid, k, u) for k, u in pool.items()],
        )
        conn.execute("UPDATE rating_groups SET pool_size=? WHERE id=?", (len(pool), gid))

    links = [
        (r[0], r[1]) for r in conn.execute("SELECT rating_group_id, node_id FROM node_rating_links")
        if r[1] in node_ids
    ]
    for gid, nid in links:
        conn.execute(
            "INSERT OR IGNORE INTO node_group_state(group_id, node_id, status, run_seq, testing_generation, "
            "current_chunk, total_chunks, completed_generation, completed_at, updated_at) "
            "VALUES(?,?,'idle',0,'',0,0,'','',?)",
            (gid, nid, now),
        )

    # Per-node ban/retention state, only what is still meaningful
    state: dict[tuple[int, str], dict] = {}
    if "node_proxy_state" in tables:
        rows = conn.execute(
            "SELECT node_id, raw_url, consecutive_failures, banned_until, retention_cycles, "
            "last_tested, last_passed FROM node_proxy_state "
            "WHERE (banned_until IS NOT NULL AND banned_until > ?) "
            "OR retention_cycles > 0 OR consecutive_failures > 0",
            (now,),
        )
        for r in rows:
            k = proxy_key(r["raw_url"])
            if r["retention_cycles"] or (r["banned_until"] and r["banned_until"] > now) or k in pool:
                state[(r["node_id"], k)] = dict(r)

    results: dict[tuple[int, str], dict] = {}
    if "node_proxy_results" in tables:
        for r in conn.execute("SELECT * FROM node_proxy_results"):
            results[(r["node_id"], proxy_key(r["raw_url"]))] = dict(r)

    batch = []
    for gid, nid in links:
        keys = {k for (n, k) in state if n == nid} | {k for (n, k) in results if n == nid}
        for k in keys:
            st = state.get((nid, k), {})
            res = results.get((nid, k), {})
            url = res.get("raw_url") or st.get("raw_url")
            passed = int(res.get("tests_passed") or 0)
            batch.append((
                gid, nid, k, url, get_proxy_identity(url) if passed > 0 else "",
                int(res.get("ping_ms") or 0), passed, int(res.get("tests_total") or 0),
                int(res.get("download_speed_kbps") or 0), int(res.get("upload_speed_kbps") or 0),
                float(res.get("speed_score") or 0.0), res.get("country_name") or "",
                res.get("last_tested") or st.get("last_tested") or "", st.get("last_passed") or "",
                int(st.get("consecutive_failures") or 0), st.get("banned_until"),
                int(st.get("retention_cycles") or 0),
            ))
    conn.executemany(
        "INSERT OR IGNORE INTO group_node_proxies(group_id, node_id, key, raw_url, ident, ping_ms, "
        "tests_passed, tests_total, download_speed_kbps, upload_speed_kbps, speed_score, country_name, "
        "last_tested, last_passed, generation_id, consecutive_failures, banned_until, retention_cycles) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'',?,?,?)",
        batch,
    )
    logger.info(
        f"Migrated v1 → v2 in {time.time() - t0:.1f}s: {len(group_ids)} groups, "
        f"{len(sub_rows)} sources, pool {len(pool)}, {len(batch)} node/proxy rows, {len(links)} links"
    )


def _drop_legacy(conn) -> None:
    tables = _tables(conn)
    for t in LEGACY_TABLES:
        if t in tables:
            conn.execute(f"DROP TABLE {t}")
    for table, cols in LEGACY_COLUMNS.items():
        have = _columns(conn, table)
        for col in cols:
            if col in have:
                try:
                    conn.execute(f"ALTER TABLE {table} DROP COLUMN {col}")
                except sqlite3.OperationalError as e:
                    logger.warning(f"Could not drop {table}.{col}: {e}")
    logger.info("Dropped v1 tables and columns")
