"""Group rating: one computation shared by the Ratings page, webhooks and MCP.

Results are aggregated per proxy identity over the group's online nodes (best
row per node, then averages). Computed lazily and cached per group: recomputed
when new results arrived (but at most every MIN_RECOMPUTE_S) or after MAX_AGE_S,
so a busy public webhook costs one dict lookup instead of a table scan.
"""
from __future__ import annotations

import threading
import time

from sqlalchemy import text

from database import Session, RatingGroup, engine
from proxy_parsers import get_proxy_identity, replace_proxy_remark

MIN_RECOMPUTE_S = 15
MAX_AGE_S = 300

_lock = threading.Lock()
_versions: dict[int, int] = {}
_cache: dict[int, tuple[int, float, list[dict]]] = {}   # gid → (version, computed_at, rows)
_compute_locks: dict[int, threading.Lock] = {}


def invalidate(gid: int) -> None:
    with _lock:
        _versions[gid] = _versions.get(gid, 0) + 1


def invalidate_all() -> None:
    with _lock:
        for gid in list(_versions) + list(_cache):
            _versions[gid] = _versions.get(gid, 0) + 1


def _compute(gid: int) -> list[dict]:
    with Session(engine) as s:
        group = s.get(RatingGroup, gid)
        if not group:
            return []
        node_ids = [nid for (nid,) in s.exec(text(
            "SELECT l.node_id FROM node_rating_links l JOIN nodes n ON n.id = l.node_id "
            "WHERE l.rating_group_id = :g AND n.is_online = 1").bindparams(g=gid)).all()]
        if not node_ids:
            return []
        rows = s.exec(text(
            "SELECT node_id, raw_url, ident, key, ping_ms, tests_passed, tests_total, download_speed_kbps, "
            "upload_speed_kbps, speed_score, country_name, last_tested FROM group_node_proxies "
            f"WHERE group_id = :g AND tests_passed > 0 AND ping_ms > 0 AND node_id IN ({','.join(map(str, node_ids))})"
        ).bindparams(g=gid)).all()
        policy = {
            "consensus": group.consensus_only, "min_dl": group.min_dl_kbps or 0,
            "min_ul": group.min_ul_kbps or 0, "geo": group.geo_check_enabled,
            "geo_top_n": max(1, group.geo_top_n or 1), "max": group.max_proxies or 0,
            "excluded": group.excluded_country_set(),
        }

    best: dict[str, dict[int, tuple]] = {}
    for r in rows:
        pid = r[2] or get_proxy_identity(r[1]) or r[3]
        per_node = best.setdefault(pid, {})
        cur = per_node.get(r[0])
        if cur is None or r[9] > cur[9]:
            per_node[r[0]] = r

    out = []
    for pid, per_node in best.items():
        nc = len(per_node)
        if policy["consensus"] and nc < len(node_ids):
            continue
        rs = list(per_node.values())
        avg_dl = sum(r[7] for r in rs) // nc
        avg_ul = sum(r[8] for r in rs) // nc
        if (policy["min_dl"] and avg_dl < policy["min_dl"]) or (policy["min_ul"] and avg_ul < policy["min_ul"]):
            continue
        top = max(rs, key=lambda r: r[9])
        out.append({
            "pid": pid, "raw_url": top[1], "node_count": nc,
            "avg_speed_score": round(sum(r[9] for r in rs) / nc, 1),
            "avg_tests_passed": sum(r[5] for r in rs) // nc,
            "tests_total": max(r[6] for r in rs),
            "best_ping_ms": min(r[4] for r in rs),
            "avg_dl_kbps": avg_dl, "avg_ul_kbps": avg_ul,
            "last_tested": max(r[11] for r in rs),
            "country_name": (top[10] or "").strip(),
        })

    if policy["geo"]:
        by_country: dict[str, list[dict]] = {}
        for p in out:
            c = p["country_name"]
            if not c or c.lower() == "unknown" or c.lower() in policy["excluded"]:
                continue
            by_country.setdefault(c, []).append(p)
        out = []
        for items in by_country.values():
            items.sort(key=lambda x: x["avg_speed_score"], reverse=True)
            out.extend(items[:policy["geo_top_n"]])
    elif policy["excluded"]:
        out = [p for p in out if p["country_name"].lower() not in policy["excluded"]]

    out.sort(key=lambda x: (-x["node_count"], -x["avg_speed_score"]))
    if policy["max"]:
        out = out[:policy["max"]]
    return out


def get_rating(gid: int) -> list[dict]:
    """Cached rating rows of a group (see module docstring)."""
    now = time.monotonic()
    with _lock:
        version = _versions.get(gid, 0)
        cached = _cache.get(gid)
        lock = _compute_locks.setdefault(gid, threading.Lock())
    if cached and (cached[0] == version or now - cached[1] < MIN_RECOMPUTE_S) and now - cached[1] < MAX_AGE_S:
        return cached[2]
    with lock:  # one computation per group at a time; others reuse its result
        with _lock:
            cached = _cache.get(gid)
            version = _versions.get(gid, 0)
        if cached and cached[0] == version and time.monotonic() - cached[1] < MAX_AGE_S:
            return cached[2]
        rows = _compute(gid)
        with _lock:
            _cache[gid] = (version, time.monotonic(), rows)
        return rows


def webhook_text(group: RatingGroup) -> str:
    """Subscription body served on the group's webhook path."""
    rows = get_rating(group.id)
    prefix = (group.rename_prefix or "").strip()
    lines = []
    if group.geo_check_enabled:
        counters: dict[str, int] = {}
        multi = (group.geo_top_n or 1) > 1
        for p in rows:
            country = p["country_name"]
            counters[country] = counters.get(country, 0) + 1
            lines.append(replace_proxy_remark(p["raw_url"], f"{country} {counters[country]}" if multi else country))
    else:
        for i, p in enumerate(rows, start=1):
            lines.append(replace_proxy_remark(p["raw_url"], f"{prefix} - {i}") if prefix else p["raw_url"])
    return "\n".join(lines)

