"""MCP servers: read-only (/mcp/read) and admin (/mcp/admin).

Tools are async wrappers around blocking SQLite helpers run in a worker
thread, so an agent call never stalls the panel's event loop.
"""
from __future__ import annotations

import functools
import json
from typing import Any

import anyio
from fastmcp import FastMCP
from sqlalchemy import text
from sqlmodel import func, select

import pipeline
import rating
from database import (
    Session,
    PROTOCOLS, GroupSource, Node, NodeRatingLink, RatingGroup, Settings, Subscription, TestUrl, engine,
)
from log_buffer import log_buffer

mcp_ro = FastMCP("vpn_checker_ro")
mcp_admin = FastMCP("vpn_checker_admin")

GROUP_FIELDS = {
    "name", "webhook_path", "max_proxies", "min_dl_kbps", "min_ul_kbps", "rename_prefix", "consensus_only",
    "geo_check_enabled", "geo_top_n", "excluded_countries", "auto_add_new_sources", "enabled_protocols",
    "schedule_interval_minutes", "good_proxy_retention_cycles", "ban_duration_hours", "ban_after_n_failures",
    "ping_threshold_ms", "concurrent_checks_limit", "http_timeout_s", "speed_test_top_n", "chunk_size",
}


def _tool(*servers):
    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))
        for srv in servers:
            srv.tool()(wrapper)
        return fn
    return deco


read_tool = _tool(mcp_ro, mcp_admin)
admin_tool = _tool(mcp_admin)


def _group_dict(s: Session, g: RatingGroup) -> dict:
    d = g.model_dump()
    d["protocols"] = g.protocols()
    d["source_ids"] = [gs.subscription_id for gs in s.exec(select(GroupSource).where(GroupSource.group_id == g.id))]
    d["skipped_source_ids"] = [gs.subscription_id for gs in s.exec(
        select(GroupSource).where(GroupSource.group_id == g.id, GroupSource.stats_disabled == True))]  # noqa: E712
    d["node_ids"] = [link.node_id for link in s.exec(select(NodeRatingLink).where(NodeRatingLink.rating_group_id == g.id))]
    d.pop("enabled_protocols", None)
    return d


# ==============================================================================
# read-only
# ==============================================================================
@read_tool
def get_dashboard_stats() -> dict:
    """Totals: sources, nodes, groups with pool sizes and rating sizes."""
    with Session(engine) as s:
        groups = s.exec(select(RatingGroup)).all()
        return {
            "total_subscriptions": s.exec(select(func.count(Subscription.id))).one(),
            "total_nodes": s.exec(select(func.count(Node.id))).one(),
            "online_nodes": s.exec(select(func.count(Node.id)).where(Node.is_online == True)).one(),  # noqa: E712
            "groups": [{"id": g.id, "name": g.name, "pool_size": g.pool_size,
                        "valid_proxies": len(rating.get_rating(g.id))} for g in groups],
            "pipeline": dict(pipeline.status),
        }


@read_tool
def get_subscriptions() -> list[dict]:
    """All sources with their last fetch result and the groups that use them."""
    with Session(engine) as s:
        subs = [x.model_dump() for x in s.exec(select(Subscription)).all()]
        usage: dict[int, list[int]] = {}
        for gs in s.exec(select(GroupSource)).all():
            usage.setdefault(gs.subscription_id, []).append(gs.group_id)
    for sub in subs:
        sub["group_ids"] = usage.get(sub["id"], [])
    return subs


@read_tool
def get_rating_groups() -> list[dict]:
    """Rating groups with all their settings, selected sources and nodes."""
    with Session(engine) as s:
        return [_group_dict(s, g) for g in s.exec(select(RatingGroup).order_by(RatingGroup.id)).all()]


@read_tool
def get_group_rating(group_id: int, limit: int = 100) -> list[dict]:
    """The group's current rating (what its webhook serves, before renaming)."""
    return rating.get_rating(group_id)[:max(1, limit)]


@read_tool
def get_proxies(limit: int = 100, group_id: int = 0) -> list[dict]:
    """Top proxies of a group (default: the first group)."""
    if not group_id:
        with Session(engine) as s:
            first = s.exec(select(RatingGroup.id).order_by(RatingGroup.id)).first()
        group_id = first or 0
    return rating.get_rating(group_id)[:max(1, limit)] if group_id else []


@read_tool
def get_nodes() -> list[dict]:
    """Registered nodes with their group assignments."""
    with Session(engine) as s:
        nodes = [n.model_dump(exclude={"instance_id"}) for n in s.exec(select(Node)).all()]
        links: dict[int, list[int]] = {}
        for link in s.exec(select(NodeRatingLink)).all():
            links.setdefault(link.node_id, []).append(link.rating_group_id)
    for n in nodes:
        n["group_ids"] = links.get(n["id"], [])
    return nodes


@read_tool
def get_node_details(node_id: int) -> dict:
    """A node, its groups and its progress / bans per group."""
    with Session(engine) as s:
        n = s.get(Node, node_id)
        if not n:
            return {"error": "Node not found"}
        rows = s.exec(text(
            "SELECT st.group_id, st.status, st.current_chunk, st.total_chunks, st.completed_generation, "
            "st.completed_at, (SELECT COUNT(*) FROM group_node_proxies p WHERE p.group_id = st.group_id "
            " AND p.node_id = st.node_id AND p.tests_passed > 0 AND p.ping_ms > 0), "
            "(SELECT COUNT(*) FROM group_node_proxies p WHERE p.group_id = st.group_id AND p.node_id = st.node_id "
            " AND p.banned_until > datetime('now')) FROM node_group_state st WHERE st.node_id = :n"
        ).bindparams(n=node_id)).all()
        return {"node": n.model_dump(exclude={"instance_id"}), "groups": [
            {"group_id": r[0], "status": r[1], "current_chunk": r[2], "total_chunks": r[3],
             "completed_generation": r[4], "completed_at": r[5], "passed": r[6], "banned": r[7]} for r in rows]}


@read_tool
def get_settings() -> dict:
    """Panel-wide settings (secrets excluded)."""
    with Session(engine) as s:
        st = s.exec(select(Settings)).first()
        return st.model_dump(exclude={"admin_pass_hash", "mcp_read_token", "mcp_admin_token", "node_api_token"}) if st else {}


@read_tool
def get_test_urls() -> list[dict]:
    """Test URLs every proxy is checked against."""
    with Session(engine) as s:
        return [x.model_dump() for x in s.exec(select(TestUrl).order_by(TestUrl.position)).all()]


@read_tool
def get_logs(lines: int = 50) -> list[str]:
    """The last N log lines of the panel and its nodes."""
    entries = log_buffer.get_all()[-max(1, min(lines, 1000)):]
    return [f"{e.get('timestamp')} [{e.get('logger')}] {e.get('level')}: {e.get('message')}" for e in entries]


# ==============================================================================
# admin
# ==============================================================================
@admin_tool
def update_settings(updates: dict[str, Any]) -> str:
    """Update panel-wide settings. Allowed: node_log_level (debug|info|warning|error|off)."""
    level = updates.get("node_log_level")
    if level not in ("debug", "info", "warning", "error", "off"):
        return "Only node_log_level (debug|info|warning|error|off) can be changed here; group settings via update_rating_group"
    with Session(engine) as s:
        st = s.exec(select(Settings)).first()
        st.node_log_level = level
        s.add(st)
        s.commit()
    return "Settings updated"


@admin_tool
def create_rating_group(name: str, webhook_path: str, all_sources: bool = True) -> str:
    """Create a rating group (all sources selected by default). Tune it with update_rating_group."""
    with Session(engine) as s:
        if s.exec(select(RatingGroup).where(RatingGroup.webhook_path == webhook_path)).first():
            return "webhook_path already used"
        g = RatingGroup(name=name, webhook_path=webhook_path.strip("/"))
        s.add(g)
        s.flush()
        if all_sources:
            pipeline.set_group_sources(s, g.id, {i for (i,) in s.exec(text("SELECT id FROM subscriptions")).all()})
        s.commit()
        gid = g.id
    pipeline.request_cycle([gid], fetch=True)
    return f"Created rating group {name} (id={gid})"


@admin_tool
def update_rating_group(group_id: int, updates: dict[str, Any]) -> str:
    """Change group settings. Fields: name, webhook_path, max_proxies, min_dl_kbps, min_ul_kbps, rename_prefix,
    consensus_only, geo_check_enabled, geo_top_n, excluded_countries, auto_add_new_sources,
    enabled_protocols ({protocol: bool}), schedule_interval_minutes, good_proxy_retention_cycles,
    ban_duration_hours, ban_after_n_failures, ping_threshold_ms, concurrent_checks_limit, http_timeout_s,
    speed_test_top_n, chunk_size."""
    unknown = set(updates) - GROUP_FIELDS
    if unknown:
        return f"Unknown fields: {sorted(unknown)}"
    with Session(engine) as s:
        g = s.get(RatingGroup, group_id)
        if not g:
            return "Rating group not found"
        rebuild = False
        for k, v in updates.items():
            if k == "enabled_protocols":
                v = json.dumps({p: bool((v or {}).get(p, False)) for p in PROTOCOLS})
                rebuild = True
            setattr(g, k, v)
        s.add(g)
        s.commit()
    rating.invalidate(group_id)
    if rebuild:
        pipeline.request_cycle([group_id], fetch=False)
    return "Rating group updated"


@admin_tool
def set_group_sources(group_id: int, source_ids: list[int]) -> str:
    """Select exactly these sources for a group (the pool is rebuilt from snapshots)."""
    with Session(engine) as s:
        if not s.get(RatingGroup, group_id):
            return "Rating group not found"
        valid = {i for (i,) in s.exec(text("SELECT id FROM subscriptions")).all()}
        changed = pipeline.set_group_sources(s, group_id, set(source_ids) & valid)
        s.commit()
    if changed:
        pipeline.request_cycle([group_id], fetch=False)
    return "Sources updated" if changed else "No change"


@admin_tool
def fetch_group(group_id: int) -> str:
    """Fetch the group's sources now and start a new test generation."""
    pipeline.request_cycle([group_id], fetch=True)
    return "Queued"


@admin_tool
def delete_rating_group(group_id: int) -> str:
    """Delete a rating group with all its data."""
    with Session(engine) as s:
        g = s.get(RatingGroup, group_id)
        if not g:
            return "Rating group not found"
        pipeline.delete_group_data(s, group_id)
        s.delete(g)
        s.commit()
    rating.invalidate(group_id)
    return f"Deleted rating group {group_id}"


@admin_tool
def assign_node_to_rating(node_id: int, rating_group_id: int) -> str:
    """Add a node to a rating group."""
    with Session(engine) as s:
        if not (s.get(Node, node_id) and s.get(RatingGroup, rating_group_id)):
            return "Node or group not found"
        pipeline.link_node(s, rating_group_id, node_id)
        s.commit()
    rating.invalidate(rating_group_id)
    return f"Assigned node {node_id} to rating group {rating_group_id}"


@admin_tool
def remove_node_from_rating(node_id: int, rating_group_id: int) -> str:
    """Remove a node from a rating group (its results there are dropped)."""
    with Session(engine) as s:
        pipeline.unlink_node(s, rating_group_id, node_id)
        s.commit()
    rating.invalidate(rating_group_id)
    return "Removed"


@admin_tool
def add_subscription(url: str, is_enabled: bool = True) -> str:
    """Add a source; groups with auto_add_new_sources get it automatically."""
    with Session(engine) as s:
        if s.exec(select(Subscription).where(Subscription.url == url)).first():
            return "Already exists"
        sub = Subscription(url=url, is_enabled=is_enabled)
        s.add(sub)
        s.flush()
        gids = pipeline.add_source_to_auto_groups(s, sub.id)
        s.commit()
        return f"Subscription {url} added (id={sub.id}), groups: {gids}"


@admin_tool
def delete_subscription(sub_id: int) -> str:
    """Delete a source from the catalog and from every group."""
    with Session(engine) as s:
        sub = s.get(Subscription, sub_id)
        if not sub:
            return "Subscription not found"
        pipeline.delete_source_data(s, sub_id)
        s.delete(sub)
        s.commit()
    return f"Deleted subscription {sub_id}"


@admin_tool
def toggle_subscription(sub_id: int, is_enabled: bool) -> str:
    """Enable or disable a source globally."""
    with Session(engine) as s:
        sub = s.get(Subscription, sub_id)
        if not sub:
            return "Subscription not found"
        sub.is_enabled = is_enabled
        s.add(sub)
        s.commit()
    return f"Subscription {sub_id} enabled={is_enabled}"


@admin_tool
def add_test_url(url: str, expect_status: int = 200, min_body_bytes: int = 100) -> str:
    """Add a test URL (shared by all groups)."""
    with Session(engine) as s:
        if s.exec(select(TestUrl).where(TestUrl.url == url)).first():
            return "Already exists"
        pos = (s.exec(select(func.max(TestUrl.position))).one() or 0) + 1
        tu = TestUrl(url=url, expect_status=expect_status, min_body_bytes=max(0, min_body_bytes), position=pos)
        s.add(tu)
        s.commit()
        return f"Added test URL {url} (id={tu.id})"


@admin_tool
def delete_test_url(url_id: int) -> str:
    """Delete a test URL."""
    with Session(engine) as s:
        tu = s.get(TestUrl, url_id)
        if not tu:
            return "Test URL not found"
        s.delete(tu)
        s.commit()
        return f"Deleted test URL {url_id}"


@admin_tool
def delete_node(node_id: int) -> str:
    """Delete a node with its results and group links."""
    with Session(engine) as s:
        n = s.get(Node, node_id)
        if not n:
            return "Node not found"
        pipeline.delete_node_data(s, node_id)
        s.delete(n)
        s.commit()
    rating.invalidate_all()
    return f"Deleted node {node_id}"


@admin_tool
def clear_all_ratings(group_id: int = 0) -> str:
    """Drop test results (one group, or all groups when group_id=0). Bans are kept."""
    with Session(engine) as s:
        where = "WHERE group_id = :g" if group_id else ""
        s.exec(text(f"UPDATE group_node_proxies SET tests_passed = 0, ping_ms = 0, generation_id = '' {where}")
               .bindparams(**({"g": group_id} if group_id else {})))
        s.commit()
    rating.invalidate_all()
    return "Cleared"
