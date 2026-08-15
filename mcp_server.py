from fastmcp import FastMCP
from sqlmodel import Session, select, func
from typing import List, Dict, Any, Optional
import os

from database import (
    engine, Settings, Node, NodeProxyResult, Subscription, 
    RatingGroup, TestUrl, ProxyResult, RawProxy, NodeRatingLink
)

# Initialize MCP servers
mcp_ro = FastMCP("vpn_checker_ro")
mcp_admin = FastMCP("vpn_checker_admin")

# ==============================================================================
# READ-ONLY TOOLS
# ==============================================================================

@mcp_ro.tool()
@mcp_admin.tool()
def get_dashboard_stats() -> dict:
    """Get global stats for the dashboard."""
    with Session(engine) as session:
        nodes = session.exec(select(func.count(Node.id))).one()
        proxies = session.exec(select(func.count(NodeProxyResult.id))).one()
        subs = session.exec(select(func.count(Subscription.id))).one()
        raw = session.exec(select(func.count(RawProxy.id))).one()
        return {
            "total_nodes": nodes, 
            "valid_proxies": proxies, 
            "total_subscriptions": subs,
            "raw_proxies": raw
        }

@mcp_ro.tool()
@mcp_admin.tool()
def get_subscriptions() -> List[dict]:
    """Get all subscriptions."""
    with Session(engine) as session:
        return [s.model_dump() for s in session.exec(select(Subscription)).all()]

@mcp_ro.tool()
@mcp_admin.tool()
def get_rating_groups() -> List[dict]:
    """Get all rating groups."""
    with Session(engine) as session:
        return [r.model_dump() for r in session.exec(select(RatingGroup)).all()]

@mcp_ro.tool()
@mcp_admin.tool()
def get_nodes() -> List[dict]:
    """Get all registered nodes."""
    with Session(engine) as session:
        return [n.model_dump() for n in session.exec(select(Node)).all()]

@mcp_ro.tool()
@mcp_admin.tool()
def get_settings() -> dict:
    """Get current settings (excludes sensitive tokens)."""
    with Session(engine) as session:
        s = session.exec(select(Settings)).first()
        if not s: return {}
        data = s.model_dump()
        for k in ["admin_pass_hash", "mcp_read_token", "mcp_admin_token", "node_api_token"]:
            data.pop(k, None)
        return data

@mcp_ro.tool()
@mcp_admin.tool()
def get_test_urls() -> List[dict]:
    """Get test URLs."""
    with Session(engine) as session:
        return [t.model_dump() for t in session.exec(select(TestUrl)).all()]

@mcp_ro.tool()
@mcp_admin.tool()
def get_logs(lines: int = 50) -> List[str]:
    """Read the last N lines from the application log."""
    if os.path.exists("data/vpn_checker.log"):
        with open("data/vpn_checker.log", "r", encoding="utf-8") as f:
            return f.readlines()[-lines:]
    return ["Log file not found."]

@mcp_ro.tool()
@mcp_admin.tool()
def get_node_details(node_id: int) -> dict:
    """Get specific node details including its rating groups."""
    with Session(engine) as session:
        n = session.get(Node, node_id)
        if not n: return {"error": "Node not found"}
        
        links = session.exec(select(NodeRatingLink).where(NodeRatingLink.node_id == node_id)).all()
        return {
            "node": n.model_dump(),
            "rating_group_ids": [link.rating_group_id for link in links]
        }

@mcp_ro.tool()
@mcp_admin.tool()
def get_proxies(limit: int = 100) -> List[dict]:
    """Get top valid proxies."""
    with Session(engine) as session:
        results = session.exec(
            select(NodeProxyResult)
            .order_by(NodeProxyResult.tests_passed.desc(), NodeProxyResult.ping_ms.asc())
            .limit(limit)
        ).all()
        return [r.model_dump() for r in results]

# ==============================================================================
# ADMIN TOOLS
# ==============================================================================

@mcp_admin.tool()
def update_settings(updates: dict) -> str:
    """Update application settings."""
    with Session(engine) as session:
        s = session.exec(select(Settings)).first()
        if not s: return "Settings not found"
        for k, v in updates.items():
            if hasattr(s, k):
                setattr(s, k, v)
        session.add(s)
        session.commit()
        return "Settings updated"

@mcp_admin.tool()
def add_subscription(url: str, is_enabled: bool = True) -> str:
    """Add a new subscription."""
    with Session(engine) as session:
        sub = Subscription(url=url, is_enabled=is_enabled)
        session.add(sub)
        session.commit()
        return f"Subscription {url} added (id={sub.id})"

@mcp_admin.tool()
def delete_subscription(sub_id: int) -> str:
    """Delete a subscription."""
    with Session(engine) as session:
        sub = session.get(Subscription, sub_id)
        if sub:
            session.delete(sub)
            session.commit()
            return f"Deleted subscription {sub_id}"
        return "Subscription not found"

@mcp_admin.tool()
def toggle_subscription(sub_id: int, is_enabled: bool) -> str:
    """Enable or disable a subscription."""
    with Session(engine) as session:
        sub = session.get(Subscription, sub_id)
        if sub:
            sub.is_enabled = is_enabled
            session.add(sub)
            session.commit()
            return f"Subscription {sub_id} enabled={is_enabled}"
        return "Subscription not found"

@mcp_admin.tool()
def add_test_url(url: str, expect_status: int = 200, min_body_bytes: int = 100) -> str:
    """Add a new test URL."""
    with Session(engine) as session:
        t = TestUrl(url=url, expect_status=expect_status, min_body_bytes=min_body_bytes)
        session.add(t)
        session.commit()
        return f"Added test URL {url} (id={t.id})"

@mcp_admin.tool()
def delete_test_url(url_id: int) -> str:
    """Delete a test URL."""
    with Session(engine) as session:
        t = session.get(TestUrl, url_id)
        if t:
            session.delete(t)
            session.commit()
            return f"Deleted test URL {url_id}"
        return "Test URL not found"

@mcp_admin.tool()
def delete_node(node_id: int) -> str:
    """Delete a node."""
    with Session(engine) as session:
        n = session.get(Node, node_id)
        if n:
            session.delete(n)
            # Delete associated results and links
            session.exec(select(NodeProxyResult).where(NodeProxyResult.node_id == node_id))
            session.exec(select(NodeRatingLink).where(NodeRatingLink.node_id == node_id))
            session.commit()
            return f"Deleted node {node_id}"
        return "Node not found"

@mcp_admin.tool()
def create_rating_group(name: str, webhook_path: str) -> str:
    """Create a new rating group."""
    with Session(engine) as session:
        g = RatingGroup(name=name, webhook_path=webhook_path)
        session.add(g)
        session.commit()
        return f"Created rating group {name} (id={g.id})"

@mcp_admin.tool()
def delete_rating_group(group_id: int) -> str:
    """Delete a rating group."""
    with Session(engine) as session:
        g = session.get(RatingGroup, group_id)
        if g:
            session.delete(g)
            session.commit()
            return f"Deleted rating group {group_id}"
        return "Rating group not found"

@mcp_admin.tool()
def assign_node_to_rating(node_id: int, rating_group_id: int) -> str:
    """Assign a node to a rating group."""
    with Session(engine) as session:
        link = NodeRatingLink(node_id=node_id, rating_group_id=rating_group_id)
        session.add(link)
        session.commit()
        return f"Assigned node {node_id} to rating group {rating_group_id}"

@mcp_admin.tool()
def clear_all_ratings() -> str:
    """Clear all proxy results from all nodes."""
    with Session(engine) as session:
        from sqlmodel import delete
        session.exec(delete(NodeProxyResult))
        session.commit()
        return "Cleared all node proxy results"


