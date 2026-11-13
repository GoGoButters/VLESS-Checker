"""Database models and engine setup for VPN Checker.

Every rating group is an isolated pipeline: its own sources, proxy pool,
schedule, ban/retention policy and worker test parameters. Results live in
``group_node_proxies`` — one row per (group, node, proxy) holding both the last
test result and that node's ban/retention state for the proxy.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from sqlalchemy import Index, LargeBinary, event, text
from sqlmodel import Field, SQLModel, UniqueConstraint, create_engine
from sqlmodel import Session as _SQLModelSession

logger = logging.getLogger("vpn_checker.database")

DB_PATH = os.environ.get("VPN_DB_PATH", "data/vpn_checker.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

PROTOCOLS = ("vless", "vmess", "trojan", "ss", "hy2", "hysteria2", "tuic", "hysteria", "anytls", "socks")
DEFAULT_PROTOCOLS = {p: True for p in PROTOCOLS}

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False, "timeout": 30.0},
    # Every connection keeps its own page cache (cache_size below): 20 x 4 MB
    # stays well inside the container limit even under a burst of requests.
    pool_size=5,
    max_overflow=15,
    pool_pre_ping=True,
    pool_recycle=1800,
    pool_timeout=60,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA wal_autocheckpoint=1000")
    cursor.execute("PRAGMA journal_size_limit=67108864")  # 64MB max WAL size
    # The page cache is per connection and charged to the container cgroup.
    cursor.execute("PRAGMA cache_size=-4000")  # 4MB
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.close()


class Session(_SQLModelSession):
    """Session whose objects stay readable after commit (no lazy refresh of
    expired attributes on detached instances)."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("expire_on_commit", False)
        super().__init__(*args, **kwargs)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Meta(SQLModel, table=True):
    __tablename__ = "meta"
    key: str = Field(primary_key=True)
    value: str = Field(default="")


class Subscription(SQLModel, table=True):
    """Global source catalog; groups pick from it via GroupSource."""
    __tablename__ = "subscriptions"
    id: int | None = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True)
    added_at: str = Field(default_factory=utcnow)
    is_enabled: bool = Field(default=True)
    last_config_count: int = Field(default=0)
    last_fetch_at: str = Field(default="")
    last_fetch_ok: bool = Field(default=False)
    last_error: str = Field(default="")


class SourceSnapshot(SQLModel, table=True):
    """Last successful fetch of a source: zlib-compressed newline-joined links.

    A failed fetch keeps the previous snapshot, so a flaky mirror never empties
    the pools of the groups that use it.
    """
    __tablename__ = "source_snapshots"
    subscription_id: int = Field(primary_key=True)
    links: bytes = Field(default=b"", sa_type=LargeBinary)
    count: int = Field(default=0)
    signature: str = Field(default="")
    fetched_at: str = Field(default="")


class TestUrl(SQLModel, table=True):
    """URLs every proxy is checked against (shared by all groups)."""
    __tablename__ = "test_urls"
    id: int | None = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True)
    expect_status: int = Field(default=200)
    min_body_bytes: int = Field(default=100)
    position: int = Field(default=0)


class RatingGroup(SQLModel, table=True):
    """A rating group: nodes + sources + policy → its own webhook."""
    __tablename__ = "rating_groups"
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(default="", index=True)
    webhook_path: str = Field(default="", unique=True)
    created_at: str = Field(default_factory=utcnow)

    # Webhook output
    max_proxies: int = Field(default=0)        # 0 = unlimited
    min_dl_kbps: int = Field(default=0)
    min_ul_kbps: int = Field(default=0)
    rename_prefix: str = Field(default="")
    consensus_only: bool = Field(default=False)
    geo_check_enabled: bool = Field(default=False)
    geo_top_n: int = Field(default=1)
    excluded_countries: str = Field(default="")  # comma-separated country names

    # Sources
    auto_add_new_sources: bool = Field(default=True)
    enabled_protocols: str = Field(default=json.dumps(DEFAULT_PROTOCOLS))

    # Auto-fetch scheduler (0 = manual only)
    schedule_interval_minutes: int = Field(default=0)

    # Proxy retention / ban management (per node inside the group)
    good_proxy_retention_cycles: int = Field(default=3)
    ban_duration_hours: int = Field(default=168)    # 0 = bans disabled
    ban_after_n_failures: int = Field(default=3)

    # Worker test parameters
    ping_threshold_ms: int = Field(default=1000)
    concurrent_checks_limit: int = Field(default=50)
    http_timeout_s: int = Field(default=10)
    speed_test_top_n: int = Field(default=0)
    chunk_size: int = Field(default=0)

    # Pipeline state (persisted: survives panel restarts)
    generation_id: str = Field(default="")
    generation_at: str = Field(default="")
    last_fetch_at: str = Field(default="")
    last_fetch_status: str = Field(default="")
    pool_size: int = Field(default=0)

    def protocols(self) -> dict:
        try:
            data = json.loads(self.enabled_protocols or "{}")
        except (TypeError, ValueError):
            data = {}
        return {p: bool(data.get(p, True)) for p in PROTOCOLS}

    def excluded_country_set(self) -> set[str]:
        return {c.strip().lower() for c in (self.excluded_countries or "").split(",") if c.strip()}


class GroupSource(SQLModel, table=True):
    """Source selected for a group, with the group's own dead-source autoskip."""
    __tablename__ = "group_sources"
    __table_args__ = (UniqueConstraint("group_id", "subscription_id", name="uq_group_source"),)
    id: int | None = Field(default=None, primary_key=True)
    group_id: int = Field(index=True)
    subscription_id: int = Field(index=True)
    stats_disabled: bool = Field(default=False)
    disabled_signature: str = Field(default="")
    disabled_at: str = Field(default="")


class GroupSourceStat(SQLModel, table=True):
    """One sample per (group, source) and fetch cycle: how many of the source's
    proxies were tested by the group's nodes and how many of them were alive."""
    __tablename__ = "group_source_stats"
    __table_args__ = (Index("ix_gss_group_sub", "group_id", "subscription_id", "id"),)
    id: int | None = Field(default=None, primary_key=True)
    group_id: int
    subscription_id: int
    generation_id: str = Field(default="")
    checked_at: str = Field(default_factory=utcnow)
    tested: int = Field(default=0)
    alive: int = Field(default=0)


class GroupProxy(SQLModel, table=True):
    """The group's proxy pool built from its sources (updated by diff)."""
    __tablename__ = "group_proxies"
    __table_args__ = (UniqueConstraint("group_id", "key", name="uq_group_proxy"),)
    id: int | None = Field(default=None, primary_key=True)
    group_id: int
    key: str
    raw_url: str


class GroupNodeProxy(SQLModel, table=True):
    """Last result + ban/retention state of one proxy on one node in one group."""
    __tablename__ = "group_node_proxies"
    __table_args__ = (
        UniqueConstraint("group_id", "node_id", "key", name="uq_group_node_proxy"),
        Index("ix_gnp_passing", "group_id", "node_id", sqlite_where=text("tests_passed > 0")),
    )
    id: int | None = Field(default=None, primary_key=True)
    group_id: int
    node_id: int = Field(index=True)
    key: str
    raw_url: str
    ident: str = Field(default="")
    ping_ms: int = Field(default=0)
    tests_passed: int = Field(default=0)
    tests_total: int = Field(default=0)
    download_speed_kbps: int = Field(default=0)
    upload_speed_kbps: int = Field(default=0)
    speed_score: float = Field(default=0.0)
    country_name: str = Field(default="")
    last_tested: str = Field(default="")
    last_passed: str = Field(default="")
    generation_id: str = Field(default="")
    consecutive_failures: int = Field(default=0)
    banned_until: str | None = Field(default=None)
    retention_cycles: int = Field(default=0)


class NodeGroupState(SQLModel, table=True):
    """Progress of one node on one group's current generation."""
    __tablename__ = "node_group_state"
    __table_args__ = (UniqueConstraint("group_id", "node_id", name="uq_node_group_state"),)
    id: int | None = Field(default=None, primary_key=True)
    group_id: int
    node_id: int = Field(index=True)
    status: str = Field(default="idle")          # idle | testing
    run_seq: int = Field(default=0)              # bumped by "Run test" on a node
    testing_generation: str = Field(default="")
    current_chunk: int = Field(default=0)
    total_chunks: int = Field(default=0)
    completed_generation: str = Field(default="")
    completed_at: str = Field(default="")
    updated_at: str = Field(default="")


class Settings(SQLModel, table=True):
    """Panel-wide settings. Pipeline parameters live on RatingGroup."""
    __tablename__ = "settings"
    id: int | None = Field(default=None, primary_key=True)
    admin_pass_hash: str = Field(default="")
    node_api_token: str = Field(default="")
    node_log_level: str = Field(default="info")  # debug|info|warning|error|off
    mcp_read_token: str = Field(default="")
    mcp_admin_token: str = Field(default="")


class Node(SQLModel, table=True):
    """Remote checker node registration."""
    __tablename__ = "nodes"
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(default="")
    region: str = Field(default="")
    ip: str = Field(default="")
    instance_id: str = Field(default="")
    protocol: int = Field(default=1)     # 1 = legacy worker, 2 = jobs API
    last_heartbeat: str = Field(default="")
    is_online: bool = Field(default=False)
    registered_at: str = Field(default_factory=utcnow)


class NodeRatingLink(SQLModel, table=True):
    """Many-to-many link between nodes and rating groups."""
    __tablename__ = "node_rating_links"
    __table_args__ = (UniqueConstraint("node_id", "rating_group_id", name="uq_node_rating"),)
    id: int | None = Field(default=None, primary_key=True)
    node_id: int = Field(index=True)
    rating_group_id: int = Field(index=True)


def effective_generation(group_generation: str, run_seq: int) -> str:
    """Generation a node works on: the group's fetch generation plus the node's
    manual re-test counter, so "Run test" re-tests without refetching sources."""
    return f"{group_generation}.{run_seq}" if group_generation else ""


def create_db_and_tables():
    """Create tables, migrate older schemas and seed defaults."""
    import migrations

    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    migrations.prepare_legacy(DB_PATH)
    SQLModel.metadata.create_all(engine)
    migrations.migrate(DB_PATH)


def get_meta(session: Session, key: str, default: str = "") -> str:
    row = session.get(Meta, key)
    return row.value if row else default


def set_meta(session: Session, key: str, value: str) -> None:
    row = session.get(Meta, key) or Meta(key=key)
    row.value = value
    session.add(row)
