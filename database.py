"""Database models and engine setup for VPN Checker."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text, event
from sqlmodel import Field, SQLModel, create_engine, Session

DATABASE_URL = "sqlite:///./data/vpn_checker.db"

# Global generation_id for chunked testing (changes on each scheduler cycle)
# Used to signal new test cycle to nodes - avoids circular import between main.py and scheduler.py
generation_id: str = str(uuid.uuid4())

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={
        "check_same_thread": False,
        "timeout": 15.0,
    },
)


# Enable WAL mode for concurrent reads/writes
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


class Subscription(SQLModel, table=True):
    __tablename__ = "subscriptions"
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True)
    added_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_enabled: bool = Field(default=True)
    last_config_count: int = Field(default=0)


class RawProxy(SQLModel, table=True):
    """Raw proxy URLs fetched from subscriptions, awaiting worker testing."""
    __tablename__ = "raw_proxies"
    id: Optional[int] = Field(default=None, primary_key=True)
    raw_url: str = Field(unique=True, index=True)
    fetched_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    banned_until: Optional[str] = Field(default=None, index=True)  # ISO timestamp or None

    consecutive_failures: int = Field(default=0)  # Consecutive check cycles failed on ALL workers

    retention_cycles: int = Field(default=0)  # How many cycles this proxy has been retained after disappearing from subscriptions


class TestUrl(SQLModel, table=True):
    """User-configurable URLs to check proxies against."""
    __tablename__ = "test_urls"
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True)
    expect_status: int = Field(default=200)
    min_body_bytes: int = Field(default=100)
    position: int = Field(default=0)


class ProxyResult(SQLModel, table=True):
    """Proxy test results. Used by workers as a data container; master reads from NodeProxyResult instead."""
    __tablename__ = "proxy_results"
    id: Optional[int] = Field(default=None, primary_key=True)
    raw_url: str = Field(default="", index=True)
    ping_ms: int = Field(default=0)
    tests_passed: int = Field(default=0)
    tests_total: int = Field(default=0)
    download_speed_kbps: int = Field(default=0)
    upload_speed_kbps: int = Field(default=0)
    speed_score: float = Field(default=0.0)
    tested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Settings(SQLModel, table=True):
    __tablename__ = "settings"
    id: Optional[int] = Field(default=None, primary_key=True)
    admin_pass_hash: str = Field(default="")
    ping_threshold_ms: int = Field(default=1000)
    webhook_secret_path: str = Field(default="secret-distrib")
    concurrent_checks_limit: int = Field(default=50)
    schedule_interval_minutes: int = Field(default=0)
    webhook_max_proxies: int = Field(default=0)
    http_timeout_s: int = Field(default=10)
    speed_test_top_n: int = Field(default=0)  # 0 = disabled
    node_api_token: str = Field(default="")
    node_check_top_n: int = Field(default=50)

    # Webhook filtering
    webhook_min_dl_kbps: int = Field(default=0)   # min download speed (KB/s), 0 = no filter
    webhook_min_ul_kbps: int = Field(default=0)   # min upload speed (KB/s), 0 = no filter
    webhook_rename_prefix: str = Field(default="")  # optional rename prefix for configs
    webhook_consensus_only: bool = Field(default=False)  # if True, return only proxies confirmed by ALL online nodes

    # Global Consensus settings
    global_sub_min_nodes: int = Field(default=1)
    global_sub_top_n: int = Field(default=50)

    # Ban settings
    ban_duration_hours: int = Field(default=168)  # 7 days = 168 hours, 0 = disabled

    ban_after_n_failures: int = Field(default=3)  # Ban after N consecutive failures on ALL workers

    # Proxy retention: remember tested proxies for N cycles after they disappear from subscriptions
    good_proxy_retention_cycles: int = Field(default=3)  # 0 = disable retention

    # Protocol filter: JSON dict with enabled protocols (e.g., {"vless":true,"vmess":true,"ss":false})
    enabled_protocols: str = Field(default='{"vless":true,"vmess":true,"trojan":true,"ss":true,"hy2":true,"hysteria2":true}')

    # Chunking: 0 = disabled (process all at once), N > 0 = process N proxies per chunk for dynamic rating updates
    chunk_size: int = Field(default=0)


class Node(SQLModel, table=True):
    """Remote checker node registration."""
    __tablename__ = "nodes"
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(default="")
    region: str = Field(default="")
    ip: str = Field(default="")
    last_heartbeat: str = Field(default="")
    is_online: bool = Field(default=False)
    proxies_checked: int = Field(default=0)
    proxies_passed: int = Field(default=0)
    registered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    # Worker-side chunking: status tracking
    status: str = Field(default="idle")            # "idle" | "testing"
    current_chunk: int = Field(default=0)          # 1-indexed: which chunk worker is testing now
    total_chunks: int = Field(default=0)           # total chunks for current test run
    testing_generation_id: str = Field(default="")  # which generation_id the worker is testing


class NodeProxyResult(SQLModel, table=True):
    """Proxy results from a specific node."""
    __tablename__ = "node_proxy_results"
    id: Optional[int] = Field(default=None, primary_key=True)
    node_id: int = Field(index=True)
    raw_url: str = Field(index=True)
    ping_ms: int = Field(default=0)
    tests_passed: int = Field(default=0)
    tests_total: int = Field(default=0)
    download_speed_kbps: int = Field(default=0)
    upload_speed_kbps: int = Field(default=0)
    speed_score: float = Field(default=0.0)
    last_tested: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def create_db_and_tables():
    """Create database tables if they don't exist."""
    import os
    os.makedirs("data", exist_ok=True)
    SQLModel.metadata.create_all(engine)
    _migrate_db()
    _seed_default_test_urls()


def _migrate_db():
    """Add new columns to existing tables if they are missing (SQLite)."""
    import sqlite3
    db_path = DATABASE_URL.replace("sqlite:///", "")
    try:
        conn = sqlite3.connect(db_path)
        
        # Settings migrations
        cursor = conn.execute("PRAGMA table_info(settings)")
        existing = {row[1] for row in cursor.fetchall()}
        settings_migrations = [
            ("schedule_interval_minutes", "INTEGER DEFAULT 0"),
            ("webhook_max_proxies", "INTEGER DEFAULT 0"),
            ("http_timeout_s", "INTEGER DEFAULT 10"),
            ("speed_test_top_n", "INTEGER DEFAULT 0"),
            ("node_api_token", "TEXT DEFAULT ''"),
            ("node_check_top_n", "INTEGER DEFAULT 50"),
            ("global_sub_min_nodes", "INTEGER DEFAULT 1"),
            ("global_sub_top_n", "INTEGER DEFAULT 50"),
            ("webhook_min_dl_kbps", "INTEGER DEFAULT 0"),
            ("webhook_min_ul_kbps", "INTEGER DEFAULT 0"),
            ("webhook_rename_prefix", "TEXT DEFAULT ''"),
            ("webhook_consensus_only", "INTEGER DEFAULT 0"),
            ("ban_duration_hours", "INTEGER DEFAULT 168"),

            ("ban_after_n_failures", "INTEGER DEFAULT 3"),
            ("good_proxy_retention_cycles", "INTEGER DEFAULT 3"),
            ("enabled_protocols", "TEXT DEFAULT '{\"vless\":true,\"vmess\":true,\"trojan\":true,\"ss\":true,\"hy2\":true,\"hysteria2\":true}'"),
            ("chunk_size", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_def in settings_migrations:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE settings ADD COLUMN {col_name} {col_def}")
        
        # Subscription migrations
        cursor = conn.execute("PRAGMA table_info(subscriptions)")
        sub_existing = {row[1] for row in cursor.fetchall()}
        if "is_enabled" not in sub_existing:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN is_enabled INTEGER DEFAULT 1")
        if "last_config_count" not in sub_existing:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN last_config_count INTEGER DEFAULT 0")
        
        # RawProxy migrations
        cursor = conn.execute("PRAGMA table_info(raw_proxies)")
        raw_existing = {row[1] for row in cursor.fetchall()}
        if "banned_until" not in raw_existing:
            conn.execute("ALTER TABLE raw_proxies ADD COLUMN banned_until TEXT DEFAULT NULL")

        if "consecutive_failures" not in raw_existing:
            conn.execute("ALTER TABLE raw_proxies ADD COLUMN consecutive_failures INTEGER DEFAULT 0")

        if "retention_cycles" not in raw_existing:
            conn.execute("ALTER TABLE raw_proxies ADD COLUMN retention_cycles INTEGER DEFAULT 0")
        
        # Node migrations (new fields for worker-side chunking status tracking)
        cursor = conn.execute("PRAGMA table_info(nodes)")
        node_existing = {row[1] for row in cursor.fetchall()}
        node_migrations = [
            ("status", "TEXT DEFAULT 'idle'"),
            ("current_chunk", "INTEGER DEFAULT 0"),
            ("total_chunks", "INTEGER DEFAULT 0"),
            ("testing_generation_id", "TEXT DEFAULT ''"),
        ]
        for col_name, col_def in node_migrations:
            if col_name not in node_existing:
                conn.execute(f"ALTER TABLE nodes ADD COLUMN {col_name} {col_def}")

        conn.commit()
        conn.close()

        # Drop legacy tables
        with engine.begin() as conn:
            try:
                conn.execute(text("DROP TABLE IF EXISTS valid_proxies"))
            except Exception:
                pass
    except Exception:
        pass


def _seed_default_test_urls():
    """Seed default test URLs if the table is empty."""
    with Session(engine) as session:
        from sqlmodel import select, func
        count = session.exec(select(func.count(TestUrl.id))).one()
        if count == 0:
            defaults = [
                TestUrl(url="https://www.gstatic.com/generate_204", expect_status=204, min_body_bytes=0, position=0),
                TestUrl(url="https://www.google.com", expect_status=200, min_body_bytes=1000, position=1),
                TestUrl(url="https://www.youtube.com", expect_status=200, min_body_bytes=1000, position=2),
            ]
            for t in defaults:
                session.add(t)
            session.commit()


def get_session():
    """Yield a database session."""
    with Session(engine) as session:
        yield session
