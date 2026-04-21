"""Database models and engine setup for VPN Checker."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text, event
from sqlmodel import Field, SQLModel, create_engine, Session

DATABASE_URL = "sqlite:///./data/vpn_checker.db"

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


class RawProxy(SQLModel, table=True):
    """Raw proxy URLs fetched from subscriptions, awaiting worker testing."""
    __tablename__ = "raw_proxies"
    id: Optional[int] = Field(default=None, primary_key=True)
    raw_url: str = Field(unique=True, index=True)
    fetched_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TestUrl(SQLModel, table=True):
    """User-configurable URLs to check proxies against."""
    __tablename__ = "test_urls"
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True)
    expect_status: int = Field(default=200)
    min_body_bytes: int = Field(default=100)
    position: int = Field(default=0)


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

    # Global Consensus settings
    global_sub_min_nodes: int = Field(default=1)
    global_sub_top_n: int = Field(default=50)


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
        ]
        for col_name, col_def in settings_migrations:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE settings ADD COLUMN {col_name} {col_def}")

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
