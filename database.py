"""Database models and async engine setup for VPN Checker."""

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel, create_engine, Session

DATABASE_URL = "sqlite:///./data/vpn_checker.db"

engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)


class Subscription(SQLModel, table=True):
    __tablename__ = "subscriptions"
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True)
    added_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ValidProxy(SQLModel, table=True):
    __tablename__ = "valid_proxies"
    id: Optional[int] = Field(default=None, primary_key=True)
    raw_vless: str = Field(unique=True, index=True)
    ping_ms: int = Field(default=0)
    tests_passed: int = Field(default=0)
    tests_total: int = Field(default=0)
    last_tested: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class TestUrl(SQLModel, table=True):
    """User-configurable URLs to check proxies against."""
    __tablename__ = "test_urls"
    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(unique=True, index=True)
    expect_status: int = Field(default=200)
    min_body_bytes: int = Field(default=100)
    position: int = Field(default=0)  # ordering


class Settings(SQLModel, table=True):
    __tablename__ = "settings"
    id: Optional[int] = Field(default=None, primary_key=True)
    admin_pass_hash: str = Field(default="")
    ping_threshold_ms: int = Field(default=1000)
    webhook_secret_path: str = Field(default="secret-distrib")
    concurrent_checks_limit: int = Field(default=50)
    schedule_interval_minutes: int = Field(default=0)  # 0 = disabled
    webhook_max_proxies: int = Field(default=0)  # 0 = unlimited
    http_timeout_s: int = Field(default=10)  # timeout for HTTP checks


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
        ]
        for col_name, col_def in settings_migrations:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE settings ADD COLUMN {col_name} {col_def}")

        # ValidProxy migrations
        cursor = conn.execute("PRAGMA table_info(valid_proxies)")
        existing = {row[1] for row in cursor.fetchall()}
        proxy_migrations = [
            ("tests_passed", "INTEGER DEFAULT 0"),
            ("tests_total", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_def in proxy_migrations:
            if col_name not in existing:
                conn.execute(f"ALTER TABLE valid_proxies ADD COLUMN {col_name} {col_def}")

        conn.commit()
        conn.close()
    except Exception:
        pass  # table doesn't exist yet — create_all will handle it


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
