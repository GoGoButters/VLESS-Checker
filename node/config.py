"""Worker node settings from the environment (or node/.env)."""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class NodeConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=Path(__file__).parent / ".env", env_file_encoding="utf-8",
                                      extra="ignore")

    master_url: str = "http://127.0.0.1:8000"
    node_token: str = ""
    node_name: str = "standalone-worker"
    node_region: str = "unknown"
    # Interface for proxy traffic (e.g. an LTE modem); empty = system routing
    bind_interface: str = ""
    # Fallback when a group does not set concurrency (CONCURRENT_CHECKS_OVERRIDE caps it)
    concurrent_checks: int = 50
    poll_interval_s: int = 60


config = NodeConfig()
