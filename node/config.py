import os
from pathlib import Path

from pydantic_settings import BaseSettings


class NodeConfig(BaseSettings):
    master_url: str = "http://127.0.0.1:8000"
    node_token: str = "default_token_change_me"
    node_name: str = "standalone-worker"
    node_region: str = "unknown"

    singbox_path: str = "/usr/local/bin/sing-box"
    singbox_port: int = 2080

    concurrent_checks: int = 50
    http_timeout_s: int = 15
    ping_threshold_ms: int = 1500

    poll_interval_s: int = 60

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._load_env_file()

    def _load_env_file(self):
        env_path = Path(__file__).parent / ".env"
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key and value and not os.environ.get(key):
                            os.environ[key] = value


config = NodeConfig()
