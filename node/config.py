from pydantic_settings import BaseSettings

class NodeConfig(BaseSettings):
    master_url: str = "http://127.0.0.1:8000"
    node_token: str = "default_token_change_me"
    node_name: str = "us-east-worker-1"
    node_region: str = "USA"

    singbox_path: str = "/usr/local/bin/sing-box"
    singbox_port: int = 2080

    concurrent_checks: int = 50
    http_timeout_s: int = 15
    ping_threshold_ms: int = 1500

    poll_interval_s: int = 60

    class Config:
        env_file = ".env"

config = NodeConfig()
