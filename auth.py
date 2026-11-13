"""Cookie-based admin authentication."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

logger = logging.getLogger("vpn_checker.auth")

SESSION_COOKIE = "vpn_session"
SESSION_MAX_AGE = 86400  # 24 hours
SECRET_FILE = os.path.join(os.path.dirname(os.environ.get("VPN_DB_PATH", "data/vpn_checker.db")) or ".", "secret_key")


def _load_secret() -> str:
    """VPN_CHECKER_SECRET_KEY, else a random key generated once and kept next
    to the database (a hard-coded default would let anyone forge sessions)."""
    env = os.environ.get("VPN_CHECKER_SECRET_KEY")
    if env:
        return env
    try:
        with open(SECRET_FILE, encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    except FileNotFoundError:
        pass
    key = secrets.token_urlsafe(48)
    os.makedirs(os.path.dirname(SECRET_FILE) or ".", exist_ok=True)
    fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(key)
    logger.info(f"Generated a session secret in {SECRET_FILE}")
    return key


serializer = URLSafeTimedSerializer(_load_secret())


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256: salt$iterations$hash."""
    salt = secrets.token_hex(16)
    iterations = 200_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"{salt}${iterations}${dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """Accepts PBKDF2 (salt$iterations$hash) and the legacy salt$sha256 format."""
    try:
        parts = hashed.split("$")
        if len(parts) == 3:
            salt, iterations, stored = parts
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
            return hmac.compare_digest(dk.hex(), stored)
        if len(parts) == 2:
            salt, stored = parts
            return hmac.compare_digest(hashlib.sha256((salt + password).encode()).hexdigest(), stored)
    except (ValueError, AttributeError):
        pass
    return False


def create_session_token(username: str) -> str:
    return serializer.dumps({"user": username})


def get_current_user(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        return serializer.loads(token, max_age=SESSION_MAX_AGE).get("user")
    except (BadSignature, SignatureExpired):
        return None
