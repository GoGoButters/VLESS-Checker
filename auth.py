"""Simple cookie-based authentication for VPN Checker."""

import hashlib
import hmac
import secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException

SECRET_KEY = "vpn-checker-secret-key-change-me-in-production"
SESSION_COOKIE = "vpn_session"
SESSION_MAX_AGE = 86400  # 24 hours

serializer = URLSafeTimedSerializer(SECRET_KEY)


def hash_password(password: str) -> str:
    """Hash a password using SHA-256 with salt."""
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash."""
    try:
        salt, stored_hash = hashed.split("$", 1)
        h = hashlib.sha256((salt + password).encode()).hexdigest()
        return hmac.compare_digest(h, stored_hash)
    except (ValueError, AttributeError):
        return False


def create_session_token(username: str) -> str:
    """Create a signed session token."""
    return serializer.dumps({"user": username})


def verify_session_token(token: str) -> dict | None:
    """Verify and decode a session token."""
    try:
        data = serializer.loads(token, max_age=SESSION_MAX_AGE)
        return data
    except (BadSignature, SignatureExpired):
        return None


def get_current_user(request: Request) -> str | None:
    """Extract current user from session cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    data = verify_session_token(token)
    if data:
        return data.get("user")
    return None


def require_auth(request: Request) -> str:
    """Dependency that requires authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user
