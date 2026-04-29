"""Simple cookie-based authentication for VPN Checker."""

import hashlib
import hmac
import secrets
import os
import warnings
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException

# Secret key for signing sessions. Load from environment to support production secrecy.
# Fallback is kept but worth replacing in production with a strong, unique key.
SECRET_KEY = os.environ.get("VPN_CHECKER_SECRET_KEY")
if not SECRET_KEY:
    # Do not crash startup; warn in development but keep running.
    warnings.warn(
        "VPN_CHECKER_SECRET_KEY is not set; using default insecure secret. "
        "Set VPN_CHECKER_SECRET_KEY in the environment for production use.")
    SECRET_KEY = "vpn-checker-secret-key-change-me-in-production"
SESSION_COOKIE = "vpn_session"
SESSION_MAX_AGE = 86400  # 24 hours

serializer = URLSafeTimedSerializer(SECRET_KEY)


def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256 with salt.

    Supports both the new PBKDF2 format (salt$iterations$hash) and the legacy
    format (salt$hash) for backward compatibility during migrations.
    """
    salt = secrets.token_hex(16)
    iterations = 100000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"{salt}${iterations}${dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash.

    Accepts both legacy (salt$hash) and new PBKDF2-based (salt$iterations$hash) formats.
    """
    try:
        parts = hashed.split("$")
        if len(parts) == 3:
            salt, iterations_s, stored_hash = parts
            iterations = int(iterations_s)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
            return hmac.compare_digest(dk.hex(), stored_hash)
        elif len(parts) == 2:
            salt, stored_hash = parts
            h = hashlib.sha256((salt + password).encode()).hexdigest()
            return hmac.compare_digest(h, stored_hash)
        else:
            return False
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
