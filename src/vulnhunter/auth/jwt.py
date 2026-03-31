"""JWT token management and password hashing."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from vulnhunter.config import AuthConfig


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_access_token(user_id: uuid.UUID, config: AuthConfig, expires_delta: timedelta | None = None) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=config.access_token_expire_minutes))
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "type": "access",
    }
    return jwt.encode(payload, config.effective_secret, algorithm=config.algorithm)


def decode_access_token(token: str, config: AuthConfig) -> uuid.UUID | None:
    """Decode a JWT and return the user_id, or None if invalid."""
    try:
        payload = jwt.decode(token, config.effective_secret, algorithms=[config.algorithm])
        if payload.get("type") != "access":
            return None
        return uuid.UUID(payload["sub"])
    except (JWTError, ValueError, KeyError):
        return None


def generate_api_token() -> tuple[str, str]:
    """Generate a raw API token and its hash. Returns (raw_token, token_hash)."""
    raw = f"vh_{secrets.token_urlsafe(48)}"
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, token_hash


def hash_api_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()
