"""FastAPI authentication dependencies."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from vulnhunter.auth.jwt import decode_access_token, hash_api_token
from vulnhunter.config import load_config
from vulnhunter.db import get_session
from vulnhunter.db.repository import Repository

_bearer_scheme = HTTPBearer(auto_error=False)


async def _resolve_user_id(token: str) -> uuid.UUID | None:
    """Try JWT first, then API token."""
    config = load_config()
    user_id = decode_access_token(token, config.auth)
    if user_id:
        return user_id

    token_hash = hash_api_token(token)
    try:
        async with get_session() as session:
            repo = Repository(session)
            api_token = await repo.get_api_token_by_hash(token_hash)
            if api_token and not api_token.revoked and api_token.expires_at > datetime.now(timezone.utc):
                return api_token.user_id
    except Exception:
        pass
    return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> uuid.UUID:
    """Require a valid JWT or API token. Returns user_id."""
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user_id = await _resolve_user_id(credentials.credentials)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return user_id


async def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> uuid.UUID | None:
    """Optionally authenticate — returns user_id or None."""
    if not credentials:
        return None
    return await _resolve_user_id(credentials.credentials)


async def ws_authenticate(websocket: WebSocket, token: str | None = Query(default=None)) -> uuid.UUID | None:
    """Authenticate WebSocket via query param. Returns user_id or None."""
    if not token:
        return None
    return await _resolve_user_id(token)
