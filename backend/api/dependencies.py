"""
AI-NIDS — FastAPI Dependencies
backend/app/core/dependencies.py

Provides:
  - get_db()          : async PostgreSQL session
  - get_current_user(): validates JWT from Authorization header
  - require_role()    : factory that enforces one or more allowed roles

FR Traceability: FR14.2 (RBAC), FR14.5 (session timeout),
                 FR14.6 (log auth attempts), NFR5.5 (least privilege)

RBAC roles (G-09 aligned, 4-role schema):
  system_admin      — full access
  soc_manager       — alerts, reports, escalation
  network_admin     — alerts, traffic, rules
  read_only_analyst — view only
"""

import logging
import os
from typing import List

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.security import TokenData, decode_access_token
from infrastructure.db.session import AsyncSessionLocal

logger = logging.getLogger("ai-nids.auth")

# ── Role constants ────────────────────────────────────────────
ROLE_SYSTEM_ADMIN      = "system_admin"
ROLE_SOC_MANAGER       = "soc_manager"
ROLE_NETWORK_ADMIN     = "network_admin"
ROLE_READ_ONLY_ANALYST = "read_only_analyst"

ALL_ROLES = [
    ROLE_SYSTEM_ADMIN,
    ROLE_SOC_MANAGER,
    ROLE_NETWORK_ADMIN,
    ROLE_READ_ONLY_ANALYST,
]

# ── Bearer token extractor ────────────────────────────────────
bearer_scheme = HTTPBearer(auto_error=True)


# ── DB session dependency ─────────────────────────────────────
async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


# ── Current user dependency ───────────────────────────────────
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> TokenData:
    """
    Extract and validate the JWT from the Authorization: Bearer <token> header.
    Returns TokenData on success; raises 401 on any failure.
    """
    secret_key = os.getenv("SECRET_KEY", "")
    if not secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: SECRET_KEY not set",
        )

    try:
        token_data = decode_access_token(credentials.credentials, secret_key)
    except JWTError as exc:
        logger.warning("JWT validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token_data


# ── RBAC factory ──────────────────────────────────────────────
def require_role(*allowed_roles: str):
    """
    Dependency factory. Usage:

        @router.get("/admin-only")
        async def endpoint(user = Depends(require_role("system_admin"))):
            ...

    Raises 403 if the authenticated user's role is not in allowed_roles.
    """
    async def _check(current_user: TokenData = Depends(get_current_user)) -> TokenData:
        if current_user.role not in allowed_roles:
            logger.warning(
                "Access denied: user=%s role=%s attempted to access route "
                "requiring roles=%s",
                current_user.username,
                current_user.role,
                allowed_roles,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not authorised for this resource",
            )
        return current_user

    return _check