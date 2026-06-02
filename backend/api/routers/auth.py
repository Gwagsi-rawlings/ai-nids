"""
AI-NIDS — Authentication Router
backend/app/api/routers/auth.py

Endpoints:
  POST /auth/login   — validate credentials, return JWT
  GET  /auth/me      — return current user info from token

FR Traceability: FR14.1 (username/password), FR14.4 (lockout after 5 attempts),
                 FR14.6 (log auth attempts), NFR5.3 (account lockout)
"""

import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user, get_db
from backend.api.security import (
    TokenData,
    create_access_token,
    verify_password,
)

logger = logging.getLogger("ai-nids.auth")
router = APIRouter(prefix="/auth", tags=["Authentication"])

MAX_FAILED_ATTEMPTS = 5


# ── Request / Response schemas ────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


# ── POST /auth/login ──────────────────────────────────────────
@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate with username + password.
    Returns a signed JWT on success.

    Security:
      - Account locked after 5 consecutive failures (FR14.4)
      - All attempts logged to audit_log (FR14.6)
      - bcrypt verification (NFR5.1)
    """
    client_ip = request.client.host if request.client else "unknown"

    # ── 1. Fetch user ─────────────────────────────────────────
    result = await db.execute(
        text(
            "SELECT id, username, password_hash, role, is_active, failed_attempts "
            "FROM users WHERE username = :username"
        ),
        {"username": payload.username},
    )
    row = result.fetchone()

    # ── 2. User not found — log and reject ────────────────────
    if row is None:
        logger.warning("Login failed: unknown user=%s ip=%s", payload.username, client_ip)
        await _write_audit(db, None, "LOGIN_FAILED_UNKNOWN_USER", client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    user_id, username, password_hash, role, is_active, failed_attempts = row

    # ── 3. Account inactive ───────────────────────────────────
    if not is_active:
        await _write_audit(db, str(user_id), "LOGIN_FAILED_INACTIVE", client_ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact your administrator.",
        )

    # ── 4. Account locked ─────────────────────────────────────
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        await _write_audit(db, str(user_id), "LOGIN_FAILED_LOCKED", client_ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account locked after too many failed attempts. Contact your administrator.",
        )

    # ── 5. Wrong password ─────────────────────────────────────
    if not verify_password(payload.password, password_hash):
        await db.execute(
            text("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = :id"),
            {"id": user_id},
        )
        await db.commit()
        await _write_audit(db, str(user_id), "LOGIN_FAILED_WRONG_PASSWORD", client_ip)
        logger.warning("Login failed: wrong password user=%s ip=%s", username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # ── 6. Success — reset counter, update last_login ─────────
    await db.execute(
        text(
            "UPDATE users SET failed_attempts = 0, last_login_at = :now "
            "WHERE id = :id"
        ),
        {"id": user_id, "now": datetime.now(timezone.utc)},
    )
    await db.commit()
    await _write_audit(db, str(user_id), "LOGIN_SUCCESS", client_ip)
    logger.info("Login success: user=%s role=%s ip=%s", username, role, client_ip)

    # ── 7. Issue JWT ──────────────────────────────────────────
    secret_key = os.getenv("SECRET_KEY", "")
    token = create_access_token(
        user_id=str(user_id),
        username=username,
        role=role,
        secret_key=secret_key,
    )

    return LoginResponse(access_token=token, role=role, username=username)


# ── GET /auth/me ──────────────────────────────────────────────
@router.get("/me")
async def get_me(current_user: TokenData = Depends(get_current_user)):
    """Return the currently authenticated user's identity from their token."""
    return {
        "user_id":  current_user.user_id,
        "username": current_user.username,
        "role":     current_user.role,
    }


# ── Audit log helper ──────────────────────────────────────────
async def _write_audit(
    db: AsyncSession,
    user_id: str | None,
    action: str,
    ip_address: str,
) -> None:
    """Insert one row into audit_log. Silently swallows errors so login path never crashes."""
    try:
        await db.execute(
            text(
                "INSERT INTO audit_log (user_id, action, entity_type, ip_address) "
                "VALUES (:uid, :action, 'auth', :ip)"
            ),
            {"uid": user_id, "action": action, "ip": ip_address},
        )
        await db.commit()
    except Exception as exc:
        logger.warning("audit_log write failed: %s", exc)