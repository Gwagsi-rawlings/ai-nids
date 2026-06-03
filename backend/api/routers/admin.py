"""
AI-NIDS — Admin Router
backend/api/routers/admin.py

Endpoints:
    GET    /users                   — List all user accounts
    POST   /users                   — Create a new user account
    DELETE /users/{user_id}         — Deactivate a user account
    PUT    /users/{user_id}/role    — Change a user's role
    GET    /audit-log               — List recent audit log entries
    GET    /config                  — Get system configuration
    PUT    /config                  — Save system configuration

All endpoints require system_admin role except where noted.

FR Traceability:
    FR14.2 — RBAC: role-based access control
    FR14.6 — Audit log
    FR17.1 — System administration dashboard
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_db, require_role
from backend.api.security import hash_password, TokenData
from infrastructure.db.models import User, AuditLog

logger = logging.getLogger("ai-nids.admin")
router = APIRouter(tags=["Administration"])

# ── In-memory system config (persisted across requests, reset on restart) ───
_system_config: dict = {
    "retention_days": 90,
    "alert_threshold": 0.50,
    "siem_enabled": False,
    "siem_url": "",
}


# ── Request / response schemas ────────────────────────────────

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    last_login_at: Optional[str]
    created_at: str

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "read_only_analyst"


class RoleUpdate(BaseModel):
    role: str


class SystemConfig(BaseModel):
    retention_days: int = 90
    alert_threshold: float = 0.50
    siem_enabled: bool = False
    siem_url: str = ""


class AuditEntryResponse(BaseModel):
    id: str
    user_id: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    ip_address: str
    created_at: str

    model_config = {"from_attributes": True}


# ── GET /users ─────────────────────────────────────────────────

@router.get(
    "/users",
    response_model=list[UserResponse],
    summary="List all user accounts (system_admin only)",
)
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("system_admin")),
):
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
    )
    users = result.scalars().all()
    return [
        UserResponse(
            id=str(u.id),
            username=u.username,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            created_at=u.created_at.isoformat(),
        )
        for u in users
    ]


# ── POST /users ────────────────────────────────────────────────

@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account (system_admin only)",
)
async def create_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("system_admin")),
):
    valid_roles = {"system_admin", "soc_manager", "network_admin", "read_only_analyst"}
    if payload.role not in valid_roles:
        raise HTTPException(status_code=422, detail=f"Invalid role. Must be one of: {valid_roles}")

    existing = await db.execute(
        select(User).where(User.username == payload.username)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Username '{payload.username}' already exists")

    email_check = await db.execute(
        select(User).where(User.email == payload.email)
    )
    if email_check.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Email '{payload.email}' already in use")

    user = User(
        id=str(uuid4()),
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        failed_attempts=0,
    )
    db.add(user)
    await db.flush()

    await _write_audit(db, current_user.user_id, "USER_CREATED", "127.0.0.1",
                       entity_type="users", entity_id=str(user.id))

    logger.info("User created: username=%s role=%s by=%s", user.username, user.role, current_user.username)
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        last_login_at=None,
        created_at=user.created_at.isoformat(),
    )


# ── DELETE /users/{user_id} ────────────────────────────────────

@router.delete(
    "/users/{user_id}",
    summary="Deactivate a user account (system_admin only)",
)
async def deactivate_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("system_admin")),
):
    if user_id == current_user.user_id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await db.flush()

    await _write_audit(db, current_user.user_id, "USER_DEACTIVATED", "127.0.0.1",
                       entity_type="users", entity_id=user_id)

    logger.info("User deactivated: user_id=%s by=%s", user_id, current_user.username)
    return {"message": f"User {user.username} deactivated"}


# ── PUT /users/{user_id}/role ──────────────────────────────────

@router.put(
    "/users/{user_id}/role",
    response_model=UserResponse,
    summary="Change a user's role (system_admin only)",
)
async def update_user_role(
    user_id: str,
    payload: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("system_admin")),
):
    valid_roles = {"system_admin", "soc_manager", "network_admin", "read_only_analyst"}
    if payload.role not in valid_roles:
        raise HTTPException(status_code=422, detail=f"Invalid role. Must be one of: {valid_roles}")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_role = user.role
    user.role = payload.role
    await db.flush()

    await _write_audit(db, current_user.user_id, "USER_ROLE_CHANGED", "127.0.0.1",
                       entity_type="users", entity_id=user_id)

    logger.info("User role changed: user_id=%s %s→%s by=%s", user_id, old_role, payload.role, current_user.username)
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        created_at=user.created_at.isoformat(),
    )


# ── GET /audit-log ─────────────────────────────────────────────

@router.get(
    "/audit-log",
    response_model=list[AuditEntryResponse],
    summary="List recent audit log entries (system_admin only)",
)
async def get_audit_log(
    limit: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: TokenData = Depends(require_role("system_admin")),
):
    result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    entries = result.scalars().all()
    return [
        AuditEntryResponse(
            id=str(e.id),
            user_id=str(e.user_id) if e.user_id else None,
            action=e.action,
            resource_type=e.entity_type,
            resource_id=str(e.entity_id) if e.entity_id else None,
            ip_address=str(e.ip_address) if e.ip_address else None,
            created_at=e.created_at.isoformat(),
        )
        for e in entries
    ]


# ── GET /config ────────────────────────────────────────────────

@router.get(
    "/config",
    response_model=SystemConfig,
    summary="Get system configuration (system_admin only)",
)
async def get_config(
    current_user: TokenData = Depends(require_role("system_admin")),
):
    return SystemConfig(**_system_config)


# ── PUT /config ────────────────────────────────────────────────

@router.put(
    "/config",
    response_model=SystemConfig,
    summary="Save system configuration (system_admin only)",
)
async def save_config(
    payload: SystemConfig,
    current_user: TokenData = Depends(require_role("system_admin")),
):
    _system_config.update(payload.model_dump())
    logger.info("System config updated by %s: %s", current_user.username, _system_config)
    return SystemConfig(**_system_config)


# ── Audit log helper ───────────────────────────────────────────

async def _write_audit(
    db: AsyncSession,
    user_id: str,
    action: str,
    ip_address: str,
    entity_type: str = "admin",
    entity_id: Optional[str] = None,
) -> None:
    try:
        entry = AuditLog(
            id=str(uuid4()),
            user_id=user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            ip_address=ip_address,
            created_at=datetime.now(timezone.utc),
        )
        db.add(entry)
    except Exception as exc:
        logger.warning("audit_log write failed: %s", exc)
