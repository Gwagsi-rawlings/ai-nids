"""
AI-NIDS — Detection Rules Router
api/routers/rules.py

Endpoints:
    GET    /rules               — List all rules with optional filters
    GET    /rules/{rule_id}     — Single rule detail
    POST   /rules               — Create a new detection rule
    PUT    /rules/{rule_id}     — Update an existing rule
    DELETE /rules/{rule_id}     — Delete a rule (soft: disable only)
    PATCH  /rules/{rule_id}/toggle — Enable / disable a rule (FR4.13)

FR Traceability:
    FR4.1   — Signature-based detection rules
    FR4.2   — Snort-like rule syntax
    FR4.3   — Parse detection rules from text files
    FR4.13  — Enable/disable individual rules
    FR11.1–FR11.12 — Rule management interface

April 3–8, 2026 | Sprint 1, Week 4
"""

import logging
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.db.database import get_db
from infrastructure.db.models import DetectionRule
from backend.api.schemas import (
    RuleCreate, RuleUpdate, RuleResponse, RuleListResponse, MessageResponse, RuleToggle,
)

logger = logging.getLogger("ai-nids.rules")
router = APIRouter(prefix="/rules", tags=["Detection Rules"])


# ── GET /rules ────────────────────────────────────────────────
@router.get(
    "",
    response_model=RuleListResponse,
    summary="List all detection rules",
    description="Optionally filter by attack_category, severity, or is_enabled. FR11.6.",
)
async def list_rules(
    attack_category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    is_enabled: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    conditions = []
    if attack_category:
        conditions.append(DetectionRule.attack_category == attack_category)
    if severity:
        conditions.append(DetectionRule.severity == severity.upper())
    if is_enabled is not None:
        conditions.append(DetectionRule.is_enabled == is_enabled)

    count_q = select(func.count(DetectionRule.id))
    data_q = select(DetectionRule).order_by(DetectionRule.attack_category, DetectionRule.rule_id)

    if conditions:
        count_q = count_q.where(and_(*conditions))
        data_q = data_q.where(and_(*conditions))

    total = (await db.execute(count_q)).scalar_one()
    rules = (await db.execute(data_q)).scalars().all()

    return RuleListResponse(total=total, rules=[RuleResponse.model_validate(r) for r in rules])


# ── GET /rules/{rule_id} ──────────────────────────────────────
@router.get(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Get a single rule by its SID (e.g. SID:1001)",
)
async def get_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return RuleResponse.model_validate(rule)


# ── POST /rules ───────────────────────────────────────────────
@router.post(
    "",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new detection rule (FR11.1)",
    description=(
        "Validates that rule_id is unique and rule_content is non-empty. "
        "Rule becomes active in the Signature Engine on next engine reload. "
        "FR4.2: Snort-compatible rule syntax is NOT validated server-side "
        "in this release — validation is handled by the Signature Engine at reload."
    ),
)
async def create_rule(
    payload: RuleCreate,
    db: AsyncSession = Depends(get_db),
):
    # Check uniqueness of rule_id (SID)
    existing = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == payload.rule_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule with rule_id '{payload.rule_id}' already exists",
        )

    rule = DetectionRule(
        id=str(uuid4()),
        rule_id=payload.rule_id,
        rule_name=payload.rule_name,
        rule_content=payload.rule_content,
        attack_category=payload.attack_category,
        severity=payload.severity.upper(),
        is_enabled=payload.is_enabled,
        version=1,
    )
    db.add(rule)
    await db.flush()

    logger.info(f"Rule created: rule_id={rule.rule_id} name='{rule.rule_name}'")
    return RuleResponse.model_validate(rule)


# ── PUT /rules/{rule_id} ──────────────────────────────────────
@router.put(
    "/{rule_id}",
    response_model=RuleResponse,
    summary="Update an existing detection rule (FR11.2)",
)
async def update_rule(
    rule_id: str,
    payload: RuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    if payload.rule_name is not None:
        rule.rule_name = payload.rule_name
    if payload.rule_content is not None:
        rule.rule_content = payload.rule_content
    if payload.attack_category is not None:
        rule.attack_category = payload.attack_category
    if payload.severity is not None:
        rule.severity = payload.severity.upper()
    if payload.is_enabled is not None:
        rule.is_enabled = payload.is_enabled

    rule.version += 1
    await db.flush()

    logger.info(f"Rule updated: rule_id={rule_id} version={rule.version}")
    return RuleResponse.model_validate(rule)


# ── DELETE /rules/{rule_id} ───────────────────────────────────
@router.delete(
    "/{rule_id}",
    response_model=MessageResponse,
    summary="Delete a detection rule (FR11.3)",
    description="Hard-deletes the rule from the database. Use PATCH /toggle to disable without deleting.",
)
async def delete_rule(rule_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    await db.delete(rule)
    await db.flush()

    logger.info(f"Rule deleted: rule_id={rule_id}")
    return MessageResponse(message=f"Rule {rule_id} deleted successfully")


# ── PATCH /rules/{rule_id}/toggle ────────────────────────────
@router.patch(
    "/{rule_id}/toggle",
    response_model=RuleResponse,
    summary="Enable or disable a rule without deleting it (FR4.13, FR11.7)",
)
async def toggle_rule(rule_id: str, payload: RuleToggle, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

    rule.is_enabled = payload.enabled
    rule.version += 1
    await db.flush()

    state = "enabled" if rule.is_enabled else "disabled"
    logger.info(f"Rule {state}: rule_id={rule_id}")
    return RuleResponse.model_validate(rule)