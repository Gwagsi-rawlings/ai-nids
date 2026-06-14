"""
AI-NIDS — Alert Router
api/routers/alerts.py

Endpoints:
    POST   /alerts                          — Ingest detection event from pipeline
    GET    /alerts                          — Paginated alert list with filters
    GET    /alerts/{alert_id}               — Single alert detail
    PATCH  /alerts/{alert_id}/acknowledge   — Acknowledge an open alert

FR Traceability:
    FR7.1–FR7.10  — Alert generation and structure
    FR8.5         — Duplicate suppression (60-second window)
    FR9.1–FR9.13  — Alert management interface
    NFR1.4        — Alert persisted <100ms of detection
    NFR2.2        — API response <200ms

April 3–8, 2026 | Sprint 1, Week 4
"""

import csv
import io
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.db.database import get_db
from infrastructure.db.models import Alert
from infrastructure.db import redis_client
from backend.api.schemas import (
    AlertCreate, AlertResponse, AlertListResponse,
    AlertAcknowledge, AlertNoteRequest,
)

logger = logging.getLogger("ai-nids.alerts")
router = APIRouter(prefix="/alerts", tags=["Alerts"])

# 60-second deduplication window key prefix (FR8.5)
_DUP_KEY_PREFIX = "nids:dedup:"
_DUP_TTL = 60


# ── Helpers ───────────────────────────────────────────────────

def _severity_to_score(severity: str) -> float:
    """Map severity label → ensemble confidence midpoint."""
    return {"CRITICAL": 0.97, "HIGH": 0.90, "MEDIUM": 0.75, "LOW": 0.55}.get(
        severity.upper(), 0.55
    )


async def _check_duplicate(src_ip: str, dst_ip: str, attack_type: str) -> Optional[str]:
    """
    Return existing alert_id if an identical event was seen within 60 seconds,
    otherwise None (FR8.5).
    """
    try:
        cache = redis_client.get_cache()
        key = f"{_DUP_KEY_PREFIX}{src_ip}:{dst_ip}:{attack_type}"
        return await cache.get(key)
    except Exception:
        return None  # Redis unavailable — allow the alert through


async def _mark_duplicate(src_ip: str, dst_ip: str, attack_type: str, alert_id: str):
    """Record this alert in the dedup window."""
    try:
        cache = redis_client.get_cache()
        key = f"{_DUP_KEY_PREFIX}{src_ip}:{dst_ip}:{attack_type}"
        await cache.setex(key, _DUP_TTL, alert_id)
    except Exception:
        pass


def _alert_to_dict(alert: Alert) -> dict:
    """Convert ORM Alert to serialisable dict for cache and WebSocket."""
    return {
        "id":               str(alert.id),
        "alert_id":         str(alert.alert_id),
        "attack_type":      alert.attack_type,
        "severity":         alert.severity,
        "confidence":       float(alert.confidence) if alert.confidence is not None else 0.0,
        "detected_by":      alert.detected_by,
        "src_ip":           str(alert.src_ip)  if alert.src_ip  is not None else None,
        "dst_ip":           str(alert.dst_ip)  if alert.dst_ip  is not None else None,
        "src_port":         alert.src_port,
        "dst_port":         alert.dst_port,
        "protocol":         alert.protocol,
        "description":      alert.description,
        "status":           alert.status,
        "detected_at":      alert.detected_at.isoformat()      if alert.detected_at      else None,
        "acknowledged_at":  alert.acknowledged_at.isoformat()  if alert.acknowledged_at  else None,
        "dup_count":        alert.dup_count,
        "sig_confidence":   float(alert.sig_confidence)  if alert.sig_confidence  is not None else None,
        "rf_confidence":    float(alert.rf_confidence)   if alert.rf_confidence   is not None else None,
        "lstm_confidence":  float(alert.lstm_confidence) if alert.lstm_confidence is not None else None,
        "if_confidence":    float(alert.if_confidence)   if alert.if_confidence   is not None else None,
        "flow_id":          str(alert.flow_id)  if alert.flow_id  else None,
        "group_id":         str(alert.group_id) if alert.group_id else None,
        "notes":            _parse_notes(alert.description),
    }


def _parse_notes(description: Optional[str]) -> list[dict]:
    if not description:
        return []

    notes = []
    for line in description.splitlines():
        if not line.startswith("[Note]"):
            continue
        payload = line[len("[Note]"):].strip()
        if not payload:
            continue

        match = re.match(r"^([0-9TZ:\.\-]+)\s+(.*)$", payload)
        if match:
            ts_raw, text = match.groups()
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                ts = None
        else:
            ts = None
            text = payload

        notes.append({"ts": ts.isoformat() if ts else None, "text": text})
    return notes


def _format_note_line(note_text: str) -> str:
    note_text = note_text.strip()
    if not note_text:
        return ""
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return f"[Note] {ts} {note_text}"


# ── POST /alerts ──────────────────────────────────────────────
@router.post(
    "",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest detection event from the pipeline",
    description=(
        "Called by the Ensemble Correlator when score >= 0.50. "
        "Performs 60-second deduplication (FR8.5), persists to PostgreSQL, "
        "caches in Redis, and publishes to the WebSocket event channel. "
        "FR7.1–FR7.10 | NFR1.4 (<100ms target)."
    ),
)
async def create_alert(
    payload: AlertCreate,
    db: AsyncSession = Depends(get_db),
):
    # ── 1. Deduplication check (FR8.5) ───────────────────────
    existing_id = await _check_duplicate(
        payload.src_ip, payload.dst_ip, payload.attack_type
    )
    if existing_id:
        result = await db.execute(
            select(Alert).where(Alert.alert_id == existing_id)
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.dup_count += 1
            await db.flush()
            logger.debug(
                f"Duplicate suppressed — alert_id={existing_id} "
                f"dup_count={existing.dup_count}"
            )
            return AlertResponse.model_validate(_alert_to_dict(existing))

    # ── 2. Assign severity-based description if empty ────────
    description = payload.description
    if not description:
        description = (
            f"{payload.severity} severity {payload.attack_type} detected from "
            f"{payload.src_ip}:{payload.src_port or '*'} → "
            f"{payload.dst_ip}:{payload.dst_port or '*'} "
            f"via {payload.protocol or 'unknown'} "
            f"(confidence={payload.confidence:.3f}, engine={payload.detected_by})"
        )

    # ── 3. Create ORM object ──────────────────────────────────
    alert = Alert(
        alert_id=str(uuid4()),
        attack_type=payload.attack_type,
        severity=payload.severity,
        confidence=payload.confidence,
        detected_by=payload.detected_by,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        src_port=payload.src_port,
        dst_port=payload.dst_port,
        protocol=payload.protocol,
        description=description,
        status="open",
        flow_id=payload.flow_id,
        sig_confidence=payload.sig_confidence,
        rf_confidence=payload.rf_confidence,
        lstm_confidence=payload.lstm_confidence,
        if_confidence=payload.if_confidence,
        dup_count=0,
    )
    db.add(alert)
    await db.flush()

    # ── 4. Mark in dedup window ──────────────────────────────
    await _mark_duplicate(
        payload.src_ip, payload.dst_ip, payload.attack_type, alert.alert_id
    )

    # ── 5. Cache alert + publish to WebSocket channel ────────
    alert_dict = _alert_to_dict(alert)
    await redis_client.cache_alert(alert.alert_id, alert_dict)
    await redis_client.publish_alert_event(alert_dict)

    logger.info(
        f"Alert created: alert_id={alert.alert_id} "
        f"severity={alert.severity} type={alert.attack_type} "
        f"src={alert.src_ip} confidence={alert.confidence:.3f}"
    )
    return AlertResponse.model_validate(alert_dict)


# ── GET /alerts ───────────────────────────────────────────────
@router.get(
    "",
    response_model=AlertListResponse,
    summary="Paginated alert list with optional filters",
    description=(
        "FR9.1–FR9.5: Filter by severity, status, src_ip, attack_type, date range. "
        "Results sorted by detected_at DESC (newest first). "
        "Default page_size=20. Max page_size=200."
    ),
)
async def list_alerts(
    severity: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    status_filter: Optional[str] = Query(None, alias="status",
                                         description="open | acknowledged | false_positive | escalated"),
    src_ip: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    from_dt: Optional[datetime] = Query(None, alias="from"),
    to_dt: Optional[datetime] = Query(None, alias="to"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    conditions = []

    if severity:
        conditions.append(Alert.severity == severity.upper())
    if status_filter:
        conditions.append(Alert.status == status_filter.lower())
    if src_ip:
        conditions.append(Alert.src_ip == src_ip)
    if attack_type:
        conditions.append(Alert.attack_type == attack_type)
    if from_dt:
        conditions.append(Alert.detected_at >= from_dt)
    if to_dt:
        conditions.append(Alert.detected_at <= to_dt)

    # Count query
    count_q = select(func.count(Alert.id))
    if conditions:
        count_q = count_q.where(and_(*conditions))
    total_result = await db.execute(count_q)
    total = total_result.scalar_one()

    # Data query — sorted newest first (FR9.1)
    data_q = select(Alert).order_by(Alert.detected_at.desc())
    if conditions:
        data_q = data_q.where(and_(*conditions))
    data_q = data_q.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(data_q)
    alerts = result.scalars().all()

    return AlertListResponse(
        total=total,
        page=page,
        page_size=page_size,
        alerts=[AlertResponse.model_validate(_alert_to_dict(a)) for a in alerts],
    )


# ── GET /alerts/export ───────────────────────────────────────

@router.get(
    "/export",
    summary="Export alerts as CSV (FR12.8)",
)
async def export_alerts_csv(
    format: str = Query(default="csv"),
    range: str = Query(default="7d", pattern="^(24h|7d|30d)$"),
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    delta = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
    since = now - delta.get(range, timedelta(days=7))

    conditions = [Alert.detected_at >= since]
    if severity:
        conditions.append(Alert.severity == severity.upper())
    if attack_type:
        conditions.append(Alert.attack_type == attack_type)

    result = await db.execute(
        select(Alert)
        .where(and_(*conditions))
        .order_by(Alert.detected_at.desc())
        .limit(10000)
    )
    alerts = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "alert_id", "detected_at", "severity", "attack_type",
        "confidence", "detected_by", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "status", "description",
    ])
    for a in alerts:
        writer.writerow([
            a.alert_id,
            a.detected_at.isoformat() if a.detected_at else "",
            a.severity,
            a.attack_type,
            round(float(a.confidence), 4) if a.confidence is not None else "",
            a.detected_by,
            str(a.src_ip) if a.src_ip else "",
            str(a.dst_ip) if a.dst_ip else "",
            a.src_port or "",
            a.dst_port or "",
            a.protocol or "",
            a.status,
            (a.description or "").replace("\n", " "),
        ])

    output.seek(0)
    filename = f"ai-nids-alerts-{range}-{int(now.timestamp())}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── GET /alerts/{alert_id} ────────────────────────────────────
@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Retrieve a single alert by alert_id",
)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
):
    cached = await redis_client.get_cached_alert(alert_id)
    if cached:
        try:
            return AlertResponse.model_validate(cached)
        except Exception:
            pass

    result = await db.execute(select(Alert).where(Alert.alert_id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    alert_dict = _alert_to_dict(alert)
    await redis_client.cache_alert(alert_id, alert_dict)
    return AlertResponse.model_validate(alert_dict)


# ── PATCH /alerts/{alert_id}/acknowledge ─────────────────────
@router.patch(
    "/{alert_id}/acknowledge",
    response_model=AlertResponse,
    summary="Acknowledge an open alert (FR9.8)",
)
async def acknowledge_alert(
    alert_id: str,
    body: Optional[AlertAcknowledge] = None,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.alert_id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    if alert.status != "open":
        raise HTTPException(
            status_code=400,
            detail=f"Alert is already '{alert.status}' — cannot acknowledge",
        )

    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    if body and body.note:
        note_line = _format_note_line(body.note)
        if note_line:
            alert.description = alert.description + ("\n" if alert.description else "") + note_line

    await db.flush()

    try:
        cache = redis_client.get_cache()
        await cache.delete(f"nids:cache:alert:{alert_id}")
    except Exception:
        pass

    logger.info(f"Alert acknowledged: alert_id={alert_id}")
    return AlertResponse.model_validate(_alert_to_dict(alert))


@router.post(
    "/{alert_id}/notes",
    response_model=AlertResponse,
    summary="Add an investigation note to an alert",
)
async def add_alert_note(
    alert_id: str,
    body: AlertNoteRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.alert_id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    note_line = _format_note_line(body.text)
    if not note_line:
        raise HTTPException(status_code=400, detail="Note text must not be empty")

    alert.description = alert.description + ("\n" if alert.description else "") + note_line
    await db.flush()

    try:
        cache = redis_client.get_cache()
        await cache.delete(f"nids:cache:alert:{alert_id}")
    except Exception:
        pass

    logger.info(f"Note added to alert: alert_id={alert_id}")
    return AlertResponse.model_validate(_alert_to_dict(alert))


# ── PATCH /alerts/{alert_id}/false-positive ──────────────────
@router.patch(
    "/{alert_id}/false-positive",
    response_model=AlertResponse,
    summary="Mark alert as false positive (FR9.13)",
)
async def mark_false_positive(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.alert_id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    alert.status = "false_positive"
    await db.flush()
    logger.info(f"Alert marked false_positive: alert_id={alert_id}")
    return AlertResponse.model_validate(_alert_to_dict(alert))
