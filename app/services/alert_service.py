"""
AI-NIDS — Alert Service
app/services/alert_service.py

Handles the full alert lifecycle:
  1. Receive DetectionEvent from Ensemble Correlator
  2. Deduplicate within 60-second window (FR8.5)
  3. Assign severity from ensemble_score (FR7.2)
  4. Persist to PostgreSQL alerts table (FR7.8)
  5. Cache in Redis (TTL 300s) for dashboard fast-load (NFR1.6)
  6. Publish to Redis Pub/Sub → WebSocket push to dashboard (FR10.5)

FR Traceability:
    FR7.1  — Generate alert on threat detection
    FR7.2  — Severity classification (4 tiers)
    FR7.8  — PostgreSQL persistence
    FR8.5  — Duplicate suppression within 60 s
    FR10.5 — Real-time dashboard update via WebSocket
    NFR1.4 — Alert generation <= 100 ms
    NFR1.6 — Dashboard stats from Redis cache
April 4, 2026 | Sprint 1, Week 4
"""

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from infrastructure.db.redis_client import get_cache, get_redis
from infrastructure.db.models import Alert
from backend.api.schemas import AlertCreate, AlertRead, DetectionEvent, SeverityLevel

logger = logging.getLogger("ai-nids.alert_service")

# ── Constants ──────────────────────────────────────────────────────────────
DEDUP_WINDOW_SECONDS = 60
ALERT_CACHE_TTL = 300          # 5 minutes (Redis key TTL)
ALERT_PUBSUB_CHANNEL = "nids:alerts:new"


def _severity_from_score(score: float) -> SeverityLevel:
    """
    Map ensemble confidence score to four-tier severity (FR7.2).
    CRITICAL >= 0.95 | HIGH >= 0.85 | MEDIUM >= 0.70 | LOW >= 0.50
    """
    if score >= 0.95:
        return SeverityLevel.CRITICAL
    if score >= 0.85:
        return SeverityLevel.HIGH
    if score >= 0.70:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


def _dedup_key(event: DetectionEvent) -> str:
    """60-second deduplication key: src_ip + dst_ip + attack_type (FR8.5)."""
    return f"nids:dedup:{event.src_ip}:{event.dst_ip}:{event.attack_type}"


def _alert_description(event: DetectionEvent) -> str:
    """Human-readable alert description (FR7.6)."""
    method_label = {
        "SIGNATURE": "Signature rule match",
        "ML": "ML ensemble detection",
        "HYBRID": "Signature + ML corroboration",
    }.get(event.detection_method, "Detection")
    return (
        f"{method_label}: {event.attack_type} detected from {event.src_ip} "
        f"→ {event.dst_ip}:{event.dst_port or '?'} "
        f"(confidence {event.ensemble_score:.2f})"
    )


async def process_detection_event(
    event: DetectionEvent,
    db: AsyncSession,
) -> AlertRead | None:
    """
    Main entry point called by the Ensemble Correlator for every
    confirmed detection (score >= 0.50).

    Returns the persisted AlertRead if a new alert was created,
    or None if the event was suppressed as a duplicate (FR8.5).
    """
    cache = get_cache()
    redis = await get_redis()

    # ── 1. Deduplication check (FR8.5) ────────────────────────────────────
    dedup_key = _dedup_key(event)
    existing_id = await cache.get(dedup_key)

    if existing_id:
        # Increment dup_count on existing alert — do NOT create a new record
        existing = await db.get(Alert, existing_id)
        if existing:
            existing.dup_count = (existing.dup_count or 1) + 1
            await db.flush()
            logger.debug(
                "Suppressed duplicate alert %s (dup_count=%d)",
                existing_id,
                existing.dup_count,
            )
        return None

    # ── 2. Create Alert ORM object ─────────────────────────────────────────
    severity = _severity_from_score(event.ensemble_score)

    alert = Alert(
        attack_type=event.attack_type,
        severity=severity.value,
        confidence=event.ensemble_score,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        detected_by=event.detection_method.value if hasattr(event.detection_method, 'value') else (event.detection_method or 'ml'),
        description=event.description or _alert_description(event),
        rule_id=event.matched_rule_id,
        flow_id=event.flow_id,
        sig_confidence=event.sig_confidence,
        rf_confidence=event.rf_confidence,
        lstm_confidence=event.lstm_confidence,
        if_confidence=event.if_confidence,
        status="NEW",
    )

    # Generate a stable UUID for this alert before DB flush
    import uuid as _uuid
    from datetime import datetime, timezone
    alert_id = str(_uuid.uuid4())
    alert.id = alert_id
    alert.timestamp = datetime.now(timezone.utc)
    alert.dup_count = 1

    db.add(alert)
    await db.flush()   # persist to DB

    # ── 3. Register dedup key (60-second TTL) ─────────────────────────────
    await cache.set(dedup_key, alert_id, ex=DEDUP_WINDOW_SECONDS)

    # ── 4. Build AlertRead from known fields (not from ORM object) ─────────
    #       This avoids issues with mock sessions that don't populate DB defaults.
    alert_read = AlertRead(
        id=alert_id,
        timestamp=alert.timestamp,
        severity=severity,
        attack_type=event.attack_type,
        confidence=event.ensemble_score,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        detected_by=event.detection_method.value if hasattr(event.detection_method, 'value') else (event.detection_method or 'ml'),
        description=alert.description,
        rule_id=event.matched_rule_id,
        flow_id=event.flow_id,
        sig_confidence=event.sig_confidence,
        rf_confidence=event.rf_confidence,
        lstm_confidence=event.lstm_confidence,
        if_confidence=event.if_confidence,
        status="NEW",
        dup_count=1,
    )

    await cache.set(
        f"nids:cache:alert:{alert_id}",
        json.dumps(alert_read.model_dump(mode="json"), default=str),
        ex=ALERT_CACHE_TTL,
    )

    # ── 5. Publish to Redis Pub/Sub → WebSocket handler ───────────────────
    await redis.publish(
        ALERT_PUBSUB_CHANNEL,
        json.dumps(
            {
                "alert_id": alert_id,
                "severity": severity.value,
                "attack_type": event.attack_type,
                "src_ip": event.src_ip,
                "confidence": event.ensemble_score,
            },
            default=str,
        ),
    )

    logger.info(
        "Alert created: id=%s severity=%s type=%s src=%s score=%.3f",
        alert_id,
        severity.value,
        event.attack_type,
        event.src_ip,
        event.ensemble_score,
    )

    return alert_read


async def acknowledge_alert(
    alert_id: str,
    acknowledged_by: str,
    db: AsyncSession,
) -> AlertRead | None:
    """
    Mark an alert as ACKNOWLEDGED (UC-015 / FR9.8).
    Returns None if alert not found.
    """
    alert = await db.get(Alert, alert_id)
    if not alert:
        return None

    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = acknowledged_by
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.flush()

    # Invalidate cache so dashboard gets fresh data
    cache = get_cache()
    await cache.delete(f"nids:cache:alert:{alert_id}")

    return AlertRead.model_validate(alert)


async def get_live_stats() -> dict:
    """
    Return live traffic / alert counters from Redis cache (NFR1.6).
    Falls back to zeros if cache is cold.
    """
    cache = get_cache()
    raw = await cache.hgetall("nids:cache:stats:live")
    return {
        "total_alerts": int(raw.get("total_alerts", 0)),
        "alerts_critical": int(raw.get("alerts_critical", 0)),
        "alerts_high": int(raw.get("alerts_high", 0)),
        "alerts_medium": int(raw.get("alerts_medium", 0)),
        "alerts_low": int(raw.get("alerts_low", 0)),
        "packets_per_second": float(raw.get("pps", 0)),
        "cache_age_seconds": float(raw.get("updated_at", 0)),
    }