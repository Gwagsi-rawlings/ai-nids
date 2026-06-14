"""
AI-NIDS — Ensemble Correlator → Alert Pipeline Connector
pipeline/alert_connector.py

This module is the wire between the detection engine and the persistence layer.
It implements the full Stage 5 → Stage 6 data flow:

    Ensemble Correlator output
        → Alert Correlator (dedup / grouping)
        → Alert Generator (severity assignment, description)
        → PostgreSQL (persist)
        → Redis (cache + WebSocket publish)
        → FastAPI consumers (dashboard / WebSocket clients)

Designed to be called from:
  - The live detection pipeline (asyncio task)
  - The PCAP replay pipeline
  - Test harnesses (inject synthetic DetectionEvent objects)

FR Traceability:
    FR6.1–FR6.6   — Ensemble Correlator logic
    FR7.1–FR7.10  — Alert generation and structure
    FR8.1–FR8.5   — Alert correlation and deduplication
    NFR1.4        — End-to-end latency ≤100 ms
    NFR20.2       — FPR ≤5% (ensemble threshold enforced here)

April 3–8, 2026 | Sprint 1, Week 4
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from infrastructure.db.database import AsyncSessionLocal
from infrastructure.db.models import Alert
from infrastructure.db import redis_client

logger = logging.getLogger("ai-nids.connector")

# ── Ensemble configuration ────────────────────────────────────
ENSEMBLE_WEIGHTS = {
    "signature": 0.40,
    "rf":        0.35,
    "lstm":      0.15,
    "if":        0.10,
}
ALERT_THRESHOLD = 0.50   # Weighted score ≥ 0.50 → generate alert

# ── Severity thresholds ───────────────────────────────────────
SEVERITY_MAP = [
    (0.95, "CRITICAL"),
    (0.85, "HIGH"),
    (0.70, "MEDIUM"),
    (0.50, "LOW"),
]


# ── Data classes ──────────────────────────────────────────────

@dataclass
class EngineResult:
    """Output from a single detection engine for one flow."""
    engine: str                     # 'signature' | 'rf' | 'lstm' | 'if'
    confidence: float               # 0.0–1.0
    attack_type: str = "UNKNOWN"    # Classification label
    rule_id: Optional[str] = None   # Matched Snort rule SID (signature engine only)


@dataclass
class DetectionEvent:
    """
    Combined input to the Ensemble Correlator.
    One DetectionEvent is created per flow after all engines have returned results.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # Per-engine results — None if engine did not fire / timed out
    sig_result: Optional[EngineResult] = None
    rf_result:  Optional[EngineResult] = None
    lstm_result: Optional[EngineResult] = None
    if_result:  Optional[EngineResult] = None

    # Filled by compute_ensemble_score()
    ensemble_score: float = 0.0
    attack_type: str = "UNKNOWN"
    detected_by: str = "ml"
    severity: str = "LOW"


# ── Ensemble Correlator ───────────────────────────────────────

def compute_ensemble_score(event: DetectionEvent) -> DetectionEvent:
    """
    Apply weighted majority vote across all four engine results.
    Mutates event in-place: sets ensemble_score, attack_type, detected_by, severity.

    Score formula (FR6.1–FR6.3):
        score = 0.40 × sig_conf + 0.35 × rf_conf + 0.15 × lstm_conf + 0.10 × if_conf

    Alert generated when score >= ALERT_THRESHOLD (0.50).
    attack_type assigned by the highest-weighted engine that flagged an attack.
    """
    sig_conf  = event.sig_result.confidence  if event.sig_result  else 0.0
    rf_conf   = event.rf_result.confidence   if event.rf_result   else 0.0
    lstm_conf = event.lstm_result.confidence if event.lstm_result else 0.0
    if_conf   = event.if_result.confidence   if event.if_result   else 0.0

    score = (
        ENSEMBLE_WEIGHTS["signature"] * sig_conf +
        ENSEMBLE_WEIGHTS["rf"]        * rf_conf  +
        ENSEMBLE_WEIGHTS["lstm"]      * lstm_conf +
        ENSEMBLE_WEIGHTS["if"]        * if_conf
    )
    event.ensemble_score = round(score, 4)

    # Determine attack_type and detected_by from highest-weight positive engine
    engines_by_weight = [
        ("signature", event.sig_result),
        ("rf",        event.rf_result),
        ("lstm",      event.lstm_result),
        ("if",        event.if_result),
    ]
    attack_engines = [
        name for name, res in engines_by_weight
        if res and res.confidence > 0 and res.attack_type != "BENIGN"
    ]

    if not attack_engines:
        event.attack_type = "UNKNOWN"
        event.detected_by = "ml"
    else:
        primary = attack_engines[0]  # First = highest weight per ordering above
        primary_result = {
            "signature": event.sig_result,
            "rf": event.rf_result,
            "lstm": event.lstm_result,
            "if": event.if_result,
        }[primary]
        event.attack_type = primary_result.attack_type
        event.detected_by = (
            "both" if "signature" in attack_engines and len(attack_engines) > 1
            else primary
        )

    # Assign severity tier
    for threshold, label in SEVERITY_MAP:
        if score >= threshold:
            event.severity = label
            break
    else:
        event.severity = "LOW"

    return event


# ── 60-second deduplication window ───────────────────────────

async def _is_duplicate(src_ip: str, dst_ip: str, attack_type: str) -> Optional[str]:
    """Return existing alert_id if seen within 60 s, else None (FR8.5)."""
    try:
        cache = redis_client.get_cache()
        key = f"nids:dedup:{src_ip}:{dst_ip}:{attack_type}"
        return await cache.get(key)
    except Exception:
        return None


async def _register_dedup(src_ip: str, dst_ip: str, attack_type: str, alert_id: str):
    try:
        cache = redis_client.get_cache()
        key = f"nids:dedup:{src_ip}:{dst_ip}:{attack_type}"
        await cache.setex(key, 60, alert_id)
    except Exception:
        pass


# ── Alert generator ───────────────────────────────────────────

def _build_description(event: DetectionEvent) -> str:
    """Construct human-readable alert description (FR7.6)."""
    return (
        f"{event.severity} severity {event.attack_type} detected. "
        f"Source: {event.src_ip}:{event.src_port or '*'} → "
        f"Destination: {event.dst_ip}:{event.dst_port or '*'} "
        f"via {event.protocol or 'unknown'}. "
        f"Ensemble confidence: {event.ensemble_score:.3f}. "
        f"Detected by: {event.detected_by}."
    )


def _alert_to_dict(alert: Alert) -> dict:
    """Serialisable representation for Redis cache and WebSocket push."""
    return {
        "id": str(alert.id),
        "alert_id": str(alert.alert_id),
        "attack_type": alert.attack_type,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "detected_by": alert.detected_by,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
        "protocol": alert.protocol,
        "description": alert.description,
        "status": alert.status,
        "detected_at": alert.detected_at.isoformat(),
        "dup_count": alert.dup_count,
        "sig_confidence": alert.sig_confidence,
        "rf_confidence": alert.rf_confidence,
        "lstm_confidence": alert.lstm_confidence,
        "if_confidence": alert.if_confidence,
        "flow_id": str(alert.flow_id) if alert.flow_id else None,
    }


# ── Main entry point ──────────────────────────────────────────

async def process_detection_event(event: DetectionEvent) -> Optional[Alert]:
    """
    Full Stage 5 → Stage 6 pipeline:
      1. Compute ensemble score
      2. Gate on ALERT_THRESHOLD
      3. Check dedup window
      4. Persist to PostgreSQL
      5. Cache in Redis + publish to WebSocket channel
      6. Return created Alert ORM object (or None if below threshold / duplicate)

    This function is the single integration point between detection engines
    and the persistence layer. Call it from any pipeline stage that has a
    completed DetectionEvent.
    """
    t0 = time.monotonic()

    # ── Step 1: Compute weighted score ───────────────────────
    event = compute_ensemble_score(event)

    # ── Step 2: Alert threshold gate (FR6.1) ─────────────────
    if event.ensemble_score < ALERT_THRESHOLD:
        logger.debug(
            f"Below threshold: flow={event.flow_id} "
            f"score={event.ensemble_score:.4f} < {ALERT_THRESHOLD}"
        )
        return None

    # ── Step 3: Deduplication (FR8.5) ────────────────────────
    existing_id = await _is_duplicate(event.src_ip, event.dst_ip, event.attack_type)
    if existing_id:
        # Increment dup_count asynchronously — fire and forget
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select as sa_select
            result = await db.execute(
                sa_select(Alert).where(Alert.alert_id == existing_id)
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.dup_count += 1
                await db.commit()
        logger.debug(f"Duplicate suppressed: alert_id={existing_id}")
        return None

    # ── Step 4: Persist to PostgreSQL ────────────────────────
    sig_rule_id = event.sig_result.rule_id if event.sig_result else None
    alert_id = str(uuid4())

    alert = Alert(
        id=str(uuid4()),
        alert_id=alert_id,
        flow_id=event.flow_id,
        attack_type=event.attack_type,
        severity=event.severity,
        confidence=event.ensemble_score,
        detected_by=event.detected_by,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        description=_build_description(event),
        status="open",
        detected_at=datetime.now(timezone.utc),
        sig_confidence=event.sig_result.confidence  if event.sig_result  else None,
        rf_confidence=event.rf_result.confidence    if event.rf_result   else None,
        lstm_confidence=event.lstm_result.confidence if event.lstm_result else None,
        if_confidence=event.if_result.confidence    if event.if_result   else None,
        dup_count=0,
    )

    async with AsyncSessionLocal() as db:
        db.add(alert)
        await db.commit()
        await db.refresh(alert)

    elapsed_ms = (time.monotonic() - t0) * 1000
    logger.info(
        f"Alert persisted: alert_id={alert.alert_id} "
        f"severity={alert.severity} type={alert.attack_type} "
        f"score={event.ensemble_score:.3f} elapsed={elapsed_ms:.1f}ms"
    )

    # ── Step 5: Register dedup window ────────────────────────
    await _register_dedup(event.src_ip, event.dst_ip, event.attack_type, alert.alert_id)

    # ── Step 6: Redis cache + WebSocket publish ───────────────
    alert_dict = _alert_to_dict(alert)
    await redis_client.cache_alert(alert.alert_id, alert_dict)
    await redis_client.publish_alert_event(alert_dict)

    # ── Step 7: Warn if approaching latency budget ────────────
    if elapsed_ms > 80:
        logger.warning(
            f"Alert pipeline latency {elapsed_ms:.1f}ms exceeds 80ms SLO "
            f"(hard ceiling NFR1.4=100ms)"
        )

    return alert


# ── Convenience: create from raw scores (for testing / pipeline integration) ─

async def process_raw_scores(
    flow_id: str,
    src_ip: str,
    dst_ip: str,
    sig_confidence: float = 0.0,
    sig_attack_type: str = "BENIGN",
    sig_rule_id: Optional[str] = None,
    rf_confidence: float = 0.0,
    rf_attack_type: str = "BENIGN",
    lstm_confidence: float = 0.0,
    lstm_attack_type: str = "BENIGN",
    if_confidence: float = 0.0,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
) -> Optional[Alert]:
    """
    Convenience wrapper — build a DetectionEvent from raw engine scores
    and run it through the full pipeline.

    Use this from the ML Inference Engine when it has all four scores ready.
    """
    event = DetectionEvent(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        sig_result=EngineResult(
            engine="signature",
            confidence=sig_confidence,
            attack_type=sig_attack_type,
            rule_id=sig_rule_id,
        ) if sig_confidence > 0 else None,
        rf_result=EngineResult(
            engine="rf",
            confidence=rf_confidence,
            attack_type=rf_attack_type,
        ) if rf_confidence > 0 else None,
        lstm_result=EngineResult(
            engine="lstm",
            confidence=lstm_confidence,
            attack_type=lstm_attack_type,
        ) if lstm_confidence > 0 else None,
        if_result=EngineResult(
            engine="if",
            confidence=if_confidence,
            attack_type="ANOMALY" if if_confidence > 0 else "BENIGN",
        ) if if_confidence > 0 else None,
    )
    return await process_detection_event(event)
