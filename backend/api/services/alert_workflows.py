"""
AI-NIDS — Alert Management Workflows
backend/api/services/alert_workflows.py

Implements the four analyst-facing lifecycle transitions for an alert:

  1. acknowledge   — analyst claims ownership of an alert  (FR9.8)
  2. escalate      — alert routed to higher tier + notification fired  (FR9.13 / US-3.7)
  3. false_positive — analyst marks detection as a false alarm  (FR9.13)
  4. resolve       — alert closed with a resolution type and mandatory note  (US-3.8)

Every transition:
  - Validates the current status is a legal predecessor  (prevents e.g.
    resolving an already-resolved alert)
  - Writes an immutable row to audit_log  (NFR7.1, NFR7.2)
  - Updates the alerts table in PostgreSQL
  - Publishes a status-change event to Redis Pub/Sub (nids:alerts:status)
    so connected dashboard clients update in real time  (FR10.5)
  - For ESCALATE: fires an async notification via NotificationService

Status machine:
    open  →  acknowledged  →  escalated  →  resolved
      ↘                    ↗
       false_positive  ────┘  (also terminal, but re-openable by SOC Manager)

Any open alert can be marked false_positive directly (skips acknowledge).
Any acknowledged or escalated alert can be resolved.

FR Traceability:
    FR9.8  — Acknowledge alerts
    FR9.9  — Track who acknowledged and when
    FR9.10 — Add notes to alerts
    FR9.11 — Assign alerts to team members (escalation target)
    FR9.12 — Close/resolve alerts
    FR9.13 — Mark alerts as false positives
    FR10.2 — Email notifications for HIGH/CRITICAL (triggered on escalation)
    NFR7.1 — Log all authentication/action attempts
    NFR7.2 — Log all administrative actions

April 24, 2026 | Sprint Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger("ai-nids.alert_workflows")


# ─────────────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────────────

class AlertNotFoundError(Exception):
    """Raised when the requested alert_id does not exist."""


class InvalidTransitionError(Exception):
    """Raised when the requested status transition is not permitted."""


class MissingRequiredFieldError(Exception):
    """Raised when a mandatory field (e.g. resolution_note) is absent."""


# ─────────────────────────────────────────────────────────────────────────────
# Valid predecessor states for each transition
# ─────────────────────────────────────────────────────────────────────────────

_VALID_PREDECESSORS: Dict[str, set] = {
    "acknowledged":    {"open"},
    "escalated":       {"open", "acknowledged"},
    "false_positive":  {"open", "acknowledged"},
    "resolved":        {"acknowledged", "escalated", "false_positive"},
}

# Resolution types accepted by the resolve workflow
VALID_RESOLUTION_TYPES = {"true_positive", "false_positive", "benign", "duplicate"}


# ─────────────────────────────────────────────────────────────────────────────
# Request dataclasses (mirror FastAPI Pydantic models in the router layer)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AcknowledgeRequest:
    performed_by: str          # username of the analyst
    note: Optional[str] = None


@dataclass
class EscalateRequest:
    performed_by: str          # username who triggered the escalation
    escalation_target: str     # username or group being escalated to
    note: Optional[str] = None


@dataclass
class FalsePositiveRequest:
    performed_by: str
    note: Optional[str] = None


@dataclass
class ResolveRequest:
    performed_by: str
    resolution_type: str       # must be in VALID_RESOLUTION_TYPES
    resolution_note: str       # mandatory (US-3.8 AC2)


# ─────────────────────────────────────────────────────────────────────────────
# Audit log helper
# ─────────────────────────────────────────────────────────────────────────────

async def _write_audit_log(
    db,
    user_id: str,
    action: str,
    entity_id: str,
    detail: Dict,
    ip_address: str = "127.0.0.1",
) -> None:
    """
    Insert an immutable row into the audit_log table.
    Rows are INSERT-only — never updated or deleted (NFR7.3).

    Parameters
    ----------
    db          : SQLAlchemy AsyncSession
    user_id     : username performing the action
    action      : action code e.g. "ALERT_ACKNOWLEDGE"
    entity_id   : alert_id (UUID string)
    detail      : arbitrary JSON context (before/after values etc.)
    ip_address  : client IP — passed in from the HTTP request in the router
    """
    if db is None:
        logger.debug("Audit log skipped — no DB session (test mode)")
        return

    try:
        from sqlalchemy import text
        stmt = text("""
            INSERT INTO audit_log (
                id, user_id, action, entity_type, entity_id,
                ip_address, detail, created_at
            ) VALUES (
                :id, :user_id, :action, 'alert', :entity_id,
                :ip_address, :detail::jsonb, NOW()
            )
        """)
        await db.execute(stmt, {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "action": action,
            "entity_id": entity_id,
            "ip_address": ip_address,
            "detail": json.dumps(detail),
        })
        await db.commit()
    except Exception as exc:
        logger.error(
            "Audit log write failed: action=%s entity_id=%s error=%s",
            action, entity_id, exc,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Redis publish helper
# ─────────────────────────────────────────────────────────────────────────────

async def _publish_status_change(
    redis,
    alert_id: str,
    new_status: str,
    severity: str,
    performed_by: str,
) -> None:
    """
    Publish a status-change event so WebSocket clients can update the
    alert row in the dashboard without a full page reload (FR10.5).
    """
    if redis is None:
        return
    try:
        payload = json.dumps({
            "event": "alert.status_changed",
            "alert_id": alert_id,
            "new_status": new_status,
            "severity": severity,
            "performed_by": performed_by,
            "timestamp": time.time(),
        })
        await redis.publish("nids:alerts:status", payload)
    except Exception as exc:
        logger.warning(
            "Redis publish failed for status change alert_id=%s: %s",
            alert_id, exc,
        )


# ─────────────────────────────────────────────────────────────────────────────
# AlertWorkflowService
# ─────────────────────────────────────────────────────────────────────────────

class AlertWorkflowService:
    """
    Implements the four alert lifecycle transitions.

    Inject a SQLAlchemy AsyncSession and redis.asyncio.Redis client at
    construction time.  Both are optional so the service can be unit-tested
    without live infrastructure.

    Example (in a FastAPI router):

        from fastapi import Depends
        from sqlalchemy.ext.asyncio import AsyncSession
        from backend.db.session import get_session
        from backend.cache.redis import get_redis

        @router.patch("/alerts/{alert_id}/acknowledge")
        async def acknowledge(
            alert_id: str,
            body: AcknowledgeBody,
            db: AsyncSession = Depends(get_session),
            redis = Depends(get_redis),
        ):
            svc = AlertWorkflowService(db=db, redis=redis)
            record = await svc.acknowledge(alert_id, AcknowledgeRequest(...))
            return record.to_api_response()
    """

    def __init__(self, db=None, redis=None) -> None:
        self._db = db
        self._redis = redis

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    async def _fetch_alert(self, alert_id: str) -> Dict:
        """
        Fetch a single alert row from PostgreSQL.
        Raises AlertNotFoundError if not found.
        """
        if self._db is None:
            raise AlertNotFoundError(f"alert_id={alert_id} (no DB session in test mode)")

        from sqlalchemy import text
        row = (await self._db.execute(
            text("SELECT * FROM alerts WHERE alert_id = :id"),
            {"id": alert_id},
        )).mappings().one_or_none()

        if row is None:
            raise AlertNotFoundError(f"alert_id={alert_id} not found")
        return dict(row)

    def _assert_transition(self, alert: Dict, target_status: str) -> None:
        """
        Validate that transitioning from alert['status'] to target_status
        is permitted.  Raises InvalidTransitionError otherwise.
        """
        current = alert.get("status", "unknown")
        allowed = _VALID_PREDECESSORS.get(target_status, set())
        if current not in allowed:
            raise InvalidTransitionError(
                f"Cannot transition alert from '{current}' to '{target_status}'. "
                f"Allowed predecessors: {sorted(allowed)}"
            )

    async def _update_alert(self, alert_id: str, updates: Dict) -> None:
        """Apply a partial UPDATE to the alerts table."""
        if self._db is None:
            return

        from sqlalchemy import text
        set_clauses = ", ".join(f"{col} = :{col}" for col in updates)
        stmt = text(f"UPDATE alerts SET {set_clauses} WHERE alert_id = :alert_id")
        await self._db.execute(stmt, {**updates, "alert_id": alert_id})
        await self._db.commit()

    # ──────────────────────────────────────────────────────────────────────
    # 1. Acknowledge  (FR9.8, FR9.9)
    # ──────────────────────────────────────────────────────────────────────

    async def acknowledge(
        self,
        alert_id: str,
        request: AcknowledgeRequest,
        client_ip: str = "127.0.0.1",
    ) -> Dict:
        """
        Mark an alert as acknowledged.

        Transitions: open → acknowledged
        Sets acknowledged_by and acknowledged_at.
        Writes audit_log row with action=ALERT_ACKNOWLEDGE.

        Returns the updated alert dict.
        """
        alert = await self._fetch_alert(alert_id)
        self._assert_transition(alert, "acknowledged")

        now = time.time()
        updates = {
            "status": "acknowledged",
            "acknowledged_by": request.performed_by,
            "acknowledged_at": now,
        }
        await self._update_alert(alert_id, updates)

        await _write_audit_log(
            db=self._db,
            user_id=request.performed_by,
            action="ALERT_ACKNOWLEDGE",
            entity_id=alert_id,
            detail={
                "previous_status": alert["status"],
                "note": request.note,
            },
            ip_address=client_ip,
        )

        await _publish_status_change(
            redis=self._redis,
            alert_id=alert_id,
            new_status="acknowledged",
            severity=alert.get("severity", "UNKNOWN"),
            performed_by=request.performed_by,
        )

        logger.info(
            "Alert acknowledged: alert_id=%s by=%s",
            alert_id, request.performed_by,
        )
        return {**alert, **updates}

    # ──────────────────────────────────────────────────────────────────────
    # 2. Escalate  (FR9.11, US-3.7)
    # ──────────────────────────────────────────────────────────────────────

    async def escalate(
        self,
        alert_id: str,
        request: EscalateRequest,
        client_ip: str = "127.0.0.1",
    ) -> Dict:
        """
        Escalate an alert to a higher tier or external team.

        Transitions: open | acknowledged → escalated
        Fires an async notification email + webhook to the escalation target.
        Writes audit_log row with action=ALERT_ESCALATE.

        Returns the updated alert dict.
        """
        alert = await self._fetch_alert(alert_id)
        self._assert_transition(alert, "escalated")

        now = time.time()
        updates = {
            "status": "escalated",
            "escalated_by": request.performed_by,
            "escalated_at": now,
        }
        await self._update_alert(alert_id, updates)

        await _write_audit_log(
            db=self._db,
            user_id=request.performed_by,
            action="ALERT_ESCALATE",
            entity_id=alert_id,
            detail={
                "previous_status": alert["status"],
                "escalation_target": request.escalation_target,
                "note": request.note,
            },
            ip_address=client_ip,
        )

        await _publish_status_change(
            redis=self._redis,
            alert_id=alert_id,
            new_status="escalated",
            severity=alert.get("severity", "UNKNOWN"),
            performed_by=request.performed_by,
        )

        # Fire escalation notification (non-blocking)
        asyncio.create_task(
            self._fire_escalation_notification(alert, request)
        )

        logger.warning(
            "Alert escalated: alert_id=%s by=%s target=%s severity=%s",
            alert_id, request.performed_by,
            request.escalation_target, alert.get("severity"),
        )
        return {**alert, **updates}

    async def _fire_escalation_notification(
        self,
        alert: Dict,
        request: EscalateRequest,
    ) -> None:
        """Build payload and call the notification service for escalations."""
        try:
            from notification_service import AlertNotificationPayload, notify_escalation
            payload = AlertNotificationPayload(
                alert_id=alert["alert_id"],
                severity=alert.get("severity", "HIGH"),
                attack_type=alert.get("attack_type", "UNKNOWN"),
                src_ip=alert.get("src_ip", ""),
                dst_ip=alert.get("dst_ip", ""),
                confidence=float(alert.get("confidence", 0.0)),
                detected_by=alert.get("detected_by", "unknown"),
                timestamp=float(alert.get("detected_at", time.time())),
                group_id=str(alert.get("group_id", "")),
                attack_chain=bool(alert.get("attack_chain", False)),
            )
            await notify_escalation(payload, escalated_by=request.performed_by)
        except Exception as exc:
            logger.error(
                "Escalation notification failed for alert_id=%s: %s",
                alert.get("alert_id"), exc,
            )

    # ──────────────────────────────────────────────────────────────────────
    # 3. False Positive  (FR9.13)
    # ──────────────────────────────────────────────────────────────────────

    async def mark_false_positive(
        self,
        alert_id: str,
        request: FalsePositiveRequest,
        client_ip: str = "127.0.0.1",
    ) -> Dict:
        """
        Mark an alert as a false positive.

        Transitions: open | acknowledged → false_positive
        Writes audit_log row with action=ALERT_FALSE_POSITIVE.

        The false-positive label is stored in the feedback log and will be
        included in the next RF/LSTM retraining cycle (FR19).

        Returns the updated alert dict.
        """
        alert = await self._fetch_alert(alert_id)
        self._assert_transition(alert, "false_positive")

        now = time.time()
        updates = {
            "status": "false_positive",
            "resolved_by": request.performed_by,
            "resolved_at": now,
            "resolution_type": "false_positive",
            "resolution_note": request.note or "Marked as false positive by analyst.",
        }
        await self._update_alert(alert_id, updates)

        await _write_audit_log(
            db=self._db,
            user_id=request.performed_by,
            action="ALERT_FALSE_POSITIVE",
            entity_id=alert_id,
            detail={
                "previous_status": alert["status"],
                "attack_type": alert.get("attack_type"),
                "confidence": alert.get("confidence"),
                "note": request.note,
            },
            ip_address=client_ip,
        )

        await _publish_status_change(
            redis=self._redis,
            alert_id=alert_id,
            new_status="false_positive",
            severity=alert.get("severity", "UNKNOWN"),
            performed_by=request.performed_by,
        )

        logger.info(
            "Alert marked false positive: alert_id=%s by=%s attack_type=%s",
            alert_id, request.performed_by, alert.get("attack_type"),
        )
        return {**alert, **updates}

    # ──────────────────────────────────────────────────────────────────────
    # 4. Resolve  (FR9.12, US-3.8)
    # ──────────────────────────────────────────────────────────────────────

    async def resolve(
        self,
        alert_id: str,
        request: ResolveRequest,
        client_ip: str = "127.0.0.1",
    ) -> Dict:
        """
        Close an alert with a mandatory resolution type and note.

        Transitions: acknowledged | escalated | false_positive → resolved
        Writes audit_log row with action=ALERT_RESOLVE.

        resolution_type must be one of:
            true_positive | false_positive | benign | duplicate

        Returns the updated alert dict.
        """
        # Validate resolution_type before touching the DB
        if request.resolution_type not in VALID_RESOLUTION_TYPES:
            raise MissingRequiredFieldError(
                f"resolution_type must be one of {sorted(VALID_RESOLUTION_TYPES)}, "
                f"got '{request.resolution_type}'"
            )
        if not request.resolution_note or not request.resolution_note.strip():
            raise MissingRequiredFieldError(
                "resolution_note is mandatory when closing an alert (US-3.8 AC2)"
            )

        alert = await self._fetch_alert(alert_id)
        self._assert_transition(alert, "resolved")

        now = time.time()
        updates = {
            "status": "resolved",
            "resolved_by": request.performed_by,
            "resolved_at": now,
            "resolution_type": request.resolution_type,
            "resolution_note": request.resolution_note.strip(),
        }
        await self._update_alert(alert_id, updates)

        await _write_audit_log(
            db=self._db,
            user_id=request.performed_by,
            action="ALERT_RESOLVE",
            entity_id=alert_id,
            detail={
                "previous_status": alert["status"],
                "resolution_type": request.resolution_type,
                "resolution_note": request.resolution_note,
            },
            ip_address=client_ip,
        )

        await _publish_status_change(
            redis=self._redis,
            alert_id=alert_id,
            new_status="resolved",
            severity=alert.get("severity", "UNKNOWN"),
            performed_by=request.performed_by,
        )

        logger.info(
            "Alert resolved: alert_id=%s by=%s resolution=%s",
            alert_id, request.performed_by, request.resolution_type,
        )
        return {**alert, **updates}

    # ──────────────────────────────────────────────────────────────────────
    # 5. Reopen  (US-3.8 AC4 — SOC Manager can reopen)
    # ──────────────────────────────────────────────────────────────────────

    async def reopen(
        self,
        alert_id: str,
        performed_by: str,
        note: Optional[str] = None,
        client_ip: str = "127.0.0.1",
    ) -> Dict:
        """
        Reopen a resolved or false_positive alert.
        Only permitted when new evidence warrants re-investigation.

        Transitions: resolved | false_positive → open
        Writes audit_log row with action=ALERT_REOPEN.
        """
        alert = await self._fetch_alert(alert_id)
        if alert.get("status") not in {"resolved", "false_positive"}:
            raise InvalidTransitionError(
                f"Can only reopen alerts in 'resolved' or 'false_positive' state, "
                f"got '{alert.get('status')}'"
            )

        updates = {"status": "open"}
        await self._update_alert(alert_id, updates)

        await _write_audit_log(
            db=self._db,
            user_id=performed_by,
            action="ALERT_REOPEN",
            entity_id=alert_id,
            detail={
                "previous_status": alert["status"],
                "note": note,
            },
            ip_address=client_ip,
        )

        await _publish_status_change(
            redis=self._redis,
            alert_id=alert_id,
            new_status="open",
            severity=alert.get("severity", "UNKNOWN"),
            performed_by=performed_by,
        )

        logger.info(
            "Alert reopened: alert_id=%s by=%s", alert_id, performed_by
        )
        return {**alert, **updates}
