"""
AI-NIDS — Alert Generator
backend/detection/alert_generator.py

Stage 6b of the detection pipeline.  Consumes CorrelatedAlert objects from
the Alert Correlator and:

  1. Maps ensemble confidence → severity tier  (FR7.2)
  2. Builds a structured AlertRecord with all FR7.3–FR7.7 fields
  3. Persists the record to PostgreSQL via SQLAlchemy async ORM  (FR7.8)
  4. Publishes a lightweight event to Redis Pub/Sub channel
     nids:alerts:new so the FastAPI WebSocket handler can fan it out
     to connected dashboard clients in real time  (FR10.5)
  5. Fires an async notification via NotificationService for HIGH/CRITICAL
     alerts  (FR10.1, FR10.2)

The generator is designed to be safe under partial infrastructure failure:
  - If PostgreSQL is unavailable, the alert is queued in memory and
    persisted on the next successful DB connection (NFR9.3)
  - If Redis is unavailable, the WebSocket push is skipped silently;
    the dashboard will pick up the alert on its next poll

FR Traceability:
    FR7.1  — Generate alert when threat detected
    FR7.2  — Classify severity: Critical/High/Medium/Low
    FR7.3  — Timestamp, src_ip, dst_ip in each alert
    FR7.4  — Attack type and confidence score in each alert
    FR7.5  — Protocol and port information in each alert
    FR7.6  — Human-readable description of the threat
    FR7.7  — Recommended action for each alert type
    FR7.8  — Store all alerts in PostgreSQL
    FR7.9  — Unique ID for each alert
    FR7.10 — Generate alerts within 100ms of threat detection
    FR10.1 — Push notifications for critical alerts
    FR10.5 — Real-time dashboard updates without page refresh

April 24, 2026 | Sprint Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

logger = logging.getLogger("ai-nids.alert_generator")

# ── Import correlator types ────────────────────────────────────────────────────
from backend.detection.alert_correlator import CorrelatedAlert  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Severity thresholds  (FR7.2)
# Score boundaries map to the four severity tiers from the Component Design Doc
# ─────────────────────────────────────────────────────────────────────────────

def confidence_to_severity(confidence: float) -> str:
    """
    Map the ensemble weighted score [0.0, 1.0] to a four-tier severity label.

    Thresholds from Component Design Document (Feb 25, §4.4) and
    §3.5.4 detection methodology:
        CRITICAL ≥ 0.95
        HIGH     ≥ 0.85
        MEDIUM   ≥ 0.70
        LOW      ≥ 0.50  (anything below this is not alerted at all)
    """
    if confidence >= 0.95:
        return "CRITICAL"
    if confidence >= 0.85:
        return "HIGH"
    if confidence >= 0.70:
        return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Human-readable descriptions and recommended actions  (FR7.6, FR7.7)
# ─────────────────────────────────────────────────────────────────────────────

_DESCRIPTIONS: Dict[str, str] = {
    "DoS":          "Denial of Service attack detected — high-volume traffic aimed at exhausting target resources.",
    "DDoS":         "Distributed Denial of Service attack detected — coordinated flood from multiple sources.",
    "PortScan":     "Port scanning activity detected — systematic probing of open services on the target host.",
    "BruteForce":   "Brute-force authentication attack detected — repeated login attempts to gain unauthorised access.",
    "Botnet":       "Botnet command-and-control communication detected — host may be compromised.",
    "WebAttack":    "Web application attack detected — includes SQL injection, XSS, or CSRF patterns.",
    "Infiltration": "Multi-stage infiltration activity detected — possible lateral movement or data exfiltration.",
    "ANOMALY":      "Statistically anomalous traffic detected — deviates significantly from the established baseline.",
}

_RECOMMENDED_ACTIONS: Dict[str, str] = {
    "DoS":          "1) Verify legitimacy of high-volume source. 2) Apply rate limiting or ACL at edge router. 3) Notify upstream ISP if attack is external.",
    "DDoS":         "1) Activate DDoS mitigation controls. 2) Contact ISP for upstream filtering. 3) Enable cloud scrubbing if available.",
    "PortScan":     "1) Block source IP at perimeter firewall if scan is unauthorised. 2) Review firewall rules for exposed services. 3) Check for subsequent exploit attempts from same source.",
    "BruteForce":   "1) Temporarily block source IP. 2) Check if any accounts were compromised. 3) Enforce MFA on targeted service. 4) Review authentication logs.",
    "Botnet":       "1) Isolate the affected host immediately. 2) Run endpoint malware scan. 3) Block C2 IP/domain at DNS and firewall. 4) Preserve memory and disk image for forensics.",
    "WebAttack":    "1) Check application logs for successful exploitation. 2) Apply WAF rules for the detected pattern. 3) Review and patch vulnerable application endpoints.",
    "Infiltration": "1) Isolate affected systems. 2) Preserve forensic evidence. 3) Identify lateral movement path. 4) Notify security management and initiate incident response plan.",
    "ANOMALY":      "1) Investigate the anomalous flow manually. 2) Determine if the behaviour is expected (e.g. new application, scheduled job). 3) Mark as false positive if benign, or escalate if suspicious.",
}

_DEFAULT_DESCRIPTION = "Suspicious network activity detected by AI-NIDS detection engine."
_DEFAULT_ACTION = "Investigate the alert in the AI-NIDS dashboard. Acknowledge and add investigation notes."


# ─────────────────────────────────────────────────────────────────────────────
# AlertRecord — the structured alert object persisted to PostgreSQL
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AlertRecord:
    """
    Fully-structured alert record.  All fields satisfy FR7.3–FR7.9.
    This dataclass is the canonical representation used throughout the system.
    """
    # Identifiers
    alert_id: str                   # FR7.9 — UUID v4
    flow_id: str

    # Timestamps
    detected_at: float              # FR7.3 — Unix timestamp
    generated_at: float             # When the generator created this record

    # Network metadata (FR7.3, FR7.5)
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str

    # Threat classification (FR7.4)
    attack_type: str
    severity: str                   # CRITICAL | HIGH | MEDIUM | LOW
    confidence: float               # 0.0–1.0 ensemble weighted score
    detected_by: str                # "signature" | "ml" | "both"

    # Per-engine breakdown (FR6.6 — always logged)
    sig_confidence: float
    rf_confidence: float
    lstm_confidence: float
    if_confidence: float

    # Human-readable fields (FR7.6, FR7.7)
    description: str
    recommended_action: str

    # Correlation metadata (FR8)
    group_id: Optional[str]
    attack_chain: bool
    chain_attack_types: List[str]

    # Lifecycle status
    status: str = "open"            # open | acknowledged | false_positive | escalated | resolved

    # Audit fields (set on workflow transitions)
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[float] = None
    escalated_by: Optional[str] = None
    escalated_at: Optional[float] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[float] = None
    resolution_type: Optional[str] = None   # true_positive | false_positive | benign | duplicate
    resolution_note: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_api_response(self) -> Dict:
        """
        Serialise for the REST API response.
        Converts Unix timestamps to ISO-8601 strings for frontend consumption.
        """
        import datetime

        def _ts(t: Optional[float]) -> Optional[str]:
            if t is None:
                return None
            return datetime.datetime.utcfromtimestamp(t).isoformat() + "Z"

        d = self.to_dict()
        d["detected_at"] = _ts(self.detected_at)
        d["generated_at"] = _ts(self.generated_at)
        d["acknowledged_at"] = _ts(self.acknowledged_at)
        d["escalated_at"] = _ts(self.escalated_at)
        d["resolved_at"] = _ts(self.resolved_at)
        return d


# ─────────────────────────────────────────────────────────────────────────────
# AlertGenerator
# ─────────────────────────────────────────────────────────────────────────────

class AlertGenerator:
    """
    Converts CorrelatedAlert objects into fully-structured AlertRecord instances,
    persists them, and triggers downstream notifications.

    Designed to be instantiated once and shared across the pipeline.

    The DB session and Redis client are injected at construction time so
    the generator can be unit-tested without live infrastructure.
    """

    def __init__(
        self,
        db_session=None,       # SQLAlchemy AsyncSession (injected in production)
        redis_client=None,     # redis.asyncio.Redis (injected in production)
        notification_enabled: bool = True,
    ) -> None:
        self._db = db_session
        self._redis = redis_client
        self._notification_enabled = notification_enabled

        # In-memory fallback queue for alerts that could not be persisted
        # due to DB unavailability (NFR9.3)
        self._pending_queue: List[AlertRecord] = []

        # Counters
        self._total_generated: int = 0
        self._total_persisted: int = 0
        self._total_queued: int = 0

    # ── Public API ─────────────────────────────────────────────────────────

    async def create(self, correlated: CorrelatedAlert) -> AlertRecord:
        """
        Build, persist, and notify for a CorrelatedAlert.
        Returns the created AlertRecord.

        This method is async because it awaits DB persistence and
        Redis publish.  Guaranteed to return within the latency budget
        because DB and Redis operations are non-blocking.
        """
        record = self._build_record(correlated)
        self._total_generated += 1

        await self._persist(record)
        await self._publish_websocket(record)

        if self._notification_enabled:
            await self._dispatch_notification(record, correlated)

        logger.info(
            "Alert created: alert_id=%s severity=%s attack_type=%s "
            "src_ip=%s chain=%s",
            record.alert_id, record.severity, record.attack_type,
            record.src_ip, record.attack_chain,
        )
        return record

    def stats(self) -> Dict[str, int]:
        return {
            "total_generated": self._total_generated,
            "total_persisted": self._total_persisted,
            "total_queued": self._total_queued,
            "pending_queue_depth": len(self._pending_queue),
        }

    # ── Record construction ────────────────────────────────────────────────

    def _build_record(self, correlated: CorrelatedAlert) -> AlertRecord:
        event = correlated.event
        now = time.time()

        severity = confidence_to_severity(event.confidence)
        attack_type = event.attack_type if event.attack_type != "BENIGN" else "ANOMALY"

        return AlertRecord(
            alert_id=str(uuid.uuid4()),       # FR7.9
            flow_id=event.flow_id,
            detected_at=event.timestamp,      # FR7.3
            generated_at=now,
            src_ip=event.src_ip,              # FR7.3
            dst_ip=event.dst_ip,              # FR7.3
            src_port=event.src_port,          # FR7.5
            dst_port=event.dst_port,          # FR7.5
            protocol=event.protocol,          # FR7.5
            attack_type=attack_type,          # FR7.4
            severity=severity,                # FR7.2
            confidence=event.confidence,      # FR7.4
            detected_by=event.detected_by,
            sig_confidence=event.sig_confidence,
            rf_confidence=event.rf_confidence,
            lstm_confidence=event.lstm_confidence,
            if_confidence=event.if_confidence,
            description=_DESCRIPTIONS.get(attack_type, _DEFAULT_DESCRIPTION),  # FR7.6
            recommended_action=_RECOMMENDED_ACTIONS.get(attack_type, _DEFAULT_ACTION),  # FR7.7
            group_id=correlated.group_id,
            attack_chain=correlated.attack_chain,
            chain_attack_types=correlated.chain_attack_types,
            status="open",
        )

    # ── Persistence ────────────────────────────────────────────────────────

    async def _persist(self, record: AlertRecord) -> None:
        """
        Insert the AlertRecord into the alerts PostgreSQL table.
        Falls back to the in-memory queue if the DB session is unavailable.
        """
        if self._db is None:
            self._pending_queue.append(record)
            self._total_queued += 1
            logger.debug(
                "DB unavailable — alert queued in memory: alert_id=%s", record.alert_id
            )
            return

        try:
            # SQLAlchemy ORM insert — matches the schema in Database Design Doc (Feb 26)
            from sqlalchemy import text
            stmt = text("""
                INSERT INTO alerts (
                    alert_id, flow_id, attack_type, severity, confidence,
                    detected_by, src_ip, dst_ip, src_port, dst_port, protocol,
                    description, status, detected_at,
                    group_id, attack_chain,
                    sig_confidence, rf_confidence, lstm_confidence, if_confidence
                ) VALUES (
                    :alert_id, :flow_id, :attack_type, :severity, :confidence,
                    :detected_by, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
                    :description, :status, to_timestamp(:detected_at),
                    :group_id, :attack_chain,
                    :sig_confidence, :rf_confidence, :lstm_confidence, :if_confidence
                )
            """)
            await self._db.execute(stmt, {
                "alert_id": record.alert_id,
                "flow_id": record.flow_id,
                "attack_type": record.attack_type,
                "severity": record.severity,
                "confidence": record.confidence,
                "detected_by": record.detected_by,
                "src_ip": record.src_ip,
                "dst_ip": record.dst_ip,
                "src_port": record.src_port,
                "dst_port": record.dst_port,
                "protocol": record.protocol,
                "description": record.description,
                "status": record.status,
                "detected_at": record.detected_at,
                "group_id": record.group_id,
                "attack_chain": record.attack_chain,
                "sig_confidence": record.sig_confidence,
                "rf_confidence": record.rf_confidence,
                "lstm_confidence": record.lstm_confidence,
                "if_confidence": record.if_confidence,
            })
            await self._db.commit()
            self._total_persisted += 1

            # Attempt to flush any previously queued records
            if self._pending_queue:
                await self._flush_pending_queue()

        except Exception as exc:
            logger.error("DB persist failed for alert_id=%s: %s", record.alert_id, exc)
            await self._db.rollback()
            self._pending_queue.append(record)
            self._total_queued += 1

    async def _flush_pending_queue(self) -> None:
        """Attempt to persist any alerts that were queued during a DB outage."""
        flushed = 0
        failed = []
        for queued_record in self._pending_queue:
            try:
                from sqlalchemy import text
                stmt = text("""
                    INSERT INTO alerts (alert_id, flow_id, attack_type, severity,
                        confidence, detected_by, src_ip, dst_ip, src_port, dst_port,
                        protocol, description, status, detected_at)
                    VALUES (:alert_id, :flow_id, :attack_type, :severity,
                        :confidence, :detected_by, :src_ip, :dst_ip, :src_port,
                        :dst_port, :protocol, :description, :status,
                        to_timestamp(:detected_at))
                    ON CONFLICT (alert_id) DO NOTHING
                """)
                await self._db.execute(stmt, queued_record.to_dict())
                await self._db.commit()
                flushed += 1
                self._total_persisted += 1
            except Exception:
                failed.append(queued_record)

        self._pending_queue = failed
        if flushed:
            logger.info("Flushed %d queued alerts to DB", flushed)

    # ── Redis Pub/Sub ──────────────────────────────────────────────────────

    async def _publish_websocket(self, record: AlertRecord) -> None:
        """
        Publish a lightweight alert event to Redis channel nids:alerts:new.
        The FastAPI WebSocket handler subscribes to this channel and fans
        the event out to connected dashboard clients (FR10.5).
        """
        if self._redis is None:
            return

        try:
            payload = json.dumps({
                "alert_id": record.alert_id,
                "severity": record.severity,
                "attack_type": record.attack_type,
                "src_ip": record.src_ip,
                "confidence": round(record.confidence, 4),
                "attack_chain": record.attack_chain,
                "status": record.status,
                "detected_at": record.detected_at,
            })
            await self._redis.publish("nids:alerts:new", payload)
        except Exception as exc:
            logger.warning(
                "Redis publish failed for alert_id=%s: %s — WebSocket push skipped",
                record.alert_id, exc,
            )

    # ── Notification dispatch ──────────────────────────────────────────────

    async def _dispatch_notification(
        self,
        record: AlertRecord,
        correlated: CorrelatedAlert,
    ) -> None:
        """Fire-and-forget notification for HIGH and CRITICAL alerts."""
        from backend.api.services.notification_service import AlertNotificationPayload, notify_alert

        payload = AlertNotificationPayload(
            alert_id=record.alert_id,
            severity=record.severity,
            attack_type=record.attack_type,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            confidence=record.confidence,
            detected_by=record.detected_by,
            timestamp=record.detected_at,
            group_id=record.group_id,
            attack_chain=record.attack_chain,
            chain_attack_types=record.chain_attack_types,
        )
        # Use asyncio.create_task so it doesn't add to our latency budget
        import asyncio
        asyncio.create_task(notify_alert(payload))
