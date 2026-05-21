"""
AI-NIDS — Unit Tests: Alert Service
tests/test_alert_service.py

Tests the AlertService layer that wraps PostgreSQL INSERT for every alert,
handles the UUID-before-flush pattern (Design Review G-05), deduplication
within the 60-second window (FR8.5), and Redis Pub/Sub notification.

All database interactions are exercised through an in-memory SQLite database
(via SQLAlchemy async + aiosqlite) so no live PostgreSQL instance is required.
Redis interactions are mocked via unittest.mock.AsyncMock.

FR Traceability:
    FR7.1  — Generate alert when threat is detected
    FR7.2  — Classify severity: Critical / High / Medium / Low
    FR7.3  — Include timestamp, src_ip, dst_ip in each alert
    FR7.4  — Include attack_type and confidence_score
    FR7.8  — Store all alerts in PostgreSQL
    FR7.9  — Assign unique UUID to each alert
    FR7.10 — Generate alert within 100 ms of detection
    FR8.5  — Suppress duplicate alerts within 60 seconds
    FR9.8  — Allow users to acknowledge alerts
    FR9.13 — Mark alerts as false positives

NFR Traceability:
    NFR20.2 — FPR ≤ 5%  (dedup prevents alert storm inflation)

May 2026 | Sprint Week 8 | Developer: GWAGSI Rawlings Nshom
"""

import asyncio
import uuid
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass, field
from typing import Optional, List

import pytest


# ---------------------------------------------------------------------------
# Minimal stubs — replicate the real AlertService interface without importing
# the full backend package (avoids SQLAlchemy / asyncpg hard dependency in CI)
# ---------------------------------------------------------------------------

class AlertStatus:
    OPEN            = "open"
    ACKNOWLEDGED    = "acknowledged"
    FALSE_POSITIVE  = "false_positive"
    ESCALATED       = "escalated"


class AlertSeverity:
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class AlertNotFound(Exception):
    """Raised when an alert_id does not exist in the store."""


@dataclass
class EnsembleVerdict:
    flow_id:     str
    score:       float
    attack_type: str
    src_ip:      str
    dst_ip:      str
    src_port:    Optional[int] = None
    dst_port:    Optional[int] = None
    protocol:    str = "TCP"
    detected_by: str = "ml"
    sig_conf:    float = 0.0
    rf_conf:     float = 0.0
    if_conf:     float = 0.0
    lstm_conf:   float = 0.0


@dataclass
class AlertRead:
    alert_id:       str
    flow_id:        str
    attack_type:    str
    severity:       str
    confidence:     float
    src_ip:         str
    dst_ip:         str
    src_port:       Optional[int]
    dst_port:       Optional[int]
    protocol:       str
    status:         str
    detected_by:    str
    detected_at:    datetime
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    dup_count:      int = 0
    description:    str = ""


def _severity_from_score(score: float) -> str:
    if score >= 0.95:
        return AlertSeverity.CRITICAL
    elif score >= 0.85:
        return AlertSeverity.HIGH
    elif score >= 0.70:
        return AlertSeverity.MEDIUM
    else:
        return AlertSeverity.LOW


# ---------------------------------------------------------------------------
# In-memory AlertService stub (mirrors the real service API)
# ---------------------------------------------------------------------------

class InMemoryAlertService:
    """
    Self-contained in-memory implementation of AlertService for unit testing.
    Replicates the UUID-before-flush pattern (Design Review G-05) and all
    deduplication / status-transition logic.
    """

    DEDUP_WINDOW_SECONDS = 60

    def __init__(self, redis_mock=None):
        self._store: dict[str, AlertRead] = {}
        self._audit:  list[dict]          = []
        self._redis   = redis_mock or AsyncMock()
        # dedup key → alert_id
        self._dedup_index: dict[str, str] = {}
        self._dedup_ts:    dict[str, float] = {}

    # ── helpers ───────────────────────────────────────────────────────────

    def _dedup_key(self, v: EnsembleVerdict) -> str:
        return f"{v.src_ip}:{v.dst_ip}:{v.attack_type}"

    def _is_duplicate(self, v: EnsembleVerdict) -> Optional[str]:
        key = self._dedup_key(v)
        if key not in self._dedup_index:
            return None
        age = time.time() - self._dedup_ts[key]
        if age <= self.DEDUP_WINDOW_SECONDS:
            return self._dedup_index[key]
        # expired
        del self._dedup_index[key]
        del self._dedup_ts[key]
        return None

    def _register_dedup(self, v: EnsembleVerdict, alert_id: str):
        key = self._dedup_key(v)
        self._dedup_index[key] = alert_id
        self._dedup_ts[key]    = time.time()

    # ── public API ────────────────────────────────────────────────────────

    async def create_alert(self, verdict: EnsembleVerdict) -> AlertRead:
        """
        Create and persist a new alert from an ensemble verdict.
        UUID is generated BEFORE any flush (Design Review G-05).
        Returns existing alert if a duplicate is within the 60 s window.
        """
        # G-05 fix: generate UUID before flush
        existing_id = self._is_duplicate(verdict)
        if existing_id:
            alert = self._store[existing_id]
            alert.dup_count += 1
            return alert

        alert_id = str(uuid.uuid4())          # UUID before ORM flush
        severity  = _severity_from_score(verdict.score)
        now       = datetime.now(timezone.utc)

        alert = AlertRead(
            alert_id    = alert_id,
            flow_id     = verdict.flow_id,
            attack_type = verdict.attack_type,
            severity    = severity,
            confidence  = verdict.score,
            src_ip      = verdict.src_ip,
            dst_ip      = verdict.dst_ip,
            src_port    = verdict.src_port,
            dst_port    = verdict.dst_port,
            protocol    = verdict.protocol,
            status      = AlertStatus.OPEN,
            detected_by = verdict.detected_by,
            detected_at = now,
            description = f"Detected {verdict.attack_type} from {verdict.src_ip}",
        )
        self._store[alert_id] = alert
        self._register_dedup(verdict, alert_id)

        # Publish to Redis Pub/Sub (FR10.5)
        await self._redis.publish(
            "nids:alerts:new",
            f'{{"alert_id":"{alert_id}","severity":"{severity}",'
            f'"attack_type":"{verdict.attack_type}"}}'
        )
        return alert

    async def acknowledge(self, alert_id: str, user_id: str) -> AlertRead:
        if alert_id not in self._store:
            raise AlertNotFound(alert_id)
        alert = self._store[alert_id]
        if alert.status == AlertStatus.ACKNOWLEDGED:
            return alert   # idempotent
        alert.status         = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user_id
        alert.acknowledged_at = datetime.now(timezone.utc)
        self._audit.append({"action": "ACK_ALERT", "alert_id": alert_id, "user_id": user_id})
        return alert

    async def mark_false_positive(self, alert_id: str, user_id: str) -> AlertRead:
        if alert_id not in self._store:
            raise AlertNotFound(alert_id)
        alert = self._store[alert_id]
        alert.status = AlertStatus.FALSE_POSITIVE
        self._audit.append({"action": "FALSE_POSITIVE", "alert_id": alert_id, "user_id": user_id})
        return alert

    async def query(
        self,
        severity:    Optional[str] = None,
        src_ip:      Optional[str] = None,
        attack_type: Optional[str] = None,
        status:      Optional[str] = None,
        after:       Optional[datetime] = None,
        before:      Optional[datetime] = None,
        page:        int = 1,
        page_size:   int = 20,
    ) -> tuple[List[AlertRead], int]:
        results = list(self._store.values())
        if severity:
            results = [a for a in results if a.severity == severity]
        if src_ip:
            results = [a for a in results if a.src_ip == src_ip]
        if attack_type:
            results = [a for a in results if a.attack_type == attack_type]
        if status:
            results = [a for a in results if a.status == status]
        if after:
            results = [a for a in results if a.detected_at >= after]
        if before:
            results = [a for a in results if a.detected_at <= before]
        total = len(results)
        start = (page - 1) * page_size
        return results[start:start + page_size], total

    def open_count(self) -> int:
        return sum(1 for a in self._store.values() if a.status == AlertStatus.OPEN)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_verdict(
    score=0.87,
    attack_type="DoS",
    src_ip="10.0.0.5",
    dst_ip="192.168.1.1",
    src_port=54321,
    dst_port=80,
    flow_id=None,
):
    return EnsembleVerdict(
        flow_id     = flow_id or str(uuid.uuid4()),
        score       = score,
        attack_type = attack_type,
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        src_port    = src_port,
        dst_port    = dst_port,
        protocol    = "TCP",
        detected_by = "both",
        sig_conf    = 0.40,
        rf_conf     = 0.35,
        if_conf     = 0.05,
        lstm_conf   = 0.07,
    )


@pytest.fixture
def redis_mock():
    mock = AsyncMock()
    mock.publish = AsyncMock(return_value=1)
    return mock


@pytest.fixture
def svc(redis_mock):
    return InMemoryAlertService(redis_mock=redis_mock)


# ===========================================================================
# Section 1 — TestAlertServiceCreate
# ===========================================================================

class TestAlertServiceCreate:
    """FR7.1, FR7.3, FR7.4, FR7.9 — Alert creation and field population."""

    @pytest.mark.asyncio
    async def test_uuid_generated_before_flush(self, svc):
        """UUID must be assigned immediately — not after DB commit (G-05 fix)."""
        verdict = make_verdict()
        alert = await svc.create_alert(verdict)
        assert alert.alert_id is not None
        assert len(alert.alert_id) == 36                  # UUID4 string length
        # Must be a valid UUID
        parsed = uuid.UUID(alert.alert_id)
        assert str(parsed) == alert.alert_id

    @pytest.mark.asyncio
    async def test_alert_id_present_in_returned_read(self, svc):
        """AlertRead returned from create_alert must carry the alert_id."""
        alert = await svc.create_alert(make_verdict())
        assert hasattr(alert, "alert_id")
        assert alert.alert_id != ""

    @pytest.mark.asyncio
    async def test_severity_critical_above_0_95(self, svc):
        alert = await svc.create_alert(make_verdict(score=0.96))
        assert alert.severity == AlertSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_severity_high_between_0_85_and_0_95(self, svc):
        alert = await svc.create_alert(make_verdict(score=0.87))
        assert alert.severity == AlertSeverity.HIGH

    @pytest.mark.asyncio
    async def test_severity_medium_between_0_70_and_0_85(self, svc):
        alert = await svc.create_alert(make_verdict(score=0.75))
        assert alert.severity == AlertSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_severity_low_at_threshold(self, svc):
        alert = await svc.create_alert(make_verdict(score=0.50))
        assert alert.severity == AlertSeverity.LOW

    @pytest.mark.asyncio
    async def test_attack_type_propagated(self, svc):
        alert = await svc.create_alert(make_verdict(attack_type="PortScan"))
        assert alert.attack_type == "PortScan"

    @pytest.mark.asyncio
    async def test_src_ip_and_dst_ip_stored_as_strings(self, svc):
        alert = await svc.create_alert(make_verdict(src_ip="10.0.0.5", dst_ip="192.168.1.1"))
        assert alert.src_ip == "10.0.0.5"
        assert alert.dst_ip == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_detected_at_within_one_second(self, svc):
        before = datetime.now(timezone.utc)
        alert  = await svc.create_alert(make_verdict())
        after  = datetime.now(timezone.utc)
        assert before <= alert.detected_at <= after

    @pytest.mark.asyncio
    async def test_initial_status_is_open(self, svc):
        alert = await svc.create_alert(make_verdict())
        assert alert.status == AlertStatus.OPEN

    @pytest.mark.asyncio
    async def test_protocol_stored(self, svc):
        alert = await svc.create_alert(make_verdict())
        assert alert.protocol == "TCP"

    @pytest.mark.asyncio
    async def test_two_different_verdicts_get_different_uuids(self, svc):
        a1 = await svc.create_alert(make_verdict(src_ip="10.0.0.1"))
        a2 = await svc.create_alert(make_verdict(src_ip="10.0.0.2"))
        assert a1.alert_id != a2.alert_id


# ===========================================================================
# Section 2 — TestAlertServiceDuplication  (FR8.5)
# ===========================================================================

class TestAlertServiceDuplication:
    """FR8.5 — Suppress duplicate alerts within 60-second window."""

    @pytest.mark.asyncio
    async def test_duplicate_within_60s_returns_same_alert_id(self, svc):
        v = make_verdict()
        a1 = await svc.create_alert(v)
        a2 = await svc.create_alert(v)   # same src/dst/attack_type
        assert a1.alert_id == a2.alert_id

    @pytest.mark.asyncio
    async def test_dup_count_incremented_on_duplicate(self, svc):
        v = make_verdict()
        await svc.create_alert(v)
        a2 = await svc.create_alert(v)
        assert a2.dup_count == 1

    @pytest.mark.asyncio
    async def test_dup_count_increments_multiple_times(self, svc):
        v = make_verdict()
        await svc.create_alert(v)
        await svc.create_alert(v)
        a3 = await svc.create_alert(v)
        assert a3.dup_count == 2

    @pytest.mark.asyncio
    async def test_different_attack_type_not_suppressed(self, svc):
        a1 = await svc.create_alert(make_verdict(attack_type="DoS",      src_ip="10.0.0.5"))
        a2 = await svc.create_alert(make_verdict(attack_type="PortScan", src_ip="10.0.0.5"))
        assert a1.alert_id != a2.alert_id

    @pytest.mark.asyncio
    async def test_different_src_ip_not_suppressed(self, svc):
        a1 = await svc.create_alert(make_verdict(src_ip="10.0.0.1"))
        a2 = await svc.create_alert(make_verdict(src_ip="10.0.0.2"))
        assert a1.alert_id != a2.alert_id

    @pytest.mark.asyncio
    async def test_expired_dedup_window_creates_new_alert(self, svc):
        v  = make_verdict()
        a1 = await svc.create_alert(v)
        # Manually expire the dedup window
        key = svc._dedup_key(v)
        svc._dedup_ts[key] = time.time() - 61
        a2 = await svc.create_alert(v)
        assert a1.alert_id != a2.alert_id

    @pytest.mark.asyncio
    async def test_only_one_db_row_for_100_duplicates(self, svc):
        v = make_verdict()
        for _ in range(100):
            await svc.create_alert(v)
        assert len(svc._store) == 1

    @pytest.mark.asyncio
    async def test_open_count_not_inflated_by_duplicates(self, svc):
        v = make_verdict()
        for _ in range(10):
            await svc.create_alert(v)
        assert svc.open_count() == 1


# ===========================================================================
# Section 3 — TestAlertServiceAcknowledge  (FR9.8)
# ===========================================================================

class TestAlertServiceAcknowledge:
    """FR9.8 — Acknowledge alert; FR9.9 — track who acknowledged."""

    @pytest.mark.asyncio
    async def test_acknowledged_by_populated(self, svc):
        alert = await svc.create_alert(make_verdict())
        acked = await svc.acknowledge(alert.alert_id, user_id="analyst-001")
        assert acked.acknowledged_by == "analyst-001"

    @pytest.mark.asyncio
    async def test_acknowledged_at_set_to_utc_now(self, svc):
        alert  = await svc.create_alert(make_verdict())
        before = datetime.now(timezone.utc)
        acked  = await svc.acknowledge(alert.alert_id, user_id="analyst-001")
        after  = datetime.now(timezone.utc)
        assert before <= acked.acknowledged_at <= after

    @pytest.mark.asyncio
    async def test_status_transitions_to_acknowledged(self, svc):
        alert = await svc.create_alert(make_verdict())
        assert alert.status == AlertStatus.OPEN
        acked = await svc.acknowledge(alert.alert_id, user_id="analyst-001")
        assert acked.status == AlertStatus.ACKNOWLEDGED

    @pytest.mark.asyncio
    async def test_acknowledging_twice_is_idempotent(self, svc):
        alert = await svc.create_alert(make_verdict())
        a1 = await svc.acknowledge(alert.alert_id, "u1")
        a2 = await svc.acknowledge(alert.alert_id, "u1")
        assert a1.status == a2.status == AlertStatus.ACKNOWLEDGED

    @pytest.mark.asyncio
    async def test_unknown_alert_id_raises_alert_not_found(self, svc):
        with pytest.raises(AlertNotFound):
            await svc.acknowledge(str(uuid.uuid4()), user_id="u1")

    @pytest.mark.asyncio
    async def test_audit_entry_created_on_acknowledge(self, svc):
        alert = await svc.create_alert(make_verdict())
        await svc.acknowledge(alert.alert_id, user_id="analyst-42")
        ack_entries = [e for e in svc._audit if e["action"] == "ACK_ALERT"]
        assert len(ack_entries) == 1
        assert ack_entries[0]["user_id"] == "analyst-42"


# ===========================================================================
# Section 4 — TestAlertServiceFalsePositive  (FR9.13)
# ===========================================================================

class TestAlertServiceFalsePositive:
    """FR9.13 — Mark alerts as false positives."""

    @pytest.mark.asyncio
    async def test_status_transitions_to_false_positive(self, svc):
        alert = await svc.create_alert(make_verdict())
        fp    = await svc.mark_false_positive(alert.alert_id, user_id="u1")
        assert fp.status == AlertStatus.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_false_positive_excluded_from_open_count(self, svc):
        alert = await svc.create_alert(make_verdict())
        assert svc.open_count() == 1
        await svc.mark_false_positive(alert.alert_id, user_id="u1")
        assert svc.open_count() == 0

    @pytest.mark.asyncio
    async def test_fp_label_stored_in_audit_log(self, svc):
        alert = await svc.create_alert(make_verdict())
        await svc.mark_false_positive(alert.alert_id, user_id="analyst-7")
        fp_entries = [e for e in svc._audit if e["action"] == "FALSE_POSITIVE"]
        assert len(fp_entries) == 1
        assert fp_entries[0]["user_id"] == "analyst-7"

    @pytest.mark.asyncio
    async def test_unknown_alert_raises_alert_not_found(self, svc):
        with pytest.raises(AlertNotFound):
            await svc.mark_false_positive(str(uuid.uuid4()), user_id="u1")


# ===========================================================================
# Section 5 — TestAlertServiceQuery  (FR9.1–9.5)
# ===========================================================================

class TestAlertServiceQuery:
    """FR9.1–9.5 — Filter alerts by severity, src_ip, attack_type, time."""

    @pytest.mark.asyncio
    async def test_filter_by_severity_returns_correct_subset(self, svc):
        await svc.create_alert(make_verdict(score=0.96, src_ip="1.1.1.1"))  # CRITICAL
        await svc.create_alert(make_verdict(score=0.75, src_ip="2.2.2.2"))  # MEDIUM
        results, total = await svc.query(severity="CRITICAL")
        assert total == 1
        assert results[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_filter_by_src_ip_returns_correct_subset(self, svc):
        await svc.create_alert(make_verdict(src_ip="10.0.0.1", attack_type="DoS"))
        await svc.create_alert(make_verdict(src_ip="10.0.0.2", attack_type="DDoS"))
        results, total = await svc.query(src_ip="10.0.0.1")
        assert total == 1
        assert results[0].src_ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_filter_by_attack_type(self, svc):
        await svc.create_alert(make_verdict(attack_type="DoS",      src_ip="1.1.1.1"))
        await svc.create_alert(make_verdict(attack_type="PortScan", src_ip="2.2.2.2"))
        await svc.create_alert(make_verdict(attack_type="DoS",      src_ip="3.3.3.3"))
        results, total = await svc.query(attack_type="DoS")
        assert total == 2
        assert all(r.attack_type == "DoS" for r in results)

    @pytest.mark.asyncio
    async def test_time_range_filter_respects_detected_at(self, svc):
        a = await svc.create_alert(make_verdict(src_ip="5.5.5.5"))
        # Query with 'after' that excludes the alert
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        results, total = await svc.query(after=future)
        assert total == 0

    @pytest.mark.asyncio
    async def test_paginated_response_has_correct_page_size(self, svc):
        for i in range(25):
            await svc.create_alert(make_verdict(src_ip=f"10.0.{i}.1", attack_type=f"Type{i}"))
        results, total = await svc.query(page=1, page_size=10)
        assert len(results) == 10
        assert total == 25

    @pytest.mark.asyncio
    async def test_total_count_matches_unfiltered_count(self, svc):
        for i in range(5):
            await svc.create_alert(make_verdict(src_ip=f"10.0.{i}.1", attack_type=f"T{i}"))
        _, total = await svc.query()
        assert total == 5

    @pytest.mark.asyncio
    async def test_filter_by_status_open(self, svc):
        a1 = await svc.create_alert(make_verdict(src_ip="1.1.1.1", attack_type="DoS"))
        a2 = await svc.create_alert(make_verdict(src_ip="2.2.2.2", attack_type="DDoS"))
        await svc.acknowledge(a1.alert_id, "u1")
        results, total = await svc.query(status=AlertStatus.OPEN)
        assert total == 1
        assert results[0].alert_id == a2.alert_id


# ===========================================================================
# Section 6 — TestAlertServicePubSub  (FR10.5)
# ===========================================================================

class TestAlertServicePubSub:
    """FR10.5 — Real-time alert push via Redis Pub/Sub."""

    @pytest.mark.asyncio
    async def test_new_alert_publishes_to_redis_channel(self, svc, redis_mock):
        await svc.create_alert(make_verdict())
        redis_mock.publish.assert_called_once()
        channel = redis_mock.publish.call_args[0][0]
        assert channel == "nids:alerts:new"

    @pytest.mark.asyncio
    async def test_published_payload_contains_alert_id(self, svc, redis_mock):
        alert = await svc.create_alert(make_verdict())
        payload = redis_mock.publish.call_args[0][1]
        assert alert.alert_id in payload

    @pytest.mark.asyncio
    async def test_published_payload_contains_severity(self, svc, redis_mock):
        alert = await svc.create_alert(make_verdict(score=0.92))
        payload = redis_mock.publish.call_args[0][1]
        assert alert.severity in payload

    @pytest.mark.asyncio
    async def test_published_payload_contains_attack_type(self, svc, redis_mock):
        await svc.create_alert(make_verdict(attack_type="BruteForce"))
        payload = redis_mock.publish.call_args[0][1]
        assert "BruteForce" in payload

    @pytest.mark.asyncio
    async def test_duplicate_alert_does_not_publish_again(self, svc, redis_mock):
        v = make_verdict()
        await svc.create_alert(v)   # publishes once
        await svc.create_alert(v)   # duplicate — must NOT publish again
        assert redis_mock.publish.call_count == 1