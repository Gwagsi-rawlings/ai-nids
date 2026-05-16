"""
AI-NIDS — Unit Tests: Alert Workflows & Alert Generator
tests/test_alert_workflows.py

Covers:
  - confidence_to_severity mapping
  - AlertRecord construction via AlertGenerator
  - AlertWorkflowService: acknowledge, escalate, false_positive, resolve, reopen
  - Status transition guard (InvalidTransitionError)
  - Mandatory field validation
  - Audit log writes (stub verification)
  - Redis Pub/Sub publish (stub verification)
  - NotificationService dispatch (patched)

FR Traceability:
    FR7.2  — Severity classification
    FR7.3–FR7.9 — Alert record fields
    FR9.8  — Acknowledge alerts
    FR9.9  — Track who acknowledged and when
    FR9.12 — Close/resolve alerts
    FR9.13 — Mark alerts as false positives
    NFR7.2 — Log all administrative actions

April 24, 2026 | Sprint Week 7 | Developer: GWAGSI Rawlings Nshom
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.detection.alert_correlator import AlertCorrelator, DetectionEvent, CorrelatedAlert
from backend.detection.alert_generator import AlertGenerator, AlertRecord, confidence_to_severity
from backend.api.services.alert_workflows import (
    AlertWorkflowService,
    AcknowledgeRequest,
    EscalateRequest,
    FalsePositiveRequest,
    ResolveRequest,
    AlertNotFoundError,
    InvalidTransitionError,
    MissingRequiredFieldError,
    VALID_RESOLUTION_TYPES,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

BASE_TS = 1_700_000_000.0


def make_correlated(
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    attack_type="DoS",
    severity="HIGH",
    confidence=0.88,
    attack_chain=False,
    chain_attack_types=None,
    detected_by="ml",
) -> CorrelatedAlert:
    event = DetectionEvent(
        flow_id=str(uuid.uuid4()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        attack_type=attack_type,
        severity=severity,
        confidence=confidence,
        detected_by=detected_by,
        timestamp=BASE_TS,
        sig_confidence=0.40,
        rf_confidence=0.35,
        lstm_confidence=0.10,
        if_confidence=0.03,
    )
    return CorrelatedAlert(
        event=event,
        group_id=str(uuid.uuid4()),
        dup_count=0,
        attack_chain=attack_chain,
        chain_attack_types=chain_attack_types or [],
        is_new_group=True,
    )


def make_alert_dict(
    alert_id=None,
    status="open",
    severity="HIGH",
    attack_type="DoS",
    confidence=0.88,
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    detected_by="ml",
    group_id=None,
    attack_chain=False,
) -> Dict:
    return {
        "alert_id": alert_id or str(uuid.uuid4()),
        "flow_id": str(uuid.uuid4()),
        "status": status,
        "severity": severity,
        "attack_type": attack_type,
        "confidence": confidence,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "detected_by": detected_by,
        "detected_at": BASE_TS,
        "group_id": group_id or str(uuid.uuid4()),
        "attack_chain": attack_chain,
        "acknowledged_by": None,
        "acknowledged_at": None,
        "escalated_by": None,
        "escalated_at": None,
        "resolved_by": None,
        "resolved_at": None,
        "resolution_type": None,
        "resolution_note": None,
    }


class FakeDB:
    """
    Minimal async DB stub that stores the last executed statement and params,
    and returns a configurable row for SELECT queries.
    """
    def __init__(self, row: Optional[Dict] = None):
        self._row = row
        self.executed: List[Dict] = []
        self.committed: int = 0
        self.rolled_back: int = 0

    async def execute(self, stmt, params=None):
        self.executed.append({"stmt": str(stmt), "params": params})
        return FakeResult(self._row)

    async def commit(self):
        self.committed += 1

    async def rollback(self):
        self.rolled_back += 1


class FakeResult:
    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self._row


class FakeRedis:
    """Async Redis stub that records publish calls."""
    def __init__(self):
        self.published: List[Dict] = []

    async def publish(self, channel: str, message: str):
        self.published.append({"channel": channel, "message": json.loads(message)})


# ─────────────────────────────────────────────────────────────────────────────
# Section 1 — confidence_to_severity mapping (FR7.2)
# ─────────────────────────────────────────────────────────────────────────────

class TestConfidenceToSeverity:

    def test_critical_at_0_95(self):
        assert confidence_to_severity(0.95) == "CRITICAL"

    def test_critical_at_1_0(self):
        assert confidence_to_severity(1.0) == "CRITICAL"

    def test_critical_just_above_threshold(self):
        assert confidence_to_severity(0.951) == "CRITICAL"

    def test_high_at_0_85(self):
        assert confidence_to_severity(0.85) == "HIGH"

    def test_high_just_below_critical(self):
        assert confidence_to_severity(0.949) == "HIGH"

    def test_medium_at_0_70(self):
        assert confidence_to_severity(0.70) == "MEDIUM"

    def test_medium_just_below_high(self):
        assert confidence_to_severity(0.849) == "MEDIUM"

    def test_low_at_0_50(self):
        assert confidence_to_severity(0.50) == "LOW"

    def test_low_just_below_medium(self):
        assert confidence_to_severity(0.699) == "LOW"

    def test_boundary_exactly_at_each_tier(self):
        assert confidence_to_severity(0.95) == "CRITICAL"
        assert confidence_to_severity(0.85) == "HIGH"
        assert confidence_to_severity(0.70) == "MEDIUM"
        assert confidence_to_severity(0.50) == "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Section 2 — AlertGenerator record construction (FR7.3–FR7.9)
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertGeneratorRecordConstruction:

    def _gen(self):
        return AlertGenerator(
            db_session=None,
            redis_client=None,
            notification_enabled=False,
        )

    def _record(self, **kwargs) -> AlertRecord:
        gen = self._gen()
        correlated = make_correlated(**kwargs)
        return gen._build_record(correlated)

    def test_alert_id_is_uuid(self):
        r = self._record()
        assert uuid.UUID(r.alert_id)  # raises ValueError if not UUID

    def test_src_ip_matches_event(self):
        r = self._record(src_ip="172.16.0.5")
        assert r.src_ip == "172.16.0.5"

    def test_dst_ip_matches_event(self):
        r = self._record(dst_ip="10.99.99.1")
        assert r.dst_ip == "10.99.99.1"

    def test_attack_type_propagated(self):
        r = self._record(attack_type="BruteForce")
        assert r.attack_type == "BruteForce"

    def test_benign_attack_type_becomes_anomaly(self):
        r = self._record(attack_type="BENIGN")
        assert r.attack_type == "ANOMALY"

    def test_severity_derived_from_confidence_critical(self):
        r = self._record(confidence=0.97)
        assert r.severity == "CRITICAL"

    def test_severity_derived_from_confidence_high(self):
        r = self._record(confidence=0.88)
        assert r.severity == "HIGH"

    def test_severity_derived_from_confidence_medium(self):
        r = self._record(confidence=0.72)
        assert r.severity == "MEDIUM"

    def test_severity_derived_from_confidence_low(self):
        r = self._record(confidence=0.55)
        assert r.severity == "LOW"

    def test_status_is_open(self):
        r = self._record()
        assert r.status == "open"

    def test_description_is_populated(self):
        r = self._record(attack_type="PortScan")
        assert len(r.description) > 0

    def test_recommended_action_is_populated(self):
        r = self._record(attack_type="Botnet")
        assert len(r.recommended_action) > 0

    def test_group_id_propagated(self):
        r = self._record()
        assert r.group_id is not None

    def test_attack_chain_propagated_true(self):
        r = self._record(attack_chain=True)
        assert r.attack_chain is True

    def test_attack_chain_propagated_false(self):
        r = self._record(attack_chain=False)
        assert r.attack_chain is False

    def test_chain_attack_types_propagated(self):
        r = self._record(chain_attack_types=["PortScan", "BruteForce"])
        assert "PortScan" in r.chain_attack_types
        assert "BruteForce" in r.chain_attack_types

    def test_per_engine_confidences_populated(self):
        r = self._record()
        assert r.sig_confidence == 0.40
        assert r.rf_confidence == 0.35
        assert r.lstm_confidence == 0.10
        assert r.if_confidence == 0.03

    def test_to_api_response_converts_timestamps(self):
        r = self._record()
        api = r.to_api_response()
        assert isinstance(api["detected_at"], str)
        assert api["detected_at"].endswith("Z")

    def test_detected_at_matches_event_timestamp(self):
        r = self._record()
        assert r.detected_at == BASE_TS


# ─────────────────────────────────────────────────────────────────────────────
# Section 3 — AlertGenerator persistence and publish
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertGeneratorPersistence:

    @pytest.mark.asyncio
    async def test_create_queues_when_db_is_none(self):
        gen = AlertGenerator(db_session=None, redis_client=None, notification_enabled=False)
        correlated = make_correlated()
        record = await gen.create(correlated)
        assert gen.stats()["pending_queue_depth"] == 1
        assert record.alert_id is not None

    @pytest.mark.asyncio
    async def test_create_persists_when_db_available(self):
        db = FakeDB()
        gen = AlertGenerator(db_session=db, redis_client=None, notification_enabled=False)
        correlated = make_correlated()
        await gen.create(correlated)
        assert db.committed >= 1
        assert gen.stats()["total_persisted"] == 1

    @pytest.mark.asyncio
    async def test_create_publishes_to_redis(self):
        db = FakeDB()
        redis = FakeRedis()
        gen = AlertGenerator(db_session=db, redis_client=redis, notification_enabled=False)
        await gen.create(make_correlated())
        assert len(redis.published) == 1
        pub = redis.published[0]
        assert pub["channel"] == "nids:alerts:new"
        assert "alert_id" in pub["message"]
        assert "severity" in pub["message"]

    @pytest.mark.asyncio
    async def test_create_skips_redis_when_unavailable(self):
        db = FakeDB()
        gen = AlertGenerator(db_session=db, redis_client=None, notification_enabled=False)
        # Should not raise
        record = await gen.create(make_correlated())
        assert record is not None

    @pytest.mark.asyncio
    async def test_stats_total_generated_increments(self):
        gen = AlertGenerator(notification_enabled=False)
        for _ in range(3):
            await gen.create(make_correlated())
        assert gen.stats()["total_generated"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# Section 4 — AlertWorkflowService: acknowledge (FR9.8, FR9.9)
# ─────────────────────────────────────────────────────────────────────────────

class TestAcknowledge:

    def _svc(self, row: Dict):
        return AlertWorkflowService(db=FakeDB(row=row), redis=FakeRedis())

    @pytest.mark.asyncio
    async def test_acknowledge_open_alert_succeeds(self):
        alert = make_alert_dict(status="open")
        svc = self._svc(alert)
        result = await svc.acknowledge(
            alert["alert_id"],
            AcknowledgeRequest(performed_by="analyst_sam"),
        )
        assert result["status"] == "acknowledged"
        assert result["acknowledged_by"] == "analyst_sam"
        assert result["acknowledged_at"] is not None

    @pytest.mark.asyncio
    async def test_acknowledge_writes_db(self):
        alert = make_alert_dict(status="open")
        db = FakeDB(row=alert)
        svc = AlertWorkflowService(db=db, redis=FakeRedis())
        await svc.acknowledge(alert["alert_id"], AcknowledgeRequest(performed_by="sam"))
        # At minimum: SELECT + UPDATE + audit INSERT = 3 executions, 2 commits
        assert db.committed >= 2

    @pytest.mark.asyncio
    async def test_acknowledge_publishes_status_change(self):
        alert = make_alert_dict(status="open")
        redis = FakeRedis()
        svc = AlertWorkflowService(db=FakeDB(row=alert), redis=redis)
        await svc.acknowledge(alert["alert_id"], AcknowledgeRequest(performed_by="sam"))
        assert any(
            p["message"]["new_status"] == "acknowledged"
            for p in redis.published
        )

    @pytest.mark.asyncio
    async def test_acknowledge_already_acknowledged_raises(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.acknowledge(
                alert["alert_id"],
                AcknowledgeRequest(performed_by="sam"),
            )

    @pytest.mark.asyncio
    async def test_acknowledge_resolved_alert_raises(self):
        alert = make_alert_dict(status="resolved")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.acknowledge(
                alert["alert_id"],
                AcknowledgeRequest(performed_by="sam"),
            )

    @pytest.mark.asyncio
    async def test_acknowledge_not_found_raises(self):
        svc = AlertWorkflowService(db=FakeDB(row=None), redis=FakeRedis())
        with pytest.raises(AlertNotFoundError):
            await svc.acknowledge("nonexistent-id", AcknowledgeRequest(performed_by="sam"))


# ─────────────────────────────────────────────────────────────────────────────
# Section 5 — AlertWorkflowService: escalate (FR9.11, US-3.7)
# ─────────────────────────────────────────────────────────────────────────────

class TestEscalate:

    def _svc(self, row: Dict, redis=None):
        return AlertWorkflowService(db=FakeDB(row=row), redis=redis or FakeRedis())

    @pytest.mark.asyncio
    async def test_escalate_open_alert_succeeds(self):
        alert = make_alert_dict(status="open")
        svc = self._svc(alert)
        result = await svc.escalate(
            alert["alert_id"],
            EscalateRequest(performed_by="sam", escalation_target="soc_manager"),
        )
        assert result["status"] == "escalated"
        assert result["escalated_by"] == "sam"

    @pytest.mark.asyncio
    async def test_escalate_acknowledged_alert_succeeds(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        result = await svc.escalate(
            alert["alert_id"],
            EscalateRequest(performed_by="sam", escalation_target="soc_manager"),
        )
        assert result["status"] == "escalated"

    @pytest.mark.asyncio
    async def test_escalate_resolved_alert_raises(self):
        alert = make_alert_dict(status="resolved")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.escalate(
                alert["alert_id"],
                EscalateRequest(performed_by="sam", escalation_target="tier2"),
            )

    @pytest.mark.asyncio
    async def test_escalate_publishes_status_change(self):
        alert = make_alert_dict(status="open")
        redis = FakeRedis()
        svc = self._svc(alert, redis=redis)
        await svc.escalate(
            alert["alert_id"],
            EscalateRequest(performed_by="sam", escalation_target="tier2"),
        )
        assert any(
            p["message"]["new_status"] == "escalated"
            for p in redis.published
        )

    @pytest.mark.asyncio
    async def test_escalate_fires_notification_task(self):
        """
        Escalation should schedule a notification task.
        We verify _fire_escalation_notification is called by patching it.
        """
        alert = make_alert_dict(status="open", severity="CRITICAL")
        svc = AlertWorkflowService(db=FakeDB(row=alert), redis=FakeRedis())
        fired = []

        async def fake_fire(a, r):
            fired.append((a, r))

        svc._fire_escalation_notification = fake_fire

        # We need to run the event loop briefly to let create_task fire
        await svc.escalate(
            alert["alert_id"],
            EscalateRequest(performed_by="sam", escalation_target="tier2"),
        )
        # Give the task a chance to run
        await asyncio.sleep(0)
        assert len(fired) == 1

    @pytest.mark.asyncio
    async def test_escalate_escalated_alert_raises(self):
        alert = make_alert_dict(status="escalated")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.escalate(
                alert["alert_id"],
                EscalateRequest(performed_by="sam", escalation_target="tier3"),
            )


# ─────────────────────────────────────────────────────────────────────────────
# Section 6 — AlertWorkflowService: false_positive (FR9.13)
# ─────────────────────────────────────────────────────────────────────────────

class TestFalsePositive:

    def _svc(self, row):
        return AlertWorkflowService(db=FakeDB(row=row), redis=FakeRedis())

    @pytest.mark.asyncio
    async def test_false_positive_open_alert_succeeds(self):
        alert = make_alert_dict(status="open")
        svc = self._svc(alert)
        result = await svc.mark_false_positive(
            alert["alert_id"],
            FalsePositiveRequest(performed_by="analyst_sam"),
        )
        assert result["status"] == "false_positive"
        assert result["resolution_type"] == "false_positive"

    @pytest.mark.asyncio
    async def test_false_positive_acknowledged_alert_succeeds(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        result = await svc.mark_false_positive(
            alert["alert_id"],
            FalsePositiveRequest(performed_by="sam"),
        )
        assert result["status"] == "false_positive"

    @pytest.mark.asyncio
    async def test_false_positive_resolved_alert_raises(self):
        alert = make_alert_dict(status="resolved")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.mark_false_positive(
                alert["alert_id"],
                FalsePositiveRequest(performed_by="sam"),
            )

    @pytest.mark.asyncio
    async def test_false_positive_stores_default_note(self):
        alert = make_alert_dict(status="open")
        svc = self._svc(alert)
        result = await svc.mark_false_positive(
            alert["alert_id"],
            FalsePositiveRequest(performed_by="sam", note=None),
        )
        assert result["resolution_note"] is not None
        assert len(result["resolution_note"]) > 0

    @pytest.mark.asyncio
    async def test_false_positive_stores_custom_note(self):
        alert = make_alert_dict(status="open")
        svc = self._svc(alert)
        result = await svc.mark_false_positive(
            alert["alert_id"],
            FalsePositiveRequest(performed_by="sam", note="Nmap scan from IT team"),
        )
        assert "Nmap scan" in result["resolution_note"]

    @pytest.mark.asyncio
    async def test_false_positive_publishes_status_change(self):
        alert = make_alert_dict(status="open")
        redis = FakeRedis()
        svc = AlertWorkflowService(db=FakeDB(row=alert), redis=redis)
        await svc.mark_false_positive(
            alert["alert_id"], FalsePositiveRequest(performed_by="sam")
        )
        assert any(
            p["message"]["new_status"] == "false_positive"
            for p in redis.published
        )


# ─────────────────────────────────────────────────────────────────────────────
# Section 7 — AlertWorkflowService: resolve (FR9.12, US-3.8)
# ─────────────────────────────────────────────────────────────────────────────

class TestResolve:

    def _svc(self, row):
        return AlertWorkflowService(db=FakeDB(row=row), redis=FakeRedis())

    @pytest.mark.asyncio
    async def test_resolve_acknowledged_alert_succeeds(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        result = await svc.resolve(
            alert["alert_id"],
            ResolveRequest(
                performed_by="sam",
                resolution_type="true_positive",
                resolution_note="Confirmed DoS from external IP.",
            ),
        )
        assert result["status"] == "resolved"
        assert result["resolution_type"] == "true_positive"

    @pytest.mark.asyncio
    async def test_resolve_escalated_alert_succeeds(self):
        alert = make_alert_dict(status="escalated")
        svc = self._svc(alert)
        result = await svc.resolve(
            alert["alert_id"],
            ResolveRequest(
                performed_by="manager",
                resolution_type="benign",
                resolution_note="Scheduled load test.",
            ),
        )
        assert result["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_resolve_open_alert_raises(self):
        alert = make_alert_dict(status="open")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.resolve(
                alert["alert_id"],
                ResolveRequest(
                    performed_by="sam",
                    resolution_type="true_positive",
                    resolution_note="Some note.",
                ),
            )

    @pytest.mark.asyncio
    async def test_resolve_already_resolved_raises(self):
        alert = make_alert_dict(status="resolved")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.resolve(
                alert["alert_id"],
                ResolveRequest(
                    performed_by="sam",
                    resolution_type="duplicate",
                    resolution_note="Already resolved.",
                ),
            )

    @pytest.mark.asyncio
    async def test_resolve_invalid_resolution_type_raises(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        with pytest.raises(MissingRequiredFieldError):
            await svc.resolve(
                alert["alert_id"],
                ResolveRequest(
                    performed_by="sam",
                    resolution_type="invalid_type",
                    resolution_note="Some note.",
                ),
            )

    @pytest.mark.asyncio
    async def test_resolve_empty_note_raises(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        with pytest.raises(MissingRequiredFieldError):
            await svc.resolve(
                alert["alert_id"],
                ResolveRequest(
                    performed_by="sam",
                    resolution_type="true_positive",
                    resolution_note="   ",  # whitespace only
                ),
            )

    @pytest.mark.asyncio
    async def test_resolve_all_valid_resolution_types(self):
        """Every valid resolution_type should succeed without raising."""
        for rtype in VALID_RESOLUTION_TYPES:
            alert = make_alert_dict(status="acknowledged")
            svc = self._svc(alert)
            result = await svc.resolve(
                alert["alert_id"],
                ResolveRequest(
                    performed_by="sam",
                    resolution_type=rtype,
                    resolution_note=f"Testing {rtype} resolution.",
                ),
            )
            assert result["status"] == "resolved"
            assert result["resolution_type"] == rtype

    @pytest.mark.asyncio
    async def test_resolve_stores_note(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        result = await svc.resolve(
            alert["alert_id"],
            ResolveRequest(
                performed_by="sam",
                resolution_type="true_positive",
                resolution_note="Blocked at firewall.",
            ),
        )
        assert "Blocked at firewall" in result["resolution_note"]

    @pytest.mark.asyncio
    async def test_resolve_publishes_status_change(self):
        alert = make_alert_dict(status="acknowledged")
        redis = FakeRedis()
        svc = AlertWorkflowService(db=FakeDB(row=alert), redis=redis)
        await svc.resolve(
            alert["alert_id"],
            ResolveRequest(
                performed_by="sam",
                resolution_type="duplicate",
                resolution_note="Duplicate of earlier alert.",
            ),
        )
        assert any(p["message"]["new_status"] == "resolved" for p in redis.published)


# ─────────────────────────────────────────────────────────────────────────────
# Section 8 — AlertWorkflowService: reopen (US-3.8 AC4)
# ─────────────────────────────────────────────────────────────────────────────

class TestReopen:

    def _svc(self, row):
        return AlertWorkflowService(db=FakeDB(row=row), redis=FakeRedis())

    @pytest.mark.asyncio
    async def test_reopen_resolved_alert_succeeds(self):
        alert = make_alert_dict(status="resolved")
        svc = self._svc(alert)
        result = await svc.reopen(
            alert["alert_id"],
            performed_by="soc_manager",
            note="New evidence found.",
        )
        assert result["status"] == "open"

    @pytest.mark.asyncio
    async def test_reopen_false_positive_alert_succeeds(self):
        alert = make_alert_dict(status="false_positive")
        svc = self._svc(alert)
        result = await svc.reopen(
            alert["alert_id"],
            performed_by="soc_manager",
        )
        assert result["status"] == "open"

    @pytest.mark.asyncio
    async def test_reopen_open_alert_raises(self):
        alert = make_alert_dict(status="open")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.reopen(alert["alert_id"], performed_by="soc_manager")

    @pytest.mark.asyncio
    async def test_reopen_acknowledged_alert_raises(self):
        alert = make_alert_dict(status="acknowledged")
        svc = self._svc(alert)
        with pytest.raises(InvalidTransitionError):
            await svc.reopen(alert["alert_id"], performed_by="soc_manager")

    @pytest.mark.asyncio
    async def test_reopen_publishes_status_change(self):
        alert = make_alert_dict(status="resolved")
        redis = FakeRedis()
        svc = AlertWorkflowService(db=FakeDB(row=alert), redis=redis)
        await svc.reopen(alert["alert_id"], performed_by="manager")
        assert any(p["message"]["new_status"] == "open" for p in redis.published)


# ─────────────────────────────────────────────────────────────────────────────
# Section 9 — Full pipeline: correlator → generator (integration smoke)
# ─────────────────────────────────────────────────────────────────────────────

class TestFullPipelineSmoke:

    @pytest.mark.asyncio
    async def test_correlator_to_generator_produces_alert(self):
        correlator = AlertCorrelator()
        db = FakeDB()
        redis = FakeRedis()
        gen = AlertGenerator(db_session=db, redis_client=redis, notification_enabled=False)

        event = DetectionEvent(
            flow_id="flow-001",
            src_ip="10.0.0.5",
            dst_ip="192.168.0.1",
            src_port=1234,
            dst_port=22,
            protocol="TCP",
            attack_type="BruteForce",
            severity="HIGH",
            confidence=0.89,
            detected_by="both",
            timestamp=BASE_TS,
        )

        correlated = correlator.process(event)
        assert correlated is not None

        record = await gen.create(correlated)
        assert record.alert_id is not None
        assert record.attack_type == "BruteForce"
        assert record.severity == "HIGH"
        assert record.status == "open"
        assert len(redis.published) == 1

    @pytest.mark.asyncio
    async def test_attack_chain_propagates_through_pipeline(self):
        correlator = AlertCorrelator()
        gen = AlertGenerator(notification_enabled=False)

        # Two distinct attack types from same src_ip → chain
        e1 = DetectionEvent(
            flow_id="f1", src_ip="10.0.0.7", dst_ip="10.0.0.1",
            src_port=9000, dst_port=80, protocol="TCP",
            attack_type="PortScan", severity="MEDIUM", confidence=0.72,
            detected_by="signature", timestamp=BASE_TS,
        )
        e2 = DetectionEvent(
            flow_id="f2", src_ip="10.0.0.7", dst_ip="10.0.0.2",
            src_port=9001, dst_port=22, protocol="TCP",
            attack_type="BruteForce", severity="HIGH", confidence=0.87,
            detected_by="ml", timestamp=BASE_TS + 90,
        )

        correlator.process(e1)
        c2 = correlator.process(e2)
        assert c2 is not None
        assert c2.attack_chain is True

        record = await gen.create(c2)
        assert record.attack_chain is True
        assert "PortScan" in record.chain_attack_types
        assert "BruteForce" in record.chain_attack_types

    @pytest.mark.asyncio
    async def test_workflow_acknowledge_then_resolve(self):
        """Smoke test for a complete open → acknowledge → resolve flow."""
        # Step 1: generate the alert
        correlated = make_correlated(confidence=0.90)
        gen = AlertGenerator(notification_enabled=False)
        record = await gen.create(correlated)

        # Step 2: acknowledge
        alert_row = record.to_dict()
        alert_row["status"] = "open"   # generator sets open
        db = FakeDB(row=alert_row)
        svc = AlertWorkflowService(db=db, redis=FakeRedis())

        ack_result = await svc.acknowledge(
            record.alert_id,
            AcknowledgeRequest(performed_by="analyst_sam"),
        )
        assert ack_result["status"] == "acknowledged"

        # Step 3: update stub row to acknowledged for the resolve call
        db._row = {**alert_row, "status": "acknowledged"}

        resolve_result = await svc.resolve(
            record.alert_id,
            ResolveRequest(
                performed_by="analyst_sam",
                resolution_type="true_positive",
                resolution_note="Confirmed external DoS attack. Blocked at edge router.",
            ),
        )
        assert resolve_result["status"] == "resolved"
        assert resolve_result["resolution_type"] == "true_positive"