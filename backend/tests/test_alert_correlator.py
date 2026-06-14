"""
AI-NIDS — Unit Tests: Alert Correlator
tests/test_alert_correlator.py

Covers AlertCorrelator deduplication window, 10-minute correlation grouping,
multi-stage attack chain detection, eviction, and stats.

FR Traceability:
    FR8.1  — Correlate alerts from same source IP within time window
    FR8.2  — Identify multi-stage attack patterns (attack chain flag)
    FR8.3  — Group related alerts into incidents
    FR8.4  — Detect coordinated attacks from multiple sources
    FR8.5  — Suppress duplicate alerts within 60 seconds

April 24, 2026 | Sprint Week 7 | Developer: GWAGSI Rawlings Nshom
"""

import pytest
from backend.detection.alert_correlator import (
    AlertCorrelator,
    DetectionEvent,
    CorrelatedAlert,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ─────────────────────────────────────────────────────────────────────────────

BASE_TS = 1_700_000_000.0  # fixed base timestamp for deterministic tests


def make_event(
    src_ip="192.168.1.10",
    dst_ip="10.0.0.1",
    attack_type="DoS",
    severity="HIGH",
    confidence=0.88,
    flow_id=None,
    ts_offset=0.0,
    protocol="TCP",
    src_port=54321,
    dst_port=80,
    detected_by="ml",
) -> DetectionEvent:
    return DetectionEvent(
        flow_id=flow_id or f"flow-{ts_offset}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        attack_type=attack_type,
        severity=severity,
        confidence=confidence,
        detected_by=detected_by,
        timestamp=BASE_TS + ts_offset,
    )


@pytest.fixture
def correlator():
    """Fresh AlertCorrelator with real window values for every test."""
    c = AlertCorrelator()
    c.reset()
    return c


@pytest.fixture
def short_correlator():
    """Correlator with tiny windows so expiry tests run fast."""
    return AlertCorrelator(dedup_window=1.0, correlation_window=2.0)


# ─────────────────────────────────────────────────────────────────────────────
# Section 1 — Basic processing
# ─────────────────────────────────────────────────────────────────────────────

class TestBasicProcessing:

    def test_single_event_emits_correlated_alert(self, correlator):
        evt = make_event(ts_offset=0.0)
        result = correlator.process(evt)
        assert result is not None
        assert isinstance(result, CorrelatedAlert)

    def test_emitted_alert_carries_original_event(self, correlator):
        evt = make_event(attack_type="PortScan", ts_offset=0.0)
        result = correlator.process(evt)
        assert result.event is evt

    def test_emitted_alert_has_group_id(self, correlator):
        evt = make_event(ts_offset=0.0)
        result = correlator.process(evt)
        assert result.group_id is not None
        assert len(result.group_id) > 0

    def test_first_event_in_group_flagged_as_new(self, correlator):
        evt = make_event(ts_offset=0.0)
        result = correlator.process(evt)
        assert result.is_new_group is True

    def test_second_distinct_event_from_same_src_not_new_group(self, correlator):
        evt1 = make_event(attack_type="DoS", ts_offset=0.0)
        evt2 = make_event(attack_type="PortScan", ts_offset=10.0)
        correlator.process(evt1)
        result2 = correlator.process(evt2)
        assert result2.is_new_group is False

    def test_different_src_ips_get_different_group_ids(self, correlator):
        evt1 = make_event(src_ip="10.0.0.1", ts_offset=0.0)
        evt2 = make_event(src_ip="10.0.0.2", ts_offset=0.0)
        r1 = correlator.process(evt1)
        r2 = correlator.process(evt2)
        assert r1.group_id != r2.group_id

    def test_dup_count_zero_on_first_emission(self, correlator):
        evt = make_event(ts_offset=0.0)
        result = correlator.process(evt)
        assert result.dup_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# Section 2 — Deduplication window (FR8.5)
# ─────────────────────────────────────────────────────────────────────────────

class TestDeduplication:

    def test_duplicate_within_window_returns_none(self, correlator):
        evt1 = make_event(ts_offset=0.0)
        evt2 = make_event(ts_offset=5.0)  # same key, within 60s
        correlator.process(evt1)
        result = correlator.process(evt2)
        assert result is None

    def test_suppressed_event_increments_stats(self, correlator):
        evt1 = make_event(ts_offset=0.0)
        evt2 = make_event(ts_offset=5.0)
        correlator.process(evt1)
        correlator.process(evt2)
        stats = correlator.stats()
        assert stats["total_suppressed"] == 1

    def test_three_duplicates_all_suppressed(self, correlator):
        base = make_event(ts_offset=0.0)
        correlator.process(base)
        for i in range(1, 4):
            r = correlator.process(make_event(ts_offset=float(i * 5)))
            assert r is None
        assert correlator.stats()["total_suppressed"] == 3

    def test_different_attack_type_not_suppressed(self, correlator):
        evt1 = make_event(attack_type="DoS", ts_offset=0.0)
        evt2 = make_event(attack_type="PortScan", ts_offset=5.0)
        correlator.process(evt1)
        result = correlator.process(evt2)
        assert result is not None

    def test_different_dst_ip_not_suppressed(self, correlator):
        evt1 = make_event(dst_ip="10.0.0.1", ts_offset=0.0)
        evt2 = make_event(dst_ip="10.0.0.2", ts_offset=5.0)
        correlator.process(evt1)
        result = correlator.process(evt2)
        assert result is not None

    def test_different_src_ip_not_suppressed(self, correlator):
        evt1 = make_event(src_ip="192.168.1.10", ts_offset=0.0)
        evt2 = make_event(src_ip="192.168.1.11", ts_offset=5.0)
        correlator.process(evt1)
        result = correlator.process(evt2)
        assert result is not None

    def test_duplicate_after_window_expires_is_emitted(self, short_correlator):
        """
        With dedup_window=1s, an event arriving after 2s should be
        treated as a fresh emission, not suppressed.
        """
        c = short_correlator
        evt1 = make_event(ts_offset=0.0)
        evt2 = make_event(ts_offset=2.0)  # 2s > 1s dedup window
        c.process(evt1)
        c.evict_expired(now=BASE_TS + 1.5)  # evict the dedup slot
        result = c.process(evt2)
        assert result is not None

    def test_total_received_counts_both_suppressed_and_emitted(self, correlator):
        evt1 = make_event(ts_offset=0.0)
        evt2 = make_event(ts_offset=5.0)   # suppressed duplicate
        evt3 = make_event(src_ip="10.0.0.99", ts_offset=5.0)  # different src
        correlator.process(evt1)
        correlator.process(evt2)
        correlator.process(evt3)
        assert correlator.stats()["total_received"] == 3


# ─────────────────────────────────────────────────────────────────────────────
# Section 3 — Correlation grouping (FR8.1, FR8.3)
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationGrouping:

    def test_same_src_ip_events_share_group_id(self, correlator):
        evt1 = make_event(attack_type="DoS", ts_offset=0.0)
        evt2 = make_event(attack_type="PortScan", ts_offset=30.0)
        r1 = correlator.process(evt1)
        r2 = correlator.process(evt2)
        assert r1.group_id == r2.group_id

    def test_events_within_10_min_share_group(self, correlator):
        evt1 = make_event(attack_type="BruteForce", ts_offset=0.0)
        evt2 = make_event(attack_type="WebAttack", ts_offset=500.0)  # 8m20s later
        r1 = correlator.process(evt1)
        r2 = correlator.process(evt2)
        assert r1.group_id == r2.group_id

    def test_new_group_started_after_window_expires(self, short_correlator):
        """With correlation_window=2s, a 3s gap should start a new group."""
        c = short_correlator
        evt1 = make_event(attack_type="DoS", ts_offset=0.0)
        evt2 = make_event(attack_type="PortScan", ts_offset=3.0)
        r1 = c.process(evt1)
        c.evict_expired(now=BASE_TS + 2.5)
        r2 = c.process(evt2)
        assert r1.group_id != r2.group_id
        assert r2.is_new_group is True

    def test_active_group_count_correct(self, correlator):
        correlator.process(make_event(src_ip="10.0.0.1", attack_type="DoS", ts_offset=0.0))
        correlator.process(make_event(src_ip="10.0.0.2", attack_type="DoS", ts_offset=0.0))
        assert correlator.stats()["active_correlation_groups"] == 2

    def test_group_composite_severity_is_max(self, correlator):
        """
        Events: MEDIUM then CRITICAL from same src_ip.
        The group's composite severity should be CRITICAL after both are processed.
        After the second event the CorrelatedAlert should reflect CRITICAL.
        """
        evt1 = make_event(attack_type="DoS", severity="MEDIUM", ts_offset=0.0)
        evt2 = make_event(attack_type="BruteForce", severity="CRITICAL", ts_offset=30.0)
        correlator.process(evt1)
        correlator.process(evt2)
        # Inspect the internal group
        group = correlator._groups.get(evt1.src_ip)
        assert group is not None
        assert group.composite_severity == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Section 4 — Multi-stage attack chain flag (FR8.2)
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackChain:

    def test_single_attack_type_no_chain(self, correlator):
        evt1 = make_event(attack_type="DoS", ts_offset=0.0)
        evt2 = make_event(attack_type="DoS", src_ip="192.168.1.10",
                          dst_ip="10.0.0.2", ts_offset=30.0)
        correlator.process(evt1)
        # Different dst so not suppressed
        r2 = correlator.process(evt2)
        assert r2.attack_chain is False

    def test_two_distinct_attack_types_sets_chain(self, correlator):
        evt1 = make_event(attack_type="PortScan", ts_offset=0.0)
        evt2 = make_event(attack_type="BruteForce", ts_offset=60.0)
        correlator.process(evt1)
        r2 = correlator.process(evt2)
        assert r2.attack_chain is True

    def test_three_distinct_attack_types_chain_remains_true(self, correlator):
        for i, atype in enumerate(["PortScan", "BruteForce", "Infiltration"]):
            evt = make_event(
                attack_type=atype,
                dst_ip=f"10.0.0.{i + 1}",  # different dst to avoid dedup
                ts_offset=float(i * 60),
            )
            correlator.process(evt)
        group = correlator._groups.get("192.168.1.10")
        assert group.attack_chain is True
        assert len(group.attack_types) == 3

    def test_chain_attack_types_list_contains_all_seen(self, correlator):
        for i, atype in enumerate(["PortScan", "BruteForce"]):
            evt = make_event(
                attack_type=atype,
                dst_ip=f"10.0.0.{i + 1}",
                ts_offset=float(i * 70),
            )
            r = correlator.process(evt)
        assert "PortScan" in r.chain_attack_types
        assert "BruteForce" in r.chain_attack_types

    def test_chain_flag_increments_counter(self, correlator):
        evt1 = make_event(attack_type="PortScan", ts_offset=0.0)
        evt2 = make_event(attack_type="BruteForce", ts_offset=60.0)
        correlator.process(evt1)
        correlator.process(evt2)
        assert correlator.stats()["chain_flags_raised"] == 1

    def test_chain_flag_not_raised_multiple_times_for_same_group(self, correlator):
        """
        A group that is already attack_chain=True should not increment the
        counter again when a third distinct attack type arrives.
        """
        types = [
            ("PortScan", "10.0.0.1"),
            ("BruteForce", "10.0.0.2"),
            ("DoS", "10.0.0.3"),
        ]
        for atype, dst in types:
            correlator.process(make_event(
                attack_type=atype, dst_ip=dst, ts_offset=float(types.index((atype, dst)) * 60)
            ))
        # Chain raised exactly once (on the transition from 1→2 distinct types)
        assert correlator.stats()["chain_flags_raised"] == 1

    def test_attack_chain_false_for_events_from_different_src(self, correlator):
        """Two src IPs each contributing one attack type — no chain on either."""
        r1 = correlator.process(make_event(src_ip="10.0.0.1", attack_type="DoS", ts_offset=0.0))
        r2 = correlator.process(make_event(src_ip="10.0.0.2", attack_type="PortScan", ts_offset=0.0))
        assert r1.attack_chain is False
        assert r2.attack_chain is False

    def test_chain_resets_on_new_correlation_window(self, short_correlator):
        """
        After the correlation window expires, a new group starts.
        The new group should have attack_chain=False until it accumulates ≥2 types.
        """
        c = short_correlator
        # First window: two attack types → chain
        c.process(make_event(attack_type="PortScan", dst_ip="10.0.0.1", ts_offset=0.0))
        c.process(make_event(attack_type="BruteForce", dst_ip="10.0.0.2", ts_offset=0.5))
        c.evict_expired(now=BASE_TS + 3.0)  # expire the group (window=2s)
        # Second window: single attack type → no chain
        r = c.process(make_event(attack_type="DoS", ts_offset=3.0))
        assert r.attack_chain is False


# ─────────────────────────────────────────────────────────────────────────────
# Section 5 — Eviction and memory management
# ─────────────────────────────────────────────────────────────────────────────

class TestEviction:

    def test_evict_expired_removes_old_dedup_slots(self, short_correlator):
        c = short_correlator
        c.process(make_event(ts_offset=0.0))
        assert c.stats()["active_dedup_slots"] == 1
        c.evict_expired(now=BASE_TS + 2.0)  # 2s > 1s dedup window
        assert c.stats()["active_dedup_slots"] == 0

    def test_evict_expired_removes_old_groups(self, short_correlator):
        c = short_correlator
        c.process(make_event(ts_offset=0.0))
        assert c.stats()["active_correlation_groups"] == 1
        c.evict_expired(now=BASE_TS + 3.0)  # 3s > 2s correlation window
        assert c.stats()["active_correlation_groups"] == 0

    def test_evict_returns_counts(self, short_correlator):
        c = short_correlator
        c.process(make_event(src_ip="10.0.0.1", ts_offset=0.0))
        c.process(make_event(src_ip="10.0.0.2", ts_offset=0.0))
        result = c.evict_expired(now=BASE_TS + 5.0)
        assert "evicted_dedup" in result
        assert "evicted_groups" in result
        assert result["evicted_groups"] == 2

    def test_live_slots_not_evicted_prematurely(self, short_correlator):
        c = short_correlator
        c.process(make_event(ts_offset=0.0))
        # Evict at 0.5s — dedup window is 1s so slot should still be live
        result = c.evict_expired(now=BASE_TS + 0.5)
        assert result["evicted_dedup"] == 0
        assert c.stats()["active_dedup_slots"] == 1

    def test_reset_clears_all_state(self, correlator):
        correlator.process(make_event(ts_offset=0.0))
        correlator.reset()
        s = correlator.stats()
        assert s["total_received"] == 0
        assert s["active_dedup_slots"] == 0
        assert s["active_correlation_groups"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Section 6 — Stats counters
# ─────────────────────────────────────────────────────────────────────────────

class TestStats:

    def test_initial_stats_all_zero(self, correlator):
        s = correlator.stats()
        for key in [
            "total_received", "total_suppressed", "total_emitted",
            "chain_flags_raised", "active_dedup_slots",
            "active_correlation_groups",
        ]:
            assert s[key] == 0, f"{key} should be 0 initially"

    def test_emitted_count_increments_on_each_new_emission(self, correlator):
        for i in range(5):
            # Unique (src, dst, type) tuples so none are suppressed
            correlator.process(make_event(
                src_ip=f"10.0.{i}.1", ts_offset=float(i),
            ))
        assert correlator.stats()["total_emitted"] == 5

    def test_received_equals_emitted_plus_suppressed(self, correlator):
        # 3 emitted + 2 suppressed from one key
        correlator.process(make_event(ts_offset=0.0))
        correlator.process(make_event(ts_offset=5.0))   # suppressed
        correlator.process(make_event(ts_offset=10.0))  # suppressed
        correlator.process(make_event(src_ip="10.0.0.2", ts_offset=0.0))
        correlator.process(make_event(src_ip="10.0.0.3", ts_offset=0.0))
        s = correlator.stats()
        assert s["total_received"] == s["total_emitted"] + s["total_suppressed"]
