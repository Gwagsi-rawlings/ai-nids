"""
AI-NIDS — Alert Correlator
backend/detection/alert_correlator.py

Stage 6a of the detection pipeline. Receives raw detection events from the
Ensemble Correlator and applies three mechanisms before forwarding to the
Alert Generator:

  1. 60-second deduplication window  (FR8.5)
     Suppresses duplicate (src_ip, dst_ip, attack_type) events within a
     rolling 60-second window.  The dup_count field is incremented on the
     existing entry rather than emitting a new event.

  2. 10-minute correlation window  (FR8.1)
     Groups all events from the same src_ip within a 600-second window
     into a CorrelationGroup.  Each group carries a list of constituent
     alert_ids and a composite severity (maximum across members).

  3. Multi-stage attack chain flag  (FR8.2)
     Sets attack_chain=True on a CorrelationGroup when the same src_ip
     produces events belonging to ≥2 DISTINCT attack categories within
     the 10-minute window.  This flags coordinated campaigns
     (e.g. PortScan → BruteForce → Infiltration).

FR Traceability:
    FR8.1  — Correlate alerts from same source IP within time window
    FR8.2  — Identify multi-stage attack patterns
    FR8.3  — Group related alerts into incidents
    FR8.4  — Detect coordinated attacks from multiple sources
    FR8.5  — Suppress duplicate alerts within 60 seconds

NFR Traceability:
    NFR20.2 — FPR ≤5%  (deduplication reduces false alert volume)
    NFR1.4  — Alert latency ≤100 ms  (correlator budget ≤15 ms)

April 24, 2026 | Sprint Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("ai-nids.alert_correlator")

# ── Timing constants ──────────────────────────────────────────────────────────
DEDUP_WINDOW_SECONDS: float = 60.0      # FR8.5: suppress duplicates
CORRELATION_WINDOW_SECONDS: float = 600.0  # FR8.1: 10-minute grouping window

# ── Severity ordering for composite calculation ───────────────────────────────
_SEVERITY_RANK: Dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
_RANK_SEVERITY: Dict[int, str] = {v: k for k, v in _SEVERITY_RANK.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectionEvent:
    """
    Raw event produced by the Ensemble Correlator (Stage 5).
    This is the input contract for the Alert Correlator.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    attack_type: str          # e.g. "DoS", "PortScan", "BruteForce", "BENIGN"
    severity: str             # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: float         # ensemble weighted score 0.0–1.0
    detected_by: str          # "signature" | "ml" | "both"
    timestamp: float = field(default_factory=time.time)
    # Per-engine confidence breakdown (FR6.6 — always logged)
    sig_confidence: float = 0.0
    rf_confidence: float = 0.0
    lstm_confidence: float = 0.0
    if_confidence: float = 0.0


@dataclass
class CorrelatedAlert:
    """
    Output of the Alert Correlator — forwarded to the Alert Generator.

    Carries:
      - The original DetectionEvent (primary event in this group slot)
      - group_id: shared UUID for all alerts in this correlation group
      - dup_count: how many times this exact (src, dst, type) was suppressed
      - attack_chain: True when src_ip has produced ≥2 distinct attack types
        within the 10-minute window (FR8.2)
      - chain_attack_types: the set of distinct attack types seen in the group
    """
    event: DetectionEvent
    group_id: str
    dup_count: int = 0
    attack_chain: bool = False
    chain_attack_types: List[str] = field(default_factory=list)
    is_new_group: bool = False   # True on first event in a fresh group


@dataclass
class _DedupEntry:
    """Internal: tracks a live dedup window slot."""
    first_seen: float
    last_seen: float
    dup_count: int
    group_id: str     # link back to the CorrelationGroup this event belongs to


@dataclass
class _CorrelationGroup:
    """Internal: tracks a live 10-minute correlation window for one src_ip."""
    group_id: str
    src_ip: str
    first_seen: float
    last_seen: float
    alert_ids: List[str]          # flow_ids that form this group
    attack_types: set             # distinct attack types seen from this src_ip
    composite_severity: str       # maximum severity across all events
    attack_chain: bool = False    # ≥2 distinct attack types → True (FR8.2)


# ─────────────────────────────────────────────────────────────────────────────
# AlertCorrelator
# ─────────────────────────────────────────────────────────────────────────────

class AlertCorrelator:
    """
    Stateful correlator.  One instance is shared across the pipeline.
    All public methods are thread-safe via an internal Lock.

    Usage (in the async pipeline, call from a sync executor):

        correlator = AlertCorrelator()

        # For each detection event from the Ensemble Correlator:
        correlated = correlator.process(event)
        if correlated is not None:
            # Forward to Alert Generator
            alert_generator.create(correlated)

    Housekeeping:
        Call correlator.evict_expired() periodically (e.g. every 30 s) to
        purge expired dedup and correlation windows and prevent unbounded
        memory growth.
    """

    def __init__(
        self,
        dedup_window: float = DEDUP_WINDOW_SECONDS,
        correlation_window: float = CORRELATION_WINDOW_SECONDS,
    ) -> None:
        self._dedup_window = dedup_window
        self._correlation_window = correlation_window
        self._lock = Lock()

        # key: (src_ip, dst_ip, attack_type)  → _DedupEntry
        self._dedup: Dict[Tuple[str, str, str], _DedupEntry] = {}

        # key: src_ip  → _CorrelationGroup
        self._groups: Dict[str, _CorrelationGroup] = {}

        # Counters for dashboard / logging
        self._total_received: int = 0
        self._total_suppressed: int = 0
        self._total_emitted: int = 0
        self._chain_flags_raised: int = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, event: DetectionEvent) -> Optional[CorrelatedAlert]:
        """
        Process a single DetectionEvent.

        Returns:
            CorrelatedAlert if the event should generate an alert.
            None if the event was suppressed by the dedup window.

        Thread-safe.
        """
        now = event.timestamp

        with self._lock:
            self._total_received += 1
            self._evict_expired_locked(now)

            dedup_key = (event.src_ip, event.dst_ip, event.attack_type)

            # ── 1. Deduplication check ────────────────────────────────────
            existing = self._dedup.get(dedup_key)
            if existing is not None and (now - existing.first_seen) <= self._dedup_window:
                # Within the dedup window — suppress and increment counter
                existing.dup_count += 1
                existing.last_seen = now
                self._total_suppressed += 1
                logger.debug(
                    "Suppressed duplicate: %s → %s [%s] dup_count=%d",
                    event.src_ip, event.dst_ip, event.attack_type, existing.dup_count,
                )
                return None

            # ── 2. Register / refresh dedup slot ─────────────────────────
            group_id = self._get_or_create_group_id(event.src_ip, now)
            self._dedup[dedup_key] = _DedupEntry(
                first_seen=now,
                last_seen=now,
                dup_count=0,
                group_id=group_id,
            )

            # ── 3. Update / create correlation group ─────────────────────
            group, is_new_group = self._update_group(event, group_id, now)

            # ── 4. Build CorrelatedAlert ──────────────────────────────────
            self._total_emitted += 1
            correlated = CorrelatedAlert(
                event=event,
                group_id=group.group_id,
                dup_count=0,
                attack_chain=group.attack_chain,
                chain_attack_types=sorted(group.attack_types),
                is_new_group=is_new_group,
            )

            if group.attack_chain and len(group.attack_types) > 1:
                logger.warning(
                    "ATTACK CHAIN detected: src_ip=%s attack_types=%s group_id=%s",
                    event.src_ip, sorted(group.attack_types), group.group_id,
                )

            return correlated

    def evict_expired(self, now: Optional[float] = None) -> Dict[str, int]:
        """
        Evict expired dedup and correlation window entries.
        Call this periodically from a background task (every 30 s is sufficient).

        Returns a dict with eviction counts for observability.
        """
        if now is None:
            now = time.time()
        with self._lock:
            return self._evict_expired_locked(now)

    def stats(self) -> Dict[str, int]:
        """Return counters for the monitoring dashboard (FR17)."""
        with self._lock:
            return {
                "total_received": self._total_received,
                "total_suppressed": self._total_suppressed,
                "total_emitted": self._total_emitted,
                "chain_flags_raised": self._chain_flags_raised,
                "active_dedup_slots": len(self._dedup),
                "active_correlation_groups": len(self._groups),
            }

    def reset(self) -> None:
        """Clear all state. Intended for testing only."""
        with self._lock:
            self._dedup.clear()
            self._groups.clear()
            self._total_received = 0
            self._total_suppressed = 0
            self._total_emitted = 0
            self._chain_flags_raised = 0

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_or_create_group_id(self, src_ip: str, now: float) -> str:
        """
        Return the group_id for src_ip if a live correlation group exists,
        otherwise allocate a new UUID.
        """
        group = self._groups.get(src_ip)
        if group is not None and (now - group.first_seen) <= self._correlation_window:
            return group.group_id
        return str(uuid.uuid4())

    def _update_group(
        self,
        event: DetectionEvent,
        group_id: str,
        now: float,
    ) -> Tuple[_CorrelationGroup, bool]:
        """
        Update the CorrelationGroup for event.src_ip.
        Creates a new group if none exists or the previous one has expired.

        Returns (group, is_new_group).
        """
        existing = self._groups.get(event.src_ip)
        is_new = False

        if existing is None or (now - existing.first_seen) > self._correlation_window:
            # Start a fresh group
            group = _CorrelationGroup(
                group_id=group_id,
                src_ip=event.src_ip,
                first_seen=now,
                last_seen=now,
                alert_ids=[event.flow_id],
                attack_types={event.attack_type},
                composite_severity=event.severity,
                attack_chain=False,
            )
            self._groups[event.src_ip] = group
            is_new = True
        else:
            group = existing
            group.last_seen = now
            group.alert_ids.append(event.flow_id)
            group.attack_types.add(event.attack_type)

            # Update composite severity to maximum observed
            current_rank = _SEVERITY_RANK.get(group.composite_severity, 1)
            new_rank = _SEVERITY_RANK.get(event.severity, 1)
            if new_rank > current_rank:
                group.composite_severity = event.severity

        # ── Multi-stage chain detection (FR8.2) ──────────────────────────
        if len(group.attack_types) >= 2 and not group.attack_chain:
            group.attack_chain = True
            self._chain_flags_raised += 1

        return group, is_new

    def _evict_expired_locked(self, now: float) -> Dict[str, int]:
        """Must be called with self._lock held."""
        # Evict dedup entries older than the dedup window
        expired_dedup = [
            k for k, v in self._dedup.items()
            if (now - v.first_seen) > self._dedup_window
        ]
        for k in expired_dedup:
            del self._dedup[k]

        # Evict correlation groups older than the correlation window
        expired_groups = [
            src_ip for src_ip, g in self._groups.items()
            if (now - g.first_seen) > self._correlation_window
        ]
        for src_ip in expired_groups:
            del self._groups[src_ip]

        return {
            "evicted_dedup": len(expired_dedup),
            "evicted_groups": len(expired_groups),
        }
