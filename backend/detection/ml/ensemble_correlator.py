"""
AI-NIDS — Ensemble Correlator
capture/ensemble_correlator.py

Combines outputs from all four detection engines using weighted majority voting.
Implements the alert threshold, severity classification, and 60-second
deduplication window documented in §4.11.

Ensemble formula:
    Score = 0.40 × sig_conf + 0.35 × rf_conf + 0.15 × lstm_conf + 0.10 × if_conf

Alert threshold: Score >= 0.50

FR Traceability:
    FR6.1  — Combine results from signature and AI detection engines
    FR6.2  — Majority voting when engines disagree
    FR6.3  — Weight detection results by engine confidence scores
    FR6.4  — Prioritise signature detection for known attacks
    FR6.5  — Use AI detection for uncertain/unknown traffic patterns
    FR6.6  — Log all individual engine results before ensemble decision
    FR7.2  — Classify alert severity (Critical / High / Medium / Low)
    FR8.5  — Suppress duplicate alerts within 60-second window

NFR Traceability:
    NFR20.2 — FPR ≤ 5%  (multi-engine threshold prevents single-engine FP)
    NFR20.5 — Ensemble ≥ 2% F1 gain over best individual model
    NFR1.4  — ≤ 100 ms end-to-end latency (correlator target: ≤ 10 ms)

April 2026 | Sprint 2 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("ai-nids.ensemble")

# ── Ensemble weights (Component Design Doc Feb 25, §4.4) ──────
W_SIG  = 0.40   # Signature Engine  — deterministic, highest precision
W_RF   = 0.35   # Random Forest     — supervised multiclass
W_LSTM = 0.15   # LSTM              — temporal sequential detection
W_IF   = 0.10   # Isolation Forest  — zero-day / unsupervised

ALERT_THRESHOLD = 0.50   # Minimum score to generate an alert

# Severity thresholds (§3.5.4 / Table 3.5.3)
SEV_CRITICAL = 0.95
SEV_HIGH     = 0.85
SEV_MEDIUM   = 0.70
SEV_LOW      = 0.50   # == ALERT_THRESHOLD

# Deduplication window in seconds (FR8.5)
DEDUP_WINDOW_SECS = 60


# ── Input dataclasses ─────────────────────────────────────────

@dataclass
class SigResult:
    """Output from the Signature Detection Engine (Stage 4a)."""
    flow_id: str
    matched: bool           # True if any rule fired
    rule_id: str            # e.g. "SID:1001"; empty string if no match
    rule_name: str          # human-readable rule name; empty if no match
    attack_type: str        # e.g. "DoS", "PortScan"; "BENIGN" if no match
    confidence: float       # 1.0 for deterministic match; 0.0 for no match
    severity: str           # rule-level severity: CRITICAL/HIGH/MEDIUM/LOW


@dataclass
class RFResult:
    """Output from the Random Forest Inference Engine."""
    flow_id: str
    predicted_class: str    # e.g. "DoS", "BENIGN"
    confidence: float       # max predict_proba value of predicted class [0,1]
    is_attack: bool         # True if predicted_class != "BENIGN"
    probabilities: dict     # class -> probability mapping


@dataclass
class LSTMResult:
    """Output from the LSTM Sequential Classifier."""
    flow_id: str
    predicted_class: str
    confidence: float       # softmax probability of predicted class [0,1]
    is_attack: bool
    window_complete: bool   # False during cold-start (< 10 flows for src_ip)


@dataclass
class IFResult:
    """Output from the Isolation Forest Anomaly Detector."""
    flow_id: str
    is_anomaly: bool
    confidence: float       # sigmoid(decision_function) mapped to [0,1]
    raw_score: float        # raw IF decision_function output


# ── Output dataclass ──────────────────────────────────────────

@dataclass
class EnsembleVerdict:
    """
    Final verdict produced by the Ensemble Correlator for one flow.
    Consumed by the Alert Generator (Stage 6).
    """
    flow_id: str
    score: float                    # weighted ensemble score [0,1]
    alert: bool                     # True if score >= ALERT_THRESHOLD
    severity: str                   # CRITICAL / HIGH / MEDIUM / LOW / NONE
    attack_type: str                # from highest-weighted engine that flagged attack
    confidence: float               # == score (reported in alert record)

    # Individual engine outputs — always persisted per FR6.6
    sig_conf: float
    rf_conf: float
    lstm_conf: float
    if_conf: float

    sig_matched: bool
    rf_class: str
    lstm_class: str
    if_anomaly: bool

    # Source attribution
    detected_by: str                # "signature" | "ml" | "both" | "none"
    contributing_engines: list      # e.g. ["signature", "rf"]

    # Deduplication
    is_duplicate: bool = False      # True if suppressed by dedup window


# ── Deduplication tracker ─────────────────────────────────────

class _DedupWindow:
    """
    Sliding 60-second deduplication window.
    Key: (src_ip, dst_ip, attack_type) — extracted from flow_id + verdict.
    Tracks duplicate count on the original alert record (FR8.5).
    """

    def __init__(self, window_secs: int = DEDUP_WINDOW_SECS):
        self._window = window_secs
        self._seen: dict[tuple, float] = {}   # key -> timestamp of first occurrence
        self._dup_count: dict[tuple, int] = {}

    def check(self, key: tuple) -> bool:
        """
        Returns True if this key is a duplicate within the window.
        Side effect: registers the key if first occurrence or window expired.
        """
        now = time.monotonic()
        last = self._seen.get(key)
        if last is not None and (now - last) < self._window:
            self._dup_count[key] = self._dup_count.get(key, 0) + 1
            return True   # duplicate
        # First occurrence or window expired — register
        self._seen[key] = now
        self._dup_count[key] = 0
        return False

    def dup_count(self, key: tuple) -> int:
        return self._dup_count.get(key, 0)

    def expire(self):
        """Purge entries older than the window. Call periodically."""
        now = time.monotonic()
        expired = [k for k, t in self._seen.items() if (now - t) >= self._window]
        for k in expired:
            del self._seen[k]
            self._dup_count.pop(k, None)


# ── Main Correlator ───────────────────────────────────────────

class EnsembleCorrelator:
    """
    Combines Signature Engine, RF, LSTM, and IF results for a single flow
    into a weighted ensemble score and final verdict.

    Usage:
        correlator = EnsembleCorrelator()
        verdict = correlator.correlate(sig_result, rf_result, lstm_result, if_result,
                                       src_ip="1.2.3.4", dst_ip="10.0.0.1")
    """

    def __init__(
        self,
        w_sig: float  = W_SIG,
        w_rf: float   = W_RF,
        w_lstm: float = W_LSTM,
        w_if: float   = W_IF,
        threshold: float = ALERT_THRESHOLD,
        dedup_window: int = DEDUP_WINDOW_SECS,
    ):
        assert abs(w_sig + w_rf + w_lstm + w_if - 1.0) < 1e-9, \
            "Ensemble weights must sum to 1.0"

        self.w_sig   = w_sig
        self.w_rf    = w_rf
        self.w_lstm  = w_lstm
        self.w_if    = w_if
        self.threshold = threshold
        self._dedup  = _DedupWindow(dedup_window)

        logger.info(
            "EnsembleCorrelator ready — weights: Sig=%.2f RF=%.2f LSTM=%.2f IF=%.2f  "
            "threshold=%.2f  dedup=%ds",
            w_sig, w_rf, w_lstm, w_if, threshold, dedup_window,
        )

    # ── Core correlation method ───────────────────────────────

    def correlate(
        self,
        sig: SigResult,
        rf: RFResult,
        lstm: LSTMResult,
        if_: IFResult,
        src_ip: str = "",
        dst_ip: str = "",
    ) -> EnsembleVerdict:
        """
        Compute weighted ensemble score and produce a verdict.

        LSTM cold-start: if lstm.window_complete is False, lstm_conf is treated
        as 0.0 regardless of the LSTMResult value (§4.10.4).

        LSTM timeout fallback: caller should pass lstm.confidence = 0.0 and
        lstm.window_complete = False when the LSTM did not return within 80 ms
        (Design Review G-03).
        """
        # Apply cold-start / timeout fallback
        lstm_conf = lstm.confidence if lstm.window_complete else 0.0

        # Weighted score (FR6.3)
        score = (
            self.w_sig  * sig.confidence +
            self.w_rf   * rf.confidence +
            self.w_lstm * lstm_conf +
            self.w_if   * if_.confidence
        )
        score = round(min(max(score, 0.0), 1.0), 6)

        alert = score >= self.threshold

        # Attack type: highest-weighted engine that flagged an attack (FR6.4 / FR6.5)
        attack_type, detected_by, contributing = self._resolve_attack_type(
            sig, rf, lstm, if_, lstm_conf
        )

        severity = self._classify_severity(score) if alert else "NONE"

        # Deduplication (FR8.5)
        is_dup = False
        if alert:
            dedup_key = (src_ip, dst_ip, attack_type)
            is_dup = self._dedup.check(dedup_key)
            if is_dup:
                logger.debug(
                    "Duplicate suppressed — flow=%s key=%s dup#%d",
                    sig.flow_id, dedup_key, self._dedup.dup_count(dedup_key),
                )

        # Always log individual engine outputs (FR6.6)
        if alert and not is_dup:
            logger.info(
                "ALERT flow=%s score=%.4f sev=%s type=%s  "
                "sig=%.3f rf=%.3f lstm=%.3f if=%.3f  by=%s",
                sig.flow_id, score, severity, attack_type,
                sig.confidence, rf.confidence, lstm_conf, if_.confidence,
                detected_by,
            )
        else:
            logger.debug(
                "flow=%s score=%.4f alert=%s  sig=%.3f rf=%.3f lstm=%.3f if=%.3f",
                sig.flow_id, score, alert,
                sig.confidence, rf.confidence, lstm_conf, if_.confidence,
            )

        return EnsembleVerdict(
            flow_id             = sig.flow_id,
            score               = score,
            alert               = alert and not is_dup,
            severity            = severity,
            attack_type         = attack_type,
            confidence          = score,
            sig_conf            = sig.confidence,
            rf_conf             = rf.confidence,
            lstm_conf           = lstm_conf,
            if_conf             = if_.confidence,
            sig_matched         = sig.matched,
            rf_class            = rf.predicted_class,
            lstm_class          = lstm.predicted_class,
            if_anomaly          = if_.is_anomaly,
            detected_by         = detected_by,
            contributing_engines= contributing,
            is_duplicate        = is_dup,
        )

    # ── Helpers ───────────────────────────────────────────────

    def _resolve_attack_type(
        self,
        sig: SigResult,
        rf: RFResult,
        lstm: LSTMResult,
        if_: IFResult,
        lstm_conf: float,
    ) -> tuple[str, str, list]:
        """
        Determine final attack_type label, detected_by tag, and contributing
        engines list based on which engines flagged an attack.

        Priority order (FR6.4): Signature > RF > LSTM > IF
        """
        engines = []

        # Signature Engine takes priority (FR6.4)
        if sig.matched:
            engines.append("signature")
            attack_type = sig.attack_type
        elif rf.is_attack:
            engines.append("rf")
            attack_type = rf.predicted_class
        elif lstm_conf > 0 and lstm.is_attack:
            engines.append("lstm")
            attack_type = lstm.predicted_class
        elif if_.is_anomaly:
            engines.append("isolation_forest")
            attack_type = "ANOMALY"
        else:
            attack_type = "BENIGN"

        # Add secondary contributors
        if rf.is_attack and "rf" not in engines:
            engines.append("rf")
        if lstm_conf > 0 and lstm.is_attack and "lstm" not in engines:
            engines.append("lstm")
        if if_.is_anomaly and "isolation_forest" not in engines:
            engines.append("isolation_forest")

        if len(engines) == 0:
            detected_by = "none"
        elif "signature" in engines and len(engines) > 1:
            detected_by = "both"
        elif "signature" in engines:
            detected_by = "signature"
        else:
            detected_by = "ml"

        return attack_type, detected_by, engines

    @staticmethod
    def _classify_severity(score: float) -> str:
        """Four-tier severity classification (FR7.2, Table 3.5.3)."""
        if score >= SEV_CRITICAL:
            return "CRITICAL"
        if score >= SEV_HIGH:
            return "HIGH"
        if score >= SEV_MEDIUM:
            return "MEDIUM"
        return "LOW"

    def expire_dedup(self):
        """Purge stale deduplication entries. Call every 60 seconds."""
        self._dedup.expire()

    # ── Convenience: LSTM not available ──────────────────────

    @staticmethod
    def make_null_lstm(flow_id: str) -> LSTMResult:
        """
        Returns a zero-contribution LSTMResult for cold-start or timeout.
        The correlator treats window_complete=False as lstm_conf=0.
        """
        return LSTMResult(
            flow_id         = flow_id,
            predicted_class = "BENIGN",
            confidence      = 0.0,
            is_attack       = False,
            window_complete = False,
        )

    @staticmethod
    def make_null_sig(flow_id: str) -> SigResult:
        """Returns a no-match SigResult (used in testing / ML-only mode)."""
        return SigResult(
            flow_id    = flow_id,
            matched    = False,
            rule_id    = "",
            rule_name  = "",
            attack_type= "BENIGN",
            confidence = 0.0,
            severity   = "LOW",
        )

    @staticmethod
    def make_null_if(flow_id: str) -> IFResult:
        """Returns a non-anomalous IFResult (used in testing)."""
        return IFResult(
            flow_id    = flow_id,
            is_anomaly = False,
            confidence = 0.0,
            raw_score  = 0.5,
        )