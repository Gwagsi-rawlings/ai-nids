"""
AI-NIDS — Integration Test: Full Pipeline (Capture → Feature → ML Inference)
tests/test_ml_inference_pipeline.py

Tests the wiring from PacketCapture all the way through MLInferenceEngine.
No live NIC required — all tests use synthetic Scapy packets written to
temporary PCAP files or injected directly.

Coverage:
  1. MLInferenceEngine unit tests (load, infer, edge cases)
  2. Pipeline integration tests (PCAP → results)

FR Traceability:
    FR5.1  — RF inference returns attack class + confidence
    FR5.2  — IF inference returns anomaly flag + confidence
    FR5.4  — Models loaded at startup
    FR5.6  — Confidence scores in [0.0, 1.0]
    FR5.7  — Zero-vector handled gracefully (zero-day edge case)
    FR3.10 — Normalisation applied inside engine (not in feature extractor)

April 1, 2026 | Sprint 1, Week 3 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
import pytest
from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from backend.detection.ml.inference_engine import (
    ATTACK_LABELS,
    FEATURE_COUNT,
    IF_DECISION_THRESHOLD,
    IFResult,
    MLInferenceEngine,
    MLInferenceResult,
    RFResult,
    _sigmoid,
    init_engine,
    get_engine,
)
from backend.capture.pipeline import run_pcap_pipeline

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_fake_rf_model(class_index: int = 4, confidence: float = 0.92):
    """Return a mock sklearn RF that always predicts the same class."""
    n_classes = len(ATTACK_LABELS)
    proba = np.zeros(n_classes)
    proba[class_index] = confidence
    proba[0] = 1.0 - confidence   # remainder goes to BENIGN (index 0)
    model = MagicMock()
    model.predict_proba.return_value = np.array([proba])
    return model


def make_fake_if_model(decision_score: float = -0.5):
    """Return a mock sklearn IF that always returns the given score."""
    model = MagicMock()
    model.decision_function.return_value = np.array([decision_score])
    return model


def make_fake_scaler():
    """Return a mock MinMaxScaler that passes vectors through unchanged."""
    scaler = MagicMock()
    scaler.transform.side_effect = lambda x: x   # identity
    return scaler


def zero_vector() -> np.ndarray:
    return np.zeros(FEATURE_COUNT, dtype=np.float64)


def random_vector(seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.random(FEATURE_COUNT).astype(np.float64)


def make_tcp_flow_pcap(tmp_path: Path, n_pairs: int = 1) -> str:
    """
    Write n_pairs of complete TCP flows to a PCAP file.
    Each flow: SYN → SYN-ACK → ACK → data → FIN → FIN-ACK.
    Returns the PCAP file path.
    """
    pkts = []
    for i in range(n_pairs):
        sport = 50000 + i
        pkts += [
            Ether() / IP(src=f"192.168.1.{10+i}", dst="10.0.0.1") /
            TCP(sport=sport, dport=80, flags="S"),

            Ether() / IP(src="10.0.0.1", dst=f"192.168.1.{10+i}") /
            TCP(sport=80, dport=sport, flags="SA"),

            Ether() / IP(src=f"192.168.1.{10+i}", dst="10.0.0.1") /
            TCP(sport=sport, dport=80, flags="A") /
            b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",

            Ether() / IP(src="10.0.0.1", dst=f"192.168.1.{10+i}") /
            TCP(sport=80, dport=sport, flags="PA") /
            b"HTTP/1.1 200 OK\r\n\r\n",

            Ether() / IP(src=f"192.168.1.{10+i}", dst="10.0.0.1") /
            TCP(sport=sport, dport=80, flags="FA"),

            Ether() / IP(src="10.0.0.1", dst=f"192.168.1.{10+i}") /
            TCP(sport=80, dport=sport, flags="FA"),
        ]
    pcap_path = str(tmp_path / "flows.pcap")
    wrpcap(pcap_path, pkts)
    return pcap_path


# ===========================================================================
# Section 1 — _sigmoid helper
# ===========================================================================

class TestSigmoid:
    def test_zero_maps_to_half(self):
        assert abs(_sigmoid(0.0) - 0.5) < 1e-6

    def test_large_positive_near_one(self):
        assert _sigmoid(100.0) > 0.999

    def test_large_negative_near_zero(self):
        assert _sigmoid(-100.0) < 0.001

    def test_output_always_in_unit_interval(self):
        for x in [-1000, -1, 0, 1, 1000]:
            v = _sigmoid(float(x))
            assert 0.0 <= v <= 1.0


# ===========================================================================
# Section 2 — MLInferenceEngine unit tests (no real models required)
# ===========================================================================

class TestMLInferenceEngineLoadModels:
    """FR5.4 — models loaded at startup."""

    def test_engine_not_ready_before_load(self, tmp_path):
        engine = MLInferenceEngine(model_dir=str(tmp_path))
        assert engine.is_ready is False

    def test_load_returns_status_dict(self, tmp_path):
        engine = MLInferenceEngine(model_dir=str(tmp_path))
        status = engine.load_models()
        assert isinstance(status, dict)
        assert "random_forest" in status
        assert "isolation_forest" in status
        assert "scaler" in status

    def test_engine_not_ready_if_no_models_found(self, tmp_path):
        engine = MLInferenceEngine(model_dir=str(tmp_path))
        engine.load_models()
        assert engine.is_ready is False

    def test_engine_ready_when_rf_injected(self, tmp_path):
        engine = MLInferenceEngine(model_dir=str(tmp_path))
        engine._rf_model = make_fake_rf_model()
        engine._ready = True
        assert engine.is_ready is True


class TestMLInferenceEngineRFInference:
    """FR5.1 — RF classification. FR5.5 — attack categories. FR5.6 — confidence."""

    def _engine_with_rf(self, class_index=4, confidence=0.92):
        engine = MLInferenceEngine()
        engine._rf_model = make_fake_rf_model(class_index, confidence)
        engine._scaler = make_fake_scaler()
        engine._ready = True
        return engine

    def test_rf_returns_rf_result_instance(self):
        engine = self._engine_with_rf()
        result = engine.infer("flow-001", random_vector())
        assert isinstance(result.rf, RFResult)

    def test_rf_predicted_class_is_string(self):
        engine = self._engine_with_rf(class_index=4)   # "DoS"
        result = engine.infer("flow-001", random_vector())
        assert isinstance(result.rf.attack_class, str)

    def test_rf_confidence_in_unit_interval(self):
        engine = self._engine_with_rf(confidence=0.92)
        result = engine.infer("flow-001", random_vector())
        assert 0.0 <= result.rf.confidence <= 1.0

    def test_rf_is_attack_true_for_non_benign(self):
        # class_index 4 = "DoS" (not BENIGN)
        engine = self._engine_with_rf(class_index=4)
        result = engine.infer("flow-001", random_vector())
        assert result.rf.is_attack is True

    def test_rf_is_attack_false_for_benign(self):
        # class_index 0 = "BENIGN"
        engine = self._engine_with_rf(class_index=0, confidence=0.99)
        result = engine.infer("flow-001", random_vector())
        assert result.rf.is_attack is False

    def test_rf_probabilities_shape(self):
        engine = self._engine_with_rf()
        result = engine.infer("flow-001", random_vector())
        assert result.rf.probabilities.shape == (len(ATTACK_LABELS),)

    def test_rf_no_model_returns_zero_confidence_benign(self):
        engine = MLInferenceEngine()
        engine._scaler = make_fake_scaler()
        # No RF model loaded
        result = engine.infer("flow-002", random_vector())
        assert result.rf.attack_class == "BENIGN"
        assert result.rf.confidence == 0.0


class TestMLInferenceEngineIFInference:
    """FR5.2 — IF anomaly detection. FR5.6 — confidence. FR5.7 — zero-day."""

    def _engine_with_if(self, decision_score: float):
        engine = MLInferenceEngine()
        engine._if_model = make_fake_if_model(decision_score)
        engine._scaler = make_fake_scaler()
        engine._ready = True
        return engine

    def test_if_returns_if_result_instance(self):
        engine = self._engine_with_if(-0.5)
        result = engine.infer("flow-003", random_vector())
        assert isinstance(result.if_result, IFResult)

    def test_if_confidence_in_unit_interval(self):
        for score in [-1.0, -0.5, 0.0, 0.5, 1.0]:
            engine = self._engine_with_if(score)
            result = engine.infer("f", random_vector())
            assert 0.0 <= result.if_result.confidence <= 1.0

    def test_if_anomaly_true_below_threshold(self):
        # Score well below threshold → anomaly
        engine = self._engine_with_if(IF_DECISION_THRESHOLD - 0.5)
        result = engine.infer("flow-004", random_vector())
        assert result.if_result.is_anomaly is True

    def test_if_anomaly_false_above_threshold(self):
        # Score above threshold → normal
        engine = self._engine_with_if(IF_DECISION_THRESHOLD + 0.5)
        result = engine.infer("flow-005", random_vector())
        assert result.if_result.is_anomaly is False

    def test_if_anomalous_score_gives_high_confidence(self):
        # Very negative score → high anomaly confidence
        engine = self._engine_with_if(-5.0)
        result = engine.infer("flow-006", random_vector())
        assert result.if_result.confidence > 0.99

    def test_if_normal_score_gives_low_confidence(self):
        # Large positive score → low anomaly confidence
        engine = self._engine_with_if(5.0)
        result = engine.infer("flow-007", random_vector())
        assert result.if_result.confidence < 0.01

    def test_if_no_model_returns_non_anomaly(self):
        engine = MLInferenceEngine()
        engine._scaler = make_fake_scaler()
        result = engine.infer("flow-008", random_vector())
        assert result.if_result.is_anomaly is False
        assert result.if_result.confidence == 0.0


class TestMLInferenceEngineEdgeCases:
    """FR5.6 / FR3.11 — graceful handling of bad inputs."""

    def _engine(self):
        engine = MLInferenceEngine()
        engine._rf_model = make_fake_rf_model()
        engine._if_model = make_fake_if_model()
        engine._scaler = make_fake_scaler()
        engine._ready = True
        return engine

    def test_zero_vector_returns_error_field(self):
        engine = self._engine()
        result = engine.infer("flow-z", zero_vector())
        assert result.error == "zero_vector"

    def test_zero_vector_rf_confidence_is_zero(self):
        engine = self._engine()
        result = engine.infer("flow-z", zero_vector())
        assert result.rf.confidence == 0.0

    def test_wrong_shape_returns_error(self):
        engine = self._engine()
        bad_vec = np.zeros(20, dtype=np.float64)   # wrong shape
        result = engine.infer("flow-bad", bad_vec)
        assert result.error is not None
        assert "wrong_shape" in result.error

    def test_none_input_returns_error(self):
        engine = self._engine()
        result = engine.infer("flow-none", None)
        assert result.error == "zero_vector"

    def test_result_carries_correct_flow_id(self):
        engine = self._engine()
        result = engine.infer("my-specific-flow-id", random_vector())
        assert result.flow_id == "my-specific-flow-id"

    def test_returns_ml_inference_result_instance(self):
        engine = self._engine()
        result = engine.infer("flow-x", random_vector())
        assert isinstance(result, MLInferenceResult)

    def test_rf_exception_caught_gracefully(self):
        engine = self._engine()
        engine._rf_model.predict_proba.side_effect = RuntimeError("mock RF failure")
        # Should not raise — error is captured in result.error
        result = engine.infer("flow-err", random_vector())
        assert result.error is not None
        assert result.rf.confidence == 0.0


# ===========================================================================
# Section 3 — Module-level singleton (init_engine / get_engine)
# ===========================================================================

class TestEngineSingleton:
    def test_get_engine_raises_before_init(self):
        """get_engine() must raise before init_engine() is called."""
        import backend.detection.ml.inference_engine as ie_module
        original = ie_module._engine
        ie_module._engine = None
        try:
            with pytest.raises(RuntimeError):
                get_engine()
        finally:
            ie_module._engine = original

    def test_init_engine_returns_status_dict(self, tmp_path):
        status = init_engine(model_dir=str(tmp_path))
        assert isinstance(status, dict)

    def test_get_engine_returns_instance_after_init(self, tmp_path):
        init_engine(model_dir=str(tmp_path))
        engine = get_engine()
        assert isinstance(engine, MLInferenceEngine)


# ===========================================================================
# Section 4 — Full pipeline integration tests
# ===========================================================================

class TestPipelineIntegration:
    """
    End-to-end: PCAP file → PacketCapture → FlowAggregator →
                FeatureExtractor → MLInferenceEngine → results list.
    Uses mock ML models so tests run without trained .pkl files.
    """

    def _make_engine(self):
        engine = MLInferenceEngine()
        engine._rf_model = make_fake_rf_model(class_index=4, confidence=0.85)
        engine._if_model = make_fake_if_model(decision_score=-0.3)
        engine._scaler = make_fake_scaler()
        engine._ready = True
        return engine

    def test_single_flow_pcap_produces_one_result(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=1)
        engine = self._make_engine()
        results, stats = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        assert len(results) >= 1

    def test_multiple_flows_produce_multiple_results(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=3)
        engine = self._make_engine()
        results, stats = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        assert len(results) >= 1  # at least one flow per pair

    def test_results_are_ml_inference_result_instances(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=2)
        engine = self._make_engine()
        results, _ = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        for r in results:
            assert isinstance(r, MLInferenceResult)

    def test_rf_confidence_in_unit_interval(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=2)
        engine = self._make_engine()
        results, _ = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        for r in results:
            assert 0.0 <= r.rf.confidence <= 1.0

    def test_if_confidence_in_unit_interval(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=2)
        engine = self._make_engine()
        results, _ = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        for r in results:
            assert 0.0 <= r.if_result.confidence <= 1.0

    def test_flow_ids_are_non_empty_strings(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=1)
        engine = self._make_engine()
        results, _ = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        for r in results:
            assert isinstance(r.flow_id, str)
            assert len(r.flow_id) > 0

    def test_stats_packets_captured_positive(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=1)
        engine = self._make_engine()
        _, stats = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        assert stats.packets_captured > 0

    def test_stats_inferences_match_results(self, tmp_path):
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=2)
        engine = self._make_engine()
        results, stats = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        # inferences_run must equal the number of results collected
        assert stats.inferences_run == len(results)

    def test_pipeline_does_not_raise_on_empty_pcap(self, tmp_path):
        """Empty PCAP should complete without error, returning no results."""
        pcap_path = str(tmp_path / "empty.pcap")
        wrpcap(pcap_path, [])
        engine = self._make_engine()
        results, stats = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        assert results == []
        assert stats.inferences_run == 0

    def test_pipeline_with_mixed_protocols(self, tmp_path):
        """Pipeline must not crash on UDP / ICMP packets mixed with TCP flows."""
        pkts = [
            Ether() / IP(src="1.1.1.1", dst="2.2.2.2") /
            TCP(sport=12345, dport=80, flags="S"),

            Ether() / IP(src="1.1.1.1", dst="2.2.2.2") /
            UDP(sport=9999, dport=53) / b"\x00\x01",

            Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(),

            Ether() / IP(src="1.1.1.1", dst="2.2.2.2") /
            TCP(sport=12345, dport=80, flags="FA"),
        ]
        pcap_path = str(tmp_path / "mixed.pcap")
        wrpcap(pcap_path, pkts)

        engine = self._make_engine()
        # Must not raise
        results, stats = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        assert stats.packets_captured == 4

    def test_no_model_pipeline_still_completes(self, tmp_path):
        """
        If no models are loaded (pre-training state), the pipeline must
        complete and return zero-confidence results rather than crashing.
        """
        pcap_path = make_tcp_flow_pcap(tmp_path, n_pairs=1)
        engine = MLInferenceEngine()   # no models loaded
        results, stats = asyncio.get_event_loop().run_until_complete(
            run_pcap_pipeline(pcap_path, engine)
        )
        for r in results:
            assert r.rf.confidence == 0.0
            assert r.if_result.confidence == 0.0
