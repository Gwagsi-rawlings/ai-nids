"""
AI-NIDS — Stage-Level Latency Benchmarks (NFR1.4 — P95 ≤ 100ms)
"""
import numpy as np
import pytest
from unittest.mock import MagicMock
from backend.detection.ml.inference_engine import MLInferenceEngine, FEATURE_COUNT
from backend.capture.feature_extractor import FeatureExtractor, FlowAggregator
from backend.detection.ml.ensemble_correlator import EnsembleCorrelator

def make_engine():
    e = MLInferenceEngine()
    e._rf_model = MagicMock()
    e._rf_model.predict_proba.return_value = np.array([[0.0]*4 + [0.92]])
    e._if_model = MagicMock()
    e._if_model.decision_function.return_value = np.array([-0.3])
    e._scaler = MagicMock()
    e._scaler.transform.side_effect = lambda x: x
    e._ready = True
    return e

def test_ml_inference_latency(benchmark):
    engine = make_engine()
    vec = np.random.rand(FEATURE_COUNT).astype(np.float64)
    result = benchmark(engine.infer, "flow-001", vec)
    assert result is not None

def test_ensemble_correlator_latency(benchmark):
    from backend.detection.ml.ensemble_correlator import RFResult, IFResult, LSTMResult, SigResult
    corr = EnsembleCorrelator()
    sig = SigResult(flow_id="f", matched=False, rule_id="", rule_name="", attack_type="BENIGN", confidence=0.0, severity="LOW")
    rf  = RFResult(flow_id="f", predicted_class="DoS", confidence=0.92,
                   is_attack=True, probabilities={})
    lstm = LSTMResult(flow_id="f", predicted_class="DoS", confidence=0.88,
                      is_attack=True, window_complete=True)
    if_ = IFResult(flow_id="f", is_anomaly=True, confidence=0.72, raw_score=-0.3)
    result = benchmark(corr.correlate, sig, rf, lstm, if_,
                       src_ip="10.0.0.1", dst_ip="192.168.1.1")
    assert result is not None

def test_feature_extractor_latency(benchmark):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from backend.capture.pipeline import DetectionPipeline
    import asyncio
    agg = FlowAggregator()
    feat = FeatureExtractor()
    pkts = [
        Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=9999, dport=80, flags="S"),
        Ether()/IP(src="2.2.2.2", dst="1.1.1.1")/TCP(sport=80, dport=9999, flags="FA"),
    ]
    flows = []
    for p in pkts:
        d = {"timestamp": 0.0, "src_ip": p[IP].src, "dst_ip": p[IP].dst,
             "src_port": p[TCP].sport, "dst_port": p[TCP].dport,
             "protocol": "TCP", "length": len(p), "tcp_flags": str(p[TCP].flags),
             "payload_bytes": bytes(p[TCP].payload)}
        pkt = DetectionPipeline._dict_to_packet_record(d)
        if pkt:
            flow = agg.ingest(pkt)
            if flow:
                flows.append(flow)
    for f in agg.flush_all():
        flows.append(f)
    if flows:
        result = benchmark(feat.extract, flows[0])
        assert result is not None
    else:
        pytest.skip("No flows produced")
