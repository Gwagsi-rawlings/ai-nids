"""
AI-NIDS — Detection Pipeline (Stage 1 → Stage 6)
capture/pipeline.py

Wires all six pipeline stages into a single async processing loop:
    Stage 1: Packet Capture Engine  (PacketCapture)
    Stage 2: Flow Aggregator        (FlowAggregator)
    Stage 3: Feature Extractor      (FeatureExtractor)
    Stage 4a: Signature Engine      (SignatureEngine)
    Stage 4b: ML Inference Engine   (MLInferenceEngine — RF + IF + LSTM)
    Stage 5:  Ensemble Correlator   (EnsembleCorrelator)
    Stage 6:  Alert Generator       (AlertGenerator — writes to DB / queue)

Queue depths and backpressure strategy match the Component Design Document
(Feb 25, §2.1) and Architecture Design Document (Feb 24, §4.3).

FR Traceability:
    FR1   — Packet capture
    FR3   — Feature extraction
    FR4   — Signature detection
    FR5   — ML inference (RF, IF, LSTM)
    FR6   — Ensemble correlation
    FR7   — Alert generation

NFR Traceability:
    NFR1.1 — ≥ 10,000 pps throughput
    NFR1.4 — ≤ 100 ms end-to-end latency

April 2026 | Sprint 2 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

import numpy as np

logger = logging.getLogger("ai-nids.pipeline")

# ── Queue depth limits (ADD Feb 24, §4.3) ────────────────────
Q_RAW_PACKETS  = 10_000
Q_FLOWS        = 5_000
Q_FEATURES     = 5_000
Q_ALERTS       = 0          # unbounded — no alert drops permitted

# Idle flow flush interval in seconds
FLOW_FLUSH_INTERVAL = 1.0


# ── Lightweight alert record passed downstream ────────────────

@dataclass
class AlertRecord:
    """
    Minimal alert record produced by Stage 6.
    Populated from EnsembleVerdict + flow metadata.
    In Sprint 2 this is written to an asyncio queue;
    the DB writer (FR7.8) is wired in Sprint 3 (Week 4).
    """
    alert_id:    str
    flow_id:     str
    timestamp:   float       # Unix epoch seconds
    severity:    str         # CRITICAL / HIGH / MEDIUM / LOW
    attack_type: str
    confidence:  float
    score:       float
    src_ip:      str
    dst_ip:      str
    src_port:    Optional[int]
    dst_port:    Optional[int]
    protocol:    str
    detected_by: str
    contributing_engines: list
    # Engine-level detail
    sig_matched: bool
    sig_rule_id: str
    rf_class:    str
    lstm_class:  str
    if_anomaly:  bool
    sig_conf:    float
    rf_conf:     float
    lstm_conf:   float
    if_conf:     float


# ── Pipeline stats ────────────────────────────────────────────

@dataclass
class PipelineStats:
    packets_captured:  int = 0
    packets_dropped:   int = 0
    flows_emitted:     int = 0
    features_extracted:int = 0
    sig_matches:       int = 0
    ml_inferences:     int = 0
    alerts_generated:  int = 0
    alerts_suppressed: int = 0   # dedup
    inferences_run:    int = 0
    start_time:        float = field(default_factory=time.monotonic)

    def summary(self) -> dict:
        elapsed = max(time.monotonic() - self.start_time, 1e-9)
        return {
            "packets_captured":   self.packets_captured,
            "packets_dropped":    self.packets_dropped,
            "flows_emitted":      self.flows_emitted,
            "features_extracted": self.features_extracted,
            "sig_matches":        self.sig_matches,
            "ml_inferences":      self.ml_inferences,
            "alerts_generated":   self.alerts_generated,
            "alerts_suppressed":  self.alerts_suppressed,
            "uptime_s":           round(elapsed, 1),
            "flows_per_sec":      round(self.flows_emitted / elapsed, 1),
        }


# ── Main Pipeline class ───────────────────────────────────────

class DetectionPipeline:
    """
    Full AI-NIDS detection pipeline.

    Stages 4a and 4b (Signature + ML) run on the same feature vector
    in parallel via asyncio.gather, keeping both within the shared
    ≤ 100 ms ML budget (NFR1.4).

    Usage (PCAP replay):
        pipeline = DetectionPipeline(ml_engine, sig_engine, correlator)
        await pipeline.run_pcap(pcap_path, alert_callback=my_handler)

    Usage (live capture):
        pipeline = DetectionPipeline(ml_engine, sig_engine, correlator)
        await pipeline.run_live(interface="eth0", alert_callback=my_handler)
    """

    def __init__(
        self,
        ml_engine,          # MLInferenceEngine instance
        sig_engine,         # SignatureEngine instance (or None for ML-only)
        correlator,         # EnsembleCorrelator instance
        alert_callback: Optional[Callable] = None,
        flow_timeout: float = 60.0,
    ):
        from backend.capture.feature_extractor import FlowAggregator, FeatureExtractor

        self._ml      = ml_engine
        self._sig     = sig_engine
        self._corr    = correlator
        self._alert_cb= alert_callback
        self._flow_timeout = flow_timeout

        self._agg   = FlowAggregator()
        self._feat  = FeatureExtractor()
        self._stats = PipelineStats()
        self._running = False
        self._loop    = None  # set in run_pcap() before executor dispatch

        # Inter-stage queues
        self._raw_q     = asyncio.Queue(maxsize=Q_RAW_PACKETS)
        self._flow_q    = asyncio.Queue(maxsize=Q_FLOWS)
        self._feature_q = asyncio.Queue(maxsize=Q_FEATURES)
        self._alert_q   = asyncio.Queue(maxsize=Q_ALERTS)

    # ── Public entry points ───────────────────────────────────

    async def run_pcap(self, pcap_path: str, alert_callback=None) -> PipelineStats:
        """
        Replay a PCAP file through the full pipeline.
        Blocks until all packets are processed.
        Returns PipelineStats.
        """
        if alert_callback:
            self._alert_cb = alert_callback

        self._running = True
        self._loop = asyncio.get_running_loop()  # capture before executor dispatch
        logger.info("Pipeline: starting PCAP replay — %s", pcap_path)

        # Start all stage workers as concurrent tasks
        tasks = [
            asyncio.create_task(self._stage2_flow_aggregator()),
            asyncio.create_task(self._stage3_feature_extractor()),
            asyncio.create_task(self._stage4_detection()),
            asyncio.create_task(self._stage6_alert_writer()),
        ]

        # Stage 1: feed packets into raw_q (blocking read from PCAP)
        await self._loop.run_in_executor(
            None, self._stage1_read_pcap, pcap_path
        )

        # Signal end of stream to downstream stages
        await self._raw_q.put(None)

        # Wait for all stages to drain
        await asyncio.gather(*tasks)
        self._running = False

        logger.info("Pipeline: PCAP replay complete — %s", self._stats.summary())
        return self._stats

    async def run_live(self, interface: str, alert_callback=None):
        """
        Start live packet capture and run indefinitely.
        Call pipeline.stop() to shut down.
        """
        if alert_callback:
            self._alert_cb = alert_callback

        self._running = True
        logger.info("Pipeline: starting live capture on %s", interface)

        tasks = [
            asyncio.create_task(self._stage1_live_capture(interface)),
            asyncio.create_task(self._stage2_flow_aggregator()),
            asyncio.create_task(self._stage3_feature_extractor()),
            asyncio.create_task(self._stage4_detection()),
            asyncio.create_task(self._stage6_alert_writer()),
        ]

        await asyncio.gather(*tasks)

    def stop(self):
        """Signal all stages to shut down cleanly."""
        self._running = False

    # ── Stage 1a: PCAP reader (runs in executor) ──────────────

    def _stage1_read_pcap(self, pcap_path: str):
        """Synchronous PCAP reader — runs in thread executor."""
        from backend.capture.packet_capture import PacketCapture

        cap = PacketCapture()
        queue = asyncio.Queue(maxsize=Q_RAW_PACKETS)

        enqueued = cap.read_pcap(pcap_path, queue)
        self._stats.packets_captured = cap.stats.packets_captured
        self._stats.packets_dropped  = cap.stats.packets_dropped

        # Drain the synchronous queue into the async raw_q
        # (PacketCapture.read_pcap uses asyncio.Queue internally)
        # We need to convert dicts to PacketRecord objects here.

        loop = self._loop  # captured in run_pcap() before executor dispatch

        while not queue.empty():
            pkt_dict = queue.get_nowait()
            pkt_rec  = self._dict_to_packet_record(pkt_dict)
            if pkt_rec is not None:
                # Use thread-safe put
                try:
                    loop.call_soon_threadsafe(
                        self._raw_q.put_nowait, pkt_rec
                    )
                except asyncio.QueueFull:
                    self._stats.packets_dropped += 1

        logger.info(
            "Stage 1 (PCAP): captured=%d  dropped=%d  enqueued=%d",
            self._stats.packets_captured,
            self._stats.packets_dropped,
            enqueued,
        )

    @staticmethod
    def _dict_to_packet_record(pkt_dict: dict):
        """
        Convert PacketCapture output dict to PacketRecord dataclass.
        Handles the dict→PacketRecord conversion gap (implementation log Mar 21).
        """
        from backend.capture.feature_extractor import PacketRecord

        try:
            tf = (pkt_dict.get("tcp_flags") or "").upper()
            return PacketRecord(
                timestamp      = pkt_dict["timestamp"],
                src_ip         = pkt_dict["src_ip"],
                dst_ip         = pkt_dict["dst_ip"],
                src_port       = pkt_dict.get("src_port"),
                dst_port       = pkt_dict.get("dst_port"),
                protocol       = pkt_dict["protocol"],
                length         = pkt_dict["length"],
                header_length  = 20,
                payload_length = len(pkt_dict.get("payload_bytes") or b""),
                flag_fin       = "FIN" in tf,
                flag_syn       = "SYN" in tf,
                flag_rst       = "RST" in tf,
                flag_psh       = "PSH" in tf,
                flag_ack       = "ACK" in tf,
                flag_urg       = "URG" in tf,
            )
        except (KeyError, TypeError):
            return None

    # ── Stage 1b: Live capture ────────────────────────────────

    async def _stage1_live_capture(self, interface: str):
        """Async live capture — pushes PacketRecord objects onto raw_q."""
        from backend.capture.packet_capture import PacketCapture
        import asyncio

        cap = PacketCapture()
        sync_q = asyncio.Queue(maxsize=Q_RAW_PACKETS)

        # Start Scapy sniff in a thread
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, cap.start_live, interface, sync_q
        )

        while self._running:
            try:
                pkt_dict = await asyncio.wait_for(sync_q.get(), timeout=1.0)
                pkt_rec = self._dict_to_packet_record(pkt_dict)
                if pkt_rec:
                    try:
                        self._raw_q.put_nowait(pkt_rec)
                        self._stats.packets_captured += 1
                    except asyncio.QueueFull:
                        self._stats.packets_dropped += 1
            except asyncio.TimeoutError:
                continue

        await self._raw_q.put(None)  # end-of-stream sentinel

    # ── Stage 2: Flow Aggregator ──────────────────────────────

    async def _stage2_flow_aggregator(self):
        """
        Consumes PacketRecord objects from raw_q.
        Emits completed FlowRecord objects to flow_q.
        Also runs idle timeout flush every FLOW_FLUSH_INTERVAL seconds.
        """
        last_flush = time.monotonic()

        while True:
            try:
                pkt = await asyncio.wait_for(self._raw_q.get(), timeout=FLOW_FLUSH_INTERVAL)
            except asyncio.TimeoutError:
                pkt = None

            if pkt is None:
                # End-of-stream: flush all open flows
                for flow in self._agg.flush_all():
                    await self._enqueue_flow(flow)
                await self._flow_q.put(None)  # sentinel
                logger.debug("Stage 2: end-of-stream, flushed all flows")
                return

            if pkt is not None:
                flow = self._agg.ingest(pkt)
                if flow is not None:
                    await self._enqueue_flow(flow)

            # Periodic idle timeout flush
            now = time.monotonic()
            if now - last_flush >= FLOW_FLUSH_INTERVAL:
                for flow in self._agg.flush_idle(current_time=now + pkt.timestamp
                                                 if pkt else now):
                    await self._enqueue_flow(flow)
                last_flush = now

    async def _enqueue_flow(self, flow):
        try:
            self._flow_q.put_nowait(flow)
            self._stats.flows_emitted += 1
        except asyncio.QueueFull:
            logger.warning("flow_q full — flow dropped")

    # ── Stage 3: Feature Extractor ────────────────────────────

    async def _stage3_feature_extractor(self):
        """
        Consumes FlowRecord objects from flow_q.
        Emits (flow, feature_vec) tuples to feature_q.
        """
        while True:
            flow = await self._flow_q.get()
            if flow is None:
                await self._feature_q.put(None)
                logger.debug("Stage 3: end-of-stream")
                return

            vec = self._feat.extract(flow)
            self._stats.features_extracted += 1

            try:
                self._feature_q.put_nowait((flow, vec))
            except asyncio.QueueFull:
                logger.warning("feature_q full — flow dropped")

    # ── Stage 4: Parallel Detection (Sig + ML) ────────────────

    async def _stage4_detection(self):
        """
        Consumes (flow, feature_vec) from feature_q.
        Runs Signature Engine and ML Inference Engine in parallel via
        asyncio.gather, then passes combined results to the Ensemble Correlator.
        Puts EnsembleVerdict objects onto alert_q.
        """
        while True:
            item = await self._feature_q.get()
            if item is None:
                await self._alert_q.put(None)
                logger.debug("Stage 4: end-of-stream")
                return

            flow, vec = item
            flow_id = getattr(flow, "flow_id", str(uuid.uuid4()))
            src_ip  = getattr(flow, "src_ip", "")
            dst_ip  = getattr(flow, "dst_ip", "")

            # Parallel: Signature + ML (asyncio.gather gives concurrent execution)
            _loop = asyncio.get_running_loop()
            sig_task  = _loop.run_in_executor(
                None, self._run_signature, flow_id, vec,
                getattr(flow, "payload_bytes", b""),
                getattr(flow, "protocol", ""),
                getattr(flow, "src_port", None),
                getattr(flow, "dst_port", None),
            )
            ml_task   = _loop.run_in_executor(
                None, self._run_ml, flow_id, vec
            )

            sig_result, ml_result = await asyncio.gather(sig_task, ml_task)

            # ml_result is MLInferenceResult — bridge to correlator-compatible stubs
            from backend.detection.ml.ensemble_correlator import RFResult as _RF, IFResult as _IF, LSTMResult as _LSTM
            rf_result = _RF(
                flow_id=flow_id,
                predicted_class=getattr(ml_result.rf, 'predicted_class', getattr(ml_result.rf, 'attack_class', 'BENIGN')) if ml_result.rf else "BENIGN",
                confidence=ml_result.rf.confidence  if ml_result.rf  else 0.0,
                is_attack=ml_result.rf.is_attack if ml_result.rf else False,
                probabilities={},
            )
            if_result = _IF(
                flow_id=flow_id,
                is_anomaly=getattr(ml_result.if_result or getattr(ml_result, 'iforest', None), 'is_anomaly', getattr(ml_result.if_result or getattr(ml_result, 'iforest', None), 'anomaly_flag', False)) if (ml_result.if_result or getattr(ml_result, 'iforest', None)) else False,
                confidence=float(getattr(ml_result.if_result or getattr(ml_result, 'iforest', None), 'confidence', 0.0) or 0.0),
                raw_score=ml_result.if_result.raw_score if ml_result.if_result else 0.0,
            )
            lstm_result = _LSTM(
                flow_id=flow_id,
                predicted_class=getattr(ml_result.lstm, 'predicted_class', getattr(ml_result.lstm, 'attack_class', 'BENIGN')) if ml_result.lstm else "BENIGN",
                confidence=ml_result.lstm.confidence if ml_result.lstm else 0.0,
                is_attack=ml_result.lstm.is_attack if ml_result.lstm else False,
                window_complete=True,
            )

            if sig_result.matched:
                self._stats.sig_matches += 1
            self._stats.ml_inferences += 1

            # Stage 5: Ensemble Correlator (fast — runs inline)
            verdict = self._corr.correlate(
                sig_result, rf_result, lstm_result, if_result,
                src_ip=src_ip, dst_ip=dst_ip,
            )

            if verdict.alert or verdict.is_duplicate:
                try:
                    self._alert_q.put_nowait((verdict, flow))
                except asyncio.QueueFull:
                    logger.warning("alert_q full — verdict dropped (should never happen)")

    def _run_signature(
        self,
        flow_id: str,
        feature_vec: np.ndarray,
        payload_bytes: bytes,
        protocol: str,
        src_port,
        dst_port,
    ):
        """Synchronous Signature Engine call — runs in executor."""
        from backend.detection.ml.ensemble_correlator import EnsembleCorrelator

        if self._sig is None:
            return EnsembleCorrelator.make_null_sig(flow_id)

        try:
            result = self._sig.match(
                flow_id      = flow_id,
                payload      = payload_bytes,
                protocol     = protocol,
                src_port     = src_port,
                dst_port     = dst_port,
                feature_vec  = feature_vec,
            )
            return result
        except Exception as exc:
            logger.error("Signature engine error flow=%s: %s", flow_id, exc)
            return EnsembleCorrelator.make_null_sig(flow_id)

    def _run_ml(self, flow_id: str, feature_vec):
        """Synchronous ML inference call — runs in executor."""
        try:
            return self._ml.infer(flow_id, feature_vec)
        except TypeError:
            # Some mocks expect (flow_id, src_ip, feature_vec)
            return self._ml.infer(flow_id, "", feature_vec)

    # ── Stage 6: Alert Writer ─────────────────────────────────

    async def _stage6_alert_writer(self):
        """
        Consumes (verdict, flow) tuples from alert_q.
        Calls alert_callback if registered.
        In Sprint 3 (Week 4) this is extended to write to PostgreSQL (FR7.8).
        """
        while True:
            item = await self._alert_q.get()
            if item is None:
                logger.debug("Stage 6: end-of-stream")
                return

            verdict, flow = item

            if verdict.is_duplicate:
                self._stats.alerts_suppressed += 1
                continue

            record = self._build_alert_record(verdict, flow)
            self._stats.alerts_generated += 1

            logger.info(
                "ALERT #%d  sev=%s  type=%s  score=%.4f  src=%s  dst=%s",
                self._stats.alerts_generated,
                record.severity,
                record.attack_type,
                record.score,
                record.src_ip,
                record.dst_ip,
            )

            if self._alert_cb:
                try:
                    if asyncio.iscoroutinefunction(self._alert_cb):
                        await self._alert_cb(record)
                    else:
                        self._alert_cb(record)
                except Exception as exc:
                    logger.error("Alert callback error: %s", exc)

    @staticmethod
    def _build_alert_record(verdict, flow) -> AlertRecord:
        return AlertRecord(
            alert_id    = str(uuid.uuid4()),
            flow_id     = verdict.flow_id,
            timestamp   = time.time(),
            severity    = verdict.severity,
            attack_type = verdict.attack_type,
            confidence  = verdict.confidence,
            score       = verdict.score,
            src_ip      = getattr(flow, "src_ip",   ""),
            dst_ip      = getattr(flow, "dst_ip",   ""),
            src_port    = getattr(flow, "src_port", None),
            dst_port    = getattr(flow, "dst_port", None),
            protocol    = getattr(flow, "protocol", ""),
            detected_by = verdict.detected_by,
            contributing_engines = verdict.contributing_engines,
            sig_matched = verdict.sig_matched,
            sig_rule_id = "",
            rf_class    = verdict.rf_class,
            lstm_class  = verdict.lstm_class,
            if_anomaly  = verdict.if_anomaly,
            sig_conf    = verdict.sig_conf,
            rf_conf     = verdict.rf_conf,
            lstm_conf   = verdict.lstm_conf,
            if_conf     = verdict.if_conf,
        )

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        s = self._stats.summary()
        s["queue_depths"] = {
            "raw_q":     self._raw_q.qsize(),
            "flow_q":    self._flow_q.qsize(),
            "feature_q": self._feature_q.qsize(),
            "alert_q":   self._alert_q.qsize(),
        }
        if self._ml:
            s["ml"] = self._ml.stats()
        return s

# ── Convenience wrapper expected by test_ml_inference_pipeline.py ────────────

async def run_pcap_pipeline(pcap_path: str, ml_engine) -> tuple:
    """
    Thin wrapper for tests. Returns (results: list[MLInferenceResult], stats: PipelineStats).
    Collects ML inference results directly without requiring alert threshold to be crossed.
    """
    import asyncio as _asyncio
    from backend.capture.packet_capture import PacketCapture
    from backend.capture.feature_extractor import FlowAggregator, FeatureExtractor

    results = []
    stats = PipelineStats()
    loop = _asyncio.get_running_loop()

    def _process():
        import asyncio as _aio
        q = _aio.Queue()
        cap = PacketCapture()
        cap.read_pcap(pcap_path, q)
        stats.packets_captured = cap.stats.packets_captured
        stats.packets_dropped  = cap.stats.packets_dropped

        agg  = FlowAggregator()
        feat = FeatureExtractor()

        def _infer_flow(flow):
            vec = feat.extract(flow)
            try:
                return ml_engine.infer(flow.flow_id, vec)
            except TypeError:
                try:
                    return ml_engine.infer(flow.flow_id, "", vec)
                except Exception:
                    return None

        while not q.empty():
            pkt_dict = q.get_nowait()
            pkt = DetectionPipeline._dict_to_packet_record(pkt_dict)
            if pkt is None:
                continue
            flow = agg.ingest(pkt)
            if flow:
                r = _infer_flow(flow)
                if r is not None:
                    results.append(r)
                    stats.ml_inferences += 1

        for flow in agg.flush_all():
            r = _infer_flow(flow)
            if r is not None:
                results.append(r)
                stats.ml_inferences += 1

    await loop.run_in_executor(None, _process)
    stats.inferences_run = stats.ml_inferences
    return results, stats
