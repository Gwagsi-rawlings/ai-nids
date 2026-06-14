"""
AI-NIDS — Pipeline Runner
ml/pipeline_runner.py

THE central data flow entry point. Boots the complete detection pipeline
and wires every stage together end-to-end:

    [Stage 1] PacketCapture     → raw_packet_q
    [Stage 2] FlowAggregator    → flow_q
    [Stage 3] FeatureExtractor  → feature_q
    [Stage 4] Ensemble Correlator (Sig + RF + IF + LSTM in parallel)
                                → DetectionEvent
    [Stage 5] AlertGenerator    → PostgreSQL INSERT
                                → Redis CACHE (TTL 300s)
                                → Redis PUBLISH nids:alerts:new
    [Stage 6] WebSocket handler → React Dashboard

Entry points:
    start_pipeline(pcap_path)   — PCAP replay mode (CAPTURE_MODE=pcap)
    start_live_pipeline(iface)  — Live capture mode (CAPTURE_MODE=live)

Both call the same stages from Stage 2 onward. Only Stage 1 differs.

FR Traceability:
    FR1.1  — Live capture (promiscuous mode)
    FR1.3  — PCAP file replay
    FR3.9  — Flow aggregation
    FR3.12 — 5-tuple key
    FR5.4  — Models loaded at startup
    FR6.1–FR6.6 — Ensemble Correlator
    FR7.1  — Alert generation
    FR7.8  — PostgreSQL persistence
    FR10.5 — Real-time WebSocket push
    NFR1.1 — >= 10,000 pps throughput
    NFR1.4 — <= 100 ms end-to-end latency
April 6, 2026 | Sprint 1, Week 4
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time

logger = logging.getLogger("ai-nids.pipeline_runner")

# ── Queue depth limits (Architecture Design Document Feb 24 §4.3) ──────────
RAW_PACKET_Q_SIZE = 10_000
FLOW_Q_SIZE = 5_000
FEATURE_Q_SIZE = 5_000


# ── Stats worker: refresh Redis live-stats cache every 10 s (NFR1.6) ───────

async def _stats_worker(feature_q: asyncio.Queue, start_time: float) -> None:
    """
    Periodically writes live counters to Redis hash nids:cache:stats:live.
    Dashboard reads this instead of hitting PostgreSQL on every poll.
    """
    from infrastructure.db.redis_client import get_cache

    while True:
        try:
            cache = get_cache()
            await cache.hset(
                "nids:cache:stats:live",
                mapping={
                    "feature_q_depth": feature_q.qsize(),
                    "uptime_seconds": round(time.time() - start_time, 1),
                    "updated_at": time.time(),
                },
            )
            await cache.expire("nids:cache:stats:live", 30)
        except Exception as e:
            logger.debug("Stats worker error: %s", e)

        await asyncio.sleep(10)


# ── Stage 2–3 worker: FlowAggregator + FeatureExtractor ───────────────────

async def _aggregation_worker(
    raw_packet_q: asyncio.Queue,
    feature_q: asyncio.Queue,
    drop_counter: dict,
    lstm_window_store: dict,     # src_ip → deque of recent feature vectors
) -> None:
    """
    Consumes PacketRecord dicts from raw_packet_q.
    Aggregates into flows, extracts 41 features, pushes to feature_q.

    Also maintains the LSTM sliding window per src_ip (10-flow window).
    """
    # Ensure project root importable
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from backend.capture.feature_extractor import FlowAggregator, FeatureExtractor, PacketRecord

    aggregator = FlowAggregator()
    extractor = FeatureExtractor()
    last_idle_flush = time.time()

    logger.info("Aggregation worker started")

    while True:
        # ── Idle flush every 5 seconds ─────────────────────────────────────
        now = time.time()
        if now - last_idle_flush >= 5.0:
            for flow in aggregator.flush_idle(current_time=now):
                vec = extractor.extract(flow)
                await _enqueue_feature(flow, vec, feature_q, drop_counter, lstm_window_store)
            last_idle_flush = now

        # ── Dequeue next packet ────────────────────────────────────────────
        try:
            pkt_dict = await asyncio.wait_for(raw_packet_q.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue

        try:
            # Convert dict → PacketRecord (bridge between capture and extractor)
            tf = (pkt_dict.get("tcp_flags") or "").upper()
            pkt_rec = PacketRecord(
                timestamp=pkt_dict["timestamp"],
                src_ip=pkt_dict["src_ip"],
                dst_ip=pkt_dict["dst_ip"],
                src_port=pkt_dict.get("src_port"),
                dst_port=pkt_dict.get("dst_port"),
                protocol=pkt_dict.get("protocol", "TCP"),
                length=pkt_dict.get("length", 0),
                header_length=20,
                payload_length=len(pkt_dict.get("payload_bytes") or b""),
                flag_fin="FIN" in tf,
                flag_syn="SYN" in tf,
                flag_rst="RST" in tf,
                flag_psh="PSH" in tf,
                flag_ack="ACK" in tf,
                flag_urg="URG" in tf,
            )

            flow = aggregator.ingest(pkt_rec)
            if flow:
                vec = extractor.extract(flow)
                await _enqueue_feature(
                    flow, vec, feature_q, drop_counter, lstm_window_store,
                    payload_bytes=pkt_dict.get("payload_bytes"),
                )
        except Exception as e:
            logger.debug("Aggregation error: %s", e)
        finally:
            raw_packet_q.task_done()


async def _enqueue_feature(
    flow,
    vec,
    feature_q: asyncio.Queue,
    drop_counter: dict,
    lstm_window_store: dict,
    payload_bytes: bytes = b"",
) -> None:
    """
    Package a completed flow + feature vector for the Ensemble Correlator.
    Maintains LSTM sliding window (10 flows per src_ip).
    Drops if feature_q is full (backpressure — NFR queue design).
    """
    import numpy as np
    from collections import deque

    src_ip = flow.src_ip if hasattr(flow, "src_ip") else ""

    # Update LSTM 10-flow sliding window
    if src_ip not in lstm_window_store:
        lstm_window_store[src_ip] = deque(maxlen=10)
    lstm_window_store[src_ip].append(vec)

    lstm_sequence = None
    if len(lstm_window_store[src_ip]) == 10:
        seq = np.array(list(lstm_window_store[src_ip]), dtype="float32")
        lstm_sequence = seq.reshape(1, 10, 41)

    meta = {
        "src_ip": getattr(flow, "src_ip", ""),
        "dst_ip": getattr(flow, "dst_ip", ""),
        "src_port": getattr(flow, "src_port", None),
        "dst_port": getattr(flow, "dst_port", None),
        "protocol": getattr(flow, "protocol", "TCP"),
        "payload_bytes": payload_bytes,
        "tcp_flags": "",
        "pkt_count": getattr(flow, "pkt_count", 0),
        "lstm_sequence": lstm_sequence,
    }

    flow_id = str(getattr(flow, "flow_id", "")) or None
    item = (flow_id, vec, meta)

    if feature_q.full():
        drop_counter["features"] = drop_counter.get("features", 0) + 1
        logger.debug("feature_q full — dropping flow %s", flow_id)
        return

    await feature_q.put(item)


# ── PCAP replay (FR1.3) ────────────────────────────────────────────────────

async def _pcap_producer(pcap_path: str, raw_packet_q: asyncio.Queue, drop_counter: dict) -> None:
    """
    Reads a PCAP file and feeds packets into raw_packet_q.
    Uses asyncio.to_thread to avoid blocking the event loop.
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from backend.capture.packet_capture import PacketCapture

    def _read():
        cap = PacketCapture()
        enqueued = cap.read_pcap(pcap_path, raw_packet_q)
        return enqueued, cap.get_stats()

    enqueued, stats = await asyncio.to_thread(_read)
    logger.info("PCAP replay complete: %d packets enqueued | stats: %s", enqueued, stats)


# ── Public API ─────────────────────────────────────────────────────────────

async def start_pipeline(
    pcap_path: str,
    signature_engine=None,
    model_bundle=None,
) -> None:
    """
    Full pipeline in PCAP replay mode (CAPTURE_MODE=pcap, FR1.3).

    Arguments:
        pcap_path        — absolute path to the PCAP/PCAPNG file
        signature_engine — SignatureEngine instance (or None to skip)
        model_bundle     — ModelBundle from ml.model_loader (or None to skip ML)

    This function runs to completion (all PCAP packets processed) then returns.
    Call asyncio.create_task(start_pipeline(...)) to run alongside the API.
    """
    from app.services.alert_generator import build_alert_generator
    from backend.detection.ml.ensemble_correlator import run_ensemble_worker

    alert_fn = build_alert_generator()
    drop_counter: dict = {}
    lstm_window_store: dict = {}
    start_time = time.time()

    # ── Create queues ──────────────────────────────────────────────────────
    raw_packet_q: asyncio.Queue = asyncio.Queue(maxsize=RAW_PACKET_Q_SIZE)
    feature_q: asyncio.Queue = asyncio.Queue(maxsize=FEATURE_Q_SIZE)

    logger.info("Starting PCAP pipeline: %s", pcap_path)

    # ── Launch background workers ──────────────────────────────────────────
    agg_task = asyncio.create_task(
        _aggregation_worker(raw_packet_q, feature_q, drop_counter, lstm_window_store),
        name="aggregation-worker",
    )
    stats_task = asyncio.create_task(
        _stats_worker(feature_q, start_time),
        name="stats-worker",
    )

    # Unpack model bundle (None-safe)
    rf = getattr(model_bundle, "rf_model", None)
    if_m = getattr(model_bundle, "if_model", None)
    lstm = getattr(model_bundle, "lstm_model", None)
    scaler = getattr(model_bundle, "scaler", None)
    le = getattr(model_bundle, "label_encoder", None)

    ensemble_task = asyncio.create_task(
        run_ensemble_worker(
            feature_q=feature_q,
            alert_generator_fn=alert_fn,
            signature_engine=signature_engine,
            rf_model=rf,
            if_model=if_m,
            lstm_model=lstm,
            scaler=scaler,
            label_encoder=le,
        ),
        name="ensemble-correlator",
    )

    # ── Stage 1: feed PCAP into raw_packet_q ──────────────────────────────
    await _pcap_producer(pcap_path, raw_packet_q, drop_counter)

    # Wait for all queued packets to be processed
    await raw_packet_q.join()
    await feature_q.join()

    elapsed = time.time() - start_time
    logger.info(
        "Pipeline complete in %.2f s | drops: %s",
        elapsed,
        drop_counter,
    )

    # Cancel background workers cleanly
    for task in (agg_task, stats_task, ensemble_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def start_live_pipeline(
    interface: str,
    signature_engine=None,
    model_bundle=None,
) -> None:
    """
    Full pipeline in live capture mode (CAPTURE_MODE=live, FR1.1).
    Runs indefinitely until cancelled.

    Requires: docker-compose network_mode: host + cap_add: NET_ADMIN, NET_RAW
    (commented out in docker-compose.yml — uncomment for live capture).
    """
    from app.services.alert_generator import build_alert_generator
    from backend.detection.ml.ensemble_correlator import run_ensemble_worker

    alert_fn = build_alert_generator()
    drop_counter: dict = {}
    lstm_window_store: dict = {}
    start_time = time.time()

    raw_packet_q: asyncio.Queue = asyncio.Queue(maxsize=RAW_PACKET_Q_SIZE)
    feature_q: asyncio.Queue = asyncio.Queue(maxsize=FEATURE_Q_SIZE)

    logger.info("Starting live capture pipeline on interface: %s", interface)

    # Unpack model bundle
    rf = getattr(model_bundle, "rf_model", None)
    if_m = getattr(model_bundle, "if_model", None)
    lstm = getattr(model_bundle, "lstm_model", None)
    scaler = getattr(model_bundle, "scaler", None)
    le = getattr(model_bundle, "label_encoder", None)

    await asyncio.gather(
        _aggregation_worker(raw_packet_q, feature_q, drop_counter, lstm_window_store),
        _stats_worker(feature_q, start_time),
        run_ensemble_worker(
            feature_q=feature_q,
            alert_generator_fn=alert_fn,
            signature_engine=signature_engine,
            rf_model=rf,
            if_model=if_m,
            lstm_model=lstm,
            scaler=scaler,
            label_encoder=le,
        ),
        _live_capture_producer(interface, raw_packet_q, drop_counter),
    )


async def _live_capture_producer(
    interface: str,
    raw_packet_q: asyncio.Queue,
    drop_counter: dict,
) -> None:
    """Live promiscuous capture via Scapy (FR1.1). Runs indefinitely."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from backend.capture.packet_capture import PacketCapture, PacketParser

    import scapy.all as scapy

    cap = PacketCapture()

    def _on_packet(pkt) -> None:
        parsed = PacketParser.parse(pkt)
        if parsed is None:
            drop_counter["malformed"] = drop_counter.get("malformed", 0) + 1
            return
        if raw_packet_q.full():
            drop_counter["raw_overflow"] = drop_counter.get("raw_overflow", 0) + 1
            return
        raw_packet_q.put_nowait(parsed)

    logger.info("Live capture started on %s (promiscuous mode)", interface)
    await asyncio.to_thread(
        scapy.sniff,
        iface=interface,
        prn=_on_packet,
        store=False,
        stop_filter=lambda _: False,
    )
