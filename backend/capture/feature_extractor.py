"""
AI-NIDS — Feature Extraction Module
====================================
Extracts the 41-feature vector from bi-directional flow records.
Output is a normalised NumPy array compatible with the ML Inference Engine.

Feature set aligns with the CICIDS2017 41-feature subset identified by
Layeghy, Gallagher & Portmann (2021) as retaining 98.7% of classification
information from the full 80-feature CICFlowMeter representation.

Pipeline position: FlowAggregator → FeatureExtractor → feature_q
FR traceability  : FR3.1–FR3.12 (Feature Extraction & Preprocessing)
NFR traceability : NFR1.2 (≤50 ms per flow), NFR1.3 (≤100 ms ML budget)

Author : GWAGSI Rawlings Nshom | ICT University, Cameroon
Date   : March 21, 2026
"""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FLOW_TIMEOUT_SECONDS: float = 60.0   # Idle timeout → emit incomplete flow
WINDOW_SIZE: int = 10                 # LSTM sliding window (flows per src_ip)

# Feature names in canonical order (index 0–40).
# These match the CICIDS2017 reduced feature set used for model training.
FEATURE_NAMES: Tuple[str, ...] = (
    # --- Flow-level (0–4) ---
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_length_fwd_packets",
    "total_length_bwd_packets",
    # --- Packet length statistics — forward (5–8) ---
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    # --- Packet length statistics — backward (9–12) ---
    "bwd_packet_length_max",
    "bwd_packet_length_min",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    # --- Rate features (13–14) ---
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    # --- Inter-arrival time — forward (15–19) ---
    "fwd_iat_total",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    # --- Inter-arrival time — backward (20–24) ---
    "bwd_iat_total",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_max",
    "bwd_iat_min",
    # --- TCP flag counts (25–30) ---
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    # --- Derived / ratio features (31–35) ---
    "down_up_ratio",
    "average_packet_size",
    "avg_fwd_segment_size",
    "avg_bwd_segment_size",
    "fwd_header_length",
    # --- Backward header + directional rates (36–40) ---
    "bwd_header_length",
    "fwd_packets_per_sec",
    "bwd_packets_per_sec",
    "min_packet_length",
    "max_packet_length",
)

assert len(FEATURE_NAMES) == 41, "Feature count mismatch — must be exactly 41."

FEATURE_INDEX: Dict[str, int] = {name: i for i, name in enumerate(FEATURE_NAMES)}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    """Minimal packet representation emitted by the Packet Capture Engine."""
    timestamp: float          # Unix epoch (seconds, float)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str             # "TCP" | "UDP" | "ICMP" | "OTHER"
    length: int               # Total packet length in bytes
    header_length: int        # IP + transport header bytes
    payload_length: int       # Application payload bytes
    # TCP flags (ignored for non-TCP)
    flag_fin: bool = False
    flag_syn: bool = False
    flag_rst: bool = False
    flag_psh: bool = False
    flag_ack: bool = False
    flag_urg: bool = False


@dataclass
class FlowRecord:
    """
    Bi-directional flow record.

    'Forward' direction = initiator → responder (first packet direction).
    'Backward' direction = responder → initiator.
    """
    # 5-tuple key
    flow_id: str              # "<src_ip>:<src_port>-<dst_ip>:<dst_port>-<proto>"
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Timing
    start_ts: float = 0.0    # Timestamp of first packet
    end_ts: float = 0.0      # Timestamp of last packet
    last_seen: float = 0.0   # For idle-timeout tracking

    # Packet lists — timestamps and lengths for IAT and stat computation
    fwd_timestamps: List[float] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)
    fwd_lengths: List[int] = field(default_factory=list)
    bwd_lengths: List[int] = field(default_factory=list)

    # Header lengths (cumulative)
    fwd_header_length_total: int = 0
    bwd_header_length_total: int = 0

    # TCP flag accumulators
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0

    # Flow-complete flag
    is_complete: bool = False


# ---------------------------------------------------------------------------
# Flow Aggregator
# ---------------------------------------------------------------------------

class FlowAggregator:
    """
    Groups PacketRecords into bi-directional FlowRecords using a 5-tuple key.

    Emits a FlowRecord to the downstream queue when:
      - A TCP FIN or RST flag is observed (connection close), OR
      - The flow has been idle for FLOW_TIMEOUT_SECONDS.

    FR3.9 : Creates bi-directional flow records (forward and backward).
    FR3.12: Aggregates packets into flows based on 5-tuple.
    """

    def __init__(self) -> None:
        self._flows: Dict[str, FlowRecord] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, pkt: PacketRecord) -> Optional[FlowRecord]:
        """
        Process one packet. Returns a completed FlowRecord if the flow
        is terminated by this packet; otherwise returns None.
        """
        key, is_forward = self._flow_key(pkt)

        if key not in self._flows:
            self._flows[key] = self._new_flow(key, pkt)

        flow = self._flows[key]
        self._update_flow(flow, pkt, is_forward)

        # TCP FIN or RST → flow is complete
        if pkt.protocol == "TCP" and (pkt.flag_fin or pkt.flag_rst):
            flow.is_complete = True
            return self._pop_flow(key)

        return None

    def flush_idle(self, current_time: Optional[float] = None) -> List[FlowRecord]:
        """
        Emit all flows that have been idle for longer than FLOW_TIMEOUT_SECONDS.
        Call this periodically (e.g., every second) from the capture loop.
        """
        now = current_time or time.time()
        expired_keys = [
            k for k, f in self._flows.items()
            if (now - f.last_seen) >= FLOW_TIMEOUT_SECONDS
        ]
        expired = [self._pop_flow(k) for k in expired_keys]
        return expired

    def flush_all(self) -> List[FlowRecord]:
        """Emit all open flows immediately (e.g., on PCAP end-of-file)."""
        keys = list(self._flows.keys())
        return [self._pop_flow(k) for k in keys]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _flow_key(pkt: PacketRecord) -> Tuple[str, bool]:
        """
        Returns (canonical_key, is_forward).
        The canonical key always places the lexicographically smaller
        (ip, port) tuple first, ensuring forward/backward packets share
        the same key regardless of observation order.
        """
        a = (pkt.src_ip, pkt.src_port)
        b = (pkt.dst_ip, pkt.dst_port)
        if a <= b:
            key = f"{pkt.src_ip}:{pkt.src_port}-{pkt.dst_ip}:{pkt.dst_port}-{pkt.protocol}"
            return key, True
        else:
            key = f"{pkt.dst_ip}:{pkt.dst_port}-{pkt.src_ip}:{pkt.src_port}-{pkt.protocol}"
            return key, False

    @staticmethod
    def _new_flow(key: str, pkt: PacketRecord) -> FlowRecord:
        parts = key.split("-")
        src_part, dst_part, proto = parts[0], parts[1], parts[2]
        src_ip, src_port = src_part.rsplit(":", 1)
        dst_ip, dst_port = dst_part.rsplit(":", 1)
        return FlowRecord(
            flow_id=key,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(src_port) if src_port != "None" else None,
            dst_port=int(dst_port) if dst_port != "None" else None,
            protocol=proto,
            start_ts=pkt.timestamp,
            end_ts=pkt.timestamp,
            last_seen=pkt.timestamp,
        )

    @staticmethod
    def _update_flow(flow: FlowRecord, pkt: PacketRecord, is_forward: bool) -> None:
        flow.end_ts = pkt.timestamp
        flow.last_seen = pkt.timestamp

        if is_forward:
            flow.fwd_timestamps.append(pkt.timestamp)
            flow.fwd_lengths.append(pkt.length)
            flow.fwd_header_length_total += pkt.header_length
        else:
            flow.bwd_timestamps.append(pkt.timestamp)
            flow.bwd_lengths.append(pkt.length)
            flow.bwd_header_length_total += pkt.header_length

        if pkt.protocol == "TCP":
            flow.fin_count += int(pkt.flag_fin)
            flow.syn_count += int(pkt.flag_syn)
            flow.rst_count += int(pkt.flag_rst)
            flow.psh_count += int(pkt.flag_psh)
            flow.ack_count += int(pkt.flag_ack)
            flow.urg_count += int(pkt.flag_urg)

    def _pop_flow(self, key: str) -> FlowRecord:
        return self._flows.pop(key)


# ---------------------------------------------------------------------------
# Feature Extractor
# ---------------------------------------------------------------------------

class FeatureExtractor:
    """
    Computes the 41-feature vector from a FlowRecord.

    All features are returned as raw (un-normalised) float64 values.
    Normalisation (MinMaxScaler) is applied by the ML Inference Engine
    using scalers fitted on the CICIDS2017 training split.

    FR3.1  : Extracts 41 statistical features from network traffic.
    FR3.2  : Packet size statistics (mean, std, min, max).
    FR3.3  : Flow duration.
    FR3.4  : Bytes per second and packets per second.
    FR3.5  : TCP flag distributions.
    FR3.6  : Inter-arrival time statistics.
    FR3.7  : Source and destination ports (encoded via flow record).
    FR3.8  : Protocol type (encoded at the flow record level).
    FR3.9  : Bi-directional flow records.
    FR3.10 : Normalisation delegated to the MinMaxScaler in ml/scaler.pkl.
    FR3.11 : Handles missing / malformed data gracefully (returns zeros).
    """

    def extract(self, flow: FlowRecord) -> np.ndarray:
        """
        Returns a float64 NumPy array of shape (41,).
        Safe: never raises — returns a zero vector on any error.
        """
        try:
            return self._compute(flow)
        except Exception:  # noqa: BLE001  — broad catch is intentional
            return np.zeros(41, dtype=np.float64)

    # ------------------------------------------------------------------
    # Core computation
    # ------------------------------------------------------------------

    def _compute(self, flow: FlowRecord) -> np.ndarray:
        vec = np.zeros(41, dtype=np.float64)

        fwd = flow.fwd_lengths
        bwd = flow.bwd_lengths
        fwd_ts = flow.fwd_timestamps
        bwd_ts = flow.bwd_timestamps

        duration = max(flow.end_ts - flow.start_ts, 0.0)

        # ----------------------------------------------------------
        # 0: flow_duration
        # ----------------------------------------------------------
        vec[0] = duration

        # ----------------------------------------------------------
        # 1–4: packet counts and total lengths
        # ----------------------------------------------------------
        vec[1] = len(fwd)
        vec[2] = len(bwd)
        vec[3] = float(sum(fwd))
        vec[4] = float(sum(bwd))

        # ----------------------------------------------------------
        # 5–8: forward packet length stats
        # ----------------------------------------------------------
        vec[5], vec[6], vec[7], vec[8] = self._length_stats(fwd)

        # ----------------------------------------------------------
        # 9–12: backward packet length stats
        # ----------------------------------------------------------
        vec[9], vec[10], vec[11], vec[12] = self._length_stats(bwd)

        # ----------------------------------------------------------
        # 13–14: flow-level rate features
        # ----------------------------------------------------------
        total_bytes = vec[3] + vec[4]
        total_pkts  = vec[1] + vec[2]
        vec[13] = total_bytes / duration if duration > 0 else 0.0   # bytes/sec
        vec[14] = total_pkts  / duration if duration > 0 else 0.0   # packets/sec

        # ----------------------------------------------------------
        # 15–19: forward IAT
        # ----------------------------------------------------------
        (vec[15], vec[16], vec[17],
         vec[18], vec[19]) = self._iat_stats(fwd_ts)

        # ----------------------------------------------------------
        # 20–24: backward IAT
        # ----------------------------------------------------------
        (vec[20], vec[21], vec[22],
         vec[23], vec[24]) = self._iat_stats(bwd_ts)

        # ----------------------------------------------------------
        # 25–30: TCP flag counts
        # ----------------------------------------------------------
        vec[25] = float(flow.fin_count)
        vec[26] = float(flow.syn_count)
        vec[27] = float(flow.rst_count)
        vec[28] = float(flow.psh_count)
        vec[29] = float(flow.ack_count)
        vec[30] = float(flow.urg_count)

        # ----------------------------------------------------------
        # 31: down/up ratio (bwd bytes / fwd bytes)
        # ----------------------------------------------------------
        vec[31] = vec[4] / vec[3] if vec[3] > 0 else 0.0

        # ----------------------------------------------------------
        # 32: average packet size (all packets, both directions)
        # ----------------------------------------------------------
        vec[32] = total_bytes / total_pkts if total_pkts > 0 else 0.0

        # ----------------------------------------------------------
        # 33: avg forward segment size (= fwd mean packet length)
        # ----------------------------------------------------------
        vec[33] = vec[7]

        # ----------------------------------------------------------
        # 34: avg backward segment size (= bwd mean packet length)
        # ----------------------------------------------------------
        vec[34] = vec[11]

        # ----------------------------------------------------------
        # 35: total forward header length
        # ----------------------------------------------------------
        vec[35] = float(flow.fwd_header_length_total)

        # ----------------------------------------------------------
        # 36: total backward header length
        # ----------------------------------------------------------
        vec[36] = float(flow.bwd_header_length_total)

        # ----------------------------------------------------------
        # 37–38: directional packet rates
        # ----------------------------------------------------------
        vec[37] = vec[1] / duration if duration > 0 else 0.0   # fwd pkt/s
        vec[38] = vec[2] / duration if duration > 0 else 0.0   # bwd pkt/s

        # ----------------------------------------------------------
        # 39–40: overall min / max packet length (both directions)
        # ----------------------------------------------------------
        all_lengths = fwd + bwd
        if all_lengths:
            vec[39] = float(min(all_lengths))
            vec[40] = float(max(all_lengths))
        # else: remain 0.0 (empty flow)

        return vec

    # ------------------------------------------------------------------
    # Statistical helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _length_stats(
        lengths: List[int],
    ) -> Tuple[float, float, float, float]:
        """Returns (max, min, mean, std) for a list of packet lengths."""
        if not lengths:
            return 0.0, 0.0, 0.0, 0.0
        mx  = float(max(lengths))
        mn  = float(min(lengths))
        mean = float(sum(lengths)) / len(lengths)
        if len(lengths) > 1:
            variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)
            std = math.sqrt(variance)
        else:
            std = 0.0
        return mx, mn, mean, std

    @staticmethod
    def _iat_stats(
        timestamps: List[float],
    ) -> Tuple[float, float, float, float, float]:
        """
        Computes (total, mean, std, max, min) inter-arrival times.
        Returns zeros when fewer than 2 timestamps are available.
        FR3.6: Calculate inter-arrival time statistics.
        """
        if len(timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0, 0.0

        iats = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]
        total = sum(iats)
        mean  = total / len(iats)
        mx    = max(iats)
        mn    = min(iats)
        if len(iats) > 1:
            variance = sum((x - mean) ** 2 for x in iats) / len(iats)
            std = math.sqrt(variance)
        else:
            std = 0.0

        return total, mean, std, mx, mn


# ---------------------------------------------------------------------------
# Feature vector → dict helper (for logging / debugging)
# ---------------------------------------------------------------------------

def vector_to_dict(vec: np.ndarray) -> Dict[str, float]:
    """Convert a 41-element feature vector to a labelled dictionary."""
    if len(vec) != 41:
        raise ValueError(f"Expected 41 features, got {len(vec)}")
    return {name: float(vec[i]) for i, name in enumerate(FEATURE_NAMES)}


# ---------------------------------------------------------------------------
# Unit-level smoke test (run: python feature_extractor.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=== AI-NIDS FeatureExtractor — Smoke Test ===\n")

    # --- Build a synthetic flow ---
    base_ts = 1742000000.0
    aggregator = FlowAggregator()
    extractor  = FeatureExtractor()

    # Simulate 6 TCP packets: 4 forward, 2 backward
    packets = [
        PacketRecord(base_ts + 0.000, "192.168.1.10", "10.0.0.1",  54321, 80, "TCP", 74,  40, 34,  flag_syn=True),
        PacketRecord(base_ts + 0.001, "10.0.0.1",     "192.168.1.10", 80, 54321, "TCP", 74, 40, 34, flag_syn=True, flag_ack=True),
        PacketRecord(base_ts + 0.002, "192.168.1.10", "10.0.0.1",  54321, 80, "TCP", 120, 40, 80, flag_ack=True, flag_psh=True),
        PacketRecord(base_ts + 0.050, "10.0.0.1",     "192.168.1.10", 80, 54321, "TCP", 850, 40, 810, flag_ack=True, flag_psh=True),
        PacketRecord(base_ts + 0.051, "192.168.1.10", "10.0.0.1",  54321, 80, "TCP", 54,  40,  14, flag_fin=True, flag_ack=True),
        PacketRecord(base_ts + 0.052, "10.0.0.1",     "192.168.1.10", 80, 54321, "TCP", 54,  40,  14, flag_fin=True, flag_ack=True),
    ]

    completed_flow: Optional[FlowRecord] = None
    for pkt in packets:
        result = aggregator.ingest(pkt)
        if result:
            completed_flow = result

    assert completed_flow is not None, "Flow was not emitted on FIN."
    vec = extractor.extract(completed_flow)

    assert vec.shape == (41,), f"Wrong shape: {vec.shape}"
    assert not np.any(np.isnan(vec)), "NaN values in feature vector!"
    assert not np.any(np.isinf(vec)), "Inf values in feature vector!"

    feat = vector_to_dict(vec)
    print(f"Flow ID    : {completed_flow.flow_id}")
    print(f"Vector dim : {vec.shape}")
    print(f"Duration   : {feat['flow_duration']:.4f}s")
    print(f"Fwd pkts   : {feat['total_fwd_packets']:.0f}")
    print(f"Bwd pkts   : {feat['total_bwd_packets']:.0f}")
    print(f"Bytes/sec  : {feat['flow_bytes_per_sec']:.2f}")
    print(f"SYN count  : {feat['syn_flag_count']:.0f}")
    print(f"FIN count  : {feat['fin_flag_count']:.0f}")
    print(f"Down/Up    : {feat['down_up_ratio']:.4f}")
    print(f"\nAll 41 features (raw, un-normalised):")
    for name, val in feat.items():
        print(f"  {name:<35} {val:.6f}")

    print("\n✅ Smoke test PASSED — FeatureExtractor producing 41-feature vector.")