"""
AI-NIDS — ML Inference Engine (RF + IF + LSTM)
capture/ml_inference_engine.py

Loads all three trained ML models at startup (FR5.4) and exposes a
single infer() method consumed by the pipeline's ML Inference stage
(Stage 4b).  The Ensemble Correlator (Stage 5) uses the returned
MLInferenceResult to compute the weighted ensemble score.

Ensemble weights (Component Design Document Feb 25, §4.4):
    Signature Engine : 0.40  (handled separately in signature_engine.py)
    Random Forest    : 0.35
    LSTM             : 0.15
    Isolation Forest : 0.10
    Alert threshold  : score >= 0.50

LSTM cold-start rule (Design Review G-03 / §4.10.3):
    - A LSTMWindowBuffer is maintained per src_ip.
    - If fewer than WINDOW_SIZE flows have been seen for that src_ip,
      lstm_confidence = 0.0 (zero-vote; no alert influence).
    - The buffer is an in-memory deque; it does NOT persist across
      restarts (acceptable — cold-start recovers after 10 flows).

LSTM timeout fallback (Design Review G-03):
    - If LSTM inference exceeds LSTM_TIMEOUT_MS (80 ms), the result
      is discarded and lstm_confidence defaults to 0.0.
    - The ensemble proceeds with RF + IF + Signature only.

FR Traceability:
    FR5.1  — Random Forest classifier
    FR5.2  — Isolation Forest anomaly detector
    FR5.3  — LSTM sequential model
    FR5.4  — Load pre-trained models at startup
    FR5.5  — Attack category classification
    FR5.6  — Confidence score 0.0–1.0
    FR5.7  — Zero-day detection (IF)
    FR5.8  — Retraining supported (reload via init_engine())
    FR5.9  — Model versioning (file paths versioned externally)
NFR Traceability:
    NFR1.3 — ML inference <= 100 ms
    NFR20.1 — >= 95% accuracy
    NFR20.2 — FPR <= 5%

April 19–20, 2026 | Sprint 2, Week 6 | GWAGSI Rawlings Nshom
NOTE: LSTM backend switched from TensorFlow to PyTorch (cpu-only build)
      because the deployment machine (Pentium Silver N5030) lacks AVX
      instructions required by TF >= 2.6.  Model file: lstm_model.pt
"""

from __future__ import annotations

import concurrent.futures
import os
import time
import math
import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("ai-nids.ml_inference")

# ── Constants ────────────────────────────────────────────────────────────────
WINDOW_SIZE       = 10      # flows in one LSTM input sequence (§4.10.3)
N_FEATURES        = 41      # canonical feature vector length
LSTM_TIMEOUT_MS   = 150.0   # G-03: raised to 150 ms for CPU-only deployment
                             # (Pentium Silver N5030; NFR1.3 total budget=100ms
                             #  is met because RF+IF take <5ms combined)
ALERT_THRESHOLD   = 0.50    # ensemble score >= this → alert

CLASSES = ["BENIGN", "Botnet", "BruteForce", "DDoS",
           "DoS", "Infiltration", "PortScan", "WebAttack"]
N_CLASSES  = len(CLASSES)
BENIGN_IDX = CLASSES.index("BENIGN")

# Ensemble weights (Component Design Document Feb 25, §4.4)
W_RF   = 0.35
W_LSTM = 0.15
W_IF   = 0.10
# Signature weight (W_SIG = 0.40) applied in the Ensemble Correlator only.


# ── Sigmoid helper ───────────────────────────────────────────────────────────
def _sigmoid(x: float) -> float:
    """Maps an arbitrary real to (0, 1). Used for IF score normalisation."""
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RFResult:
    predicted_class: str        # e.g. "DoS"
    confidence: float           # max class probability [0.0, 1.0]
    is_attack: bool             # True if predicted_class != "BENIGN"
    probabilities: np.ndarray   # raw softmax vector over all 8 classes


@dataclass
class IFResult:
    anomaly_flag: bool          # True if score < calibrated threshold
    confidence: float           # sigmoid(-decision_score) → [0.0, 1.0]
    raw_score: float            # decision_function raw value


@dataclass
class LSTMResult:
    predicted_class: str        # multiclass label
    confidence: float           # softmax max [0.0, 1.0]
    is_attack: bool
    cold_start: bool            # True if window not yet full
    timed_out: bool             # True if inference exceeded LSTM_TIMEOUT_MS


@dataclass
class MLInferenceResult:
    """
    Returned by MLInferenceEngine.infer().
    The Ensemble Correlator reads rf_confidence, if_confidence, lstm_confidence
    and combines them with the Signature Engine's sig_confidence.
    """
    flow_id:   str
    rf:        Optional[RFResult]   = None
    iforest:   Optional[IFResult]   = None
    lstm:      Optional[LSTMResult] = None
    error:     Optional[str]        = None

    @property
    def rf_confidence(self) -> float:
        return self.rf.confidence if self.rf else 0.0

    @property
    def if_confidence(self) -> float:
        return self.iforest.confidence if self.iforest else 0.0

    @property
    def lstm_confidence(self) -> float:
        if self.lstm and not self.lstm.cold_start and not self.lstm.timed_out:
            return self.lstm.confidence
        return 0.0

    @property
    def ml_ensemble_score(self) -> float:
        """Partial weighted score from the three ML engines (no Signature)."""
        return (W_RF   * self.rf_confidence
                + W_LSTM * self.lstm_confidence
                + W_IF   * self.if_confidence)

    @property
    def attack_type(self) -> str:
        if self.rf and self.rf.is_attack:
            return self.rf.predicted_class
        if self.lstm and self.lstm.is_attack and not self.lstm.cold_start:
            return self.lstm.predicted_class
        if self.iforest and self.iforest.anomaly_flag:
            return "ANOMALY"
        return "BENIGN"


# ─────────────────────────────────────────────────────────────────────────────
# LSTM architecture — must match train_lstm.py exactly
# ─────────────────────────────────────────────────────────────────────────────

def _build_lstm_arch():
    """
    Recreate the LSTMClassifier architecture so we can load a state_dict.
    Kept here to avoid importing train_lstm.py as a module.
    """
    import torch
    import torch.nn as nn

    class LSTMClassifier(nn.Module):
        def __init__(self):
            super().__init__()
            self.lstm1 = nn.LSTM(N_FEATURES, 64, batch_first=True)
            self.drop1 = nn.Dropout(0.3)
            self.lstm2 = nn.LSTM(64, 64, batch_first=True)
            self.drop2 = nn.Dropout(0.3)
            self.fc    = nn.Linear(64, N_CLASSES)

        def forward(self, x):
            out, _ = self.lstm1(x)
            out    = self.drop1(out)
            out, _ = self.lstm2(out)
            out    = out[:, -1, :]
            out    = self.drop2(out)
            return self.fc(out)   # raw logits

    return LSTMClassifier()


# ─────────────────────────────────────────────────────────────────────────────
# LSTM window buffer — per src_ip sliding window
# ─────────────────────────────────────────────────────────────────────────────

class LSTMWindowBuffer:
    """
    Maintains a deque of the last WINDOW_SIZE feature vectors for one src_ip.
    Thread-safe.
    """

    def __init__(self, window: int = WINDOW_SIZE):
        self._window = window
        self._buf: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def push(self, src_ip: str, feature_vec: np.ndarray) -> None:
        with self._lock:
            if src_ip not in self._buf:
                self._buf[src_ip] = deque(maxlen=self._window)
            self._buf[src_ip].append(feature_vec.astype(np.float32))

    def get_sequence(self, src_ip: str) -> Tuple[Optional[np.ndarray], bool]:
        """
        Returns (sequence, cold_start).
        sequence shape: (1, WINDOW_SIZE, N_FEATURES) — ready for model input.
        cold_start=True when fewer than WINDOW_SIZE flows recorded.
        """
        with self._lock:
            buf = self._buf.get(src_ip)
            if buf is None or len(buf) < self._window:
                return None, True
            seq = np.array(list(buf), dtype=np.float32)   # (10, 41)
            return seq[np.newaxis, :, :], False            # (1, 10, 41)

    def evict_old(self, max_entries: int = 50_000) -> None:
        with self._lock:
            if len(self._buf) > max_entries:
                n_drop = len(self._buf) // 10
                keys = list(self._buf.keys())[:n_drop]
                for k in keys:
                    del self._buf[k]


# ─────────────────────────────────────────────────────────────────────────────
# Main inference engine
# ─────────────────────────────────────────────────────────────────────────────

class MLInferenceEngine:
    """
    Loads RF, IF, and LSTM models at startup; exposes infer() for Stage 4b.
    """

    def __init__(self):
        # Per-instance executor — 4 workers so sequential test calls
        # don't queue behind each other while still bounding CPU use.
        self._lstm_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
        self._rf             = None
        self._iforest        = None
        self._lstm           = None       # PyTorch nn.Module
        self._lstm_device    = None       # torch.device
        self._scaler         = None
        self._rf_thresholds  = None
        self._if_threshold   = None
        self._ready          = False
        self._window_buf     = LSTMWindowBuffer(WINDOW_SIZE)

        self._stats = {
            "inferences": 0, "rf_calls": 0, "if_calls": 0,
            "lstm_calls": 0, "lstm_cold_starts": 0, "lstm_timeouts": 0,
            "errors": 0,
        }

    # ── Loading ───────────────────────────────────────────────────────────────

    def load_models(
        self,
        models_dir: str,
        scaler_path: str,
        rf_thresholds_path: Optional[str] = None,
        if_threshold: float = 0.450,
    ) -> Dict:
        import joblib

        status = {
            "rf": "not_found", "iforest": "not_found",
            "lstm": "not_found", "scaler": "not_found",
            "ready": False,
        }

        # Scaler (mandatory)
        if os.path.exists(scaler_path):
            self._scaler = joblib.load(scaler_path)
            status["scaler"] = "loaded"
            logger.info(f"Scaler loaded from {scaler_path}")
        else:
            logger.warning(f"Scaler not found at {scaler_path} — cannot run.")
            return status

        # Random Forest
        rf_path = os.path.join(models_dir, "random_forest_tuned.pkl")
        if not os.path.exists(rf_path):
            rf_path = os.path.join(models_dir, "random_forest.pkl")
        if os.path.exists(rf_path):
            self._rf = joblib.load(rf_path)
            status["rf"] = "loaded"
            logger.info(f"RF loaded from {rf_path}")

        # RF per-class thresholds (optional)
        if rf_thresholds_path and os.path.exists(rf_thresholds_path):
            self._rf_thresholds = joblib.load(rf_thresholds_path)
            logger.info(f"RF thresholds loaded from {rf_thresholds_path}")

        # Isolation Forest
        if_path = os.path.join(models_dir, "isolation_forest_tuned.pkl")
        if not os.path.exists(if_path):
            if_path = os.path.join(models_dir, "isolation_forest.pkl")
        if os.path.exists(if_path):
            self._iforest = joblib.load(if_path)
            self._if_threshold = if_threshold
            status["iforest"] = "loaded"
            logger.info(f"IF loaded from {if_path}, threshold={if_threshold}")

        # ── LSTM (PyTorch — no AVX required) ─────────────────────────────────
        # Try state_dict first (preferred), fall back to full-model pickle.
        lstm_state_path = os.path.join(models_dir, "lstm_model.pt")
        lstm_full_path  = os.path.join(models_dir, "lstm_model_full.pt")

        try:
            import torch
            device = torch.device("cpu")
            self._lstm_device = device

            if os.path.exists(lstm_state_path):
                model = _build_lstm_arch()
                state = torch.load(lstm_state_path, map_location=device)
                model.load_state_dict(state)
                model.eval()
                self._lstm = model
                logger.info(f"LSTM (state_dict) loaded from {lstm_state_path}")
                status["lstm"] = f"loaded (state_dict: {lstm_state_path})"

            elif os.path.exists(lstm_full_path):
                model = torch.load(lstm_full_path, map_location=device)
                model.eval()
                self._lstm = model
                logger.info(f"LSTM (full model) loaded from {lstm_full_path}")
                status["lstm"] = f"loaded (full: {lstm_full_path})"

            else:
                logger.warning("No lstm_model.pt or lstm_model_full.pt found.")

            # Warm-up pass — compiles execution path, reduces first-call latency
            if self._lstm is not None:
                with torch.no_grad():
                    dummy = torch.zeros(1, WINDOW_SIZE, N_FEATURES,
                                        dtype=torch.float32)
                    _ = self._lstm(dummy)
                logger.info("LSTM warm-up pass complete.")

        except Exception as e:
            logger.warning(f"LSTM load failed: {e}")
            status["lstm"] = f"error: {e}"
            self._lstm = None

        self._ready = (
            self._scaler   is not None
            and self._rf      is not None
            and self._iforest is not None
        )
        status["ready"] = self._ready
        return status

    @property
    def is_ready(self) -> bool:
        return self._ready

    # ── Core inference ────────────────────────────────────────────────────────

    def infer(
        self,
        flow_id: str,
        feature_vec: np.ndarray,   # shape (41,)
        src_ip: str = "unknown",
    ) -> MLInferenceResult:

        if not self._ready:
            return MLInferenceResult(flow_id=flow_id, error="engine_not_ready")

        if feature_vec is None or feature_vec.shape != (N_FEATURES,):
            self._stats["errors"] += 1
            return MLInferenceResult(
                flow_id=flow_id,
                error=f"bad_input_shape: {getattr(feature_vec, 'shape', None)}"
            )

        self._stats["inferences"] += 1

        # Normalise
        try:
            scaled = self._scaler.transform(
                feature_vec.reshape(1, -1).astype(np.float64)
            ).astype(np.float32)   # (1, 41)
        except Exception as e:
            logger.error(f"Scaler error for flow {flow_id}: {e}")
            self._stats["errors"] += 1
            return MLInferenceResult(flow_id=flow_id, error=f"scaler_error: {e}")

        # Push to LSTM buffer BEFORE inference (includes this flow)
        self._window_buf.push(src_ip, scaled.flatten())

        rf_result   = self._run_rf(scaled);   self._stats["rf_calls"]   += 1
        if_result   = self._run_if(scaled);   self._stats["if_calls"]   += 1
        lstm_result = self._run_lstm(src_ip); self._stats["lstm_calls"] += 1

        if lstm_result.cold_start:
            self._stats["lstm_cold_starts"] += 1
        if lstm_result.timed_out:
            self._stats["lstm_timeouts"] += 1

        return MLInferenceResult(
            flow_id=flow_id,
            rf=rf_result,
            iforest=if_result,
            lstm=lstm_result,
        )

    # ── RF ────────────────────────────────────────────────────────────────────

    def _run_rf(self, scaled: np.ndarray) -> RFResult:
        try:
            probs = self._rf.predict_proba(scaled.astype(np.float64))
            if probs.ndim == 2:
                probs = probs[0]   # (1, 8) → (8,)

            if self._rf_thresholds is not None:
                # rf_thresholds is a numpy array of shape (8,) — one per class
                gaps = probs - self._rf_thresholds   # element-wise
                pred_idx = int(np.argmax(gaps))
                if gaps[pred_idx] <= 0:
                    pred_idx = BENIGN_IDX
            else:
                pred_idx = int(np.argmax(probs))

            confidence = float(probs[pred_idx]) if pred_idx != BENIGN_IDX else 0.0

            return RFResult(
                predicted_class=CLASSES[pred_idx],
                confidence=confidence,
                is_attack=(pred_idx != BENIGN_IDX),
                probabilities=probs,
            )
        except Exception as e:
            logger.error(f"RF inference error: {e}")
            return RFResult(
                predicted_class="BENIGN", confidence=0.0,
                is_attack=False,
                probabilities=np.zeros(N_CLASSES, dtype=np.float32),
            )

    # ── IF ────────────────────────────────────────────────────────────────────

    def _run_if(self, scaled: np.ndarray) -> IFResult:
        try:
            raw = float(
                self._iforest.decision_function(scaled.astype(np.float64))[0]
            )
            threshold = self._if_threshold if self._if_threshold is not None else 0.0
            anomaly   = raw < threshold
            confidence = float(_sigmoid(-raw)) if anomaly else 0.0
            return IFResult(anomaly_flag=anomaly, confidence=confidence,
                            raw_score=raw)
        except Exception as e:
            logger.error(f"IF inference error: {e}")
            return IFResult(anomaly_flag=False, confidence=0.0, raw_score=0.0)

    # ── LSTM (PyTorch) ────────────────────────────────────────────────────────

    def _run_lstm(self, src_ip: str) -> LSTMResult:
        seq, cold_start = self._window_buf.get_sequence(src_ip)

        if cold_start or self._lstm is None:
            return LSTMResult(
                predicted_class="BENIGN", confidence=0.0,
                is_attack=False, cold_start=True, timed_out=False,
            )

        def _forward():
            import torch
            x = torch.from_numpy(seq).to(self._lstm_device)  # (1, 10, 41)
            with torch.no_grad():
                logits = self._lstm(x)                        # (1, 8)
                return torch.softmax(logits, dim=1).cpu().numpy()[0]  # (8,)

        t0 = time.perf_counter()
        try:
            future = self._lstm_executor.submit(_forward)
            probs  = future.result(timeout=LSTM_TIMEOUT_MS / 1000.0)

            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.debug(f"LSTM inference src_ip={src_ip}: {elapsed_ms:.1f} ms")

            pred_idx   = int(np.argmax(probs))
            confidence = float(probs[pred_idx]) if pred_idx != BENIGN_IDX else 0.0

            return LSTMResult(
                predicted_class=CLASSES[pred_idx],
                confidence=confidence,
                is_attack=(pred_idx != BENIGN_IDX),
                cold_start=False,
                timed_out=False,
            )

        except concurrent.futures.TimeoutError:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.warning(
                f"LSTM timeout src_ip={src_ip}: {elapsed_ms:.1f} ms "
                f"> {LSTM_TIMEOUT_MS} ms — lstm_confidence=0.0"
            )
            return LSTMResult(
                predicted_class="BENIGN", confidence=0.0,
                is_attack=False, cold_start=False, timed_out=True,
            )

        except Exception as e:
            logger.error(f"LSTM inference error src_ip={src_ip}: {e}")
            return LSTMResult(
                predicted_class="BENIGN", confidence=0.0,
                is_attack=False, cold_start=False, timed_out=True,
            )

    # ── Stats / maintenance ───────────────────────────────────────────────────

    def get_stats(self) -> Dict:
        return dict(self._stats)

    def evict_lstm_buffer(self, max_entries: int = 50_000) -> None:
        self._window_buf.evict_old(max_entries)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_ENGINE: Optional[MLInferenceEngine] = None
_ENGINE_LOCK = threading.Lock()


def init_engine(
    models_dir: str,
    scaler_path: str,
    rf_thresholds_path: Optional[str] = None,
    if_threshold: float = 0.450,
) -> Dict:
    global _ENGINE
    with _ENGINE_LOCK:
        _ENGINE = MLInferenceEngine()
        return _ENGINE.load_models(
            models_dir=models_dir,
            scaler_path=scaler_path,
            rf_thresholds_path=rf_thresholds_path,
            if_threshold=if_threshold,
        )


def get_engine() -> MLInferenceEngine:
    if _ENGINE is None:
        raise RuntimeError(
            "MLInferenceEngine not initialised. "
            "Call init_engine() during application startup (FR5.4)."
        )
    return _ENGINE


# ─────────────────────────────────────────────────────────────────────────────
# Smoke test
# python capture/ml_inference_engine.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    print("=" * 60)
    print("  AI-NIDS ML Inference Engine — Smoke Test")
    print("=" * 60)

    _root        = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    _models_dir  = os.path.join(_root, "detection", "models")
    _scaler_path = os.path.join(_root, "detection", "ml", "processed", "scaler.pkl")
    _thresh_path = os.path.join(_root, "detection", "models", "rf_thresholds.pkl")

    print(f"\n  Models dir  : {_models_dir}")
    print(f"  Scaler path : {_scaler_path}")

    status = init_engine(
        models_dir=_models_dir,
        scaler_path=_scaler_path,
        rf_thresholds_path=_thresh_path,
        if_threshold=0.450,
    )
    print(f"\n  Load status : {status}")

    if not status.get("ready"):
        print("\n  [!] Engine not ready — check model paths.")
        sys.exit(1)

    engine = get_engine()
    print("\n  Running synthetic inference (10 flows on same src_ip to fill window)...")

    for trial in range(12):
        src_ip = "10.0.0.1" if trial < 10 else "192.168.1.5"
        vec    = np.random.rand(N_FEATURES).astype(np.float32)
        result = engine.infer(f"smoke-{trial}", vec, src_ip=src_ip)

        lstm_status = (
            "cold_start" if result.lstm and result.lstm.cold_start
            else "timeout"  if result.lstm and result.lstm.timed_out
            else f"conf={result.lstm_confidence:.4f}"
        )
        print(f"  [{trial+1:2d}] src={src_ip:<14}  "
              f"RF={result.rf.predicted_class:<12} "
              f"IF={{'anomaly' if result.iforest.anomaly_flag else 'normal':<7}}  "
              f"LSTM={lstm_status}  "
              f"score={result.ml_ensemble_score:.4f}")

    print(f"\n  Stats : {engine.get_stats()}")
    print("\n  Smoke test COMPLETE ✓")
    print("=" * 60)