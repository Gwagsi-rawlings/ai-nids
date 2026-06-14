"""
AI-NIDS — LSTM Inference Engine
capture/lstm_inference.py

Loads the trained PyTorch LSTM model and manages the 10-flow sliding window
per source IP for sequential temporal detection (FR5.3).

Cold-start behaviour: source IPs with fewer than 10 accumulated flows receive
a zero-confidence result (window_complete=False). The EnsembleCorrelator
treats this as lstm_conf=0.0, falling back to Signature + RF + IF only.

LSTM timeout fallback (Design Review G-03): if inference exceeds 80 ms,
the caller (pipeline.py) should use make_null_lstm() from ensemble_correlator.

FR Traceability:
    FR5.3  — LSTM neural network for sequential pattern analysis
    FR5.4  — Load pre-trained ML models at startup
    FR5.5  — Classify attacks into categories
    FR5.6  — Assign confidence score (0.0 to 1.0)
    FR5.9  — Store model versions and allow rollback

April 2026 | Sprint 2 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import logging
import os
import time
from collections import deque

import numpy as np

logger = logging.getLogger("ai-nids.lstm")

# Window size matches training configuration (Component Design Doc Feb 25, §4.3)
WINDOW_SIZE = 10
LSTM_TIMEOUT_MS = 80.0   # Design Review G-03 SLO

# Class labels matching training label_encoder order
CLASSES = [
    "BENIGN", "Botnet", "BruteForce", "DDoS",
    "DoS", "Infiltration", "PortScan", "WebAttack",
]
BENIGN_IDX = 0


class LSTMInferenceEngine:
    """
    Wraps the trained PyTorch LSTM model and manages per-src_ip flow windows.

    Usage:
        engine = LSTMInferenceEngine()
        engine.load(model_path)

        # Call for each completed flow
        result = engine.infer(flow_id="uuid", src_ip="1.2.3.4", feature_vec=vec)
    """

    def __init__(self, window_size: int = WINDOW_SIZE):
        self._window_size = window_size
        self._model = None
        self._ready = False
        self._device = None
        # Per src_ip sliding window: src_ip -> deque of feature vectors
        self._windows: dict[str, deque] = {}
        self._inferences = 0
        self._latencies: list[float] = []

    # ── Model loading ─────────────────────────────────────────

    def load(self, model_path: str) -> dict:
        """
        Load the trained PyTorch LSTM model from disk.
        Supports full model save (lstm_model_full.pt) or state_dict (.pt).
        Returns a status dict for the FastAPI /health endpoint.
        """
        if not os.path.exists(model_path):
            logger.warning("LSTM model not found at %s", model_path)
            return {"lstm": "not_found", "path": model_path}

        try:
            import torch  # import lazily — TF/sklearn imports are heavy

            self._device = torch.device("cpu")

            # Try loading full model first (lstm_model_full.pt)
            loaded = torch.load(model_path, map_location=self._device,
                                weights_only=False)

            if hasattr(loaded, "eval"):
                # Full model object
                self._model = loaded
            else:
                # state_dict — need to reconstruct architecture
                logger.info("Detected state_dict — reconstructing LSTM architecture")
                self._model = self._build_model()
                self._model.load_state_dict(loaded)

            self._model.eval()
            self._ready = True

            size_mb = os.path.getsize(model_path) / (1024 ** 2)
            param_count = sum(p.numel() for p in self._model.parameters())
            logger.info(
                "LSTM loaded: %s  (%.1f MB, %d params)",
                model_path, size_mb, param_count,
            )
            return {
                "lstm": "ready",
                "path": model_path,
                "size_mb": round(size_mb, 1),
                "params": param_count,
            }

        except Exception as exc:
            logger.error("LSTM load failed: %s", exc)
            self._ready = False
            return {"lstm": "load_error", "error": str(exc)}

    def _build_model(self):
        """
        Reconstruct the LSTM architecture from §4.10.1.
        2-layer LSTM (64 units), dropout 0.3, Linear(8) output.
        Must match train_lstm.py exactly.
        """
        import torch.nn as nn

        class LSTMClassifier(nn.Module):
            def __init__(self):
                super().__init__()
                self.lstm1 = nn.LSTM(41, 64, batch_first=True)
                self.drop1 = nn.Dropout(0.3)
                self.lstm2 = nn.LSTM(64, 64, batch_first=True)
                self.drop2 = nn.Dropout(0.3)
                self.fc    = nn.Linear(64, 8)

            def forward(self, x):
                out, _ = self.lstm1(x)
                out = self.drop1(out)
                out, _ = self.lstm2(out)
                out = self.drop2(out)
                return self.fc(out[:, -1, :])

        return LSTMClassifier()

    # ── Sliding window management ─────────────────────────────

    def push_flow(self, src_ip: str, feature_vec: np.ndarray) -> bool:
        """
        Add a feature vector to the src_ip's sliding window.
        Returns True when the window reaches WINDOW_SIZE (ready for inference).
        """
        if src_ip not in self._windows:
            self._windows[src_ip] = deque(maxlen=self._window_size)
        self._windows[src_ip].append(feature_vec.astype(np.float32))
        return len(self._windows[src_ip]) >= self._window_size

    def get_window_tensor(self, src_ip: str):
        """
        Returns the current window for src_ip as a float32 numpy array
        of shape (1, WINDOW_SIZE, 41), ready for model input.
        Returns None if window is incomplete.
        """
        win = self._windows.get(src_ip)
        if win is None or len(win) < self._window_size:
            return None
        return np.array(list(win), dtype=np.float32)[np.newaxis, ...]  # (1, 10, 41)

    def clear_window(self, src_ip: str):
        """Remove the window for a source IP (e.g. on connection teardown)."""
        self._windows.pop(src_ip, None)

    # ── Inference ─────────────────────────────────────────────

    def infer(
        self,
        flow_id: str,
        src_ip: str,
        feature_vec: np.ndarray,
    ):
        """
        Push feature_vec into the src_ip window and run LSTM inference
        if the window is complete.

        Returns an LSTMResult-compatible dict. Import LSTMResult from
        ensemble_correlator to construct the typed object if needed.

        Dict keys:
            flow_id, predicted_class, confidence, is_attack, window_complete
        """
        from ensemble_correlator import LSTMResult

        # Push into window
        window_ready = self.push_flow(src_ip, feature_vec)

        if not window_ready:
            # Cold-start — window not yet full
            return LSTMResult(
                flow_id         = flow_id,
                predicted_class = "BENIGN",
                confidence      = 0.0,
                is_attack       = False,
                window_complete = False,
            )

        if not self._ready or self._model is None:
            logger.warning("LSTM not ready — returning null result for flow %s", flow_id)
            return LSTMResult(
                flow_id         = flow_id,
                predicted_class = "BENIGN",
                confidence      = 0.0,
                is_attack       = False,
                window_complete = False,
            )

        return self._run_inference(flow_id, src_ip)

    def _run_inference(self, flow_id: str, src_ip: str):
        """Run the actual PyTorch forward pass."""
        from ensemble_correlator import LSTMResult
        import torch

        tensor_np = self.get_window_tensor(src_ip)
        if tensor_np is None:
            return LSTMResult(
                flow_id=flow_id, predicted_class="BENIGN",
                confidence=0.0, is_attack=False, window_complete=False,
            )

        t0 = time.perf_counter()
        try:
            with torch.no_grad():
                x = torch.from_numpy(tensor_np).to(self._device)
                logits = self._model(x)                         # (1, 8)
                probs  = torch.softmax(logits, dim=-1).cpu().numpy()[0]  # (8,)

            elapsed_ms = (time.perf_counter() - t0) * 1000
            self._latencies.append(elapsed_ms)
            self._inferences += 1

            pred_idx   = int(np.argmax(probs))
            confidence = float(probs[pred_idx])
            pred_class = CLASSES[pred_idx] if pred_idx < len(CLASSES) else "UNKNOWN"
            is_attack  = pred_idx != BENIGN_IDX

            logger.debug(
                "LSTM flow=%s src=%s class=%s conf=%.4f lat=%.2f ms",
                flow_id, src_ip, pred_class, confidence, elapsed_ms,
            )

            if elapsed_ms > LSTM_TIMEOUT_MS:
                logger.warning(
                    "LSTM exceeded 80 ms SLO: %.2f ms — flow %s  (G-03 fallback active)",
                    elapsed_ms, flow_id,
                )

            return LSTMResult(
                flow_id         = flow_id,
                predicted_class = pred_class,
                confidence      = confidence,
                is_attack       = is_attack,
                window_complete = True,
            )

        except Exception as exc:
            logger.error("LSTM inference error flow=%s: %s", flow_id, exc)
            return LSTMResult(
                flow_id         = flow_id,
                predicted_class = "BENIGN",
                confidence      = 0.0,
                is_attack       = False,
                window_complete = False,
            )

    # ── Stats ─────────────────────────────────────────────────

    def stats(self) -> dict:
        lats = self._latencies[-1000:] if self._latencies else [0]
        return {
            "ready":        self._ready,
            "inferences":   self._inferences,
            "active_windows": len(self._windows),
            "lat_mean_ms":  round(float(np.mean(lats)), 3),
            "lat_p95_ms":   round(float(np.percentile(lats, 95)), 3),
        }

    @property
    def ready(self) -> bool:
        return self._ready
