"""
AI-NIDS — ML Inference Engine
ml/inference_engine.py

Loads pre-trained RF and IF models at startup and exposes a single
async-friendly method that accepts a 41-dimensional normalised feature
vector and returns per-engine confidence scores for the Ensemble Correlator.

Pipeline position:
    Feature Extractor  →  [ML Inference Engine]  →  Ensemble Correlator

Engines handled here (FR5.1, FR5.2):
    - Random Forest (weight 0.35)    — supervised multiclass classification
    - Isolation Forest (weight 0.10) — unsupervised anomaly / zero-day detection

LSTM (weight 0.15) is handled separately in ml/lstm_inference.py (Week 6)
because it requires a 10-flow sliding window, not a single feature vector.

FR Traceability:
    FR5.1  — Random Forest multiclass classification
    FR5.2  — Isolation Forest anomaly detection
    FR5.4  — Pre-trained models loaded at startup
    FR5.5  — Attack category classification
    FR5.6  — Confidence score 0.0–1.0 per engine
    FR5.7  — Zero-day detection (IF, benign-only training)
    FR5.9  — Model versioning / rollback (MODEL_DIR env var)
    FR3.10 — MinMaxScaler normalisation applied at inference time

April 1, 2026 | Sprint 1 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations
 
import logging
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
 
import joblib
import numpy as np
 
logger = logging.getLogger("ai-nids.inference")
 
# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
 
FEATURE_COUNT = 41
 
ATTACK_LABELS = [
    "BENIGN",
    "Botnet",
    "BruteForce",
    "DDoS",
    "DoS",
    "Infiltration",
    "PortScan",
    "WebAttack",
]
 
IF_DECISION_THRESHOLD = 0.1135
ATTACK_CONFIDENCE_FLOOR = 0.01
 
 
# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------
 
@dataclass
class RFResult:
    attack_class: str
    confidence: float
    probabilities: np.ndarray
    is_attack: bool
 
 
@dataclass
class IFResult:
    raw_score: float
    confidence: float
    is_anomaly: bool
 
 
@dataclass
class MLInferenceResult:
    flow_id: str
    rf: RFResult
    if_result: IFResult
    error: Optional[str] = None
 
 
# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
 
def _sigmoid(x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0
 
 
# ---------------------------------------------------------------------------
# MLInferenceEngine
# ---------------------------------------------------------------------------
 
class MLInferenceEngine:
 
    def __init__(self, model_dir: Optional[str] = None):
        self._model_dir = Path(
            model_dir or os.getenv("MODEL_DIR", "/app/models")
        )
        self._rf_model = None
        self._if_model = None
        self._scaler = None
        self._label_encoder = None
        self._ready = False
 
    # ------------------------------------------------------------------
    # Startup loading
    # ------------------------------------------------------------------
 
    def load_models(self) -> dict:
        status: dict = {
            "random_forest": "not found",
            "isolation_forest": "not found",
            "scaler": "not found",
            "label_encoder": "not found",
        }
 
        scaler_path = self._model_dir / "scaler.pkl"
        if not scaler_path.exists():
            alt_scaler = Path(os.getenv("ML_DIR", "/app/ml")) / "scaler.pkl"
            if alt_scaler.exists():
                scaler_path = alt_scaler
 
        if scaler_path.exists():
            self._scaler = joblib.load(scaler_path)
            status["scaler"] = f"loaded ({scaler_path})"
            logger.info("MinMaxScaler loaded from %s", scaler_path)
        else:
            logger.warning("scaler.pkl not found — raw vectors will be used.")
 
        le_path = self._model_dir / "label_encoder.pkl"
        if not le_path.exists():
            le_path = Path(os.getenv("ML_DIR", "/app/ml")) / "label_encoder.pkl"
 
        if le_path.exists():
            self._label_encoder = joblib.load(le_path)
            status["label_encoder"] = f"loaded ({le_path})"
            logger.info("LabelEncoder loaded from %s", le_path)
        else:
            logger.warning("label_encoder.pkl not found — using ATTACK_LABELS fallback.")
 
        rf_path = self._model_dir / "random_forest.pkl"
        if rf_path.exists():
            self._rf_model = joblib.load(rf_path)
            status["random_forest"] = f"loaded ({rf_path})"
            logger.info("Random Forest loaded from %s", rf_path)
        else:
            logger.warning("random_forest.pkl not found — RF inference disabled")
 
        if_path = self._model_dir / "isolation_forest.pkl"
        if if_path.exists():
            self._if_model = joblib.load(if_path)
            status["isolation_forest"] = f"loaded ({if_path})"
            logger.info("Isolation Forest loaded from %s", if_path)
        else:
            logger.warning("isolation_forest.pkl not found — IF inference disabled")
 
        self._ready = (self._rf_model is not None) or (self._if_model is not None)
        return status
 
    @property
    def is_ready(self) -> bool:
        return self._ready
 
    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------
 
    def _normalise(self, vector: np.ndarray) -> np.ndarray:
        if self._scaler is None:
            return vector.astype(np.float64)
        return self._scaler.transform(vector.reshape(1, -1)).flatten().astype(np.float64)
 
    # ------------------------------------------------------------------
    # Class label resolution
    # ------------------------------------------------------------------
 
    def _class_name(self, class_index: int) -> str:
        """Resolve integer class index to attack category string."""
        if self._label_encoder is not None:
            try:
                return str(self._label_encoder.inverse_transform([class_index])[0])
            except Exception:
                pass
        if 0 <= class_index < len(ATTACK_LABELS):
            return ATTACK_LABELS[class_index]
        return f"UNKNOWN_{class_index}"
 
    # ------------------------------------------------------------------
    # RF inference
    # ------------------------------------------------------------------
 
    def _run_rf(self, scaled_vector: np.ndarray) -> RFResult:
        if self._rf_model is None:
            return RFResult(
                attack_class="BENIGN",
                confidence=0.0,
                probabilities=np.zeros(len(ATTACK_LABELS)),
                is_attack=False,
            )
 
        proba = self._rf_model.predict_proba(scaled_vector.reshape(1, -1))[0]
        pred_index = int(np.argmax(proba))
        pred_label = self._class_name(pred_index)
        pred_conf = float(proba[pred_index])
 
        return RFResult(
            attack_class=pred_label,
            confidence=pred_conf,
            probabilities=proba,
            is_attack=(pred_label != "BENIGN"),
        )
 
    # ------------------------------------------------------------------
    # IF inference
    # ------------------------------------------------------------------
 
    def _run_if(self, scaled_vector: np.ndarray) -> IFResult:
        if self._if_model is None:
            return IFResult(raw_score=0.0, confidence=0.0, is_anomaly=False)
 
        raw_score = float(
            self._if_model.decision_function(scaled_vector.reshape(1, -1))[0]
        )
        confidence = _sigmoid(-raw_score)
        is_anomaly = raw_score < IF_DECISION_THRESHOLD
 
        return IFResult(
            raw_score=raw_score,
            confidence=confidence,
            is_anomaly=is_anomaly,
        )
 
    # ------------------------------------------------------------------
    # Public inference entry point
    # ------------------------------------------------------------------
 
    def infer(self, flow_id: str, feature_vector: np.ndarray) -> MLInferenceResult:
        # 1. None check first — must come before .shape access
        if feature_vector is None:
            return MLInferenceResult(
                flow_id=flow_id,
                rf=RFResult(
                    attack_class="BENIGN",
                    confidence=0.0,
                    probabilities=np.zeros(len(ATTACK_LABELS)),
                    is_attack=False,
                ),
                if_result=IFResult(raw_score=0.0, confidence=0.0, is_anomaly=False),
                error="zero_vector",
            )
 
        # 2. Shape check second — catches wrong-dimension vectors
        if feature_vector.shape != (FEATURE_COUNT,):
            return MLInferenceResult(
                flow_id=flow_id,
                rf=RFResult(
                    attack_class="BENIGN",
                    confidence=0.0,
                    probabilities=np.zeros(len(ATTACK_LABELS)),
                    is_attack=False,
                ),
                if_result=IFResult(raw_score=0.0, confidence=0.0, is_anomaly=False),
                error=f"wrong_shape:{feature_vector.shape}",
            )
 
        # 3. Zero-vector check last
        if np.all(feature_vector == 0):
            return MLInferenceResult(
                flow_id=flow_id,
                rf=RFResult(
                    attack_class="BENIGN",
                    confidence=0.0,
                    probabilities=np.zeros(len(ATTACK_LABELS)),
                    is_attack=False,
                ),
                if_result=IFResult(raw_score=0.0, confidence=0.0, is_anomaly=False),
                error="zero_vector",
            )
 
        try:
            scaled = self._normalise(feature_vector)
            rf_result = self._run_rf(scaled)
            if_result = self._run_if(scaled)
 
            return MLInferenceResult(
                flow_id=flow_id,
                rf=rf_result,
                if_result=if_result,
            )
 
        except Exception as exc:
            logger.error("MLInferenceEngine.infer() failed for flow %s: %s", flow_id, exc)
            return MLInferenceResult(
                flow_id=flow_id,
                rf=RFResult(
                    attack_class="BENIGN",
                    confidence=0.0,
                    probabilities=np.zeros(len(ATTACK_LABELS)),
                    is_attack=False,
                ),
                if_result=IFResult(raw_score=0.0, confidence=0.0, is_anomaly=False),
                error=str(exc),
            )
 
 
# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
 
_engine: Optional[MLInferenceEngine] = None
 
 
def get_engine() -> MLInferenceEngine:
    if _engine is None:
        raise RuntimeError(
            "MLInferenceEngine not initialised. "
            "Call ml.inference_engine.init_engine() at application startup."
        )
    return _engine
 
 
def init_engine(model_dir: Optional[str] = None) -> dict:
    global _engine
    _engine = MLInferenceEngine(model_dir=model_dir)
    return _engine.load_models()
 