"""
AI-NIDS — ML Model Loader
ml/model_loader.py

Loads all trained model artifacts from the models/ directory at startup.
Returns a ModelBundle dataclass consumed by the pipeline runner.

Models loaded (FR5.4):
    random_forest.pkl       — Random Forest classifier
    rf_thresholds.pkl       — Per-class probability thresholds (tuning output)
    isolation_forest.pkl    — Isolation Forest anomaly detector
    lstm_model.h5           — LSTM sequential classifier (Week 6)
    scaler.pkl              — MinMaxScaler fitted on CICIDS2017 training split
    label_encoder.pkl       — LabelEncoder for 8-class taxonomy

Graceful degradation: missing models are loaded as None.
The Ensemble Correlator skips engines whose model is None
(confidence stays 0.0 — weight is not counted).

FR Traceability:
    FR5.1  — Random Forest
    FR5.2  — Isolation Forest
    FR5.3  — LSTM
    FR5.4  — Load pre-trained models at startup
    FR5.9  — Model versioning (version logged from ml_models DB table)
    FR3.10 — MinMaxScaler applied at inference
April 6, 2026 | Sprint 1, Week 4
"""

import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger("ai-nids.model_loader")

MODELS_DIR = os.getenv("MODEL_DIR", os.path.join(os.path.dirname(__file__), "..", "models"))


@dataclass
class ModelBundle:
    """
    All runtime ML artifacts consumed by the Ensemble Correlator.
    Any field may be None if the corresponding file is not yet trained.
    The pipeline worker checks for None before calling each model.
    """
    rf_model: Optional[Any] = None          # sklearn RandomForestClassifier
    rf_thresholds: Optional[dict] = None    # {class_idx: float} calibrated thresholds
    if_model: Optional[Any] = None          # sklearn IsolationForest
    lstm_model: Optional[Any] = None        # keras.Model
    scaler: Optional[Any] = None            # sklearn MinMaxScaler
    label_encoder: Optional[Any] = None     # sklearn LabelEncoder

    @property
    def is_ml_ready(self) -> bool:
        """True if at least RF and scaler are loaded (minimum for ML inference)."""
        return self.rf_model is not None and self.scaler is not None

    def summary(self) -> dict:
        return {
            "random_forest": self.rf_model is not None,
            "rf_thresholds": self.rf_thresholds is not None,
            "isolation_forest": self.if_model is not None,
            "lstm": self.lstm_model is not None,
            "scaler": self.scaler is not None,
            "label_encoder": self.label_encoder is not None,
        }


def load_models(models_dir: str = MODELS_DIR) -> ModelBundle:
    """
    Load all model artifacts from disk. Called once at pipeline startup.
    Missing files → None (not an error; model is simply inactive in the ensemble).
    """
    import joblib

    bundle = ModelBundle()

    def _load(filename: str, description: str) -> Optional[Any]:
        path = os.path.join(models_dir, filename)
        if not os.path.exists(path):
            logger.info("Model not found (not yet trained): %s", filename)
            return None
        try:
            obj = joblib.load(path)
            logger.info("Loaded: %s (%s)", filename, description)
            return obj
        except Exception as e:
            logger.warning("Failed to load %s: %s", filename, e)
            return None

    # ── Scikit-learn models ────────────────────────────────────────────────
    bundle.rf_model = _load("random_forest.pkl", "Random Forest classifier")
    bundle.rf_thresholds = _load("rf_thresholds.pkl", "Per-class probability thresholds")
    bundle.if_model = _load("isolation_forest.pkl", "Isolation Forest anomaly detector")
    bundle.scaler = _load("scaler.pkl", "MinMaxScaler")
    bundle.label_encoder = _load("label_encoder.pkl", "LabelEncoder")

    # ── PyTorch LSTM ──────────────────────────────────────────────────────
    lstm_path = os.path.join(models_dir, "lstm_model.pt")
    if os.path.exists(lstm_path):
        try:
            import torch
            import torch.nn as nn

            class LSTMClassifier(nn.Module):
                def __init__(self, input_size=41, hidden_size=64, num_classes=8):
                    super().__init__()
                    self.lstm1 = nn.LSTM(input_size, hidden_size, batch_first=True)
                    self.lstm2 = nn.LSTM(hidden_size, hidden_size, batch_first=True)
                    self.fc = nn.Linear(hidden_size, num_classes)

                def forward(self, x):
                    out, _ = self.lstm1(x)
                    out, _ = self.lstm2(out)
                    return self.fc(out[:, -1, :])

            model = LSTMClassifier()
            state_dict = torch.load(lstm_path, map_location="cpu")
            model.load_state_dict(state_dict)
            model.eval()
            bundle.lstm_model = model
            logger.info("Loaded: lstm_model.pt (LSTM sequential classifier, PyTorch)")
        except Exception as e:
            logger.warning("Failed to load lstm_model.pt: %s", e)

    logger.info("Model bundle summary: %s", bundle.summary())
    return bundle
