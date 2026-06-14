"""
AI-NIDS — Isolation Forest Training Script
ml/train_isolation_forest.py

Trains an Isolation Forest anomaly detector on BENIGN-only CICIDS2017 flows,
evaluates zero-day detection capability on the full test set, and serialises
the trained model + sigmoid confidence mapper to disk.

FR Traceability:
    FR5.2  — Isolation Forest model for anomaly detection
    FR5.4  — Load pre-trained models at startup
    FR5.7  — Detect zero-day attacks (unknown patterns)
    FR5.6  — Assign confidence score (0.0-1.0) to each detection

NFR Traceability:
    NFR20.1 — >= 95% accuracy on CICIDS2017 test set (evaluated on full set)
    NFR20.2 — FPR <= 5%  (primary IF target)

March 29, 2026 | Sprint 1 | Developer: GWAGSI Rawlings Nshom
"""

import gc
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

# ---------------------------------------------------------------------------
# Paths -- adjust BASE_DIR if running from a different working directory
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).resolve().parent.parent   # ~/ai-nids/
PROCESSED   = BASE_DIR / "ml" / "processed"
MODELS_DIR  = BASE_DIR / "models"
METRICS_DIR = BASE_DIR / "ml"

MODELS_DIR.mkdir(parents=True, exist_ok=True)

X_TRAIN_PATH = PROCESSED / "X_train.npy"
X_TEST_PATH  = PROCESSED / "X_test.npy"
Y_TRAIN_PATH = PROCESSED / "y_train.npy"
Y_TEST_PATH  = PROCESSED / "y_test.npy"
LE_PATH      = PROCESSED / "label_encoder.pkl"

MODEL_OUT   = MODELS_DIR / "isolation_forest.pkl"
METRICS_OUT = METRICS_DIR / "if_metrics.json"

# ---------------------------------------------------------------------------
# Hyperparameters  (Component Design Document, Feb 25, Section 4.3)
# ---------------------------------------------------------------------------
N_ESTIMATORS  = 100
CONTAMINATION = 0.01   # Expected ~1% anomaly rate in steady-state network
MAX_SAMPLES   = "auto" # sqrt(n_training_samples) per tree
RANDOM_STATE  = 42
N_JOBS        = -1     # Parallelise across all CPU cores


# ---------------------------------------------------------------------------
# Helper: sigmoid for confidence mapping (FR5.6)
# ---------------------------------------------------------------------------

def sigmoid(x: np.ndarray) -> np.ndarray:
    """
    Maps raw IF decision_function scores to [0.0, 1.0] confidence.

    decision_function() returns negative values for anomalies and positive
    for normal flows. We negate and pass through sigmoid so that:
      - highly anomalous flows  -> confidence approaching 1.0
      - clearly normal flows    -> confidence approaching 0.0

    This matches the Ensemble Correlator convention where all engines
    emit confidence in [0.0, 1.0] with higher = more likely attack (FR5.6).
    """
    # Negate: large negative score (anomaly) -> large positive -> sigmoid ~1.0
    return 1.0 / (1.0 + np.exp(x))


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def compute_fpr(y_true_binary: np.ndarray, y_pred_binary: np.ndarray) -> float:
    """False Positive Rate = FP / (FP + TN) on binary labels."""
    tn = int(np.sum((y_true_binary == 0) & (y_pred_binary == 0)))
    fp = int(np.sum((y_true_binary == 0) & (y_pred_binary == 1)))
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def compute_tpr(y_true_binary: np.ndarray, y_pred_binary: np.ndarray) -> float:
    """True Positive Rate (Detection Rate) = TP / (TP + FN)."""
    tp = int(np.sum((y_true_binary == 1) & (y_pred_binary == 1)))
    fn = int(np.sum((y_true_binary == 1) & (y_pred_binary == 0)))
    return tp / (tp + fn) if (tp + fn) > 0 else 0.0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> dict:
    print("=" * 70)
    print("AI-NIDS -- Isolation Forest Training  |  March 29, 2026")
    print("=" * 70)

    # ── 1. Load preprocessed arrays ──────────────────────────────────────
    print("\n[1/6] Loading preprocessed CICIDS2017 arrays...")
    t0 = time.time()

    X_train = np.load(X_TRAIN_PATH)
    y_train = np.load(Y_TRAIN_PATH)
    X_test  = np.load(X_TEST_PATH)
    y_test  = np.load(Y_TEST_PATH)

    print(f"    X_train : {X_train.shape}  |  y_train : {y_train.shape}")
    print(f"    X_test  : {X_test.shape}   |  y_test  : {y_test.shape}")
    print(f"    Load time: {time.time() - t0:.1f}s")

    # ── 2. Load label encoder to identify BENIGN class index ─────────────
    print("\n[2/6] Loading label encoder...")
    le = joblib.load(LE_PATH)
    classes = list(le.classes_)
    print(f"    Classes ({len(classes)}): {classes}")

    benign_idx = int(le.transform(["BENIGN"])[0])
    print(f"    BENIGN label index: {benign_idx}")

    # ── 3. Build BENIGN-only training set ─────────────────────────────────
    # IF is unsupervised -- trained on normal traffic only (FR5.2, FR5.7).
    # It learns the statistical structure of benign flows and flags
    # deviations at inference time, independent of any attack labels.
    print("\n[3/6] Filtering BENIGN-only training samples for IF...")
    benign_mask       = (y_train == benign_idx)
    X_train_benign    = X_train[benign_mask]
    n_benign_train    = int(X_train_benign.shape[0])
    n_dropped         = int(X_train.shape[0]) - n_benign_train

    print(f"    BENIGN training samples : {n_benign_train:,}")
    print(f"    (dropped {n_dropped:,} labelled attack samples -- not used by IF)")

    del X_train
    del y_train
    gc.collect()

    # ── 4. Train Isolation Forest ─────────────────────────────────────────
    print("\n[4/6] Training Isolation Forest...")
    print(f"    n_estimators  = {N_ESTIMATORS}")
    print(f"    contamination = {CONTAMINATION}")
    print(f"    max_samples   = {MAX_SAMPLES}")
    print(f"    n_jobs        = {N_JOBS}")
    print(f"    random_state  = {RANDOM_STATE}")

    t_train = time.time()
    iforest = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        max_samples=MAX_SAMPLES,
        n_jobs=N_JOBS,
        random_state=RANDOM_STATE,
    )
    iforest.fit(X_train_benign)
    train_elapsed = time.time() - t_train
    print(f"    Training complete in {train_elapsed:.1f}s ({train_elapsed / 60:.1f} min)")

    del X_train_benign
    gc.collect()

    # ── 5. Evaluate on full test set ──────────────────────────────────────
    print("\n[5/6] Evaluating on CICIDS2017 full test set...")
    t_eval = time.time()

    # Raw decision scores: negative = more anomalous (sklearn convention)
    decision_scores = iforest.decision_function(X_test)

    # Binary predictions from sklearn: -1 (anomaly) or 1 (normal)
    sklearn_preds = iforest.predict(X_test)

    # Our convention: 1 = anomaly/attack, 0 = benign
    y_pred_binary = np.where(sklearn_preds == -1, 1, 0)

    # Ground truth binary: 0 = BENIGN, 1 = any attack class
    y_true_binary = np.where(y_test == benign_idx, 0, 1)

    # Confidence scores for Ensemble Correlator (FR5.6)
    confidence_scores = sigmoid(decision_scores)  # shape (n_test,), range [0,1]

    eval_elapsed   = time.time() - t_eval
    n_test         = int(X_test.shape[0])
    latency_ms     = (eval_elapsed / n_test) * 1000

    print(f"    Inference complete in {eval_elapsed:.1f}s")
    print(f"    Per-sample latency: {latency_ms:.4f} ms  (target: <= 3.0 ms)")

    # ── 6. Compute and report metrics ─────────────────────────────────────
    print("\n[6/6] Computing evaluation metrics...")

    acc  = float(accuracy_score(y_true_binary, y_pred_binary))
    prec = float(precision_score(y_true_binary, y_pred_binary, zero_division=0))
    rec  = float(recall_score(y_true_binary, y_pred_binary, zero_division=0))
    f1   = float(f1_score(y_true_binary, y_pred_binary, zero_division=0))
    fpr  = compute_fpr(y_true_binary, y_pred_binary)
    tpr  = compute_tpr(y_true_binary, y_pred_binary)

    # Per-class detection rate against each individual attack class
    attack_classes = [c for c in classes if c != "BENIGN"]
    per_class_tpr: dict = {}
    for cls in attack_classes:
        cls_idx  = int(le.transform([cls])[0])
        cls_mask = (y_test == cls_idx)
        if cls_mask.sum() == 0:
            per_class_tpr[cls] = None
            continue
        cls_pred           = y_pred_binary[cls_mask]
        per_class_tpr[cls] = float(np.mean(cls_pred == 1))

    # Confusion matrix
    cm            = confusion_matrix(y_true_binary, y_pred_binary)
    tn, fp, fn, tp = cm.ravel()

    # ── Print results table ───────────────────────────────────────────────
    PASS_SIGN = "PASS"
    FAIL_SIGN = "FAIL"

    def pf(val, tgt, op):
        return PASS_SIGN if (val >= tgt if op == ">=" else val <= tgt) else FAIL_SIGN

    print("\n" + "=" * 70)
    print("ISOLATION FOREST EVALUATION RESULTS")
    print("=" * 70)
    print(f"\n  {'Metric':<30} {'Result':>10}  {'Target':>12}  {'Status':>6}")
    print(f"  {'-' * 62}")
    print(f"  {'Accuracy':<30} {acc:>10.4f}  {'>=0.9500':>12}  {pf(acc, 0.95, '>='):>6}")
    print(f"  {'Precision':<30} {prec:>10.4f}  {'>=0.9000':>12}  {pf(prec, 0.90, '>='):>6}")
    print(f"  {'Recall / TPR':<30} {rec:>10.4f}  {'>=0.8500':>12}  {pf(rec, 0.85, '>='):>6}")
    print(f"  {'F1-Score (binary)':<30} {f1:>10.4f}  {'>=0.9000':>12}  {pf(f1, 0.90, '>='):>6}")
    print(f"  {'False Positive Rate':<30} {fpr:>10.4f}  {'<=0.0500':>12}  {pf(fpr, 0.05, '<='):>6}")
    print(f"  {'Inference Latency (ms)':<30} {latency_ms:>10.4f}  {'<=3.0000':>12}  {pf(latency_ms, 3.0, '<='):>6}")
    print("\n  Confusion Matrix (binary: 0=BENIGN, 1=ATTACK):")
    print(f"    TN (correct benign)  = {tn:>10,}")
    print(f"    FP (false alert)     = {fp:>10,}")
    print(f"    FN (missed attack)   = {fn:>10,}")
    print(f"    TP (caught attack)   = {tp:>10,}")
    print("\n  Per-class Detection Rate (TPR >= 0.85 target):")
    for cls, rate in per_class_tpr.items():
        if rate is None:
            print(f"    {cls:<20} : N/A (no test samples)")
        else:
            status = PASS_SIGN if rate >= 0.85 else FAIL_SIGN
            print(f"    {cls:<20} : {rate:.4f}  {status}")

    # ── Save model ────────────────────────────────────────────────────────
    print(f"\n  Saving model to {MODEL_OUT} ...")
    joblib.dump(iforest, MODEL_OUT)
    model_size_mb = MODEL_OUT.stat().st_size / (1024 * 1024)
    print(f"  Model file size: {model_size_mb:.1f} MB")

    # ── Save metrics JSON ─────────────────────────────────────────────────
    metrics = {
        "model": "IsolationForest",
        "training_date": "2026-03-29",
        "dataset": "CICIDS2017",
        "training_on": "BENIGN flows only (unsupervised -- FR5.2, FR5.7)",
        "training_samples_benign": n_benign_train,
        "test_samples_total": n_test,
        "test_samples_benign": int(tn + fp),
        "test_samples_attack": int(fn + tp),
        "hyperparameters": {
            "n_estimators": N_ESTIMATORS,
            "contamination": CONTAMINATION,
            "max_samples": MAX_SAMPLES,
            "random_state": RANDOM_STATE,
            "n_jobs": N_JOBS,
        },
        "metrics": {
            "accuracy":            round(acc, 6),
            "precision":           round(prec, 6),
            "recall_tpr":          round(rec, 6),
            "f1_score_binary":     round(f1, 6),
            "false_positive_rate": round(fpr, 6),
            "inference_latency_ms":round(latency_ms, 6),
        },
        "confusion_matrix": {
            "TN": int(tn), "FP": int(fp),
            "FN": int(fn), "TP": int(tp),
        },
        "per_class_tpr": {
            k: (round(v, 6) if v is not None else None)
            for k, v in per_class_tpr.items()
        },
        "confidence_mapping": {
            "method": "sigmoid(decision_function_score)",
            "convention": "higher confidence = more anomalous = more likely attack",
            "range": "[0.0, 1.0]",
        },
        "ensemble_role": {
            "weight": 0.10,
            "alert_threshold": 0.50,
            "note": (
                "IF weight 0.10 implements soft-gating: IF-only false positive "
                "contributes max 0.10 to ensemble score, below the 0.50 alert "
                "threshold. Multi-engine corroboration required to trigger alert."
            ),
        },
        "nfr_targets": {
            "NFR20.1_accuracy_pass":  bool(acc >= 0.95),
            "NFR20.2_fpr_pass":       bool(fpr <= 0.05),
            "latency_pass":           bool(latency_ms <= 3.0),
        },
        "training_time_seconds": round(train_elapsed, 1),
        "model_file": str(MODEL_OUT),
        "notes": (
            "Isolation Forest trained on BENIGN-only CICIDS2017 training split. "
            "SMOTE not applicable -- IF is unsupervised and requires no attack labels. "
            "class_weight parameter not applicable to IsolationForest. "
            "Confidence mapped to [0.0, 1.0] via sigmoid(decision_function score). "
            "Higher confidence = more anomalous flow = higher attack probability."
        ),
    }

    with open(METRICS_OUT, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics saved to {METRICS_OUT}")

    print("\n" + "=" * 70)
    print("ISOLATION FOREST TRAINING COMPLETE")
    print(f"  Model  : {MODEL_OUT}")
    print(f"  Metrics: {METRICS_OUT}")
    print("=" * 70 + "\n")

    return metrics


if __name__ == "__main__":
    main()
