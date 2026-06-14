"""
AI-NIDS — Random Forest Classifier Training
ml/train_random_forest.py

Loads preprocessed CICIDS2017 arrays from ml/processed/,
trains a Random Forest classifier, evaluates on the held-out
test set, prints a full metrics report, and saves:
  - models/random_forest.pkl   (trained model)
  - ml/rf_metrics.json         (accuracy, precision, recall, F1, FPR)
  - ml/rf_confusion_matrix.npy (confusion matrix array)

FR Traceability:
    FR5.1  — Random Forest classifier for multi-class attack classification
    FR5.4  — Load pre-trained models at startup
    FR5.5  — Classify attacks into categories
    FR5.6  — Assign confidence score (0.0–1.0) to each detection
    NFR20.1 — ≥95% accuracy on CICIDS2017 test set
    NFR20.2 — FPR ≤5%

Usage (from project root ~/ai-nids/):
    source venv/bin/activate
    python ml/train_random_forest.py

Expects:
    ml/processed/X_train.npy
    ml/processed/X_test.npy
    ml/processed/y_train.npy
    ml/processed/y_test.npy
    ml/label_encoder.pkl

March 28, 2026 | Sprint 1, Week 3 | Developer: GWAGSI Rawlings Nshom
"""

import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

# ── Paths ──────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "ml" / "processed"
MODELS_DIR    = PROJECT_ROOT / "models"
ML_DIR        = PROJECT_ROOT / "ml"

MODELS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH   = MODELS_DIR / "random_forest.pkl"
METRICS_PATH = ML_DIR / "rf_metrics.json"
CM_PATH      = ML_DIR / "rf_confusion_matrix.npy"

# ── Hyperparameters (Component Design Doc Feb 25 §4.2) ─────────
RF_PARAMS = {
    "n_estimators":    200,
    "max_depth":       None,
    "min_samples_leaf": 2,
    "class_weight":    "balanced",   # replaces SMOTE (WSL2 memory constraint)
    "n_jobs":          -1,
    "random_state":    42,
    "verbose":         1,
}


def load_data():
    """Load preprocessed arrays and label encoder."""
    print("── Loading preprocessed data ──────────────────────────")
    required = ["X_train.npy", "X_test.npy", "y_train.npy", "y_test.npy"]
    for f in required:
        path = PROCESSED_DIR / f
        if not path.exists():
            raise FileNotFoundError(
                f"Missing: {path}\n"
                "Run ml/preprocess_cicids2017.py first."
            )

    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    X_test  = np.load(PROCESSED_DIR / "X_test.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy")
    y_test  = np.load(PROCESSED_DIR / "y_test.npy")

    encoder_path = ML_DIR / "processed" / "label_encoder.pkl"
    if not encoder_path.exists():
        raise FileNotFoundError(f"Missing label encoder: {encoder_path}")
    le = joblib.load(encoder_path)

    print(f"  X_train : {X_train.shape}  y_train : {y_train.shape}")
    print(f"  X_test  : {X_test.shape}   y_test  : {y_test.shape}")
    print(f"  Classes : {list(le.classes_)}")

    # Class distribution in training set
    unique, counts = np.unique(y_train, return_counts=True)
    print("\n  Training class distribution:")
    for cls_idx, cnt in zip(unique, counts):
        pct = cnt / len(y_train) * 100
        print(f"    [{cls_idx}] {le.classes_[cls_idx]:<20} {cnt:>8,}  ({pct:.2f}%)")

    return X_train, X_test, y_train, y_test, le


def train(X_train, y_train):
    """Train the Random Forest classifier."""
    print("\n── Training Random Forest ─────────────────────────────")
    print(f"  Parameters: {RF_PARAMS}")

    clf = RandomForestClassifier(**RF_PARAMS)
    t0 = time.time()
    clf.fit(X_train, y_train)
    elapsed = time.time() - t0

    print(f"  Training complete in {elapsed:.1f}s")
    return clf


def evaluate(clf, X_test, y_test, le):
    """Evaluate the trained model and compute all NFR20 metrics."""
    print("\n── Evaluating on held-out test set ────────────────────")
    t0 = time.time()
    y_pred = clf.predict(X_test)
    inf_time_ms = (time.time() - t0) / len(X_test) * 1000
    print(f"  Inference: {len(X_test):,} samples in {time.time()-t0:.2f}s "
          f"({inf_time_ms:.4f} ms/sample)")

    class_names = list(le.classes_)

    # ── Core metrics ───────────────────────────────────────────
    accuracy  = accuracy_score(y_test, y_pred)
    macro_f1  = f1_score(y_test, y_pred, average="macro", zero_division=0)
    macro_pre = precision_score(y_test, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_test, y_pred, average="macro", zero_division=0)

    # ── False Positive Rate (NFR20.2) ──────────────────────────
    # FPR = FP / (FP + TN)  averaged across all non-BENIGN classes
    # For multi-class: compute binary FPR treating each class as positive
    benign_idx = list(le.classes_).index("BENIGN")
    cm = confusion_matrix(y_test, y_pred)

    # Per-class FPR computation
    fp_rates = []
    for i, cls in enumerate(class_names):
        tp = cm[i, i]
        fp = cm[:, i].sum() - tp          # predicted i, actually something else
        fn = cm[i, :].sum() - tp          # actually i, predicted something else
        tn = cm.sum() - tp - fp - fn
        fpr_i = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fp_rates.append(fpr_i)

    # Overall FPR: false positives on BENIGN flows (most operationally relevant)
    # = BENIGN flows misclassified as attack / total BENIGN flows
    benign_mask   = y_test == benign_idx
    benign_total  = benign_mask.sum()
    benign_fp     = (y_pred[benign_mask] != benign_idx).sum()
    overall_fpr   = benign_fp / benign_total if benign_total > 0 else 0.0

    # ── Print results ──────────────────────────────────────────
    print(f"\n  {'Metric':<35} {'Value':>10}  {'Target':>10}  {'Pass':>6}")
    print(f"  {'─'*65}")
    print(f"  {'Accuracy (macro)':<35} {accuracy:>10.4f}  {'≥0.9500':>10}  "
          f"{'✓' if accuracy >= 0.95 else '✗':>6}")
    print(f"  {'Macro F1-Score':<35} {macro_f1:>10.4f}  {'≥0.9500':>10}  "
          f"{'✓' if macro_f1 >= 0.95 else '✗':>6}")
    print(f"  {'Macro Precision':<35} {macro_pre:>10.4f}  {'≥0.9000':>10}  "
          f"{'✓' if macro_pre >= 0.90 else '✗':>6}")
    print(f"  {'Macro Recall':<35} {macro_rec:>10.4f}  {'≥0.9000':>10}  "
          f"{'✓' if macro_rec >= 0.90 else '✗':>6}")
    print(f"  {'FPR (benign misclassified)':<35} {overall_fpr:>10.4f}  {'≤0.0500':>10}  "
          f"{'✓' if overall_fpr <= 0.05 else '✗':>6}")
    print(f"  {'Inference latency (ms/sample)':<35} {inf_time_ms:>10.4f}  {'≤5.0000':>10}  "
          f"{'✓' if inf_time_ms <= 5.0 else '✗':>6}")

    print("\n  Per-class classification report:")
    print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    print("  Per-class FPR:")
    for cls, fpr_i in zip(class_names, fp_rates):
        print(f"    {cls:<20} FPR = {fpr_i:.4f}")

    # ── Confusion matrix ───────────────────────────────────────
    print("\n  Confusion matrix (rows=actual, cols=predicted):")
    print(f"  Classes: {class_names}")
    print(cm)

    metrics = {
        "model":              "RandomForestClassifier",
        "training_dataset":   "CICIDS2017",
        "n_estimators":       RF_PARAMS["n_estimators"],
        "test_samples":       int(len(y_test)),
        "accuracy":           float(round(accuracy, 6)),
        "macro_f1":           float(round(macro_f1, 6)),
        "macro_precision":    float(round(macro_pre, 6)),
        "macro_recall":       float(round(macro_rec, 6)),
        "fpr_overall":        float(round(overall_fpr, 6)),
        "fpr_per_class":      {cls: float(round(fpr, 6))
                               for cls, fpr in zip(class_names, fp_rates)},
        "inference_ms_per_sample": float(round(inf_time_ms, 6)),
        "nfr20_1_accuracy_pass":   bool(accuracy >= 0.95),
        "nfr20_2_fpr_pass":        bool(overall_fpr <= 0.05),
        "nfr20_3_precision_pass":  bool(macro_pre >= 0.90),
        "nfr20_4_recall_pass":     bool(macro_rec >= 0.90),
        "trained_at":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    return metrics, cm


def save_outputs(clf, metrics, cm):
    """Save model, metrics JSON, and confusion matrix."""
    print("\n── Saving outputs ─────────────────────────────────────")

    joblib.dump(clf, MODEL_PATH)
    print(f"  Model saved      → {MODEL_PATH}")

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics saved    → {METRICS_PATH}")

    np.save(CM_PATH, cm)
    print(f"  Confusion matrix → {CM_PATH}")


def main():
    print("=" * 65)
    print("  AI-NIDS — Random Forest Training  |  March 28, 2026")
    print("=" * 65)

    X_train, X_test, y_train, y_test, le = load_data()
    clf = train(X_train, y_train)
    metrics, cm = evaluate(clf, X_test, y_test, le)
    save_outputs(clf, metrics, cm)

    print("\n── Summary ────────────────────────────────────────────")
    passes = sum([
        metrics["nfr20_1_accuracy_pass"],
        metrics["nfr20_2_fpr_pass"],
        metrics["nfr20_3_precision_pass"],
        metrics["nfr20_4_recall_pass"],
    ])
    print(f"  NFR20 targets passed: {passes}/4")
    print(f"  Accuracy : {metrics['accuracy']:.4f}")
    print(f"  Macro F1 : {metrics['macro_f1']:.4f}")
    print(f"  FPR      : {metrics['fpr_overall']:.4f}")
    print("=" * 65)
    print("  Training complete. Paste the output above back for §4.8.")
    print("=" * 65)


if __name__ == "__main__":
    main()
