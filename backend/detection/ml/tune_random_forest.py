"""
AI-NIDS — Random Forest Tuning Run
ml/tune_random_forest.py

Problem identified in initial training run (March 28, 2026):
  - Macro F1:  0.6639  (target ≥0.95) — dragged down by Botnet/BruteForce/WebAttack
  - Macro Pre: 0.6507  (target ≥0.90) — minority classes have very low precision
  - FPR:       0.0723  (target ≤0.05) — BENIGN misclassified at 7.23% rate
  - Macro Rec: 0.9250  ✓              — recall is strong across all classes

Root cause:
  class_weight='balanced' over-weights the 3 ultra-minority classes
  (Botnet: 29 train samples→1,573 test; Infiltration: 29 train samples).
  The model achieves high recall but very low precision on these classes,
  causing BENIGN flows to be misclassified as Botnet/BruteForce/WebAttack.

Tuning strategy (two steps):
  Step 1 — Custom class weights: reduce weight of ultra-minority classes
           relative to 'balanced', preventing over-prediction.
  Step 2 — Probability threshold calibration: instead of default 0.5 threshold,
           find per-class thresholds that maximise F1 on a validation split,
           then apply to the test set. Documented as post-hoc calibration.

FR Traceability:
    FR5.1   — Random Forest classifier
    NFR20.1 — ≥95% accuracy
    NFR20.2 — FPR ≤5%
    NFR20.3 — ≥90% precision for critical alerts
    NFR20.5 — Ensemble must outperform any individual model by ≥2% F1

Usage:
    source venv/bin/activate
    python ml/tune_random_forest.py

Outputs:
    models/random_forest_tuned.pkl       — tuned model (custom weights)
    models/rf_thresholds.pkl             — per-class probability thresholds
    ml/rf_tuned_metrics.json             — full metrics for both passes
    ml/rf_tuned_confusion_matrix.npy     — confusion matrix (threshold-calibrated)

March 28, 2026 | Sprint 1, Week 3 | Developer: GWAGSI Rawlings Nshom
"""

import json
import os
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
from sklearn.model_selection import train_test_split

# ── Paths ──────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "ml" / "processed"
MODELS_DIR    = PROJECT_ROOT / "models"
ML_DIR        = PROJECT_ROOT / "ml"

TUNED_MODEL_PATH  = MODELS_DIR / "random_forest_tuned.pkl"
THRESHOLD_PATH    = MODELS_DIR / "rf_thresholds.pkl"
METRICS_PATH      = ML_DIR / "rf_tuned_metrics.json"
CM_PATH           = ML_DIR / "rf_tuned_confusion_matrix.npy"

# ── Class names (must match label encoder order) ────────────────
CLASS_NAMES = ['BENIGN', 'Botnet', 'BruteForce', 'DDoS',
               'DoS', 'Infiltration', 'PortScan', 'WebAttack']

# ── Step 1: Custom class weights ────────────────────────────────
# Strategy: start from 'balanced' logic but dampen ultra-minority classes
# that caused precision collapse in the baseline run.
#
# Baseline (class_weight='balanced') implicit weights (approx):
#   BENIGN: 1x, DoS: 9x, PortScan: 14x, DDoS: 18x
#   BruteForce: 182x, WebAttack: 1300x, Botnet: 1440x, Infiltration: 69000x
#
# Tuned: cap ultra-minority multipliers to reduce over-prediction.
# Values below are multipliers relative to BENIGN.
CUSTOM_WEIGHTS = {
    0: 1,      # BENIGN        — baseline reference
    1: 150,    # Botnet        — was ~1440x; cap to 150x
    2: 50,     # BruteForce    — was ~182x; reduce to 50x
    3: 18,     # DDoS          — keep ~balanced
    4: 9,      # DoS           — keep ~balanced
    5: 500,    # Infiltration  — was ~69000x; cap to 500x (only 29 samples)
    6: 14,     # PortScan      — keep ~balanced
    7: 150,    # WebAttack     — was ~1300x; cap to 150x
}

RF_PARAMS = {
    "n_estimators":     200,
    "max_depth":        None,
    "min_samples_leaf": 2,
    "class_weight":     CUSTOM_WEIGHTS,
    "n_jobs":           -1,
    "random_state":     42,
    "verbose":          1,
}


def load_data():
    print("── Loading preprocessed data ──────────────────────────")
    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    X_test  = np.load(PROCESSED_DIR / "X_test.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy")
    y_test  = np.load(PROCESSED_DIR / "y_test.npy")
    le      = joblib.load(ML_DIR / "processed" / "label_encoder.pkl")

    print(f"  X_train: {X_train.shape}  X_test: {X_test.shape}")

    # Hold out 20% of train for threshold calibration
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.20, stratify=y_train, random_state=42
    )
    print(f"  Train split: {X_tr.shape[0]:,}  Val split: {X_val.shape[0]:,}")
    return X_tr, X_val, X_test, y_tr, y_val, y_test, le


def train(X_tr, y_tr):
    print("\n── Step 1: Training with custom class weights ─────────")
    print(f"  Custom weights: {CUSTOM_WEIGHTS}")
    clf = RandomForestClassifier(**RF_PARAMS)
    t0 = time.time()
    clf.fit(X_tr, y_tr)
    print(f"  Training complete in {time.time()-t0:.1f}s")
    return clf


def calibrate_thresholds(clf, X_val, y_val):
    """
    Step 2: Find per-class probability thresholds that maximise F1
    on the validation split. Default threshold is 0.5 for all classes.
    For each class, sweep thresholds [0.1, 0.9] and pick the one
    that maximises that class's F1 score.
    """
    print("\n── Step 2: Threshold calibration on validation split ──")
    proba_val = clf.predict_proba(X_val)   # shape (n_samples, n_classes)
    n_classes = proba_val.shape[1]
    thresholds = np.zeros(n_classes)

    for i, cls in enumerate(CLASS_NAMES):
        best_f1, best_thresh = 0.0, 0.5
        # Binary: class i vs rest
        y_bin = (y_val == i).astype(int)
        for t in np.arange(0.05, 0.95, 0.02):
            y_pred_bin = (proba_val[:, i] >= t).astype(int)
            f1 = f1_score(y_bin, y_pred_bin, zero_division=0)
            if f1 > best_f1:
                best_f1, best_thresh = f1, t
        thresholds[i] = best_thresh
        print(f"  {cls:<15} best threshold = {best_thresh:.2f}  (val F1 = {best_f1:.4f})")

    return thresholds


def apply_thresholds(proba, thresholds):
    """
    Convert probability matrix to class predictions using per-class thresholds.
    For each sample: pick the class with highest (proba - threshold) gap.
    Falls back to argmax if no class exceeds its threshold.
    """
    adjusted = proba - thresholds[np.newaxis, :]   # shape (n, n_classes)
    predictions = np.argmax(adjusted, axis=1)
    return predictions


def evaluate(clf, X_test, y_test, thresholds, le):
    print("\n── Evaluating threshold-calibrated model on test set ──")
    t0 = time.time()
    proba_test = clf.predict_proba(X_test)
    y_pred = apply_thresholds(proba_test, thresholds)
    inf_ms = (time.time() - t0) / len(X_test) * 1000

    class_names = list(le.classes_)
    accuracy  = accuracy_score(y_test, y_pred)
    macro_f1  = f1_score(y_test, y_pred, average="macro",     zero_division=0)
    macro_pre = precision_score(y_test, y_pred, average="macro", zero_division=0)
    macro_rec = recall_score(y_test, y_pred, average="macro",  zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    # FPR: BENIGN flows misclassified
    benign_idx   = class_names.index("BENIGN")
    benign_mask  = y_test == benign_idx
    benign_fp    = (y_pred[benign_mask] != benign_idx).sum()
    overall_fpr  = benign_fp / benign_mask.sum()

    # Per-class FPR
    cm = confusion_matrix(y_test, y_pred)
    fp_rates = []
    for i in range(len(class_names)):
        tp = cm[i, i]
        fp = cm[:, i].sum() - tp
        fn = cm[i, :].sum() - tp
        tn = cm.sum() - tp - fp - fn
        fp_rates.append(fp / (fp + tn) if (fp + tn) > 0 else 0.0)

    # ── Print ──────────────────────────────────────────────────
    print(f"\n  {'Metric':<35} {'Baseline':>10}  {'Tuned':>10}  {'Target':>10}  {'Pass':>6}")
    print(f"  {'─'*75}")

    baseline = {"acc": 0.9412, "f1": 0.6639, "pre": 0.6507, "rec": 0.9250, "fpr": 0.0723}
    rows = [
        ("Accuracy (macro)", accuracy, baseline["acc"], 0.95, accuracy >= 0.95),
        ("Macro F1-Score",   macro_f1, baseline["f1"], 0.95, macro_f1 >= 0.95),
        ("Macro Precision",  macro_pre, baseline["pre"], 0.90, macro_pre >= 0.90),
        ("Macro Recall",     macro_rec, baseline["rec"], 0.90, macro_rec >= 0.90),
        ("FPR (benign miscl.)", overall_fpr, baseline["fpr"], 0.05, overall_fpr <= 0.05),
        ("Weighted F1",      weighted_f1, None, None, None),
        ("Inf. latency ms",  inf_ms, None, 5.0, inf_ms <= 5.0),
    ]
    for name, val, base, tgt, passed in rows:
        base_str = f"{base:.4f}" if base is not None else "  —"
        tgt_str  = f"{'≥' if passed is not None and tgt >= 0.5 else '≤'}{tgt:.4f}" if tgt is not None else "  —"
        pass_str = ('✓' if passed else '✗') if passed is not None else "  —"
        print(f"  {name:<35} {base_str:>10}  {val:>10.4f}  {tgt_str:>10}  {pass_str:>6}")

    print(f"\n  Per-class classification report (tuned):")
    print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    print(f"  Per-class FPR (tuned):")
    for cls, fpr_i in zip(class_names, fp_rates):
        delta = fpr_i - [0.0031,0.0183,0.0221,0.0001,0.0140,0.0000,0.0004,0.0048][
            class_names.index(cls)]
        arrow = "↓" if delta < 0 else ("↑" if delta > 0 else "—")
        print(f"    {cls:<20} FPR = {fpr_i:.4f}  {arrow}")

    print(f"\n  Confusion matrix (tuned):")
    print(cm)

    metrics = {
        "model":              "RandomForestClassifier_tuned",
        "strategy":           "custom_class_weights + threshold_calibration",
        "training_dataset":   "CICIDS2017",
        "test_samples":       int(len(y_test)),
        "baseline_macro_f1":  0.6639,
        "accuracy":           float(round(accuracy, 6)),
        "macro_f1":           float(round(macro_f1, 6)),
        "macro_precision":    float(round(macro_pre, 6)),
        "macro_recall":       float(round(macro_rec, 6)),
        "weighted_f1":        float(round(weighted_f1, 6)),
        "fpr_overall":        float(round(overall_fpr, 6)),
        "fpr_per_class":      {cls: float(round(fpr, 6))
                               for cls, fpr in zip(class_names, fp_rates)},
        "thresholds":         {cls: float(round(thresholds[i], 4))
                               for i, cls in enumerate(class_names)},
        "inf_ms_per_sample":  float(round(inf_ms, 6)),
        "nfr20_1_pass":       bool(accuracy >= 0.95),
        "nfr20_2_pass":       bool(overall_fpr <= 0.05),
        "nfr20_3_pass":       bool(macro_pre >= 0.90),
        "nfr20_4_pass":       bool(macro_rec >= 0.90),
        "trained_at":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return metrics, cm, y_pred


def save_outputs(clf, metrics, cm, thresholds):
    print("\n── Saving outputs ─────────────────────────────────────")
    joblib.dump(clf, TUNED_MODEL_PATH)
    joblib.dump(thresholds, THRESHOLD_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    np.save(CM_PATH, cm)
    print(f"  Tuned model    → {TUNED_MODEL_PATH}")
    print(f"  Thresholds     → {THRESHOLD_PATH}")
    print(f"  Metrics        → {METRICS_PATH}")
    print(f"  Confusion mat  → {CM_PATH}")


def main():
    print("=" * 65)
    print("  AI-NIDS — RF Tuning Run  |  March 28, 2026")
    print("  Strategy: Custom weights + threshold calibration")
    print("=" * 65)

    X_tr, X_val, X_test, y_tr, y_val, y_test, le = load_data()
    clf = train(X_tr, y_tr)
    thresholds = calibrate_thresholds(clf, X_val, y_val)
    metrics, cm, _ = evaluate(clf, X_test, y_test, thresholds, le)
    save_outputs(clf, metrics, cm, thresholds)

    passes = sum([metrics["nfr20_1_pass"], metrics["nfr20_2_pass"],
                  metrics["nfr20_3_pass"], metrics["nfr20_4_pass"]])
    print(f"\n── Summary ────────────────────────────────────────────")
    print(f"  NFR20 targets passed: {passes}/4")
    print(f"  Macro F1 : {metrics['macro_f1']:.4f}  (was 0.6639)")
    print(f"  FPR      : {metrics['fpr_overall']:.4f}  (was 0.0723)")
    print(f"  Weighted F1: {metrics['weighted_f1']:.4f}")
    print("=" * 65)
    print("  Paste output back to complete §4.8 tuned results.")
    print("=" * 65)


if __name__ == "__main__":
    main()