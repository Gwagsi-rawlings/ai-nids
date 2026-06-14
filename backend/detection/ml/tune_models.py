"""
AI-NIDS — Fast Hyperparameter Tuning: RF + IF
ml/tune_models.py  (v2 — optimised for speed)

Strategy changes vs v1:
  - RF: trains on a 20% STRATIFIED SUBSAMPLE of training data for grid search
        then re-trains the winner on the full training set once
  - RF: uses n_jobs=-1 throughout, n_estimators capped at 100 for search
  - IF: contamination search only (n_estimators fixed at 100) — 5 candidates
  - Grid is 12 RF combinations instead of 36

Total expected time: ~25–40 min instead of 3–5 hours.

March 30, 2026 | Sprint 1 | Developer: GWAGSI Rawlings Nshom
"""

import gc
import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedShuffleSplit

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).resolve().parent.parent.parent  # ~/ai-nids/
PROCESSED   = BASE_DIR / "detection" / "ml" / "processed"
MODELS_DIR  = BASE_DIR / "detection" / "models"
METRICS_DIR = BASE_DIR / "detection" / "ml"

MODELS_DIR.mkdir(parents=True, exist_ok=True)

X_TRAIN_PATH = PROCESSED / "X_train.npy"
Y_TRAIN_PATH = PROCESSED / "y_train.npy"
X_TEST_PATH  = PROCESSED / "X_test.npy"
Y_TEST_PATH  = PROCESSED / "y_test.npy"
LE_PATH      = PROCESSED / "label_encoder.pkl"

RF_TUNED_OUT  = MODELS_DIR / "random_forest_tuned.pkl"
RF_THRESH_OUT = MODELS_DIR / "rf_thresholds_tuned.pkl"
IF_TUNED_OUT  = MODELS_DIR / "isolation_forest_tuned.pkl"
RESULTS_OUT   = METRICS_DIR / "tuning_results.json"

RANDOM_STATE = 42

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(x))


def compute_fpr(y_true, y_pred, benign_idx: int) -> float:
    tn = int(np.sum((y_true == benign_idx) & (y_pred == benign_idx)))
    fp = int(np.sum((y_true == benign_idx) & (y_pred != benign_idx)))
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def compute_binary_fpr(y_true_bin, y_pred_bin) -> float:
    tn = int(np.sum((y_true_bin == 0) & (y_pred_bin == 0)))
    fp = int(np.sum((y_true_bin == 0) & (y_pred_bin == 1)))
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


# ---------------------------------------------------------------------------
# RF tuning  — search on 20% subsample, re-train winner on full data
# ---------------------------------------------------------------------------

def tune_random_forest(X_train, y_train, X_val, y_val, le, benign_idx):
    print("\n--- RF Hyperparameter Search (subsampled) ---")

    # ── Step 1: subsample 20% of training data for fast grid search ──────
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.80, random_state=RANDOM_STATE)
    sub_idx, _ = next(sss.split(X_train, y_train))
    X_sub, y_sub = X_train[sub_idx], y_train[sub_idx]
    print(f"  Search subsample: {X_sub.shape[0]:,} rows  ({X_sub.shape[0]/X_train.shape[0]*100:.0f}% of train)")

    # ── Step 2: compact grid ──────────────────────────────────────────────
    # Custom weight dict indices match label_encoder order:
    # 0=BENIGN, 1=Botnet, 2=BruteForce, 3=DDoS, 4=DoS, 5=Infiltration, 6=PortScan, 7=WebAttack
    CUSTOM_W = {0: 1, 1: 150, 2: 50, 3: 1, 4: 5, 5: 500, 6: 2, 7: 150}

    param_grid = [
        # (max_depth, min_samples_leaf, class_weight_label, class_weight_value)
        (None, 2,  "balanced",  "balanced"),
        (None, 5,  "balanced",  "balanced"),
        (None, 10, "balanced",  "balanced"),
        (50,   2,  "balanced",  "balanced"),
        (50,   5,  "balanced",  "balanced"),
        (30,   5,  "balanced",  "balanced"),
        (None, 2,  "custom",    CUSTOM_W),
        (None, 5,  "custom",    CUSTOM_W),
        (None, 10, "custom",    CUSTOM_W),
        (50,   2,  "custom",    CUSTOM_W),
        (50,   5,  "custom",    CUSTOM_W),
        (30,   5,  "custom",    CUSTOM_W),
    ]
    print(f"  Grid size: {len(param_grid)} combinations  (n_estimators=100 for search)")

    best_score  = -1.0
    best_params = None
    results     = []

    for i, (max_depth, min_leaf, cw_label, cw_val) in enumerate(param_grid):
        t0 = time.time()
        rf = RandomForestClassifier(
            n_estimators    =100,          # fast for search
            max_depth       =max_depth,
            min_samples_leaf=min_leaf,
            class_weight    =cw_val,
            n_jobs          =-1,
            random_state    =RANDOM_STATE,
        )
        rf.fit(X_sub, y_sub)
        preds    = rf.predict(X_val)
        macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
        fpr      = compute_fpr(y_val, preds, benign_idx)
        elapsed  = time.time() - t0

        feasible = fpr <= 0.05
        if feasible and macro_f1 > best_score:
            best_score  = macro_f1
            best_params = (max_depth, min_leaf, cw_label, cw_val)

        print(f"  [{i+1:>2}/{len(param_grid)}] depth={str(max_depth):<6} "
              f"leaf={min_leaf:<3} cw={cw_label:<8} "
              f"F1={macro_f1:.4f}  FPR={fpr:.4f}  "
              f"{'FEASIBLE *BEST*' if feasible and macro_f1 == best_score else ('FEASIBLE' if feasible else 'infeasible')}"
              f"  ({elapsed:.0f}s)")

        results.append({
            "max_depth": max_depth, "min_samples_leaf": min_leaf,
            "class_weight": cw_label, "macro_f1": round(macro_f1, 4),
            "fpr": round(fpr, 4), "feasible": feasible,
        })
        del rf; gc.collect()

    # Fallback if nothing feasible
    if best_params is None:
        print("  No feasible candidate — relaxing FPR constraint, selecting best macro F1")
        best_idx   = max(range(len(results)), key=lambda i: results[i]["macro_f1"])
        bp         = param_grid[best_idx]
        best_params= bp

    max_depth, min_leaf, cw_label, cw_val = best_params
    print(f"\n  Best search params: depth={max_depth} leaf={min_leaf} cw={cw_label}")
    print(f"  Best val macro F1 (on subsample search): {best_score:.4f}")

    # ── Step 3: re-train winner on FULL training set with n_estimators=200 ─
    print(f"\n  Re-training winner on full {X_train.shape[0]:,} samples (n_estimators=200)...")
    t0 = time.time()
    rf_final = RandomForestClassifier(
        n_estimators    =200,
        max_depth       =max_depth,
        min_samples_leaf=min_leaf,
        class_weight    =cw_val,
        n_jobs          =-1,
        random_state    =RANDOM_STATE,
    )
    rf_final.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"  Full re-train done in {elapsed:.0f}s ({elapsed/60:.1f} min)")

    # ── Step 4: validate final model ──────────────────────────────────────
    preds_final = rf_final.predict(X_val)
    final_f1    = f1_score(y_val, preds_final, average="macro", zero_division=0)
    final_fpr   = compute_fpr(y_val, preds_final, benign_idx)
    print(f"  Final val macro F1: {final_f1:.4f}  |  FPR: {final_fpr:.4f}")

    # ── Step 5: per-class threshold calibration on val split ─────────────
    print("  Calibrating per-class probability thresholds on validation split...")
    proba     = rf_final.predict_proba(X_val)
    classes   = list(le.classes_)
    thresholds= {}
    for idx, cls in enumerate(classes):
        y_bin = (y_val == idx).astype(int)
        best_thresh, best_f1 = 0.5, -1.0
        for thresh in np.linspace(0.1, 0.9, 33):
            pr   = (proba[:, idx] >= thresh).astype(int)
            f1   = f1_score(y_bin, pr, zero_division=0)
            if f1 > best_f1:
                best_f1, best_thresh = f1, thresh
        thresholds[cls] = float(round(best_thresh, 4))
    print(f"  Thresholds: {thresholds}")

    return rf_final, {
        "max_depth": max_depth, "min_samples_leaf": min_leaf,
        "class_weight": cw_label, "n_estimators": 200,
    }, final_f1, final_fpr, thresholds, results


# ---------------------------------------------------------------------------
# IF tuning  — 5 contamination values only, fixed n_estimators=100
# ---------------------------------------------------------------------------

def tune_isolation_forest(X_train_benign, X_val, y_val, benign_idx):
    print("\n--- IF Hyperparameter Search (contamination only) ---")

    y_val_bin   = np.where(y_val == benign_idx, 0, 1)
    contam_vals = [0.005, 0.008, 0.01, 0.015, 0.02]
    print(f"  Candidates: contamination in {contam_vals}  (n_estimators=100 fixed)")

    best_tpr    = -1.0
    best_fpr    = 1.0
    best_contam = 0.01
    best_model  = None
    best_thresh = 0.5
    results     = []

    for contam in contam_vals:
        t0 = time.time()
        iforest = IsolationForest(
            n_estimators =100,
            contamination=contam,
            max_samples  ="auto",
            n_jobs       =-1,
            random_state =RANDOM_STATE,
        )
        iforest.fit(X_train_benign)

        scores = sigmoid(iforest.decision_function(X_val))

        # Calibrate threshold
        best_t, best_f1 = 0.5, -1.0
        for t in np.linspace(0.3, 0.9, 25):
            preds = (scores >= t).astype(int)
            f1    = f1_score(y_val_bin, preds, zero_division=0)
            if f1 > best_f1:
                best_f1, best_t = f1, t

        preds = (scores >= best_t).astype(int)
        tpr   = float(np.mean(preds[y_val_bin == 1] == 1)) if y_val_bin.sum() > 0 else 0.0
        fpr   = compute_binary_fpr(y_val_bin, preds)
        elapsed = time.time() - t0

        feasible = fpr <= 0.05
        if feasible and tpr > best_tpr:
            best_tpr    = tpr
            best_fpr    = fpr
            best_contam = contam
            best_model  = iforest
            best_thresh = best_t

        print(f"  contam={contam:.3f}  thresh={best_t:.3f}  "
              f"TPR={tpr:.4f}  FPR={fpr:.4f}  "
              f"{'FEASIBLE' if feasible else 'infeasible'}  ({elapsed:.0f}s)")

        results.append({
            "contamination": contam, "threshold": round(best_t, 4),
            "tpr": round(tpr, 4), "fpr": round(fpr, 4), "feasible": feasible,
        })
        del iforest; gc.collect()

    if best_model is None:
        print("  No feasible IF — selecting lowest FPR")
        best_result = min(results, key=lambda r: r["fpr"])
        best_contam = best_result["contamination"]
        best_thresh = best_result["threshold"]
        best_model  = IsolationForest(
            n_estimators=100, contamination=best_contam,
            max_samples="auto", n_jobs=-1, random_state=RANDOM_STATE,
        )
        best_model.fit(X_train_benign)
        best_tpr = best_result["tpr"]
        best_fpr = best_result["fpr"]

    print(f"\n  Best contamination : {best_contam}")
    print(f"  Best TPR           : {best_tpr:.4f}  |  FPR: {best_fpr:.4f}")
    print(f"  Calibrated threshold: {best_thresh:.4f}")

    return best_model, best_contam, best_tpr, best_fpr, best_thresh, results


# ---------------------------------------------------------------------------
# Final evaluation on held-out test set
# ---------------------------------------------------------------------------

def evaluate_on_test(rf_tuned, if_tuned, X_test, y_test, le, benign_idx):
    print("\n--- Final Evaluation on Test Set ---")
    classes = list(le.classes_)

    # RF
    rf_preds    = rf_tuned.predict(X_test)
    rf_macro_f1 = f1_score(y_test, rf_preds, average="macro", zero_division=0)
    rf_weighted = f1_score(y_test, rf_preds, average="weighted", zero_division=0)
    rf_fpr      = compute_fpr(y_test, rf_preds, benign_idx)

    # IF
    y_bin    = np.where(y_test == benign_idx, 0, 1)
    if_score = sigmoid(if_tuned.decision_function(X_test))
    if_preds = np.where(if_tuned.predict(X_test) == -1, 1, 0)
    if_tpr   = float(np.mean(if_preds[y_bin == 1] == 1))
    if_fpr   = compute_binary_fpr(y_bin, if_preds)

    print(f"\n  Tuned RF — macro F1: {rf_macro_f1:.4f}  weighted F1: {rf_weighted:.4f}  FPR: {rf_fpr:.4f}")
    print(f"  Tuned IF — TPR: {if_tpr:.4f}  FPR: {if_fpr:.4f}")

    # Per-class RF TPR
    BASELINE = {"Botnet": 0.8703, "BruteForce": 0.9892, "DDoS": 0.9998,
                "DoS": 0.9953, "Infiltration": 0.7143, "PortScan": 1.0000, "WebAttack": 0.9083}
    print("\n  Per-class RF TPR (tuned vs baseline):")
    per_class = {}
    for cls in [c for c in classes if c != "BENIGN"]:
        cls_idx  = int(le.transform([cls])[0])
        cls_mask = (y_test == cls_idx)
        if cls_mask.sum() == 0:
            continue
        tpr_tuned    = float(np.mean(rf_preds[cls_mask] == cls_idx))
        tpr_baseline = BASELINE.get(cls, 0.0)
        delta        = tpr_tuned - tpr_baseline
        per_class[cls] = {"baseline": tpr_baseline, "tuned": round(tpr_tuned, 4), "delta": round(delta, 4)}
        print(f"    {cls:<20} baseline={tpr_baseline:.4f}  tuned={tpr_tuned:.4f}  delta={delta:+.4f}")

    return {
        "rf_macro_f1":    round(rf_macro_f1, 4),
        "rf_weighted_f1": round(rf_weighted, 4),
        "rf_fpr":         round(rf_fpr, 4),
        "if_tpr":         round(if_tpr, 4),
        "if_fpr":         round(if_fpr, 4),
        "per_class_rf":   per_class,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 65)
    print("AI-NIDS -- Fast Hyperparameter Tuning  |  March 30, 2026")
    print("=" * 65)

    print("\n[1/5] Loading arrays...")
    X_train = np.load(X_TRAIN_PATH)
    y_train = np.load(Y_TRAIN_PATH)
    X_test  = np.load(X_TEST_PATH)
    y_test  = np.load(Y_TEST_PATH)
    le      = joblib.load(LE_PATH)
    benign_idx = int(le.transform(["BENIGN"])[0])
    print(f"  X_train: {X_train.shape}  |  classes: {list(le.classes_)}")

    print("\n[2/5] Creating validation split (20% of training)...")
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.20, random_state=RANDOM_STATE)
    train_idx, val_idx = next(sss.split(X_train, y_train))
    X_val, y_val = X_train[val_idx], y_train[val_idx]
    # For full re-train we keep X_train intact
    print(f"  Val: {X_val.shape}")

    # BENIGN-only for IF (use full train)
    benign_mask  = (y_train == benign_idx)
    X_tr_benign  = X_train[benign_mask]
    print(f"  IF training (BENIGN-only): {X_tr_benign.shape}")

    print("\n[3/5] Tuning Random Forest...")
    rf_tuned, rf_best_params, rf_f1, rf_fpr, rf_thresholds, rf_results = \
        tune_random_forest(X_train, y_train, X_val, y_val, le, benign_idx)

    joblib.dump(rf_tuned, RF_TUNED_OUT)
    joblib.dump(rf_thresholds, RF_THRESH_OUT)
    print(f"  Saved: {RF_TUNED_OUT}")

    print("\n[4/5] Tuning Isolation Forest...")
    if_tuned, if_contam, if_tpr, if_fpr, if_thresh, if_results = \
        tune_isolation_forest(X_tr_benign, X_val, y_val, benign_idx)

    joblib.dump(if_tuned, IF_TUNED_OUT)
    print(f"  Saved: {IF_TUNED_OUT}")

    print("\n[5/5] Final evaluation on test set...")
    test_results = evaluate_on_test(rf_tuned, if_tuned, X_test, y_test, le, benign_idx)

    output = {
        "tuning_date": "2026-03-30",
        "rf": {
            "best_params":             rf_best_params,
            "val_macro_f1":            round(rf_f1, 4),
            "val_fpr":                 round(rf_fpr, 4),
            "calibrated_thresholds":   rf_thresholds,
            "grid_results":            rf_results,
            "model_file":              str(RF_TUNED_OUT),
        },
        "if": {
            "best_contamination":      if_contam,
            "val_tpr":                 round(if_tpr, 4),
            "val_fpr":                 round(if_fpr, 4),
            "calibrated_threshold":    round(if_thresh, 4),
            "grid_results":            if_results,
            "model_file":              str(IF_TUNED_OUT),
        },
        "test_set_results": test_results,
        "baseline_vs_tuned": {
            "rf_baseline_macro_f1": 0.6639, "rf_tuned_macro_f1": test_results["rf_macro_f1"],
            "rf_baseline_fpr":      0.0723, "rf_tuned_fpr":      test_results["rf_fpr"],
            "if_baseline_tpr":      0.3471, "if_tuned_tpr":      test_results["if_tpr"],
            "if_baseline_fpr":      0.0501, "if_tuned_fpr":      test_results["if_fpr"],
        }
    }
    with open(RESULTS_OUT, "w") as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 65)
    print("TUNING COMPLETE")
    print(f"  RF macro F1 : baseline=0.6639  ->  tuned={test_results['rf_macro_f1']}")
    print(f"  RF FPR      : baseline=0.0723  ->  tuned={test_results['rf_fpr']}")
    print(f"  IF TPR      : baseline=0.3471  ->  tuned={test_results['if_tpr']}")
    print(f"  IF FPR      : baseline=0.0501  ->  tuned={test_results['if_fpr']}")
    print(f"  Results: {RESULTS_OUT}")
    print("=" * 65)


if __name__ == "__main__":
    main()
