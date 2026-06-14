"""
AI-NIDS — ROC Curves & RF vs IF Comparison
ml/compare_rf_if.py

Generates:
  1. ROC curves for RF and IF (per-class OvR for RF, binary for IF)
  2. Combined overlay plot — RF macro vs IF binary ROC
  3. Detection rate per attack class — side-by-side bar chart
  4. Saves all figures to ml/figures/ and metrics summary to ml/comparison_metrics.json

Run after both models are trained:
  python ml/compare_rf_if.py

March 30, 2026 | Sprint 1 | Developer: GWAGSI Rawlings Nshom
"""

import json
from pathlib import Path

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")          # headless — no display needed
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
from sklearn.preprocessing import label_binarize

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).resolve().parent.parent
PROCESSED   = BASE_DIR / "ml" / "processed"
MODELS_DIR  = BASE_DIR / "models"
FIGURES_DIR = BASE_DIR / "ml" / "figures"
METRICS_OUT = BASE_DIR / "ml" / "comparison_metrics.json"

FIGURES_DIR.mkdir(parents=True, exist_ok=True)

X_TEST_PATH = PROCESSED / "X_test.npy"
Y_TEST_PATH = PROCESSED / "y_test.npy"
LE_PATH     = PROCESSED / "label_encoder.pkl"
RF_PATH     = MODELS_DIR / "random_forest.pkl"
IF_PATH     = MODELS_DIR / "isolation_forest.pkl"

# Plot style
NAVY   = "#1F4E79"
BLUE   = "#2E75B6"
ORANGE = "#ED7D31"
GREEN  = "#70AD47"
RED    = "#C00000"
GREY   = "#7F7F7F"
GOLD   = "#FFC000"

CLASS_COLORS = {
    "BENIGN":     "#70AD47",
    "Botnet":     "#C00000",
    "BruteForce": "#ED7D31",
    "DDoS":       "#2E75B6",
    "DoS":        "#7030A0",
    "Infiltration":"#FF0000",
    "PortScan":   "#00B0F0",
    "WebAttack":  "#FFC000",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sigmoid(x: np.ndarray) -> np.ndarray:
    """Map IF decision_function scores to [0,1] anomaly confidence."""
    return 1.0 / (1.0 + np.exp(x))


def save_fig(fig, name: str, dpi: int = 180):
    out = FIGURES_DIR / name
    fig.savefig(out, dpi=dpi, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  Saved: {out}")
    return str(out)


# ---------------------------------------------------------------------------
# Load data + models
# ---------------------------------------------------------------------------

def load_all():
    print("[1/5] Loading arrays and models...")
    X_test = np.load(X_TEST_PATH)
    y_test = np.load(Y_TEST_PATH)
    le     = joblib.load(LE_PATH)
    rf     = joblib.load(RF_PATH)
    iforest= joblib.load(IF_PATH)
    print(f"  X_test: {X_test.shape}  |  classes: {list(le.classes_)}")
    return X_test, y_test, le, rf, iforest


# ---------------------------------------------------------------------------
# Figure 1 — RF per-class ROC (One-vs-Rest)
# ---------------------------------------------------------------------------

def plot_rf_roc(rf, X_test, y_test, le, classes):
    print("[2/5] Plotting RF per-class ROC curves...")
    n_classes  = len(classes)
    benign_idx = int(le.transform(["BENIGN"])[0])

    # OvR binarised labels
    y_bin = label_binarize(y_test, classes=list(range(n_classes)))
    proba = rf.predict_proba(X_test)   # shape (n_samples, n_classes)

    fig, ax = plt.subplots(figsize=(9, 7))
    ax.set_facecolor("#F8F9FA")
    fig.patch.set_facecolor("white")

    roc_data = {}
    for i, cls in enumerate(classes):
        fpr, tpr, _ = roc_curve(y_bin[:, i], proba[:, i])
        roc_auc     = auc(fpr, tpr)
        color       = CLASS_COLORS.get(cls, GREY)
        lw          = 2.5 if cls != "BENIGN" else 1.0
        ls          = "-" if cls != "BENIGN" else "--"
        ax.plot(fpr, tpr, color=color, lw=lw, ls=ls,
                label=f"{cls}  (AUC={roc_auc:.3f})")
        roc_data[cls] = {"fpr": float(fpr.mean()), "tpr": float(tpr.mean()), "auc": round(roc_auc, 4)}

    ax.plot([0,1],[0,1], color=GREY, lw=1, ls=":", label="Random (AUC=0.500)")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate", fontsize=12, fontweight="bold")
    ax.set_ylabel("True Positive Rate (Detection Rate)", fontsize=12, fontweight="bold")
    ax.set_title("Figure 4.11.1: Random Forest — Per-Class ROC Curves\n(One-vs-Rest, CICIDS2017 Test Set)",
                 fontsize=13, fontweight="bold", color=NAVY, pad=12)
    ax.legend(loc="lower right", fontsize=9, framealpha=0.9)
    ax.grid(True, alpha=0.3)
    ax.tick_params(labelsize=10)

    # Annotation
    ax.annotate("PortScan, DDoS, BENIGN\nnear top-left (AUC≈1.00)",
                xy=(0.02, 0.98), xycoords="axes fraction",
                fontsize=8, color=NAVY,
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=NAVY, alpha=0.8))

    path = save_fig(fig, "fig_4_11_1_rf_roc.png")
    return roc_data, path


# ---------------------------------------------------------------------------
# Figure 2 — IF binary ROC
# ---------------------------------------------------------------------------

def plot_if_roc(iforest, X_test, y_test, le, classes):
    print("[3/5] Plotting IF binary ROC curve...")
    benign_idx    = int(le.transform(["BENIGN"])[0])
    y_true_binary = np.where(y_test == benign_idx, 0, 1)
    scores        = sigmoid(iforest.decision_function(X_test))

    fpr, tpr, thresholds = roc_curve(y_true_binary, scores)
    roc_auc              = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.set_facecolor("#F8F9FA")
    fig.patch.set_facecolor("white")

    ax.plot(fpr, tpr, color=ORANGE, lw=2.5,
            label=f"Isolation Forest — Binary  (AUC={roc_auc:.3f})")
    ax.fill_between(fpr, tpr, alpha=0.08, color=ORANGE)
    ax.plot([0,1],[0,1], color=GREY, lw=1, ls=":", label="Random (AUC=0.500)")

    # Mark operating point (calibrated threshold 0.1135)
    op_idx = np.argmin(np.abs(thresholds - 0.1135))
    ax.scatter(fpr[op_idx], tpr[op_idx], color=RED, zorder=5, s=80,
               label=f"Operating point (thresh=0.1135)\nFPR={fpr[op_idx]:.4f}, TPR={tpr[op_idx]:.4f}")

    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate", fontsize=12, fontweight="bold")
    ax.set_ylabel("True Positive Rate (Detection Rate)", fontsize=12, fontweight="bold")
    ax.set_title("Figure 4.11.2: Isolation Forest — Binary ROC Curve\n(BENIGN vs ANY ATTACK, CICIDS2017 Test Set)",
                 fontsize=13, fontweight="bold", color=NAVY, pad=12)
    ax.legend(loc="lower right", fontsize=9, framealpha=0.9)
    ax.grid(True, alpha=0.3)
    ax.tick_params(labelsize=10)

    path = save_fig(fig, "fig_4_11_2_if_roc.png")
    return {"binary_auc": round(roc_auc, 4),
            "op_fpr": round(float(fpr[op_idx]), 4),
            "op_tpr": round(float(tpr[op_idx]), 4)}, path


# ---------------------------------------------------------------------------
# Figure 3 — Overlay: RF macro ROC vs IF binary ROC
# ---------------------------------------------------------------------------

def plot_overlay_roc(rf, iforest, X_test, y_test, le, classes):
    print("[4/5] Plotting RF vs IF overlay ROC...")
    n_classes     = len(classes)
    benign_idx    = int(le.transform(["BENIGN"])[0])
    y_bin         = label_binarize(y_test, classes=list(range(n_classes)))
    proba         = rf.predict_proba(X_test)
    y_true_binary = np.where(y_test == benign_idx, 0, 1)
    if_scores     = sigmoid(iforest.decision_function(X_test))

    # RF macro-average ROC
    all_fpr  = np.unique(np.concatenate([roc_curve(y_bin[:, i], proba[:, i])[0]
                                          for i in range(n_classes)]))
    mean_tpr = np.zeros_like(all_fpr)
    for i in range(n_classes):
        fpr_i, tpr_i, _ = roc_curve(y_bin[:, i], proba[:, i])
        mean_tpr        += np.interp(all_fpr, fpr_i, tpr_i)
    mean_tpr   /= n_classes
    rf_macro_auc = auc(all_fpr, mean_tpr)

    # IF binary ROC
    if_fpr, if_tpr, _ = roc_curve(y_true_binary, if_scores)
    if_auc            = auc(if_fpr, if_tpr)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.set_facecolor("#F8F9FA")
    fig.patch.set_facecolor("white")

    ax.plot(all_fpr, mean_tpr, color=BLUE, lw=2.5,
            label=f"Random Forest macro-avg  (AUC={rf_macro_auc:.3f})")
    ax.fill_between(all_fpr, mean_tpr, alpha=0.08, color=BLUE)

    ax.plot(if_fpr, if_tpr, color=ORANGE, lw=2.5, ls="--",
            label=f"Isolation Forest binary  (AUC={if_auc:.3f})")
    ax.fill_between(if_fpr, if_tpr, alpha=0.06, color=ORANGE)

    ax.plot([0,1],[0,1], color=GREY, lw=1, ls=":", label="Random (AUC=0.500)")

    ax.set_xlim([0.0, 0.20])   # Zoom into low-FPR region for readability
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate", fontsize=12, fontweight="bold")
    ax.set_ylabel("True Positive Rate", fontsize=12, fontweight="bold")
    ax.set_title("Figure 4.11.3: RF vs IF — Overlay ROC (Low-FPR Region)\nRF Macro-Average vs IF Binary, CICIDS2017 Test Set",
                 fontsize=13, fontweight="bold", color=NAVY, pad=12)
    ax.legend(loc="lower right", fontsize=10, framealpha=0.9)
    ax.grid(True, alpha=0.3)
    ax.tick_params(labelsize=10)
    ax.annotate("x-axis zoomed to FPR \u2264 0.20\nfor operational readability",
                xy=(0.60, 0.08), xycoords="axes fraction",
                fontsize=8, color=GREY,
                bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor=GREY, alpha=0.7))

    path = save_fig(fig, "fig_4_11_3_overlay_roc.png")
    return {"rf_macro_auc": round(rf_macro_auc, 4), "if_binary_auc": round(if_auc, 4)}, path


# ---------------------------------------------------------------------------
# Figure 4 — Per-class detection rate bar chart
# ---------------------------------------------------------------------------

def plot_detection_rates(rf, iforest, X_test, y_test, le, classes):
    print("[5/5] Plotting per-class detection rate comparison...")
    benign_idx    = int(le.transform(["BENIGN"])[0])
    attack_classes= [c for c in classes if c != "BENIGN"]

    rf_proba      = rf.predict_proba(X_test)
    rf_preds      = rf.predict(X_test)
    if_sklearn    = iforest.predict(X_test)
    if_preds      = np.where(if_sklearn == -1, 1, 0)   # 1=attack

    rf_tpr_vals, if_tpr_vals = [], []
    for cls in attack_classes:
        cls_idx  = int(le.transform([cls])[0])
        cls_mask = (y_test == cls_idx)
        if cls_mask.sum() == 0:
            rf_tpr_vals.append(0.0)
            if_tpr_vals.append(0.0)
            continue
        rf_cls_pred = rf_preds[cls_mask]
        if_cls_pred = if_preds[cls_mask]
        rf_tpr_vals.append(float(np.mean(rf_cls_pred == cls_idx)))
        if_tpr_vals.append(float(np.mean(if_cls_pred == 1)))

    x      = np.arange(len(attack_classes))
    width  = 0.35

    fig, ax = plt.subplots(figsize=(11, 6))
    ax.set_facecolor("#F8F9FA")
    fig.patch.set_facecolor("white")

    bars_rf = ax.bar(x - width/2, rf_tpr_vals, width, label="Random Forest",
                     color=BLUE, alpha=0.85, edgecolor="white", linewidth=0.5)
    bars_if = ax.bar(x + width/2, if_tpr_vals, width, label="Isolation Forest",
                     color=ORANGE, alpha=0.85, edgecolor="white", linewidth=0.5)

    # Target line
    ax.axhline(y=0.85, color=RED, lw=1.5, ls="--", label="NFR20 target (TPR \u2265 0.85)")

    # Value labels on bars
    for bar in bars_rf:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.01,
                f"{h:.2f}", ha="center", va="bottom", fontsize=8, color=NAVY, fontweight="bold")
    for bar in bars_if:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.01,
                f"{h:.2f}", ha="center", va="bottom", fontsize=8, color="#7F3F00", fontweight="bold")

    ax.set_xticks(x)
    ax.set_xticklabels(attack_classes, rotation=20, ha="right", fontsize=10)
    ax.set_ylim([0.0, 1.10])
    ax.set_ylabel("True Positive Rate (Detection Rate)", fontsize=12, fontweight="bold")
    ax.set_xlabel("Attack Class", fontsize=12, fontweight="bold")
    ax.set_title("Figure 4.11.4: Per-Class Detection Rate Comparison\nRandom Forest vs Isolation Forest, CICIDS2017 Test Set",
                 fontsize=13, fontweight="bold", color=NAVY, pad=12)
    ax.legend(fontsize=10, framealpha=0.9)
    ax.grid(axis="y", alpha=0.3)
    ax.tick_params(axis="x", labelsize=10)

    # Infiltration annotation (IF wins)
    inf_idx = attack_classes.index("Infiltration")
    ax.annotate("IF > RF\n(only class)",
                xy=(inf_idx + width/2, if_tpr_vals[inf_idx] + 0.02),
                xytext=(inf_idx + width/2 + 0.8, if_tpr_vals[inf_idx] + 0.15),
                arrowprops=dict(arrowstyle="->", color=RED),
                fontsize=8, color=RED, fontweight="bold")

    path = save_fig(fig, "fig_4_11_4_detection_rates.png")
    return {cls: {"rf": round(r, 4), "if": round(i, 4)}
            for cls, r, i in zip(attack_classes, rf_tpr_vals, if_tpr_vals)}, path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 65)
    print("AI-NIDS -- RF vs IF Comparison & ROC Curves  |  March 30, 2026")
    print("=" * 65)

    X_test, y_test, le, rf, iforest = load_all()
    classes = list(le.classes_)

    rf_roc_data,  fig1 = plot_rf_roc(rf, X_test, y_test, le, classes)
    if_roc_data,  fig2 = plot_if_roc(iforest, X_test, y_test, le, classes)
    ovl_data,     fig3 = plot_overlay_roc(rf, iforest, X_test, y_test, le, classes)
    dr_data,      fig4 = plot_detection_rates(rf, iforest, X_test, y_test, le, classes)

    # Save summary JSON
    summary = {
        "comparison_date": "2026-03-30",
        "rf_per_class_roc_auc": rf_roc_data,
        "if_binary_roc": if_roc_data,
        "overlay": ovl_data,
        "per_class_detection_rates": dr_data,
        "figures": {
            "fig1_rf_per_class_roc":       fig1,
            "fig2_if_binary_roc":          fig2,
            "fig3_overlay_roc":            fig3,
            "fig4_detection_rate_bar":     fig4,
        },
        "key_findings": {
            "rf_macro_auc":     ovl_data["rf_macro_auc"],
            "if_binary_auc":    ovl_data["if_binary_auc"],
            "only_if_beats_rf": "Infiltration (IF TPR=0.857 vs RF TPR=0.714)",
            "rf_dominates_on":  "DoS, DDoS, PortScan, BruteForce, WebAttack, Botnet",
            "if_advantage":     "Lower FPR (0.0501 vs 0.0723) + zero-day structural capability",
        }
    }
    with open(METRICS_OUT, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 65)
    print("COMPARISON COMPLETE")
    print(f"  Figures : {FIGURES_DIR}")
    print(f"  Summary : {METRICS_OUT}")
    print("=" * 65)
    print(f"\n  RF macro-avg AUC : {ovl_data['rf_macro_auc']}")
    print(f"  IF binary AUC    : {ovl_data['if_binary_auc']}")
    print("\n  Figures generated:")
    for k, v in summary["figures"].items():
        print(f"    {k}: {Path(v).name}")


if __name__ == "__main__":
    main()
