"""
AI-NIDS — LSTM Sequential Classifier Training  (PyTorch rewrite)
ml/train_lstm.py

Architecture:
    Input  → LSTM(64, return_sequences=True) → Dropout(0.3)
           → LSTM(64)                         → Dropout(0.3)
           → Dense(8, softmax)

Training:
    Optimizer   : Adam(lr=0.001)
    Batch size  : 64
    Epochs      : 50 max (early stopping patience=5 on val_loss)
    Val split   : 15% of training sequences

Outputs:
    models/lstm_model.pt           — saved PyTorch model (state_dict)
    models/lstm_model_full.pt      — full model (backup)
    ml/lstm_metrics.json           — full evaluation metrics + per-class stats

FR Traceability:
    FR5.3  — LSTM sequential model
    FR5.4  — Load pre-trained models at startup
    FR5.5  — Attack classification (8 categories)
    FR5.6  — Confidence score (0.0–1.0) via softmax probabilities
    NFR20.1 — ≥95% accuracy on CICIDS2017 test set
    NFR20.2 — ≤5% FPR

March 2026 | Sprint 2 Week 6 | Developer: GWAGSI Rawlings Nshom
"""

import json
import os
import sys
import time

import numpy as np
import torch
import torch.nn
import torch.utils.data

# ── Config ────────────────────────────────────────────────────────────────
WINDOW        = 10
NUM_FEATURES  = 41
NUM_CLASSES   = 8
LSTM_UNITS    = 64
DROPOUT       = 0.3
BATCH_SIZE    = 64
EPOCHS        = 50
PATIENCE      = 5        # early stopping patience on val_loss
VAL_SPLIT     = 0.15     # fraction of training sequences for validation
LEARNING_RATE = 0.001

BASE_DIR    = os.path.expanduser("~/ai-nids/backend/detection/ml/processed")
MODELS_DIR  = os.path.expanduser("~/ai-nids/backend/detection/models")

SEQ_TRAIN_X = os.path.join(BASE_DIR, "X_lstm_train.npy")
SEQ_TRAIN_Y = os.path.join(BASE_DIR, "y_lstm_train.npy")
SEQ_TEST_X  = os.path.join(BASE_DIR, "X_lstm_test.npy")
SEQ_TEST_Y  = os.path.join(BASE_DIR, "y_lstm_test.npy")

MODEL_PT     = os.path.join(MODELS_DIR, "lstm_model.pt")
MODEL_FULL   = os.path.join(MODELS_DIR, "lstm_model_full.pt")
METRICS_FILE = os.path.join(BASE_DIR,   "lstm_metrics.json")

CLASS_NAMES = [
    "BENIGN", "Botnet", "BruteForce", "DDoS",
    "DoS", "Infiltration", "PortScan", "WebAttack"
]


# ── Model ─────────────────────────────────────────────────────────────────

class LSTMClassifier(torch.nn.Module):
    """
    2-layer stacked LSTM with dropout between layers.
    Input shape : (batch, window, features) = (batch, 10, 41)
    Output      : log-softmax over num_classes
    """
    def __init__(self, window: int, features: int, num_classes: int,
                 lstm_units: int, dropout: float):
        super().__init__()
        self.lstm1 = torch.nn.LSTM(features, lstm_units,
                                   batch_first=True)
        self.drop1 = torch.nn.Dropout(dropout)
        self.lstm2 = torch.nn.LSTM(lstm_units, lstm_units,
                                   batch_first=True)
        self.drop2 = torch.nn.Dropout(dropout)
        self.fc    = torch.nn.Linear(lstm_units, num_classes)

    def forward(self, x):
        # x: (batch, window, features)
        out, _ = self.lstm1(x)          # (batch, window, lstm_units)
        out    = self.drop1(out)
        out, _ = self.lstm2(out)        # (batch, window, lstm_units)
        out    = out[:, -1, :]          # take last time-step → (batch, lstm_units)
        out    = self.drop2(out)
        out    = self.fc(out)           # (batch, num_classes)
        return out                      # raw logits; use CrossEntropyLoss


def build_model(window, features, num_classes):
    model = LSTMClassifier(window, features, num_classes, LSTM_UNITS, DROPOUT)
    return model


# ── Dataset ───────────────────────────────────────────────────────────────

class SequenceDataset(torch.utils.data.Dataset):
    def __init__(self, X: np.ndarray, y: np.ndarray):
        self.X = torch.from_numpy(X.astype(np.float32))
        self.y = torch.from_numpy(y.astype(np.int64))

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


# ── Evaluation helpers ────────────────────────────────────────────────────

def compute_metrics(y_true: np.ndarray, y_pred_proba: np.ndarray) -> dict:
    """
    Compute accuracy, macro F1, per-class precision/recall/F1, FPR.
    Uses only numpy — no sklearn dependency at runtime.
    """
    y_pred = np.argmax(y_pred_proba, axis=1)
    n = len(y_true)

    cm = np.zeros((NUM_CLASSES, NUM_CLASSES), dtype=np.int64)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1

    accuracy = float(np.trace(cm)) / n

    per_class = {}
    precisions, recalls, f1s = [], [], []

    for c in range(NUM_CLASSES):
        tp = int(cm[c, c])
        fp = int(cm[:, c].sum()) - tp
        fn = int(cm[c, :].sum()) - tp
        tn = int(cm.sum()) - tp - fp - fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) > 0 else 0.0)
        fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        per_class[CLASS_NAMES[c]] = {
            "precision": round(precision, 4),
            "recall":    round(recall,    4),
            "f1":        round(f1,        4),
            "fpr":       round(fpr,       4),
            "support":   int(cm[c, :].sum()),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }
        precisions.append(precision)
        recalls.append(recall)
        f1s.append(f1)

    macro_precision = float(np.mean(precisions))
    macro_recall    = float(np.mean(recalls))
    macro_f1        = float(np.mean(f1s))

    benign_idx     = CLASS_NAMES.index("BENIGN")
    benign_total   = int(cm[benign_idx, :].sum())
    benign_correct = int(cm[benign_idx, benign_idx])
    fpr_overall    = (benign_total - benign_correct) / benign_total if benign_total > 0 else 0.0

    return {
        "accuracy":        round(accuracy, 4),
        "macro_precision": round(macro_precision, 4),
        "macro_recall":    round(macro_recall,    4),
        "macro_f1":        round(macro_f1,        4),
        "fpr_overall":     round(fpr_overall,     4),
        "per_class":       per_class,
        "confusion_matrix": cm.tolist(),
    }


def nfr20_assessment(metrics: dict) -> dict:
    return {
        "NFR20.1_accuracy_ge_0.95":   metrics["accuracy"]        >= 0.95,
        "NFR20.1_macro_f1_ge_0.95":   metrics["macro_f1"]        >= 0.95,
        "NFR20.2_fpr_le_0.05":        metrics["fpr_overall"]     <= 0.05,
        "NFR20.3_precision_ge_0.90":  metrics["macro_precision"] >= 0.90,
        "NFR20.4_recall_ge_0.90":     metrics["macro_recall"]    >= 0.90,
    }


# ── Training loop ─────────────────────────────────────────────────────────

def train_one_epoch(model, loader, criterion, optimizer, device):
    model.train()
    total_loss, correct, total = 0.0, 0, 0
    for X_batch, y_batch in loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)
        optimizer.zero_grad()
        logits = model(X_batch)
        loss   = criterion(logits, y_batch)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * len(y_batch)
        correct    += (logits.argmax(1) == y_batch).sum().item()
        total      += len(y_batch)
    return total_loss / total, correct / total


@torch.no_grad()
def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss, correct, total = 0.0, 0, 0
    for X_batch, y_batch in loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)
        logits = model(X_batch)
        loss   = criterion(logits, y_batch)
        total_loss += loss.item() * len(y_batch)
        correct    += (logits.argmax(1) == y_batch).sum().item()
        total      += len(y_batch)
    return total_loss / total, correct / total


@torch.no_grad()
def predict_proba(model, loader, device) -> np.ndarray:
    model.eval()
    all_probs = []
    for X_batch, _ in loader:
        X_batch = X_batch.to(device)
        logits  = model(X_batch)
        probs   = torch.softmax(logits, dim=1).cpu().numpy()
        all_probs.append(probs)
    return np.concatenate(all_probs, axis=0)


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 60)
    print("AI-NIDS — LSTM Sequential Classifier Training")
    print("=" * 60)

    # ── Validate inputs ───────────────────────────────────────
    for p in [SEQ_TRAIN_X, SEQ_TRAIN_Y, SEQ_TEST_X, SEQ_TEST_Y]:
        if not os.path.exists(p):
            print(f"[ERROR] Required file not found: {p}")
            print("  Run: python ml/prepare_lstm_sequences.py  first.")
            sys.exit(1)

    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── PyTorch ───────────────────────────────────────────────
    print("\nImporting PyTorch...")
    torch.manual_seed(42)
    device = torch.device("cpu")   # Pentium Silver N5030 — CPU only
    print(f"  PyTorch version : {torch.__version__}")
    print(f"  Device          : {device}")

    # ── Load sequence arrays ──────────────────────────────────
    print("\nLoading sequence arrays...")
    X_train_full = np.load(SEQ_TRAIN_X)    # (N, 10, 41) float32
    y_train_full = np.load(SEQ_TRAIN_Y)    # (N,) int8
    X_test       = np.load(SEQ_TEST_X)
    y_test       = np.load(SEQ_TEST_Y)

    print(f"  X_train: {X_train_full.shape}  y_train: {y_train_full.shape}")
    print(f"  X_test:  {X_test.shape}         y_test:  {y_test.shape}")

    assert X_train_full.shape[1:] == (WINDOW, NUM_FEATURES), \
        f"Expected sequence shape ({WINDOW}, {NUM_FEATURES}), got {X_train_full.shape[1:]}"

    # ── Class distribution ────────────────────────────────────
    print("\nTraining set class distribution:")
    for c, name in enumerate(CLASS_NAMES):
        count = int(np.sum(y_train_full == c))
        pct   = 100 * count / len(y_train_full)
        print(f"  {c:2d} {name:<14} {count:>9,}  ({pct:.2f}%)")

    # ── Val split ─────────────────────────────────────────────
    n_total = len(X_train_full)
    n_val   = int(n_total * VAL_SPLIT)
    n_train = n_total - n_val

    # Shuffle before splitting
    rng  = np.random.default_rng(42)
    idx  = rng.permutation(n_total)
    X_tr = X_train_full[idx[:n_train]]
    y_tr = y_train_full[idx[:n_train]]
    X_vl = X_train_full[idx[n_train:]]
    y_vl = y_train_full[idx[n_train:]]

    print(f"\n  Train sequences : {n_train:,}")
    print(f"  Val sequences   : {n_val:,}")

    # ── Class weights ─────────────────────────────────────────
    raw_counts   = {c: int(np.sum(y_tr == c)) for c in range(NUM_CLASSES)}
    benign_count = raw_counts[CLASS_NAMES.index("BENIGN")]
    raw_weights  = {c: benign_count / max(raw_counts[c], 1) for c in range(NUM_CLASSES)}

    WEIGHT_CAPS = {
        CLASS_NAMES.index("Botnet"):       150.0,
        CLASS_NAMES.index("WebAttack"):    150.0,
        CLASS_NAMES.index("BruteForce"):    50.0,
        CLASS_NAMES.index("Infiltration"): 200.0,
    }
    class_weights = {
        c: min(raw_weights[c], WEIGHT_CAPS.get(c, raw_weights[c]))
        for c in range(NUM_CLASSES)
    }

    print("\nClass weights (capped):")
    for c, name in enumerate(CLASS_NAMES):
        print(f"  {name:<14} raw={raw_weights[c]:.1f}  capped={class_weights[c]:.1f}")

    weight_tensor = torch.tensor(
        [class_weights[c] for c in range(NUM_CLASSES)],
        dtype=torch.float32, device=device
    )

    # ── DataLoaders ───────────────────────────────────────────
    train_ds = SequenceDataset(X_tr, y_tr)
    val_ds   = SequenceDataset(X_vl, y_vl)
    test_ds  = SequenceDataset(X_test, y_test)

    train_loader = torch.utils.data.DataLoader(
        train_ds, batch_size=BATCH_SIZE, shuffle=True,
        num_workers=0, pin_memory=False
    )
    val_loader = torch.utils.data.DataLoader(
        val_ds, batch_size=512, shuffle=False,
        num_workers=0, pin_memory=False
    )
    test_loader = torch.utils.data.DataLoader(
        test_ds, batch_size=512, shuffle=False,
        num_workers=0, pin_memory=False
    )

    # ── Build model ───────────────────────────────────────────
    print("\nBuilding LSTM model...")
    model = build_model(WINDOW, NUM_FEATURES, NUM_CLASSES).to(device)

    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Total parameters : {total_params:,}")
    print(f"  Architecture     : LSTM({LSTM_UNITS}) → Drop({DROPOUT})"
          f" → LSTM({LSTM_UNITS}) → Drop({DROPOUT}) → Linear({NUM_CLASSES})")

    criterion = torch.nn.CrossEntropyLoss(weight=weight_tensor)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=3, min_lr=1e-6
    )

    # ── Training loop ─────────────────────────────────────────
    print(f"\nTraining — epochs={EPOCHS}, batch={BATCH_SIZE}, "
          f"val_split={VAL_SPLIT}, patience={PATIENCE}")

    best_val_loss   = float("inf")
    best_state      = None
    patience_count  = 0
    history         = {"loss": [], "val_loss": [], "accuracy": [], "val_accuracy": []}

    t_train = time.time()

    for epoch in range(1, EPOCHS + 1):
        tr_loss, tr_acc = train_one_epoch(model, train_loader, criterion, optimizer, device)
        vl_loss, vl_acc = evaluate(model, val_loader, criterion, device)
        scheduler.step(vl_loss)

        history["loss"].append(round(tr_loss, 6))
        history["val_loss"].append(round(vl_loss, 6))
        history["accuracy"].append(round(tr_acc, 6))
        history["val_accuracy"].append(round(vl_acc, 6))

        print(f"  Epoch {epoch:3d}/{EPOCHS}  "
              f"loss={tr_loss:.4f}  acc={tr_acc:.4f}  "
              f"val_loss={vl_loss:.4f}  val_acc={vl_acc:.4f}")

        # Early stopping + checkpoint
        if vl_loss < best_val_loss:
            best_val_loss  = vl_loss
            best_state     = {k: v.cpu().clone() for k, v in model.state_dict().items()}
            patience_count = 0
            torch.save(best_state, MODEL_PT)
            print(f"    ✓ Best val_loss={best_val_loss:.4f} — checkpoint saved")
        else:
            patience_count += 1
            if patience_count >= PATIENCE:
                print(f"\n  Early stopping triggered after {epoch} epochs "
                      f"(no improvement for {PATIENCE} epochs).")
                break

    train_time  = round(time.time() - t_train, 1)
    epochs_ran  = len(history["loss"])
    print(f"\nTraining complete in {train_time:.1f} s "
          f"({train_time/60:.1f} min) — {epochs_ran} epochs ran.")

    # Restore best weights
    model.load_state_dict(best_state)

    # ── Evaluate on test set ──────────────────────────────────
    print("\nEvaluating on held-out test set...")
    t_inf = time.time()
    y_pred_proba = predict_proba(model, test_loader, device)
    inf_time_total  = time.time() - t_inf
    inf_ms_per_seq  = (inf_time_total / len(X_test)) * 1000

    metrics = compute_metrics(y_test, y_pred_proba)
    nfr     = nfr20_assessment(metrics)

    # ── Print results ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS (CICIDS2017 test set)")
    print("=" * 60)
    print(f"  Accuracy        : {metrics['accuracy']:.4f}  "
          f"{'✓' if nfr['NFR20.1_accuracy_ge_0.95'] else '✗'}  target ≥0.95")
    print(f"  Macro F1        : {metrics['macro_f1']:.4f}  "
          f"{'✓' if nfr['NFR20.1_macro_f1_ge_0.95'] else '✗'}  target ≥0.95")
    print(f"  Macro Precision : {metrics['macro_precision']:.4f}  "
          f"{'✓' if nfr['NFR20.3_precision_ge_0.90'] else '✗'}  target ≥0.90")
    print(f"  Macro Recall    : {metrics['macro_recall']:.4f}  "
          f"{'✓' if nfr['NFR20.4_recall_ge_0.90'] else '✗'}  target ≥0.90")
    print(f"  FPR (overall)   : {metrics['fpr_overall']:.4f}  "
          f"{'✓' if nfr['NFR20.2_fpr_le_0.05'] else '✗'}  target ≤0.05")
    print(f"  Inf latency/seq : {inf_ms_per_seq:.4f} ms  (target ≤50 ms)")
    print()
    print(f"  {'Class':<14}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}  "
          f"{'FPR':>6}  {'Support':>9}")
    print(f"  {'-'*14}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*9}")
    for name in CLASS_NAMES:
        pc = metrics["per_class"][name]
        print(f"  {name:<14}  {pc['precision']:>6.4f}  {pc['recall']:>6.4f}  "
              f"{pc['f1']:>6.4f}  {pc['fpr']:>6.4f}  {pc['support']:>9,}")

    # ── Per-class TPR vs RF / IF baselines ───────────────────
    # RF baselines from §4.8.3.1, IF baselines from §4.9.3.2
    RF_TPR = {
        "BENIGN":      0.9281, "Botnet":       0.8703, "BruteForce":  0.9892,
        "DDoS":        0.9998, "DoS":          0.9953, "Infiltration":0.7143,
        "PortScan":    1.0000, "WebAttack":    0.9083,
    }
    IF_TPR = {
        "BENIGN":      None,   "Botnet":       0.0127, "BruteForce":  0.0000,
        "DDoS":        0.0000, "DoS":          0.1772, "Infiltration":0.0000,
        "PortScan":    0.0002, "WebAttack":    0.0000,
    }

    cm_arr = np.array(metrics["confusion_matrix"])
    print("\n" + "=" * 60)
    print("PER-CLASS TPR  —  LSTM vs RF vs IF")
    print("=" * 60)
    print(f"  {'Class':<15} {'LSTM TPR':>10} {'RF TPR':>10} {'IF TPR':>10} {'Target':>8}")
    print("  " + "-" * 57)
    per_class_tpr = {}
    for i, name in enumerate(CLASS_NAMES):
        row_total = int(cm_arr[i].sum())
        tpr = cm_arr[i, i] / row_total if row_total > 0 else 0.0
        per_class_tpr[name] = round(float(tpr), 4)
        rf_str = f"{RF_TPR[name]:.4f}" if RF_TPR.get(name) is not None else "  —   "
        if_str = f"{IF_TPR[name]:.4f}" if IF_TPR.get(name) is not None else "  —   "
        tgt    = "FPR" if name == "BENIGN" else "≥0.85"
        print(f"  {name:<15} {tpr:>10.4f} {rf_str:>10} {if_str:>10} {tgt:>8}")

    # ── Latency benchmark — single-sequence (live pipeline) ──
    print("\n" + "=" * 60)
    print("SINGLE-SEQUENCE LATENCY BENCHMARK  (200 reps)")
    print("=" * 60)
    model.eval()
    dummy = torch.zeros(1, WINDOW, NUM_FEATURES, dtype=torch.float32)
    # warm-up
    with torch.no_grad():
        for _ in range(5):
            _ = model(dummy)
    latencies = []
    with torch.no_grad():
        for _ in range(200):
            t_s = time.perf_counter()
            model(dummy)
            latencies.append((time.perf_counter() - t_s) * 1000)
    lat_mean = float(np.mean(latencies))
    lat_p95  = float(np.percentile(latencies, 95))
    lat_p99  = float(np.percentile(latencies, 99))
    print(f"  Mean latency : {lat_mean:.2f} ms")
    print(f"  P95 latency  : {lat_p95:.2f} ms  "
          f"{'✓ PASS' if lat_p95 <= 50 else '✗ FAIL — exceeds 50 ms target'}")
    print(f"  P99 latency  : {lat_p99:.2f} ms")
    print("  Target       : ≤50 ms (NFR G-03)")

    # ── LSTM vs RF vs IF summary table ────────────────────────
    print("\n" + "=" * 60)
    print("THREE-MODEL COMPARISON  —  LSTM  vs  RF  vs  IF")
    print("=" * 60)
    wt_f1 = float(np.average(
        [metrics["per_class"][n]["f1"] for n in CLASS_NAMES],
        weights=[metrics["per_class"][n]["support"] for n in CLASS_NAMES]
    ))
    print(f"  {'Metric':<30} {'LSTM':>10} {'RF (tuned)':>12} {'IF':>10}")
    print("  " + "-" * 65)
    comparison = [
        ("Accuracy",          metrics["accuracy"],        0.9867, 0.8312),
        ("Macro F1",          metrics["macro_f1"],        0.8911, 0.4475),
        ("Macro Precision",   metrics["macro_precision"], 0.8800, None  ),
        ("Macro Recall",      metrics["macro_recall"],    0.9100, None  ),
        ("FPR (overall)",     metrics["fpr_overall"],     0.0114, 0.0100),
        ("Weighted F1",       wt_f1,                      0.9867, None  ),
        ("Lat P95 (ms)",      lat_p95,                    0.033,  0.335 ),
    ]
    for row_name, lstm_v, rf_v, if_v in comparison:
        rf_str = f"{rf_v:.4f}" if rf_v is not None else "     —"
        if_str = f"{if_v:.4f}" if if_v is not None else "     —"
        print(f"  {row_name:<30} {lstm_v:>10.4f} {rf_str:>12} {if_str:>10}")

    print("""
  Coverage assessment:
    RF   → supervised multiclass; strong on known attacks (TPR 0.87–1.00)
    IF   → zero-day coverage; lowest FPR of all three models
    LSTM → temporal sequences; captures flow-sequence patterns

  Ensemble weights (design §4.11): Sig=0.40  RF=0.35  LSTM=0.15  IF=0.10
""")

    # ── Save full model ───────────────────────────────────────
    try:
        torch.save(model, MODEL_FULL)
        print(f"\nModel saved (full):        {MODEL_FULL}")
    except Exception as e:
        print(f"\n[WARN] Could not save full model: {e}")

    print(f"Model saved (state_dict):  {MODEL_PT}")

    # ── Save metrics JSON ─────────────────────────────────────
    elapsed = round(time.time() - t0, 1)
    output = {
        "model": "LSTM",
        "framework": f"PyTorch {torch.__version__}",
        "architecture": {
            "layers": "2-layer stacked LSTM",
            "lstm_units": LSTM_UNITS,
            "dropout": DROPOUT,
            "output_activation": "softmax",
            "num_classes": NUM_CLASSES,
            "input_shape": [WINDOW, NUM_FEATURES],
        },
        "training": {
            "optimizer": "Adam",
            "learning_rate": LEARNING_RATE,
            "batch_size": BATCH_SIZE,
            "max_epochs": EPOCHS,
            "early_stopping_patience": PATIENCE,
            "epochs_ran": epochs_ran,
            "val_split": VAL_SPLIT,
            "training_sequences": int(n_train),
            "train_time_seconds": train_time,
        },
        "evaluation": {
            "test_sequences": int(len(X_test)),
            "inference_latency_ms_per_seq": round(inf_ms_per_seq, 4),
            "lat_mean_ms":  round(lat_mean, 2),
            "lat_p95_ms":   round(lat_p95,  2),
            "lat_p99_ms":   round(lat_p99,  2),
            "weighted_f1":  round(wt_f1,    4),
            "per_class_tpr": per_class_tpr,
            **metrics,
        },
        "nfr20_assessment": nfr,
        "model_files": {
            "state_dict": MODEL_PT,
            "full_model": MODEL_FULL,
        },
        "total_elapsed_seconds": elapsed,
        "training_history": history,
    }

    with open(METRICS_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Metrics saved: {METRICS_FILE}")

    # ── Final summary ─────────────────────────────────────────
    all_pass = all(nfr.values())
    print("\n" + "=" * 60)
    print(f"TRAINING COMPLETE — "
          f"{'ALL NFR20 TARGETS MET ✓' if all_pass else 'SOME TARGETS MISSED — see §4.10 analysis'}")
    print(f"Total elapsed: {elapsed:.1f} s ({elapsed/60:.1f} min)")
    print("=" * 60)
    print("\nNext step: paste terminal output → Claude generates §4.10 .docx")


if __name__ == "__main__":
    main()
