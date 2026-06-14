"""
AI-NIDS — LSTM Sequence Preparation
ml/prepare_lstm_sequences.py

Builds 10-flow sliding window sequences from preprocessed CICIDS2017 arrays.
Uses positional grouping: consecutive rows within each class are treated as
belonging to the same 'source'. This is the standard academic benchmark approach
when src_ip is not available in the feature array.

Strategy:
    For each class label c:
        rows = X[y == c]                         # all rows of class c
        for i in range(0, len(rows) - WINDOW + 1, STRIDE):
            sequence = rows[i : i + WINDOW]      # shape (10, 41)
            label    = c
        → append to sequences list

Output:
    ml/X_lstm_train.npy   shape (N_train_seqs, 10, 41)  float32
    ml/y_lstm_train.npy   shape (N_train_seqs,)          int8
    ml/X_lstm_test.npy    shape (N_test_seqs,  10, 41)  float32
    ml/y_lstm_test.npy    shape (N_test_seqs,)           int8

FR Traceability:
    FR5.3  — LSTM sequential classifier
    FR5.5  — Attack sequence classification (8-class taxonomy)
    FR3.10 — MinMaxScaler already applied; arrays arrive normalised

March 2026 | Sprint 2 Week 6 | Developer: GWAGSI Rawlings Nshom
"""

import gc
import json
import os
import sys
import time

import numpy as np

# ── Config ────────────────────────────────────────────────────────────────
WINDOW    = 10       # Flows per sequence (Component Design Doc Feb 25 §4.3)
STRIDE    = 5        # Step between windows — 50% overlap, doubles dataset size vs stride=10
NUM_FEATURES = 41

# Paths — adjust if your layout differs
BASE_DIR   = os.path.expanduser("~/ai-nids/backend/detection/ml/processed")
TRAIN_X    = os.path.join(BASE_DIR, "X_train.npy")
TRAIN_Y    = os.path.join(BASE_DIR, "y_train.npy")
TEST_X     = os.path.join(BASE_DIR, "X_test.npy")
TEST_Y     = os.path.join(BASE_DIR, "y_test.npy")

OUT_TRAIN_X = os.path.join(BASE_DIR, "X_lstm_train.npy")
OUT_TRAIN_Y = os.path.join(BASE_DIR, "y_lstm_train.npy")
OUT_TEST_X  = os.path.join(BASE_DIR, "X_lstm_test.npy")
OUT_TEST_Y  = os.path.join(BASE_DIR, "y_lstm_test.npy")
STATS_FILE  = os.path.join(BASE_DIR, "lstm_seq_stats.json")

# Class names matching LabelEncoder order from preprocessing
# Must match label_encoder.pkl classes_ order exactly
CLASS_NAMES = [
    "BENIGN", "Botnet", "BruteForce", "DDoS",
    "DoS", "Infiltration", "PortScan", "WebAttack"
]
NUM_CLASSES = len(CLASS_NAMES)


# ── Helpers ───────────────────────────────────────────────────────────────

def build_sequences(X: np.ndarray, y: np.ndarray,
                    window: int = WINDOW, stride: int = STRIDE,
                    split_name: str = "train") -> tuple[np.ndarray, np.ndarray]:
    """
    Build sliding-window sequences per class.

    Args:
        X          : float32 array shape (N, 41) — already MinMaxScaled
        y          : int array shape (N,)
        window     : sequence length (10)
        stride     : step between windows (5)
        split_name : 'train' or 'test' — for logging only

    Returns:
        X_seq : float32 array shape (n_seqs, window, 41)
        y_seq : int8   array shape (n_seqs,)
    """
    all_seqs   = []
    all_labels = []
    stats      = {}

    unique_classes = np.unique(y)
    print(f"\n[{split_name}] Building sequences — window={window}, stride={stride}")
    print(f"  Input shape: {X.shape}, classes: {len(unique_classes)}")

    for cls in unique_classes:
        mask = (y == cls)
        X_cls = X[mask]          # rows for this class
        n_rows = len(X_cls)

        if n_rows < window:
            cls_name = CLASS_NAMES[cls] if cls < len(CLASS_NAMES) else str(cls)
            print(f"  [SKIP] class {cls} ({cls_name}): only {n_rows} rows < window {window}")
            stats[int(cls)] = {"rows": n_rows, "sequences": 0, "skipped": True}
            continue

        # Slide window over consecutive rows
        seq_list = []
        for i in range(0, n_rows - window + 1, stride):
            seq_list.append(X_cls[i : i + window])   # shape (10, 41)

        n_seqs = len(seq_list)
        cls_name = CLASS_NAMES[cls] if cls < len(CLASS_NAMES) else str(cls)
        print(f"  class {cls:2d} ({cls_name:<12}): {n_rows:>8} rows → {n_seqs:>7} sequences")

        all_seqs.append(np.array(seq_list, dtype=np.float32))   # (n_seqs, 10, 41)
        all_labels.extend([cls] * n_seqs)

        stats[int(cls)] = {"rows": n_rows, "sequences": n_seqs, "skipped": False}

        # Free per-class array immediately
        del seq_list, X_cls
        gc.collect()

    # Concatenate across classes
    print(f"\n  Concatenating {len(all_seqs)} class arrays...")
    X_seq = np.concatenate(all_seqs, axis=0)    # (total_seqs, 10, 41)
    y_seq = np.array(all_labels, dtype=np.int8)  # (total_seqs,)
    del all_seqs, all_labels
    gc.collect()

    # Shuffle (important — sequences are currently grouped by class)
    print(f"  Shuffling {len(y_seq):,} sequences...")
    rng   = np.random.default_rng(42)
    idx   = rng.permutation(len(y_seq))
    X_seq = X_seq[idx]
    y_seq = y_seq[idx]
    del idx
    gc.collect()

    print(f"  Final shape: X={X_seq.shape}, y={y_seq.shape}")
    return X_seq, y_seq, stats


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 60)
    print("AI-NIDS — LSTM Sequence Preparation")
    print("=" * 60)

    # ── Validate inputs ───────────────────────────────────────
    for p in [TRAIN_X, TRAIN_Y, TEST_X, TEST_Y]:
        if not os.path.exists(p):
            print(f"[ERROR] Required file not found: {p}")
            sys.exit(1)

    # ── Load arrays ───────────────────────────────────────────
    print("\nLoading preprocessed arrays...")
    X_train = np.load(TRAIN_X).astype(np.float32)
    y_train = np.load(TRAIN_Y).astype(np.int64)
    print(f"  X_train: {X_train.shape}  y_train: {y_train.shape}")

    X_test  = np.load(TEST_X).astype(np.float32)
    y_test  = np.load(TEST_Y).astype(np.int64)
    print(f"  X_test:  {X_test.shape}   y_test:  {y_test.shape}")

    assert X_train.shape[1] == NUM_FEATURES, \
        f"Expected {NUM_FEATURES} features, got {X_train.shape[1]}"

    # ── Build train sequences ─────────────────────────────────
    X_lstm_train, y_lstm_train, train_stats = build_sequences(
        X_train, y_train, split_name="train"
    )
    del X_train, y_train
    gc.collect()

    # ── Build test sequences ──────────────────────────────────
    X_lstm_test, y_lstm_test, test_stats = build_sequences(
        X_test, y_test, stride=WINDOW, split_name="test"   # stride=window → non-overlapping for test
    )
    del X_test, y_test
    gc.collect()

    # ── Save arrays ───────────────────────────────────────────
    print(f"\nSaving arrays to {BASE_DIR} ...")
    np.save(OUT_TRAIN_X, X_lstm_train)
    np.save(OUT_TRAIN_Y, y_lstm_train)
    np.save(OUT_TEST_X,  X_lstm_test)
    np.save(OUT_TEST_Y,  y_lstm_test)

    # ── Save stats ────────────────────────────────────────────
    elapsed = round(time.time() - t0, 1)
    summary = {
        "window": WINDOW,
        "stride_train": STRIDE,
        "stride_test": WINDOW,
        "num_features": NUM_FEATURES,
        "train_sequences": int(len(y_lstm_train)),
        "test_sequences":  int(len(y_lstm_test)),
        "train_class_stats": train_stats,
        "test_class_stats":  test_stats,
        "elapsed_seconds": elapsed,
    }
    with open(STATS_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("SEQUENCE PREPARATION COMPLETE")
    print("=" * 60)
    print(f"  Train sequences : {len(y_lstm_train):>10,}  shape {X_lstm_train.shape}")
    print(f"  Test sequences  : {len(y_lstm_test):>10,}  shape {X_lstm_test.shape}")
    print(f"  Elapsed         : {elapsed:.1f} s")
    print("\nOutputs saved:")
    print(f"  {OUT_TRAIN_X}")
    print(f"  {OUT_TRAIN_Y}")
    print(f"  {OUT_TEST_X}")
    print(f"  {OUT_TEST_Y}")
    print(f"  {STATS_FILE}")
    print("\nNext step: python ml/train_lstm.py")


if __name__ == "__main__":
    main()
