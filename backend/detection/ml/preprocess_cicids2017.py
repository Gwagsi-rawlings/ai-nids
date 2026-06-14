"""
AI-NIDS — CICIDS2017 Preprocessing (No SMOTE — memory safe)
Uses class_weight='balanced' in RF as imbalance handling.
March 27, 2026 | Week 3, Day 1
"""

import os
import glob
import gc
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split

# ── Output directory ──────────────────────────────────────────
OUTPUT_DIR = "/home/rawlings/ai-nids/backend/detection/ml/processed"
os.makedirs(OUTPUT_DIR, exist_ok=True)

DATA_DIR = "/home/rawlings/ai-nids/ml/datasets/CICIDS2017/MachineLearningCSV/MachineLearningCVE"
os.makedirs(DATA_DIR, exist_ok=True)

FEATURE_COLUMNS = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length',
]

LABEL_MAP = {
    'BENIGN': 'BENIGN',
    'DoS Hulk': 'DoS', 'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS', 'DoS Slowhttptest': 'DoS',
    'Heartbleed': 'DoS',
    'DDoS': 'DDoS',
    'PortScan': 'PortScan',
    'FTP-Patator': 'BruteForce', 'SSH-Patator': 'BruteForce',
    'Bot': 'Botnet',
    'Infiltration': 'Infiltration',
}

def map_label(raw):
    raw = raw.strip()
    if raw in LABEL_MAP:
        return LABEL_MAP[raw]
    r = raw.lower().replace('\ufffd', '').replace('?', '').strip()
    if 'brute' in r: return 'WebAttack'
    if 'xss'   in r: return 'WebAttack'
    if 'sql'   in r: return 'WebAttack'
    if 'web'   in r: return 'WebAttack'
    return 'BENIGN'

# ─────────────────────────────────────────────────────────────
# PASS 1: Per-file processing
# ─────────────────────────────────────────────────────────────
print("=" * 60)
print("PASS 1: Per-file processing")
print("=" * 60)

files = sorted(glob.glob(os.path.join(DATA_DIR, "*.csv")))
all_X_parts = []
all_y_parts = []

for f in files:
    fname = os.path.basename(f)
    print(f"\n  Processing {fname}...")
    df = pd.read_csv(f, encoding='utf-8', low_memory=False)
    df.columns = df.columns.str.strip()
    df['label_mapped'] = df['Label'].apply(map_label)

    avail = {c.lower(): c for c in df.columns}
    resolved = []
    for c in FEATURE_COLUMNS:
        if c in df.columns:
            resolved.append(c)
        elif c.lower() in avail:
            resolved.append(avail[c.lower()])
        else:
            df[c] = 0.0
            resolved.append(c)

    X_part = df[resolved].replace([np.inf, -np.inf], np.nan)
    X_part = X_part.fillna(X_part.max()).fillna(0)
    X_part = X_part.values.astype(np.float32)
    y_part = df['label_mapped'].values

    print(f"    Shape: {X_part.shape} | "
          f"Labels: {pd.Series(y_part).value_counts().to_dict()}")

    all_X_parts.append(X_part)
    all_y_parts.append(y_part)
    del df; gc.collect()

# ─────────────────────────────────────────────────────────────
# PASS 2: Concatenate + encode + split
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("PASS 2: Concatenate + encode + split")
print("=" * 60)

X = np.concatenate(all_X_parts, axis=0)
y_raw = np.concatenate(all_y_parts, axis=0)
del all_X_parts, all_y_parts; gc.collect()

print(f"  Full X shape: {X.shape}")
print(f"  Label distribution:\n{pd.Series(y_raw).value_counts()}")

le = LabelEncoder()
y = le.fit_transform(y_raw)
print(f"\n  Classes: {list(le.classes_)}")
joblib.dump(le, os.path.join(OUTPUT_DIR, 'label_encoder.pkl'))
print("  Saved: label_encoder.pkl")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
del X; gc.collect()
print(f"  Train: {X_train.shape} | Test: {X_test.shape}")

# ─────────────────────────────────────────────────────────────
# PASS 3: Scale (fit on train only)
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("PASS 3: MinMaxScaler (fit on train only)")
print("=" * 60)

scaler = MinMaxScaler(feature_range=(0, 1))
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled  = scaler.transform(X_test)
del X_train, X_test; gc.collect()

joblib.dump(scaler, os.path.join(OUTPUT_DIR, 'scaler.pkl'))
print("  Scaler saved.")
print(f"  Train range: [{X_train_scaled.min():.3f}, {X_train_scaled.max():.3f}]")
print(f"  Test  range: [{X_test_scaled.min():.3f},  {X_test_scaled.max():.3f}]")

# ─────────────────────────────────────────────────────────────
# PASS 4: Save all arrays immediately
# ─────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("PASS 4: Saving arrays")
print("=" * 60)

np.save(os.path.join(OUTPUT_DIR, 'X_train.npy'), X_train_scaled)
np.save(os.path.join(OUTPUT_DIR, 'X_test.npy'),  X_test_scaled)
np.save(os.path.join(OUTPUT_DIR, 'y_train.npy'), y_train)
np.save(os.path.join(OUTPUT_DIR, 'y_test.npy'),  y_test)

print(f"  X_train: {X_train_scaled.shape} → X_train.npy")
print(f"  X_test:  {X_test_scaled.shape}  → X_test.npy")
print(f"  y_train: {y_train.shape}         → y_train.npy")
print(f"  y_test:  {y_test.shape}           → y_test.npy")

# Also copy scaler to project ml/ directory for inference pipeline
import shutil
project_scaler = os.path.expanduser("~/ai-nids/ml/scaler.pkl")
shutil.copy(os.path.join(OUTPUT_DIR, 'scaler.pkl'), project_scaler)
shutil.copy(os.path.join(OUTPUT_DIR, 'label_encoder.pkl'),
            os.path.expanduser("~/ai-nids/ml/label_encoder.pkl"))
print("\n  Copied scaler.pkl → ~/ai-nids/ml/scaler.pkl")
print("  Copied label_encoder.pkl → ~/ai-nids/ml/label_encoder.pkl")

print(f"\n  All outputs saved to: {OUTPUT_DIR}")
print("\n" + "=" * 60)
print("PREPROCESSING COMPLETE")
print("  → No SMOTE applied: use class_weight='balanced' in RF")
print("  → IF trains on BENIGN subset only (no balancing needed)")
print("=" * 60)

print(f"""
SUMMARY
-------
Total samples:    {X_train_scaled.shape[0] + X_test_scaled.shape[0]:,}
Features:         41
Classes:          {list(le.classes_)}
Train set:        {X_train_scaled.shape[0]:,} (80%)
Test set:         {X_test_scaled.shape[0]:,} (20%)
Imbalance fix:    class_weight='balanced' in RandomForest
Scaler:           MinMaxScaler [0,1] — fit on train only
Ready for:        RF training, IF training
""")
