import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score

from config import DATA_DIR, MODEL_DIR, MODEL_PATH
from download_dataset import find_existing_cicids_csv, generate_cicids_benchmark_dataset

# Normalized canonical feature list to extract from any CIC-IDS2017 CSV
FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "Average Packet Size"
]

def load_and_preprocess_dataset(csv_path: str):
    print(f"[INFO] Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)

    # Clean whitespace from column names (CIC-IDS2017 often has leading spaces like ' Destination Port')
    df.columns = df.columns.str.strip()

    # Identify label column (usually 'Label')
    label_col = None
    for col in ["Label", "label", "Attack", "class"]:
        if col in df.columns:
            label_col = col
            break

    if not label_col:
        raise ValueError(f"No Label column found in {csv_path}. Columns: {list(df.columns)}")

    # Verify matching features or fallback to available numeric features
    available_features = [col for col in FEATURE_COLUMNS if col in df.columns]
    if len(available_features) < 4:
        # Fallback to numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        available_features = [c for c in numeric_cols if c != label_col][:10]

    print(f"[INFO] Using {len(available_features)} features: {available_features}")

    # Clean missing and infinite values
    X = df[available_features].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    y = df[label_col].astype(str).str.strip()
    return X, y, available_features

def train_models():
    os.makedirs(MODEL_DIR, exist_ok=True)

    csv_path = find_existing_cicids_csv()
    if not csv_path:
        print("[INFO] No CSV found. Generating benchmark dataset automatically...")
        csv_path = generate_cicids_benchmark_dataset()

    X, y, feature_cols = load_and_preprocess_dataset(csv_path)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\n[INFO] Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)

    y_pred = rf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    print(f"[SUCCESS] Random Forest Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Train Isolation Forest on benign samples for zero-day anomaly detection
    print("[INFO] Training Isolation Forest for Anomaly Detection...")
    benign_mask = (y_train.str.upper() == "BENIGN")
    X_benign = X_train_scaled[benign_mask] if np.any(benign_mask) else X_train_scaled

    iso = IsolationForest(contamination=0.10, random_state=42, n_jobs=-1)
    iso.fit(X_benign)

    # Save artifact bundle
    model_bundle = {
        "rf_model": rf,
        "isolation_forest": iso,
        "scaler": scaler,
        "features": feature_cols,
        "classes": list(rf.classes_),
        "accuracy": float(acc)
    }

    joblib.dump(model_bundle, MODEL_PATH)
    print(f"[SUCCESS] Model artifact saved to: {MODEL_PATH}")
    return model_bundle

if __name__ == "__main__":
    train_models()
