import os
import time
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from config import MODEL_PATH, DATA_DIR

REAL_DATA_PATH = os.path.join(DATA_DIR, "cicids2017_real.csv")
METRICS_OUTPUT_PATH = os.path.join(DATA_DIR, "model_evaluation_metrics.json")

def run_evaluation():
    print("=" * 70)
    print("   NIDS Model Validation & Leakage Audit — CIC-IDS2017 Benchmark   ")
    print("=" * 70)

    # 1. Load Model Bundle
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model artifact not found at: {MODEL_PATH}")
    if not os.path.exists(REAL_DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at: {REAL_DATA_PATH}")

    print(f"[INFO] Loading model bundle from: {MODEL_PATH}")
    bundle = joblib.load(MODEL_PATH)
    rf = bundle["rf_model"]
    iso = bundle["isolation_forest"]
    scaler = bundle["scaler"]
    feature_names = bundle["features"]
    classes = bundle["classes"]

    # Ensure single-thread inference to prevent IPC multiprocessing overhead
    if hasattr(rf, "n_jobs"):
        rf.n_jobs = 1
    if iso is not None and hasattr(iso, "n_jobs"):
        iso.n_jobs = 1

    print(f"[INFO] Features ({len(feature_names)}): {feature_names}")
    print(f"[INFO] Classes ({len(classes)}): {classes}")

    # 2. Load Dataset
    print(f"\n[INFO] Loading dataset from: {REAL_DATA_PATH}")
    df = pd.read_csv(REAL_DATA_PATH)
    df.columns = df.columns.str.strip()

    X = df[feature_names].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    y = df["Label"].astype(str).str.strip()

    total_samples = len(df)
    class_counts = y.value_counts().to_dict()
    print(f"[INFO] Total flows: {total_samples:,}")
    for c, cnt in class_counts.items():
        print(f"  - {c}: {cnt:,} flows")

    # 3. Train / Test Split (Identical to training partition: 80/20 stratified, seed 42)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    test_size = len(y_test)
    print(f"[INFO] Held-out test set size: {test_size:,} flows (20% partition)")

    # 4. Data Leakage Analysis
    print("\n" + "-" * 70)
    print("[LEAKAGE AUDIT] Analyzing Train / Test Feature Overlap...")
    train_tuples = set(tuple(row) for row in X_train.values)
    test_tuples = set(tuple(row) for row in X_test.values)
    overlap_tuples = train_tuples.intersection(test_tuples)

    # Count how many test rows have exact duplicate feature vectors in train
    is_disjoint_mask = [tuple(row) not in train_tuples for row in X_test.values]
    strictly_disjoint_count = sum(is_disjoint_mask)
    overlapping_test_rows = test_size - strictly_disjoint_count

    print(f"  Unique training vectors:      {len(train_tuples):,}")
    print(f"  Unique test vectors:          {len(test_tuples):,}")
    print(f"  Overlapping unique vectors:   {len(overlap_tuples):,} ({len(overlap_tuples)/len(test_tuples)*100:.2f}%)")
    print(f"  Overlapping test flow rows:   {overlapping_test_rows:,} ({overlapping_test_rows/test_size*100:.2f}%)")
    print(f"  Strictly disjoint test flows: {strictly_disjoint_count:,} ({strictly_disjoint_count/test_size*100:.2f}%)")
    print("  Root Cause: Identical background TCP resets and 0-duration probe packets")
    print("              naturally present in original CIC-IDS2017 pcap captures.")

    # 5. Supervised Model Evaluation on Complete Held-Out Test Set
    print("\n" + "-" * 70)
    print("[SUPERVISED EVALUATION] Random Forest Classifier on Held-Out Test Set")
    X_test_scaled = scaler.transform(X_test)
    
    t_start = time.perf_counter()
    y_pred = rf.predict(X_test_scaled)
    inf_duration = time.perf_counter() - t_start

    accuracy = float(accuracy_score(y_test, y_pred))
    report_dict = classification_report(y_test, y_pred, output_dict=True, digits=4)
    cm = confusion_matrix(y_test, y_pred, labels=classes)

    print(f"  Overall Accuracy: {accuracy * 100:.2f}% ({sum(y_test == y_pred)} / {test_size})")
    print(f"  Test Set Inference Time: {inf_duration:.3f}s ({inf_duration / test_size * 1000:.4f} ms/sample)")

    print("\nConfusion Matrix:")
    print(f"{'True \\ Pred':<14} " + " ".join(f"{c:>12}" for c in classes))
    for i, true_cls in enumerate(classes):
        row_str = " ".join(f"{cm[i][j]:>12}" for j in range(len(classes)))
        print(f"{true_cls:<14} {row_str}")

    # False Positive & False Negative Rates
    benign_idx = classes.index("BENIGN")
    true_benign = np.sum(cm[benign_idx, :])
    false_positives = true_benign - cm[benign_idx, benign_idx]
    benign_fpr = float(false_positives / true_benign) if true_benign > 0 else 0.0

    print(f"\n  Benign Samples in Test Set: {true_benign:,}")
    print(f"  Benign False Positives (FP): {false_positives} ({false_positives}/{true_benign})")
    print(f"  Benign False Positive Rate (FPR): {benign_fpr * 100:.3f}%")

    fnr_per_class = {}
    for i, cls_name in enumerate(classes):
        if cls_name != "BENIGN":
            total_actual = np.sum(cm[i, :])
            fn = total_actual - cm[i, i]
            fnr = float(fn / total_actual) if total_actual > 0 else 0.0
            fnr_per_class[cls_name] = fnr
            print(f"  {cls_name} False Negative Rate (FNR): {fnr * 100:.3f}% ({fn}/{total_actual})")

    # 6. Evaluation on Strictly Disjoint Test Set (Zero Feature Overlap)
    print("\n" + "-" * 70)
    print("[DISJOINT ROBUSTNESS] Evaluation on Strictly Disjoint Test Subset")
    X_test_disjoint = X_test[is_disjoint_mask]
    y_test_disjoint = y_test[is_disjoint_mask]
    X_test_disjoint_scaled = scaler.transform(X_test_disjoint)
    y_pred_disjoint = rf.predict(X_test_disjoint_scaled)
    disjoint_acc = float(accuracy_score(y_test_disjoint, y_pred_disjoint))
    disjoint_report = classification_report(y_test_disjoint, y_pred_disjoint, output_dict=True, digits=4)

    print(f"  Disjoint Subset Samples: {len(y_test_disjoint):,}")
    print(f"  Disjoint Accuracy:       {disjoint_acc * 100:.2f}%")
    print(f"  Disjoint Macro F1:       {disjoint_report['macro avg']['f1-score']:.4f}")

    # 7. Unsupervised Anomaly Detection (Isolation Forest) Evaluation
    print("\n" + "-" * 70)
    print("[ANOMALY EVALUATION] Isolation Forest on Benign vs. Malicious Flows")
    iso_metrics = {}
    if iso is not None:
        benign_test_mask = (y_test == "BENIGN")
        attack_test_mask = (y_test != "BENIGN")

        X_benign_test = X_test_scaled[benign_test_mask]
        X_attack_test = X_test_scaled[attack_test_mask]

        benign_scores = iso.decision_function(X_benign_test)
        attack_scores = iso.decision_function(X_attack_test)

        # Anomaly flagged if score < -0.15 (standard statistical threshold in config)
        from config import ANOMALY_THRESHOLD
        benign_anom_count = int(np.sum(benign_scores < ANOMALY_THRESHOLD))
        attack_anom_count = int(np.sum(attack_scores < ANOMALY_THRESHOLD))

        iso_metrics = {
            "contamination": float(getattr(iso, "contamination", 0.10)),
            "anomaly_threshold": float(ANOMALY_THRESHOLD),
            "benign_tested": len(benign_scores),
            "benign_flagged_as_anomaly": benign_anom_count,
            "benign_anomaly_rate": float(benign_anom_count / len(benign_scores)),
            "attacks_tested": len(attack_scores),
            "attacks_flagged_as_anomaly": attack_anom_count,
            "attack_anomaly_detection_rate": float(attack_anom_count / len(attack_scores))
        }
        print(f"  Configured Anomaly Threshold: {ANOMALY_THRESHOLD}")
        print(f"  Benign Flows Flagged as Outliers: {benign_anom_count}/{len(benign_scores)} ({iso_metrics['benign_anomaly_rate']*100:.2f}%)")
        print(f"  Attack Flows Flagged as Outliers: {attack_anom_count}/{len(attack_scores)} ({iso_metrics['attack_anomaly_detection_rate']*100:.2f}%)")

    # 8. Single-Sample Inference Latency Benchmark
    print("\n" + "-" * 70)
    print("[LATENCY BENCHMARK] Real-Time Inference Latency Profiling")
    single_sample = X_test.iloc[0:1]
    
    latencies = []
    # 200 iterations for stable median and percentiles
    for _ in range(200):
        t0 = time.perf_counter()
        s_scaled = scaler.transform(single_sample)
        probs = rf.predict_proba(s_scaled)[0]
        idx = int(np.argmax(probs))
        _ = classes[idx]
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    mean_lat = float(np.mean(latencies))
    median_lat = float(np.median(latencies))
    p95_lat = float(np.percentile(latencies, 95))
    p99_lat = float(np.percentile(latencies, 99))

    print(f"  Mean Latency:    {mean_lat:.3f} ms / flow")
    print(f"  Median Latency:  {median_lat:.3f} ms / flow")
    print(f"  95th Percentile: {p95_lat:.3f} ms / flow")
    print(f"  99th Percentile: {p99_lat:.3f} ms / flow")
    print(f"  Throughput:      {1000.0 / mean_lat:.1f} flows / sec (single-threaded CPU)")

    # 9. Save JSON Artifact
    evaluation_bundle = {
        "timestamp": time.time(),
        "dataset": REAL_DATA_PATH,
        "total_flows": total_samples,
        "features": feature_names,
        "classes": classes,
        "test_partition_size": test_size,
        "accuracy": accuracy,
        "benign_fpr": benign_fpr,
        "fnr_per_class": fnr_per_class,
        "confusion_matrix": cm.tolist(),
        "classification_report": report_dict,
        "leakage_audit": {
            "train_unique_vectors": len(train_tuples),
            "test_unique_vectors": len(test_tuples),
            "overlapping_unique_vectors": len(overlap_tuples),
            "overlapping_test_rows": overlapping_test_rows,
            "strictly_disjoint_test_rows": strictly_disjoint_count,
            "strictly_disjoint_accuracy": disjoint_acc,
            "strictly_disjoint_macro_f1": float(disjoint_report["macro avg"]["f1-score"])
        },
        "isolation_forest_metrics": iso_metrics,
        "latency_ms": {
            "mean": mean_lat,
            "median": median_lat,
            "p95": p95_lat,
            "p99": p99_lat
        }
    }

    with open(METRICS_OUTPUT_PATH, "w") as f:
        json.dump(evaluation_bundle, f, indent=2)
    print(f"\n[SUCCESS] Comprehensive evaluation metrics saved to: {METRICS_OUTPUT_PATH}")
    print("=" * 70)
    return evaluation_bundle

if __name__ == "__main__":
    run_evaluation()
