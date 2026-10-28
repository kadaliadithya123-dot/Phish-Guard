"""
PHISH GUARD - Hybrid AI Browser Security System
Module: models.train_hybrid_models

Multi-Algorithm Training, Benchmarking, and Evaluation Pipeline:
1. Random Forest (Ensemble)
2. Gradient Boosting (Champion Boosting)
3. Extra Trees (Extremely Randomized Trees)
4. AdaBoost (Adaptive Boosting)
5. Voting Ensemble (Soft Voting of RF + ET + GB)
6. Decision Tree (CART)
7. K-Nearest Neighbors (KNN)
8. Gaussian Naive Bayes

Computes Accuracy, Precision, Recall, F1 Score, ROC-AUC, Training Latency,
generates ROC Curves & Confusion Matrix visualizations, and exports production models.
"""

import json
import os
import sys
import time
from typing import Any, Dict

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    AdaBoostClassifier,
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)
sys.path.append(os.path.join(BASE_DIR, "backend"))

import database_manager

DATASET_CSV = os.path.join(BASE_DIR, "dataset", "hybrid_features_dataset.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")


def train_and_benchmark_hybrid_pipeline():
    print("=" * 84)
    print("   PHISH GUARD - NEXT-GEN HYBRID AI MULTI-MODEL BENCHMARKING PIPELINE")
    print("=" * 84)

    # 1. Load Dataset
    if not os.path.exists(DATASET_CSV):
        raise FileNotFoundError(f"Hybrid dataset missing at {DATASET_CSV}")

    df = pd.read_csv(DATASET_CSV)
    df.dropna(inplace=True)

    y = df["label"].astype(int)
    feature_names = [col for col in df.columns if col != "label"]
    X = df[feature_names]

    print(f"[+] Loaded {len(X)} samples with {len(feature_names)} multi-modal features.")
    print(f"[+] Class Balance: Safe = {sum(y == 0)}, Phishing = {sum(y == 1)}")

    # 2. Train / Test Split (80% train, 20% test, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Train Partition: {len(X_train)} | Test Partition: {len(X_test)}")

    # 3. Fit Feature Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    scaler_path = os.path.join(MODELS_DIR, "hybrid_scaler.pkl")
    joblib.dump(scaler, scaler_path)
    print(f"[+] Saved feature scaler to: {scaler_path}")

    # 4. Define 8 Machine Learning Estimators
    rf = RandomForestClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1)
    et = ExtraTreesClassifier(n_estimators=100, max_depth=16, random_state=42, n_jobs=-1)
    gb = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42)

    candidate_models = {
        "Random Forest": rf,
        "Extra Trees": et,
        "Gradient Boosting": gb,
        "AdaBoost": AdaBoostClassifier(n_estimators=100, random_state=42),
        "Voting Ensemble": VotingClassifier(
            estimators=[("rf", rf), ("et", et), ("gb", gb)],
            voting="soft",
            n_jobs=-1
        ),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, random_state=42),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
        "Gaussian Naive Bayes": GaussianNB()
    }

    # 5. Benchmarking Loop
    results = {}
    fitted_models = {}
    roc_data = {}

    print("\n" + "-" * 88)
    print(f"{'Algorithm':<26} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8} | {'Time (s)':<8}")
    print("-" * 88)

    for name, model in candidate_models.items():
        t0 = time.perf_counter()
        model.fit(X_train_scaled, y_train)
        elapsed = time.perf_counter() - t0

        y_pred = model.predict(X_test_scaled)

        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test_scaled)[:, 1]
        elif hasattr(model, "decision_function"):
            y_proba = model.decision_function(X_test_scaled)
        else:
            y_proba = y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc = roc_auc_score(y_test, y_proba)
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(roc), 4),
            "training_time": round(float(elapsed), 4),
            "confusion_matrix": cm.tolist()
        }
        fitted_models[name] = model

        # Calculate ROC curve coordinates
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_data[name] = (fpr, tpr, roc)

        print(f"{name:<26} | {acc:<8.4f} | {prec:<9.4f} | {rec:<8.4f} | {f1:<8.4f} | {roc:<8.4f} | {elapsed:<8.3f}")

    print("-" * 88)

    # 6. Select Champion Model based on balanced F1-score & ROC-AUC
    champion_name = max(results.keys(), key=lambda k: (results[k]["f1_score"], results[k]["roc_auc"], -results[k]["training_time"]))
    champion_model = fitted_models[champion_name]
    champion_metrics = results[champion_name]

    print(f"\n[+] CHAMPION HYBRID ESTIMATOR SELECTED: {champion_name}")
    print(f"    - Accuracy:  {champion_metrics['accuracy'] * 100:.2f}%")
    print(f"    - F1 Score:  {champion_metrics['f1_score']:.4f}")
    print(f"    - Precision: {champion_metrics['precision']:.4f}")
    print(f"    - Recall:    {champion_metrics['recall']:.4f}")
    print(f"    - ROC-AUC:   {champion_metrics['roc_auc']:.4f}")
    print(f"    - Latency:   {champion_metrics['training_time']:.3f} s")

    # 7. Save Champion Model artifacts
    model_save_path = os.path.join(MODELS_DIR, "hybrid_model.pkl")
    joblib.dump(champion_model, model_save_path)
    print(f"[+] Saved champion model to: {model_save_path}")

    # Backwards-compatible aliases
    joblib.dump(champion_model, os.path.join(MODELS_DIR, "model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))

    # 8. Plot and Save Confusion Matrix
    cm = np.array(champion_metrics["confusion_matrix"])
    plt.figure(figsize=(6, 5))
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title(f"Hybrid Confusion Matrix - {champion_name}", fontsize=12, pad=15)
    plt.colorbar()
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ["Safe (0)", "Phishing (1)"], fontsize=10)
    plt.yticks(tick_marks, ["Safe (0)", "Phishing (1)"], fontsize=10)

    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(
                j, i, format(cm[i, j], "d"),
                horizontalalignment="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=14,
                fontweight="bold"
            )

    plt.ylabel("True Class", fontsize=11)
    plt.xlabel("Predicted Class", fontsize=11)
    plt.tight_layout()
    cm_path = os.path.join(MODELS_DIR, "hybrid_confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[+] Confusion matrix plot saved to: {cm_path}")

    # 9. Plot and Save Multi-Model ROC Curves Comparison
    plt.figure(figsize=(9, 6))
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2", "#17becf"]
    for idx, (name, (fpr, tpr, roc_score)) in enumerate(roc_data.items()):
        plt.plot(fpr, tpr, label=f"{name} (AUC = {roc_score:.3f})", color=colors[idx % len(colors)], linewidth=2)

    plt.plot([0, 1], [0, 1], "k--", label="Random Chance (AUC = 0.500)", linewidth=1.5)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate (1 - Specificity)", fontsize=11)
    plt.ylabel("True Positive Rate (Sensitivity)", fontsize=11)
    plt.title("Multi-Model Receiver Operating Characteristic (ROC) Comparison", fontsize=12, pad=15)
    plt.legend(loc="lower right", fontsize=8)
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    roc_path = os.path.join(MODELS_DIR, "roc_curves.png")
    plt.savefig(roc_path, dpi=300)
    plt.close()
    print(f"[+] ROC curves plot saved to: {roc_path}")

    # 10. Extract Feature Importances
    feature_importances = {}
    if hasattr(champion_model, "feature_importances_"):
        raw_imp = champion_model.feature_importances_
        for feat, imp in zip(feature_names, raw_imp):
            feature_importances[feat] = round(float(imp), 4)
        feature_importances = dict(sorted(feature_importances.items(), key=lambda x: x[1], reverse=True))

    # 11. Save Comprehensive Metadata JSON
    metadata = {
        "active_model_name": champion_name,
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "champion_metrics": champion_metrics,
        "all_model_benchmarks": results,
        "feature_importances": feature_importances,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    metadata_path = os.path.join(MODELS_DIR, "hybrid_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    with open(os.path.join(MODELS_DIR, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)
    print(f"[+] Saved metadata to: {metadata_path}")

    # 12. Sync Benchmarks into SQLite Database
    try:
        database_manager.save_model_benchmarks(results, champion_name)
        print("[+] Benchmarks successfully synchronized into SQLite database.")
    except Exception as e:
        print(f"[!] Warning: Database sync note: {e}")

    print("\n[+] Hybrid Machine Learning Pipeline completed successfully!")
    return metadata


if __name__ == "__main__":
    train_and_benchmark_hybrid_pipeline()
