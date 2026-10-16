"""
Model Training & Evaluation Pipeline
Trains:
1. Deployment Random Forest Pipeline (Doc model on 3 features: packet_size, failed_logins, request_frequency)
2. Full Multi-Class Random Forest Model on all engineered network flow features
3. Baseline Logistic Regression Model
4. Unsupervised Isolation Forest Anomaly Detector (trained on benign traffic only)
5. Phishing Detector (URL Indicators)
6. Malware Detector (Host Process Telemetry)
Includes hyperparameter tuning, cross-validation, and metrics persistence.
"""

import os
import json
from datetime import datetime
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

from src.utils.logger import logger
from src.data.loader import load_network_data, load_phishing_data, load_malware_data
from src.preprocessing.pipeline import (
    prepare_training_data, build_preprocessor,
    build_doc_deployment_pipeline, DOC_FEATURES
)

SEED = 42

def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: Optional[np.ndarray] = None) -> Dict[str, float]:
    """Computes comprehensive binary or multi-class classification metrics."""
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="weighted", zero_division=0)
    rec = recall_score(y_true, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    metrics = {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4)
    }
    
    # Calculate ROC-AUC if probabilities available
    if y_prob is not None:
        try:
            if y_prob.ndim == 1 or y_prob.shape[1] == 2:
                # Binary ROC-AUC
                prob = y_prob[:, 1] if y_prob.ndim > 1 else y_prob
                metrics["roc_auc"] = round(float(roc_auc_score(y_true, prob)), 4)
            else:
                # Multi-class ROC-AUC (ovr)
                metrics["roc_auc"] = round(float(roc_auc_score(y_true, y_prob, multi_class="ovr")), 4)
        except Exception as e:
            logger.debug(f"ROC-AUC calculation skipped: {e}")
            metrics["roc_auc"] = 0.0
            
    return metrics


def train_deployment_model(X_train: pd.DataFrame, y_train: np.ndarray,
                           X_test: pd.DataFrame, y_test: np.ndarray) -> Tuple[Pipeline, Dict[str, Any]]:
    """
    Trains the Doc's required 3-feature deployment model wrapped in a StandardScaler pipeline.
    Saved to models/cybersecurity_model.pkl as requested in the source document.
    """
    logger.info("Training Deployment Model (3 features: packet_size, failed_logins, request_frequency)...")
    
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1
    )
    pipeline = build_doc_deployment_pipeline(rf)
    pipeline.fit(X_train, y_train)
    
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)
    metrics = compute_metrics(y_test, preds, probs)
    logger.info(f"Deployment Model Test Metrics: {metrics}")
    
    return pipeline, metrics


def train_full_model(X_train: pd.DataFrame, y_train: np.ndarray,
                     X_test: pd.DataFrame, y_test: np.ndarray,
                     numeric_cols: list, categorical_cols: list) -> Tuple[Pipeline, Dict[str, Any], Dict[str, Any]]:
    """
    Trains full multi-class Random Forest model on all preprocessed flow features.
    Includes hyperparameter tuning via RandomizedSearchCV (Step 7).
    """
    logger.info("Training Full Multi-Class Random Forest Model on all engineered features...")
    preprocessor = build_preprocessor(numeric_cols, categorical_cols)
    
    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=15,
        min_samples_split=4,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1
    )
    
    full_pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", rf)
    ])
    
    # Hyperparameter tuning on a representative subset for efficiency
    param_dist = {
        "classifier__n_estimators": [100, 150],
        "classifier__max_depth": [12, 16, 20],
        "classifier__min_samples_split": [2, 5]
    }
    logger.info("Executing RandomizedSearchCV hyperparameter optimization (Step 7)...")
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)
    search = RandomizedSearchCV(
        full_pipeline,
        param_distributions=param_dist,
        n_iter=4,
        cv=cv,
        scoring="f1_weighted",
        random_state=SEED,
        n_jobs=-1
    )
    
    # Fit search
    sample_size = min(15000, len(X_train))
    sample_indices = np.random.choice(len(X_train), size=sample_size, replace=False)
    search.fit(X_train.iloc[sample_indices], y_train[sample_indices])
    
    best_pipeline = search.best_estimator_
    best_params = search.best_params_
    logger.info(f"Optimal Hyperparameters: {best_params}")
    
    # Refit best model on full training set
    logger.info("Refitting best model on complete training set...")
    best_pipeline.fit(X_train, y_train)
    
    preds = best_pipeline.predict(X_test)
    probs = best_pipeline.predict_proba(X_test)
    metrics = compute_metrics(y_test, preds, probs)
    logger.info(f"Full Random Forest Test Metrics: {metrics}")
    
    return best_pipeline, metrics, best_params


def train_logistic_regression(X_train: pd.DataFrame, y_train: np.ndarray,
                              X_test: pd.DataFrame, y_test: np.ndarray,
                              numeric_cols: list, categorical_cols: list) -> Tuple[Pipeline, Dict[str, Any]]:
    """Trains baseline Logistic Regression model for comparison."""
    logger.info("Training baseline Logistic Regression model...")
    preprocessor = build_preprocessor(numeric_cols, categorical_cols)
    
    lr = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1
    )
    
    pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("classifier", lr)
    ])
    pipeline.fit(X_train, y_train)
    
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)
    metrics = compute_metrics(y_test, preds, probs)
    logger.info(f"Logistic Regression Test Metrics: {metrics}")
    
    return pipeline, metrics


def train_isolation_forest(X_normal: pd.DataFrame, X_test: pd.DataFrame, y_binary_test: np.ndarray,
                           numeric_cols: list, categorical_cols: list) -> Tuple[Pipeline, Dict[str, Any]]:
    """
    Trains unsupervised Isolation Forest on benign (normal) traffic only.
    Evaluates ability to flag out-of-distribution cyber anomalies.
    """
    logger.info("Training Isolation Forest on benign baseline traffic only...")
    preprocessor = build_preprocessor(numeric_cols, categorical_cols)
    
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=SEED,
        n_jobs=-1
    )
    
    # Fit preprocessor on normal data
    X_normal_proc = preprocessor.fit_transform(X_normal)
    iso.fit(X_normal_proc)
    
    iso_pipeline = Pipeline(steps=[
        ("preprocessor", preprocessor),
        ("detector", iso)
    ])
    
    # Predict on test set: IsolationForest returns 1 for inlier (normal), -1 for outlier (anomaly)
    raw_preds = iso_pipeline.predict(X_test)
    # Convert to binary threat: -1 (anomaly) -> 1, 1 (normal) -> 0
    threat_preds = (raw_preds == -1).astype(int)
    
    metrics = compute_metrics(y_binary_test, threat_preds)
    logger.info(f"Isolation Forest Anomaly Detection Metrics: {metrics}")
    
    return iso_pipeline, metrics


def train_phishing_model(data_dir: str = "data/raw") -> Tuple[Pipeline, Dict[str, Any]]:
    """Trains Random Forest model on URL telemetry for phishing detection."""
    logger.info("Training Phishing Detection Model on URL indicators...")
    df = load_phishing_data(data_dir)
    
    X = df.drop(columns=["Attack_Label"])
    y = (df["Attack_Label"] == "phishing").astype(int).values
    
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=SEED, stratify=y)
    
    pipeline = Pipeline(steps=[
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=80, max_depth=10, random_state=SEED, n_jobs=-1))
    ])
    pipeline.fit(X_train, y_train)
    
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)
    metrics = compute_metrics(y_test, preds, probs)
    logger.info(f"Phishing Model Metrics: {metrics}")
    return pipeline, metrics


def train_malware_model(data_dir: str = "data/raw") -> Tuple[Pipeline, Dict[str, Any]]:
    """Trains Random Forest model on process telemetry for malware detection."""
    logger.info("Training Malware Detection Model on process behavior...")
    df = load_malware_data(data_dir)
    
    X = df.drop(columns=["Attack_Label"])
    y = (df["Attack_Label"] == "malware").astype(int).values
    
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=SEED, stratify=y)
    
    pipeline = Pipeline(steps=[
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=80, max_depth=10, random_state=SEED, n_jobs=-1))
    ])
    pipeline.fit(X_train, y_train)
    
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)
    metrics = compute_metrics(y_test, preds, probs)
    logger.info(f"Malware Model Metrics: {metrics}")
    return pipeline, metrics


def run_training_pipeline(data_dir: str = "data/raw", models_dir: str = "models", outputs_dir: str = "outputs") -> Dict[str, Any]:
    """Orchestrates end-to-end model training, comparison, and persistence."""
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(os.path.join(outputs_dir, "reports"), exist_ok=True)
    os.makedirs(os.path.join(outputs_dir, "plots"), exist_ok=True)
    
    # 1. Load primary network data
    df_raw, source_file = load_network_data(data_dir)
    prep = prepare_training_data(df_raw, test_size=0.20, random_state=SEED)
    
    # Save processed dataframe summary
    os.makedirs("data/processed", exist_ok=True)
    prep["df_engineered"].to_csv("data/processed/network_traffic_features.csv", index=False)
    logger.info("Saved engineered features to data/processed/network_traffic_features.csv")
    
    # Save label encoder
    joblib.dump(prep["label_encoder"], os.path.join(models_dir, "label_encoder.pkl"))
    
    # 2. Train Deployment Model (3 features, Doc spec)
    deploy_model, deploy_metrics = train_deployment_model(
        prep["X_deploy_train"], prep["y_binary_train"],
        prep["X_deploy_test"], prep["y_binary_test"]
    )
    # Save with the EXACT name required by doc: cybersecurity_model.pkl
    deploy_model_path = os.path.join(models_dir, "cybersecurity_model.pkl")
    joblib.dump(deploy_model, deploy_model_path)
    logger.info(f"Saved deployment model to {deploy_model_path}")
    
    # 3. Train Full Multi-Class Random Forest Model
    full_model, full_metrics, best_params = train_full_model(
        prep["X_full_train"], prep["y_multi_train"],
        prep["X_full_test"], prep["y_multi_test"],
        prep["numeric_cols"], prep["categorical_cols"]
    )
    full_model_path = os.path.join(models_dir, "full_model.pkl")
    joblib.dump(full_model, full_model_path)
    logger.info(f"Saved full model to {full_model_path}")
    
    # 4. Train Baseline Logistic Regression
    lr_model, lr_metrics = train_logistic_regression(
        prep["X_full_train"], prep["y_binary_train"],
        prep["X_full_test"], prep["y_binary_test"],
        prep["numeric_cols"], prep["categorical_cols"]
    )
    joblib.dump(lr_model, os.path.join(models_dir, "logistic_regression.pkl"))
    
    # 5. Train Isolation Forest Anomaly Detector
    normal_mask = (prep["y_binary_train"] == 0)
    X_normal_train = prep["X_full_train"].iloc[normal_mask]
    iso_model, iso_metrics = train_isolation_forest(
        X_normal_train, prep["X_full_test"], prep["y_binary_test"],
        prep["numeric_cols"], prep["categorical_cols"]
    )
    joblib.dump(iso_model, os.path.join(models_dir, "isolation_forest.pkl"))
    
    # 6. Train Domain Detectors (Phishing & Malware)
    phish_model, phish_metrics = train_phishing_model(data_dir)
    joblib.dump(phish_model, os.path.join(models_dir, "phishing_model.pkl"))
    
    malware_model, malware_metrics = train_malware_model(data_dir)
    joblib.dump(malware_model, os.path.join(models_dir, "malware_model.pkl"))
    
    # 7. Model Comparison Table
    comparison = pd.DataFrame([
        {"Model": "Deployment Random Forest (3-Feature)", **deploy_metrics},
        {"Model": "Full Multi-Class Random Forest", **full_metrics},
        {"Model": "Logistic Regression (Baseline)", **lr_metrics},
        {"Model": "Isolation Forest (Anomaly Detector)", **iso_metrics},
        {"Model": "Phishing Detector (URL Telemetry)", **phish_metrics},
        {"Model": "Malware Detector (Host Telemetry)", **malware_metrics}
    ])
    
    csv_rep = os.path.join(outputs_dir, "reports", "model_comparison.csv")
    json_rep = os.path.join(outputs_dir, "reports", "model_comparison.json")
    comparison.to_csv(csv_rep, index=False)
    comparison.to_json(json_rep, orient="records", indent=2)
    logger.info(f"Model comparison table saved to {csv_rep} and {json_rep}")
    
    # 8. Detailed Classification Report for Full Multi-Class Model
    y_multi_pred = full_model.predict(prep["X_full_test"])
    target_names = list(prep["label_encoder"].classes_)
    cls_report = classification_report(
        prep["y_multi_test"], y_multi_pred,
        target_names=target_names,
        output_dict=True,
        zero_division=0
    )
    cls_report_path = os.path.join(outputs_dir, "reports", "classification_report.json")
    with open(cls_report_path, "w", encoding="utf-8") as f:
        json.dump(cls_report, f, indent=2)
        
    # Save confusion matrices for plotting
    cm_multi = confusion_matrix(prep["y_multi_test"], y_multi_pred)
    np.save(os.path.join(outputs_dir, "reports", "cm_multiclass.npy"), cm_multi)
    
    y_deploy_pred = deploy_model.predict(prep["X_deploy_test"])
    cm_binary = confusion_matrix(prep["y_binary_test"], y_deploy_pred)
    np.save(os.path.join(outputs_dir, "reports", "cm_binary.npy"), cm_binary)
    
    # 9. Save Metadata JSON
    metadata = {
        "version": "1.0.0",
        "training_timestamp": datetime.now().isoformat(),
        "source_dataset": source_file,
        "features": {
            "deployment_features": DOC_FEATURES,
            "numeric_features": prep["numeric_cols"],
            "categorical_features": prep["categorical_cols"]
        },
        "target_classes": target_names,
        "best_hyperparameters_rf": best_params,
        "metrics": {
            "deployment_rf": deploy_metrics,
            "full_rf": full_metrics,
            "logistic_regression": lr_metrics,
            "isolation_forest": iso_metrics,
            "phishing_rf": phish_metrics,
            "malware_rf": malware_metrics
        }
    }
    with open(os.path.join(models_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Metadata saved to {os.path.join(models_dir, 'metadata.json')}")

    print("\n" + "=" * 60)
    print("MODEL COMPARISON SUMMARY")
    print("=" * 60)
    print(comparison.to_string(index=False))
    print("=" * 60 + "\n")
    
    return metadata

if __name__ == "__main__":
    run_training_pipeline()
