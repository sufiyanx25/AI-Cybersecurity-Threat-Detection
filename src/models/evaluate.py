"""
Model Evaluation and Feature Importance Analysis
Computes detailed diagnostics, feature importances, ROC curves,
and false positive rates across all trained cybersecurity models.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List

from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
from src.utils.logger import logger
from src.data.loader import load_network_data
from src.preprocessing.pipeline import prepare_training_data, DOC_FEATURES

def evaluate_models(models_dir: str = "models", data_dir: str = "data/raw", outputs_dir: str = "outputs") -> Dict[str, Any]:
    """Runs rigorous evaluation on saved models against held-out test data."""
    logger.info("Starting model evaluation...")
    os.makedirs(os.path.join(outputs_dir, "reports"), exist_ok=True)
    
    # Load dataset
    df, _ = load_network_data(data_dir)
    prep = prepare_training_data(df, test_size=0.20, random_state=42)
    
    # Load models
    deploy_model = joblib.load(os.path.join(models_dir, "cybersecurity_model.pkl"))
    full_model = joblib.load(os.path.join(models_dir, "full_model.pkl"))
    lr_model = joblib.load(os.path.join(models_dir, "logistic_regression.pkl"))
    label_encoder = joblib.load(os.path.join(models_dir, "label_encoder.pkl"))
    
    # 1. Feature Importance Analysis
    # Deployment model feature importance
    deploy_rf = deploy_model.named_steps["classifier"]
    deploy_importances = dict(zip(DOC_FEATURES, deploy_rf.feature_importances_))
    logger.info(f"Deployment Model Feature Importances: {deploy_importances}")
    
    # Full model feature importance
    full_rf = full_model.named_steps["classifier"]
    preprocessor = full_model.named_steps["preprocessor"]
    
    # Extract feature names after ColumnTransformer transformation
    num_features = prep["numeric_cols"]
    cat_encoder = preprocessor.named_transformers_["cat"].named_steps["encoder"]
    cat_features = list(cat_encoder.get_feature_names_out(prep["categorical_cols"]))
    all_feature_names = num_features + cat_features
    
    full_importances = pd.DataFrame({
        "feature": all_feature_names[:len(full_rf.feature_importances_)],
        "importance": full_rf.feature_importances_
    }).sort_values(by="importance", ascending=False)
    
    feat_imp_path = os.path.join(outputs_dir, "reports", "feature_importance.csv")
    full_importances.to_csv(feat_imp_path, index=False)
    logger.info(f"Full feature importances saved to {feat_imp_path}")
    
    # 2. Deployment ROC and False Positive Rate
    y_test_bin = prep["y_binary_test"]
    y_deploy_prob = deploy_model.predict_proba(prep["X_deploy_test"])[:, 1]
    fpr_deploy, tpr_deploy, _ = roc_curve(y_test_bin, y_deploy_prob)
    roc_auc_deploy = auc(fpr_deploy, tpr_deploy)
    
    # 3. Logistic Regression ROC
    y_lr_prob = lr_model.predict_proba(prep["X_full_test"])[:, 1]
    fpr_lr, tpr_lr, _ = roc_curve(y_test_bin, y_lr_prob)
    roc_auc_lr = auc(fpr_lr, tpr_lr)
    
    # Save ROC curves data
    roc_data = {
        "deploy_rf": {"fpr": fpr_deploy.tolist(), "tpr": tpr_deploy.tolist(), "auc": float(roc_auc_deploy)},
        "logistic_regression": {"fpr": fpr_lr.tolist(), "tpr": tpr_lr.tolist(), "auc": float(roc_auc_lr)}
    }
    with open(os.path.join(outputs_dir, "reports", "roc_curves.json"), "w", encoding="utf-8") as f:
        json.dump(roc_data, f)
        
    print("\n--- Top 10 Most Important Features in Network Intrusion Detection ---")
    print(full_importances.head(10).to_string(index=False))
    print(f"\nDeployment Model 3-Feature Weights: {deploy_importances}")
    print(f"Deployment Model ROC-AUC: {roc_auc_deploy:.4f} | Logistic Regression ROC-AUC: {roc_auc_lr:.4f}\n")
    
    return {
        "deploy_importances": deploy_importances,
        "full_importances": full_importances.to_dict(orient="records"),
        "roc_auc_deploy": roc_auc_deploy,
        "roc_auc_lr": roc_auc_lr
    }

if __name__ == "__main__":
    evaluate_models()
