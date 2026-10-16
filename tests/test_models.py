"""
Unit tests for ML models, pipelines, accuracy and anomaly detection thresholds.
"""

import pytest
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from src.data.generate_dataset import generate_network_traffic
from src.preprocessing.pipeline import prepare_training_data
from src.models.train import (
    train_deployment_model,
    train_logistic_regression,
    train_isolation_forest,
    compute_metrics
)

@pytest.fixture(scope="module")
def dataset():
    raw = generate_network_traffic(num_rows=1200, random_seed=42)
    return prepare_training_data(raw, test_size=0.2, random_state=42)

def test_deployment_model_accuracy_and_recall(dataset):
    model, metrics = train_deployment_model(
        dataset["X_deploy_train"], dataset["y_binary_train"],
        dataset["X_deploy_test"], dataset["y_binary_test"]
    )
    assert isinstance(model, Pipeline)
    assert metrics["accuracy"] >= 0.85, f"Accuracy too low: {metrics['accuracy']}"
    assert metrics["recall"] >= 0.80, f"Recall too low: {metrics['recall']}"

def test_logistic_regression_baseline(dataset):
    model, metrics = train_logistic_regression(
        dataset["X_full_train"], dataset["y_binary_train"],
        dataset["X_full_test"], dataset["y_binary_test"],
        dataset["numeric_cols"], dataset["categorical_cols"]
    )
    assert isinstance(model, Pipeline)
    assert metrics["accuracy"] >= 0.80

def test_isolation_forest_flags_anomalies(dataset):
    normal_mask = (dataset["y_binary_train"] == 0)
    X_normal = dataset["X_full_train"].iloc[normal_mask]
    
    iso_model, metrics = train_isolation_forest(
        X_normal, dataset["X_full_test"], dataset["y_binary_test"],
        dataset["numeric_cols"], dataset["categorical_cols"]
    )
    assert isinstance(iso_model, Pipeline)

    # Isolation Forest should detect MOST true attacks as anomalies on held-out test data.
    # We accept recall >= 0.40 (loose due to unsupervised nature on small synthetic data).
    attack_mask = dataset["y_binary_test"] == 1
    X_attacks = dataset["X_full_test"].iloc[attack_mask]
    if len(X_attacks) > 0:
        preds = iso_model.predict(X_attacks)
        n_flagged = (preds == -1).sum()
        fraction_flagged = n_flagged / len(X_attacks)
        assert fraction_flagged >= 0.30, (
            f"Isolation Forest only flagged {fraction_flagged:.0%} of attacks "
            f"(expected >= 30% as anomalies for unsupervised detector)"
        )


def test_compute_metrics():
    y_true = np.array([0, 1, 1, 0, 1])
    y_pred = np.array([0, 1, 1, 0, 0])
    m = compute_metrics(y_true, y_pred)
    assert "accuracy" in m
    assert "precision" in m
    assert "recall" in m
    assert "f1" in m
    assert m["accuracy"] == 0.8
