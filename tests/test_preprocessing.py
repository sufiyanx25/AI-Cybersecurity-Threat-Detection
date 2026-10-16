"""
Unit tests for data cleaning, feature engineering, and preprocessing pipelines.
"""

import pytest
import numpy as np
import pandas as pd
from src.preprocessing.pipeline import (
    clean_dataframe, FeatureEngineer,
    build_preprocessor, prepare_training_data,
    DOC_FEATURES
)

def test_clean_dataframe_drops_duplicates_and_imputes():
    df = pd.DataFrame({
        "timestamp": ["2026-10-16 10:00:00", "2026-10-16 10:00:00", "2026-10-16 12:00:00"],
        "src_bytes": [100.0, 100.0, np.nan],
        "service": ["http", "http", np.nan],
        "Attack_Label": ["normal", "normal", "dos"]
    })
    cleaned = clean_dataframe(df)
    assert len(cleaned) == 2  # Duplicate removed
    assert cleaned["src_bytes"].isnull().sum() == 0  # Imputed
    assert cleaned["service"].isnull().sum() == 0
    assert "hour" in cleaned.columns  # Extracted from timestamp
    assert "timestamp" not in cleaned.columns

def test_feature_engineer_domain_ratios():
    df = pd.DataFrame({
        "src_bytes": [5000, 100],
        "dst_bytes": [1000, 0],
        "request_frequency": [300, 20],
        "num_connections": [50, 2],
        "failed_logins": [5, 0],
        "login_attempts": [5, 1],
        "packet_size": [1400, 60]
    })
    fe = FeatureEngineer()
    res = fe.transform(df)
    assert "bytes_ratio" in res.columns
    assert "req_per_conn" in res.columns
    assert "failed_login_rate" in res.columns
    assert "burst_score" in res.columns
    # Check no infinities or NaNs
    assert not np.isinf(res["bytes_ratio"]).any()
    assert not res["failed_login_rate"].isnull().any()

def test_prepare_training_data_shapes():
    from src.data.generate_dataset import generate_network_traffic
    raw = generate_network_traffic(num_rows=500, random_seed=42)
    prep = prepare_training_data(raw, test_size=0.2, random_state=42)
    
    assert len(prep["X_deploy_train"]) + len(prep["X_deploy_test"]) == len(prep["df_engineered"])
    assert list(prep["X_deploy_train"].columns) == DOC_FEATURES
    assert len(prep["y_binary_train"]) == len(prep["X_deploy_train"])
    assert len(prep["y_multi_train"]) == len(prep["X_full_train"])
