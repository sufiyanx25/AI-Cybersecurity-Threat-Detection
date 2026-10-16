"""
Data Preprocessing & Feature Engineering Pipelines
Handles cleaning, feature extraction, scaling, encoding, and creates
reproducible sklearn pipelines for deployment and full model training.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, List, Dict, Any, Optional
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from src.utils.logger import logger

DOC_FEATURES = ["packet_size", "failed_logins", "request_frequency"]

CORE_NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "packet_size",
    "failed_logins", "request_frequency", "num_connections",
    "login_attempts", "geo_risk", "bytes_ratio",
    "req_per_conn", "failed_login_rate", "burst_score"
]

CORE_CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]


class FeatureEngineer(BaseEstimator, TransformerMixin):
    """Custom transformer to add domain-specific cybersecurity features."""
    
    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        df = X.copy()
        if not isinstance(df, pd.DataFrame):
            # If numpy array, return as is
            return df
            
        # Extract temporal features if timestamp column exists
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"], errors="coerce")
            df["hour"] = ts.dt.hour.fillna(12).astype(int)
            df["day_of_week"] = ts.dt.dayofweek.fillna(0).astype(int)
            df["is_weekend"] = df["day_of_week"].apply(lambda x: 1 if x >= 5 else 0)
            if "unusual_hour" not in df.columns:
                df["unusual_hour"] = df["hour"].apply(lambda h: 1 if (h < 6 or h >= 23) else 0)
            df.drop(columns=["timestamp"], inplace=True)

        # Domain cyber ratios
        src_b = df["src_bytes"].fillna(0) if "src_bytes" in df.columns else 0
        dst_b = df["dst_bytes"].fillna(0) if "dst_bytes" in df.columns else 0
        freq = df["request_frequency"].fillna(1) if "request_frequency" in df.columns else 1
        conns = df["num_connections"].fillna(1) if "num_connections" in df.columns else 1
        fails = df["failed_logins"].fillna(0) if "failed_logins" in df.columns else 0
        attempts = df["login_attempts"].fillna(fails) if "login_attempts" in df.columns else fails
        pkt = df["packet_size"].fillna(500) if "packet_size" in df.columns else 500

        df["bytes_ratio"] = src_b / (dst_b + 1.0)
        df["req_per_conn"] = freq / (conns + 1.0)
        df["failed_login_rate"] = fails / (attempts + 1.0)
        df["burst_score"] = (pkt * freq) / 1000.0

        # Outlier clipping & infinite values fix
        for col in ["bytes_ratio", "req_per_conn", "burst_score"]:
            if col in df.columns:
                df[col] = df[col].replace([np.inf, -np.inf], np.nan).fillna(0)
                df[col] = np.clip(df[col], 0, 10000)

        return df


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Removes duplicates, trims strings, and handles structural anomalies."""
    logger.info(f"Cleaning raw data. Initial shape: {df.shape}")
    
    # Drop exact duplicate rows
    initial_len = len(df)
    df = df.drop_duplicates().copy()
    dropped_dups = initial_len - len(df)
    if dropped_dups > 0:
        logger.info(f"Removed {dropped_dups} duplicate records.")

    # Strip whitespaces from column names
    df.columns = [c.strip() for c in df.columns]

    # If timestamp exists, process and drop
    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"] = ts.dt.hour.fillna(12).astype(int)
        df["is_weekend"] = ts.dt.dayofweek.fillna(0).apply(lambda x: 1 if x >= 5 else 0)
        if "unusual_hour" not in df.columns:
            df["unusual_hour"] = df["hour"].apply(lambda h: 1 if (h < 6 or h >= 23) else 0)
        df.drop(columns=["timestamp"], inplace=True)

    # Impute missing numeric values with median
    num_cols = df.select_dtypes(include=[np.number]).columns
    for col in num_cols:
        if df[col].isnull().sum() > 0:
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val)

    # Impute categorical values with mode
    cat_cols = df.select_dtypes(include=["object"]).columns
    for col in cat_cols:
        if col != "Attack_Label" and df[col].isnull().sum() > 0:
            mode_val = df[col].mode()[0] if not df[col].mode().empty else "unknown"
            df[col] = df[col].fillna(mode_val)

    logger.info(f"Cleaning completed. Cleaned shape: {df.shape}")
    return df


def build_preprocessor(numeric_cols: List[str], categorical_cols: List[str]) -> ColumnTransformer:
    """Builds a robust sklearn ColumnTransformer with scaling and one-hot encoding."""
    numeric_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler())
    ])

    categorical_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="constant", fill_value="unknown")),
        ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", numeric_transformer, numeric_cols),
            ("cat", categorical_transformer, categorical_cols)
        ],
        remainder="drop"
    )
    return preprocessor


def build_doc_deployment_pipeline(classifier) -> Pipeline:
    """
    Creates the sklearn Pipeline for the doc's 3-feature deployment model.
    Scales [packet_size, failed_logins, request_frequency] then feeds to classifier.
    Ensures identical preprocessing inside Flask API without separate manual scaling.
    """
    pipeline = Pipeline(steps=[
        ("scaler", StandardScaler()),
        ("classifier", classifier)
    ])
    return pipeline


def prepare_training_data(
    df: pd.DataFrame, 
    test_size: float = 0.20, 
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Cleans, engineers features, encodes labels, and creates stratified train/test splits
    for both the 3-feature deployment model and the full multi-feature model.
    """
    from sklearn.model_selection import train_test_split
    
    df_clean = clean_dataframe(df)
    
    # Engineer additional features
    engineer = FeatureEngineer()
    df_feat = engineer.transform(df_clean)

    # Separate targets
    if "Attack_Label" not in df_feat.columns:
        raise ValueError("DataFrame must contain 'Attack_Label' column.")

    y_raw = df_feat["Attack_Label"].astype(str)
    # Binary target: 0 for normal, 1 for threat
    y_binary = (y_raw != "normal").astype(int).values

    # Multi-class target encoding
    label_encoder = LabelEncoder()
    y_multiclass = label_encoder.fit_transform(y_raw)

    # 1. Deployment 3-feature slice (exact match for doc POST /predict schema)
    X_deploy = df_feat[DOC_FEATURES].copy()

    # 2. Full feature set slice
    present_num_cols = [c for c in CORE_NUMERIC_FEATURES if c in df_feat.columns]
    present_cat_cols = [c for c in CORE_CATEGORICAL_FEATURES if c in df_feat.columns]

    X_full = df_feat[present_num_cols + present_cat_cols].copy()

    # Stratified 80/20 train/test splits
    indices = np.arange(len(df_feat))
    train_idx, test_idx = train_test_split(
        indices,
        test_size=test_size,
        random_state=random_state,
        stratify=y_binary
    )

    return {
        "train_idx": train_idx,
        "test_idx": test_idx,
        "X_deploy_train": X_deploy.iloc[train_idx],
        "X_deploy_test": X_deploy.iloc[test_idx],
        "X_full_train": X_full.iloc[train_idx],
        "X_full_test": X_full.iloc[test_idx],
        "y_binary_train": y_binary[train_idx],
        "y_binary_test": y_binary[test_idx],
        "y_multi_train": y_multiclass[train_idx],
        "y_multi_test": y_multiclass[test_idx],
        "label_encoder": label_encoder,
        "numeric_cols": present_num_cols,
        "categorical_cols": present_cat_cols,
        "df_engineered": df_feat
    }
