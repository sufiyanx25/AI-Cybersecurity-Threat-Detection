"""
Unit tests for data generation and schema normalization.
"""

import pytest
import pandas as pd
from src.data.generate_dataset import (
    generate_network_traffic,
    generate_phishing_dataset,
    generate_malware_dataset
)
from src.data.loader import detect_and_normalize_schema

def test_network_traffic_generator_shape_and_columns():
    df = generate_network_traffic(num_rows=200, random_seed=42)
    assert len(df) >= 200
    assert "Attack_Label" in df.columns
    assert "packet_size" in df.columns
    assert "failed_logins" in df.columns
    assert "request_frequency" in df.columns
    assert "src_ip" in df.columns
    assert "dst_ip" in df.columns

def test_network_traffic_seed_determinism():
    df1 = generate_network_traffic(num_rows=100, random_seed=99)
    df2 = generate_network_traffic(num_rows=100, random_seed=99)
    pd.testing.assert_frame_equal(df1, df2)

def test_label_distribution_classes():
    df = generate_network_traffic(num_rows=1000, random_seed=42)
    labels = set(df["Attack_Label"].unique())
    # Should contain normal and attacks
    assert "normal" in labels
    assert "dos" in labels
    assert "brute_force" in labels

def test_phishing_generator():
    df = generate_phishing_dataset(num_rows=100, random_seed=42)
    assert len(df) == 100
    assert "url_length" in df.columns
    assert "Attack_Label" in df.columns
    assert set(df["Attack_Label"].unique()) == {"normal", "phishing"}

def test_malware_generator():
    df = generate_malware_dataset(num_rows=100, random_seed=42)
    assert len(df) == 100
    assert "api_call_count" in df.columns
    assert "entropy" in df.columns
    assert "Attack_Label" in df.columns
    assert set(df["Attack_Label"].unique()) == {"normal", "malware"}

def test_schema_normalizer_external_dataset():
    raw_external = pd.DataFrame({
        "Flow Duration": [100, 200],
        "Average Packet Size": [1200, 450],
        "Flow Packets/s": [500, 15],
        "Label": ["BENIGN", "DoS Hulk"]
    })
    norm = detect_and_normalize_schema(raw_external, "external.csv")
    assert "Attack_Label" in norm.columns
    assert norm["Attack_Label"].tolist() == ["normal", "dos"]
    assert "packet_size" in norm.columns
    assert "request_frequency" in norm.columns
