"""
Dataset Loader & Schema Normalizer
Supports loading generated synthetic datasets or external benchmark datasets
(NSL-KDD, CICIDS2017) dropped into data/raw/.
"""

import os
import glob
from typing import Tuple, Dict, Any, Optional
import pandas as pd
from src.utils.logger import logger

def detect_and_normalize_schema(df: pd.DataFrame, filename: str) -> pd.DataFrame:
    """
    Detects external dataset schemas (NSL-KDD, CICIDS2017) and maps columns
    to the standardized unified project schema.
    """
    df = df.copy()
    col_map = {}
    
    # Check for CICIDS-2017 style
    lower_cols = {c.strip().lower(): c for c in df.columns}
    
    # Identify target column
    target_candidates = ["attack_label", "label", "class", "attack", "attack_type"]
    found_target = None
    for cand in target_candidates:
        if cand in lower_cols:
            found_target = lower_cols[cand]
            break
            
    if found_target and found_target != "Attack_Label":
        logger.info(f"Mapping target column '{found_target}' to 'Attack_Label' for {filename}")
        df["Attack_Label"] = df[found_target].astype(str).str.strip().str.lower()
        if found_target != "Attack_Label":
            df.drop(columns=[found_target], inplace=True)
            
    # Normalize labels: e.g. BENIGN -> normal, DoS Hulk -> dos, PortScan -> port_scan
    if "Attack_Label" in df.columns:
        def standardize_label(val: str) -> str:
            v = str(val).lower()
            if "benign" in v or "normal" in v:
                return "normal"
            elif "dos" in v or "ddos" in v:
                return "dos"
            elif "brute" in v or "patator" in v or "ssh" in v or "ftp" in v:
                return "brute_force"
            elif "port" in v or "scan" in v:
                return "port_scan"
            elif "phish" in v:
                return "phishing"
            elif "bot" in v or "malware" in v or "infil" in v:
                return "malware"
            elif "privilege" in v or "unauth" in v or "admin" in v:
                return "unauthorized_access"
            return "anomaly"
        df["Attack_Label"] = df["Attack_Label"].apply(standardize_label)

    # Standardize core feature names if present
    feature_mappings = {
        "packet length mean": "packet_size",
        "average packet size": "packet_size",
        "total length of fwd packets": "src_bytes",
        "total length of bwd packets": "dst_bytes",
        "flow duration": "duration",
        "flow packets/s": "request_frequency",
        "num_failed_logins": "failed_logins",
        "num_compromised": "failed_logins",
        "count": "num_connections",
    }
    for orig_norm, target in feature_mappings.items():
        if orig_norm in lower_cols and target not in df.columns:
            df[target] = df[lower_cols[orig_norm]]

    # Ensure doc's 3 required deployment features exist with sensible fallbacks
    if "packet_size" not in df.columns:
        df["packet_size"] = 500
    if "failed_logins" not in df.columns:
        df["failed_logins"] = 0
    if "request_frequency" not in df.columns:
        df["request_frequency"] = 20

    return df


def load_network_data(data_dir: str = "data/raw") -> Tuple[pd.DataFrame, str]:
    """
    Loads network dataset. Looks first for external CICIDS/NSL-KDD files,
    falls back to network_traffic.csv.
    """
    # Check for external raw datasets dropped in
    external_candidates = [
        os.path.join(data_dir, "CICIDS2017.csv"),
        os.path.join(data_dir, "cicids2017.csv"),
        os.path.join(data_dir, "KDDTrain+.csv"),
        os.path.join(data_dir, "kddcup.data.csv"),
        os.path.join(data_dir, "nsl_kdd.csv")
    ]
    
    for candidate in external_candidates:
        if os.path.exists(candidate):
            logger.info(f"Detected external benchmark dataset at {candidate}")
            raw_df = pd.read_csv(candidate, low_memory=False)
            norm_df = detect_and_normalize_schema(raw_df, os.path.basename(candidate))
            return norm_df, candidate

    primary_path = os.path.join(data_dir, "network_traffic.csv")
    if os.path.exists(primary_path):
        logger.info(f"Loading primary network traffic dataset from {primary_path}")
        df = pd.read_csv(primary_path, low_memory=False)
        return df, primary_path
        
    raise FileNotFoundError(
        f"No dataset found in {data_dir}. Run python src/data/generate_dataset.py first."
    )


def load_phishing_data(data_dir: str = "data/raw") -> pd.DataFrame:
    """Loads phishing URL telemetry dataset."""
    path = os.path.join(data_dir, "phishing_urls.csv")
    if os.path.exists(path):
        return pd.read_csv(path)
    raise FileNotFoundError(f"Phishing dataset not found at {path}.")


def load_malware_data(data_dir: str = "data/raw") -> pd.DataFrame:
    """Loads malware behavior telemetry dataset."""
    path = os.path.join(data_dir, "malware_behavior.csv")
    if os.path.exists(path):
        return pd.read_csv(path)
    raise FileNotFoundError(f"Malware dataset not found at {path}.")
