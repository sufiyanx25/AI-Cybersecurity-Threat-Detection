"""
Unified Threat Detection Engine
Scores incoming traffic telemetry using supervised classifiers and
unsupervised Isolation Forest anomaly detection, calculating confidence
and calibrated SOC severity ratings.
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from src.utils.logger import logger
from src.preprocessing.pipeline import DOC_FEATURES, FeatureEngineer

class ThreatDetector:
    """Combines Random Forest classifiers and Isolation Forest for hybrid threat scoring."""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.deploy_model = None
        self.full_model = None
        self.iso_forest = None
        self.phish_model = None
        self.malware_model = None
        self.label_encoder = None
        self.feature_engineer = FeatureEngineer()
        self._load_models()

    def _load_models(self):
        """Loads available models from disk."""
        deploy_path = os.path.join(self.models_dir, "cybersecurity_model.pkl")
        if os.path.exists(deploy_path):
            self.deploy_model = joblib.load(deploy_path)
            
        full_path = os.path.join(self.models_dir, "full_model.pkl")
        if os.path.exists(full_path):
            self.full_model = joblib.load(full_path)
            
        iso_path = os.path.join(self.models_dir, "isolation_forest.pkl")
        if os.path.exists(iso_path):
            self.iso_forest = joblib.load(iso_path)
            
        phish_path = os.path.join(self.models_dir, "phishing_model.pkl")
        if os.path.exists(phish_path):
            self.phish_model = joblib.load(phish_path)
            
        malware_path = os.path.join(self.models_dir, "malware_model.pkl")
        if os.path.exists(malware_path):
            self.malware_model = joblib.load(malware_path)
            
        enc_path = os.path.join(self.models_dir, "label_encoder.pkl")
        if os.path.exists(enc_path):
            self.label_encoder = joblib.load(enc_path)
            
        logger.info("ThreatDetector initialized with available model artifacts.")

    def compute_severity(self, attack_type: str, confidence: float, anomaly_flag: bool = False) -> str:
        """
        Calculates SOC severity level: LOW, MEDIUM, HIGH, CRITICAL.
        """
        attack_norm = attack_type.lower()
        if attack_norm in ["dos", "unauthorized_access"]:
            return "CRITICAL" if confidence >= 0.70 else "HIGH"
        elif attack_norm in ["brute_force", "malware"]:
            return "HIGH" if confidence >= 0.65 else "MEDIUM"
        elif attack_norm in ["phishing", "port_scan"]:
            return "MEDIUM" if confidence >= 0.60 else "LOW"
        elif attack_norm == "anomaly" or anomaly_flag:
            return "MEDIUM" if confidence >= 0.75 else "LOW"
        elif attack_norm == "normal":
            return "INFORMATIONAL"
        return "LOW"

    def predict_doc_features(self, packet_size: float, failed_logins: int, request_frequency: float) -> Dict[str, Any]:
        """
        Exact implementation for the source document's POST /predict API:
        Inputs: packet_size, failed_logins, request_frequency
        Outputs: Threat_Detected (bool), attack_type, confidence, severity
        """
        if self.deploy_model is None:
            raise RuntimeError("Deployment model 'cybersecurity_model.pkl' not loaded.")
            
        input_df = pd.DataFrame([{
            "packet_size": float(packet_size),
            "failed_logins": int(failed_logins),
            "request_frequency": float(request_frequency)
        }])[DOC_FEATURES]

        # Raw prediction from pipeline
        raw_pred = self.deploy_model.predict(input_df)[0]
        # Binary prediction (0 = normal, 1 = threat)
        threat_detected = bool(raw_pred != 0)
        
        # Estimate probabilities
        probs = self.deploy_model.predict_proba(input_df)[0]
        confidence = float(np.max(probs))

        # Determine heuristic attack classification from the 3 features for rich reporting
        attack_type = "normal"
        if threat_detected:
            if failed_logins >= 3:
                attack_type = "brute_force"
            elif request_frequency >= 300 or packet_size >= 1300:
                attack_type = "dos"
            elif request_frequency >= 120 and packet_size <= 200:
                attack_type = "port_scan"
            else:
                attack_type = "network_intrusion"

        severity = self.compute_severity(attack_type, confidence)
        
        return {
            "Threat_Detected": threat_detected,
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "severity": severity,
            "input_features": {
                "packet_size": packet_size,
                "failed_logins": failed_logins,
                "request_frequency": request_frequency
            }
        }

    def predict_network_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive threat detection on full telemetry record using
        full multi-class Random Forest + Isolation Forest.
        """
        df_single = pd.DataFrame([record])
        df_eng = self.feature_engineer.transform(df_single)

        # 1. Supervised multi-class prediction
        if self.full_model is not None and self.label_encoder is not None:
            y_pred_idx = self.full_model.predict(df_eng)[0]
            probs = self.full_model.predict_proba(df_eng)[0]
            confidence = float(np.max(probs))
            attack_type = self.label_encoder.inverse_transform([y_pred_idx])[0]
        else:
            # Fallback to deploy model
            deploy_res = self.predict_doc_features(
                record.get("packet_size", 500),
                record.get("failed_logins", 0),
                record.get("request_frequency", 20)
            )
            return deploy_res

        # 2. Unsupervised Anomaly Detection via Isolation Forest
        anomaly_detected = False
        anomaly_score = 0.0
        if self.iso_forest is not None:
            try:
                # Detector step inside pipeline
                iso_prep = self.iso_forest.named_steps["preprocessor"]
                iso_model = self.iso_forest.named_steps["detector"]
                
                # Transform using fitted preprocessor
                transformed = iso_prep.transform(df_eng)
                raw_score = iso_model.decision_function(transformed)[0]
                is_outlier = iso_model.predict(transformed)[0] == -1
                
                anomaly_score = round(float(raw_score), 4)
                if is_outlier and attack_type == "normal":
                    anomaly_detected = True
                    attack_type = "anomaly"
                    confidence = 0.72
            except Exception as e:
                logger.debug(f"Isolation Forest inference skipped: {e}")

        threat_detected = (attack_type != "normal")
        severity = self.compute_severity(attack_type, confidence, anomaly_detected)

        return {
            "Threat_Detected": threat_detected,
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "severity": severity,
            "anomaly_detected": anomaly_detected,
            "anomaly_score": anomaly_score,
            "src_ip": record.get("src_ip", "0.0.0.0"),
            "dst_ip": record.get("dst_ip", "0.0.0.0")
        }

    def predict_phishing(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classifies URL indicators for phishing attacks."""
        if self.phish_model is None:
            raise RuntimeError("Phishing model not loaded.")
        # Enforce exact training column order
        PHISHING_COLS = [
            "url_length", "has_ip_in_url", "num_special_chars",
            "https_flag", "domain_age_days", "num_redirects", "suspicious_keywords"
        ]
        row = {col: features.get(col, 0) for col in PHISHING_COLS}
        df = pd.DataFrame([row], columns=PHISHING_COLS)
        pred = self.phish_model.predict(df)[0]
        probs = self.phish_model.predict_proba(df)[0]
        confidence = float(np.max(probs))
        threat = bool(pred == 1)
        return {
            "Threat_Detected": threat,
            "attack_type": "phishing" if threat else "normal",
            "confidence": round(confidence, 4),
            "severity": "HIGH" if threat else "INFORMATIONAL"
        }

    def predict_malware(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classifies host telemetry for malware activity."""
        if self.malware_model is None:
            raise RuntimeError("Malware model not loaded.")
        # Enforce exact training column order
        MALWARE_COLS = [
            "api_call_count", "registry_changes", "files_modified",
            "network_connections", "entropy", "memory_usage_mb", "execution_time_sec"
        ]
        row = {col: features.get(col, 0) for col in MALWARE_COLS}
        df = pd.DataFrame([row], columns=MALWARE_COLS)
        pred = self.malware_model.predict(df)[0]
        probs = self.malware_model.predict_proba(df)[0]
        confidence = float(np.max(probs))
        threat = bool(pred == 1)
        return {
            "Threat_Detected": threat,
            "attack_type": "malware" if threat else "normal",
            "confidence": round(confidence, 4),
            "severity": "CRITICAL" if threat else "INFORMATIONAL"
        }
