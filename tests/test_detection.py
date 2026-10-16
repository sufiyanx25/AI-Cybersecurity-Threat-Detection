"""
Unit tests for ThreatDetector, SOC severity calculation, and AlertEngine.
"""

import os
import pytest
from src.detection.detector import ThreatDetector
from src.detection.alert_engine import AlertEngine

def test_compute_severity_logic():
    detector = ThreatDetector(models_dir="models")
    
    # DoS with high confidence -> CRITICAL
    assert detector.compute_severity("dos", 0.85) == "CRITICAL"
    # Brute force with moderate confidence -> HIGH
    assert detector.compute_severity("brute_force", 0.70) == "HIGH"
    # Port scan with moderate confidence -> MEDIUM
    assert detector.compute_severity("port_scan", 0.65) == "MEDIUM"
    # Normal -> INFORMATIONAL
    assert detector.compute_severity("normal", 0.99) == "INFORMATIONAL"

def test_alert_engine_logging_and_deduplication(tmp_path):
    alerts_dir = str(tmp_path / "alerts")
    engine = AlertEngine(alerts_dir=alerts_dir, dedup_window_sec=1.0)
    
    detection_res = {
        "Threat_Detected": True,
        "attack_type": "dos",
        "confidence": 0.92,
        "severity": "CRITICAL",
        "src_ip": "185.220.101.5",
        "dst_ip": "192.168.1.10"
    }
    
    # First alert should emit
    a1 = engine.emit_alert(detection_res, print_console=False)
    assert a1 is not None
    assert os.path.exists(engine.jsonl_path)
    assert os.path.exists(engine.csv_path)
    
    # Immediate duplicate from same IP should be rate-limited
    a2 = engine.emit_alert(detection_res, print_console=False)
    assert a2 is None
    
    # Different IP should emit
    detection_res_diff_ip = detection_res.copy()
    detection_res_diff_ip["src_ip"] = "194.26.29.1"
    a3 = engine.emit_alert(detection_res_diff_ip, print_console=False)
    assert a3 is not None
