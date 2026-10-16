"""
Automated Test Client for Cybersecurity Threat Detection API (Doc Step 6)
Sends test requests including the source document sample payload,
benign traffic, DoS, brute force, phishing, malware, and invalid inputs.
"""

import sys
import json
import requests
from typing import Dict, Any

API_BASE_URL = "http://127.0.0.1:5000"

def test_endpoint(name: str, method: str, url: str, payload: Any = None, expected_status: int = 200, client=None) -> Dict[str, Any]:
    """Helper to test an endpoint either via live HTTP requests or Flask test client."""
    print(f"\n[*] Testing: {name} [{method} {url}]")
    if payload:
        print(f"    Payload: {json.dumps(payload)}")
        
    if client:
        # Flask test client
        if method == "GET":
            res = client.get(url)
        else:
            res = client.post(url, json=payload)
        status_code = res.status_code
        try:
            data = res.get_json()
        except Exception:
            data = res.data.decode("utf-8")
    else:
        # Live HTTP request
        full_url = f"{API_BASE_URL}{url}"
        if method == "GET":
            res = requests.get(full_url, timeout=5)
        else:
            res = requests.post(full_url, json=payload, timeout=5)
        status_code = res.status_code
        try:
            data = res.json()
        except Exception:
            data = res.text

    passed = (status_code == expected_status)
    status_str = "PASS" if passed else f"FAIL (Got {status_code}, expected {expected_status})"
    print(f"    Response [{status_code}]: {json.dumps(data) if isinstance(data, dict) else str(data)[:120]}")
    print(f"    Status: [{status_str}]")
    
    if not passed:
        raise AssertionError(f"Test '{name}' failed with status {status_code}!")
    return data


def run_all_tests(use_live_server: bool = True):
    """Executes all API verification tests."""
    client = None
    if not use_live_server:
        from app import app
        app.config["TESTING"] = True
        client = app.test_client()

    print("=" * 65)
    print("AI CYBERSECURITY THREAT DETECTION SYSTEM - API TEST SUITE")
    print("=" * 65)

    # 1. Health check
    test_endpoint("System Health Check", "GET", "/health", expected_status=200, client=client)

    # 2. Source Document Sample Payload (Doc Step 6)
    # Doc sample: {"packet_size": 1500, "failed_logins": 5, "request_frequency": 250}
    doc_payload = {
        "packet_size": 1500,
        "failed_logins": 5,
        "request_frequency": 250
    }
    doc_res = test_endpoint("Source Doc Sample Telemetry (5 Logins, 250 Freq)", "POST", "/predict", payload=doc_payload, expected_status=200, client=client)
    assert "Threat_Detected" in doc_res, "Response must include 'Threat_Detected'"
    print(f"    --> Doc Sample Evaluation: Threat_Detected = {doc_res['Threat_Detected']} ({doc_res.get('attack_type')}, Sev: {doc_res.get('severity')})")

    # 3. Benign Normal Traffic
    normal_payload = {
        "packet_size": 520,
        "failed_logins": 0,
        "request_frequency": 18
    }
    norm_res = test_endpoint("Benign Office Network Flow", "POST", "/predict", payload=normal_payload, expected_status=200, client=client)
    print(f"    --> Normal Traffic: Threat_Detected = {norm_res['Threat_Detected']}")

    # 4. Extreme DoS Attack
    dos_payload = {
        "packet_size": 1450,
        "failed_logins": 0,
        "request_frequency": 1200
    }
    dos_res = test_endpoint("High-Volume DoS SYN Flood", "POST", "/predict", payload=dos_payload, expected_status=200, client=client)
    assert dos_res["Threat_Detected"] is True, "DoS flood must be flagged as Threat_Detected: True"

    # 5. SSH Brute-Force Attack
    brute_payload = {
        "packet_size": 480,
        "failed_logins": 16,
        "request_frequency": 280
    }
    brute_res = test_endpoint("SSH Automated Brute-Force", "POST", "/predict", payload=brute_payload, expected_status=200, client=client)
    assert brute_res["Threat_Detected"] is True, "Brute force must be flagged as Threat_Detected: True"

    # 6. Invalid Request: Missing fields
    bad_payload_1 = {"packet_size": 1000}
    test_endpoint("Invalid Input: Missing Fields (Expect 400)", "POST", "/predict", payload=bad_payload_1, expected_status=400, client=client)

    # 7. Invalid Request: Non-numeric data type
    bad_payload_2 = {"packet_size": "NOT_A_NUMBER", "failed_logins": 5, "request_frequency": 100}
    test_endpoint("Invalid Input: Bad Types (Expect 400)", "POST", "/predict", payload=bad_payload_2, expected_status=400, client=client)

    # 8. Phishing Endpoint
    phish_payload = {
        "url_length": 115,
        "has_ip_in_url": 1,
        "num_special_chars": 14,
        "https_flag": 0,
        "domain_age_days": 12,
        "num_redirects": 3,
        "suspicious_keywords": 2
    }
    test_endpoint("Phishing URL Telemetry", "POST", "/predict_phishing", payload=phish_payload, expected_status=200, client=client)

    # 9. Malware Endpoint
    malware_payload = {
        "api_call_count": 920,
        "registry_changes": 22,
        "files_modified": 58,
        "network_connections": 18,
        "entropy": 7.4,
        "memory_usage_mb": 280.0,
        "execution_time_sec": 8.5
    }
    test_endpoint("Host Malware Telemetry", "POST", "/predict_malware", payload=malware_payload, expected_status=200, client=client)

    # 10. Incident Alerts Feed
    test_endpoint("SOC Alerts Feed", "GET", "/alerts", expected_status=200, client=client)

    print("\n" + "=" * 65)
    print(">>> ALL API AND INFERENCE INTEGRATION TESTS PASSED (10/10) <<<")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    # Check if server is running; if not, use test client
    try:
        requests.get(f"{API_BASE_URL}/health", timeout=1)
        run_all_tests(use_live_server=True)
    except Exception:
        print("[!] Live server not responding on localhost:5000. Running tests via Flask test client...")
        run_all_tests(use_live_server=False)
