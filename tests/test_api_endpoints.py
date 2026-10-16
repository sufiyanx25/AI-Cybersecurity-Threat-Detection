"""
Integration tests for Flask API endpoints using pytest.
"""

import pytest
import json
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert "status" in data
    assert "models_loaded" in data

def test_predict_endpoint_doc_sample(client):
    payload = {
        "packet_size": 1500,
        "failed_logins": 5,
        "request_frequency": 250
    }
    res = client.post("/predict", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "Threat_Detected" in data
    assert isinstance(data["Threat_Detected"], bool)
    assert "attack_type" in data
    assert "confidence" in data
    assert "severity" in data

def test_predict_endpoint_missing_fields(client):
    payload = {"packet_size": 1000}
    res = client.post("/predict", json=payload)
    assert res.status_code == 400
    data = res.get_json()
    assert "error" in data

def test_predict_endpoint_invalid_type(client):
    payload = {
        "packet_size": "INVALID",
        "failed_logins": 0,
        "request_frequency": 20
    }
    res = client.post("/predict", json=payload)
    assert res.status_code == 400

def test_predict_batch_endpoint(client):
    payload = [
        {"packet_size": 500, "failed_logins": 0, "request_frequency": 20},
        {"packet_size": 1400, "failed_logins": 10, "request_frequency": 300}
    ]
    res = client.post("/predict_batch", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["batch_size"] == 2
    assert len(data["predictions"]) == 2

def test_predict_phishing_endpoint(client):
    payload = {
        "url_length": 120,
        "has_ip_in_url": 1,
        "num_special_chars": 15,
        "https_flag": 0,
        "domain_age_days": 10,
        "num_redirects": 3,
        "suspicious_keywords": 2
    }
    res = client.post("/predict_phishing", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "Threat_Detected" in data

def test_predict_malware_endpoint(client):
    payload = {
        "api_call_count": 800,
        "registry_changes": 20,
        "files_modified": 40,
        "network_connections": 15,
        "entropy": 7.5,
        "memory_usage_mb": 250,
        "execution_time_sec": 10
    }
    res = client.post("/predict_malware", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "Threat_Detected" in data

def test_dashboard_endpoint(client):
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert b"AI Cybersecurity Threat Detection Center" in res.data
