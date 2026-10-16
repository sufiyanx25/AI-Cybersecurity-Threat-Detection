"""
Flask REST API for AI-Powered Cybersecurity Threat Detection System
Serves the Doc's required POST /predict endpoint, batch scoring, alerts feed,
phishing/malware detectors, and interactive SOC dashboard.
"""

import os
import json
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, render_template_string

from src.utils.logger import logger
from src.detection.detector import ThreatDetector
from src.detection.alert_engine import AlertEngine
from src.visualization.dashboard_gen import generate_dashboard_html

app = Flask(__name__, static_folder="outputs/plots")

# Initialize detection and alert subsystems
detector = ThreatDetector(models_dir="models")
alert_engine = AlertEngine(alerts_dir="outputs/alerts", dedup_window_sec=1.5)

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint indicating model loading status and system uptime."""
    models_ready = (detector.deploy_model is not None)
    return jsonify({
        "status": "healthy" if models_ready else "degraded",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": {
            "deployment_rf": detector.deploy_model is not None,
            "full_rf": detector.full_model is not None,
            "isolation_forest": detector.iso_forest is not None,
            "phishing_rf": detector.phish_model is not None,
            "malware_rf": detector.malware_model is not None
        }
    }), 200


@app.route("/predict", methods=["POST"])
def predict():
    """
    Source Document Core Specification:
    Takes JSON payload: {"packet_size": float, "failed_logins": int, "request_frequency": float}
    Returns: {"Threat_Detected": bool, "attack_type": str, "confidence": float, "severity": str}
    """
    if not request.is_json:
        return jsonify({"error": "Invalid request: Content-Type must be application/json"}), 400

    payload = request.get_json()
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    # Strict validation of required fields
    required_keys = ["packet_size", "failed_logins", "request_frequency"]
    missing = [k for k in required_keys if k not in payload]
    if missing:
        return jsonify({
            "error": f"Missing required fields: {missing}",
            "expected_format": {
                "packet_size": "numeric (e.g. 1500)",
                "failed_logins": "integer (e.g. 5)",
                "request_frequency": "numeric (e.g. 250)"
            }
        }), 400

    # Type validation
    try:
        pkt_size = float(payload["packet_size"])
        logins = int(payload["failed_logins"])
        req_freq = float(payload["request_frequency"])
        if pkt_size < 0 or logins < 0 or req_freq < 0:
            return jsonify({"error": "Telemetry values cannot be negative"}), 400
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Invalid data types for features: {str(e)}"}), 400

    try:
        result = detector.predict_doc_features(
            packet_size=pkt_size,
            failed_logins=logins,
            request_frequency=req_freq
        )
        
        # If threat detected, log SOC alert
        if result["Threat_Detected"]:
            alert_engine.emit_alert(result, record={
                "src_ip": request.remote_addr or "127.0.0.1",
                "dst_ip": "Protected-API-Endpoint"
            }, print_console=True)
            
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Prediction inference error: {e}")
        return jsonify({"error": f"Inference pipeline error: {str(e)}"}), 500


@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    """Scores a batch of telemetry flow records."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    payload = request.get_json()
    if not isinstance(payload, list):
        return jsonify({"error": "Batch payload must be a JSON array of telemetry records"}), 400

    results = []
    for item in payload:
        try:
            res = detector.predict_doc_features(
                packet_size=float(item.get("packet_size", 500)),
                failed_logins=int(item.get("failed_logins", 0)),
                request_frequency=float(item.get("request_frequency", 20))
            )
            results.append(res)
        except Exception as e:
            results.append({"error": str(e)})

    return jsonify({"batch_size": len(results), "predictions": results}), 200


@app.route("/predict_phishing", methods=["POST"])
def predict_phishing():
    """Endpoint for classifying suspicious URL indicators."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json()
    try:
        res = detector.predict_phishing(data)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/predict_malware", methods=["POST"])
def predict_malware():
    """Endpoint for classifying host process telemetry."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json()
    try:
        res = detector.predict_malware(data)
        return jsonify(res), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/alerts", methods=["GET"])
def get_alerts():
    """Returns recent SOC incident alerts."""
    limit = request.args.get("limit", default=50, type=int)
    alerts = alert_engine.get_recent_alerts(limit=limit)
    return jsonify({"count": len(alerts), "alerts": alerts}), 200


@app.route("/metrics", methods=["GET"])
def get_metrics():
    """Returns model metadata, performance metrics and feature rankings."""
    meta_path = "models/metadata.json"
    if os.path.exists(meta_path):
        with open(meta_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f)), 200
    return jsonify({"error": "Model metadata not found. Train models first."}), 404


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Renders the live SOC web console."""
    dash_file = generate_dashboard_html(outputs_dir="outputs", models_dir="models")
    with open(dash_file, "r", encoding="utf-8") as f:
        content = f.read()
    return render_template_string(content)


@app.route("/plots/<path:filename>")
def serve_plot(filename):
    """Serves generated plots for dashboard display."""
    return send_from_directory("outputs/plots", filename)


if __name__ == "__main__":
    logger.info("Starting AI Cybersecurity Threat Detection REST API on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
