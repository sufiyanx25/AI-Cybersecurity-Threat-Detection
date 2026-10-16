# Future Improvements

## 1. Real-Time Streaming with Apache Kafka
Replace file-based processing with event-driven streaming:
- **Kafka Producer** sends network flow records to `threat-events` topic
- **Kafka Consumer** calls `detector.predict_network_record()` on each message
- Alerts published to `soc-alerts` topic → SIEM or Elasticsearch

## 2. SIEM Integration
- **Splunk:** Export `alerts.jsonl` via HTTP Event Collector (HEC) API
- **IBM QRadar:** Format alerts as CEF (Common Event Format) Syslog
- **Elastic SIEM / OpenSearch:** Index alerts.jsonl to Elasticsearch and visualise in Kibana

## 3. Deep Learning Models
- **LSTM Autoencoder** for temporal anomaly detection across sequential flow windows
- **1D-CNN** on raw packet byte features for malware classification
- **GRU-based** sequence model for detecting slow-burn APT (Advanced Persistent Threats)
- Replace or supplement `full_model.pkl` — Flask API interface stays identical

## 4. Explainability with SHAP
```python
import shap
explainer = shap.TreeExplainer(deploy_model.named_steps["classifier"])
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
```
Enables SOC analysts to understand *why* a specific flow was flagged — critical for enterprise adoption.

## 5. Threat Intelligence Feed Integration
- Query **VirusTotal API** for source IP reputation scoring
- Enrich `geo_risk` feature with **MaxMind GeoIP2** real ASN data
- Cross-reference **AbuseIPDB** blocklists for known attacker IPs
- Integrate **MITRE ATT&CK** technique mapping to each attack type

## 6. Interactive Grafana / Streamlit Dashboard
- **Grafana:** Connect Prometheus metrics from Flask, display attack trends, ROC AUC drift
- **Streamlit:** Interactive dashboard with live model inference, threshold sliders, and SHAP plots
- Replace static `dashboard.html` with a live-updating dark-mode console

## 7. Automated Incident Response Playbooks
- **Firewall Integration:** Automatically block attacker IPs via pfSense/iptables API
- **Active Directory:** Disable compromised user accounts on brute-force detection
- **PagerDuty/Slack:** Send CRITICAL alerts to on-call SOC engineer's phone

## 8. Model Drift Monitoring
- Track incoming feature distributions with Population Stability Index (PSI)
- Alert when accuracy on labeled production samples drops below threshold
- Automated retraining pipeline triggered by drift detection

## 9. Federated Learning for Privacy-Preserving Detection
- Train across multiple enterprise networks without centralising raw flow data
- Each organisation trains a local model; only model weights are shared and aggregated

## 10. Zero-Day Detection with Active Learning
- Unknown attack patterns flagged by Isolation Forest are queued for human labelling
- Labelled samples are added to training set and model is periodically retrained
- Reduces false negative rate over time as the system learns new attack signatures
