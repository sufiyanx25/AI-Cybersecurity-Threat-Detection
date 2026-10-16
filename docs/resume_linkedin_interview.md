# Resume, LinkedIn & Interview Preparation Guide

## 3 Resume Bullets

- **Built AI-Powered Cybersecurity Threat Detection System** using Python, scikit-learn Random Forest and Isolation Forest; achieved **98.17% accuracy** detecting DoS, brute-force, port scan, phishing and malware across 52,000+ flow records with real-time SOC alerting via Flask REST API.
- **Designed 7-endpoint Flask REST API** for real-time threat scoring (POST /predict, /predict_phishing, /predict_malware); implemented sklearn Pipeline to eliminate training-serving skew; validated with 23 automated pytest tests across edge cases and adversarial inputs.
- **Applied MLOps practices** — stratified 80/20 splits, RandomizedSearchCV hyperparameter tuning, joblib model persistence, labeled confusion matrices, ROC-AUC comparison, feature importance analysis, Isolation Forest anomaly detection, and JSON structured audit logging.

---

## 3 LinkedIn Project Descriptions

1. *"Developed an AI-powered network intrusion detection system that classifies 7 attack categories (DoS, brute force, port scan, phishing, malware, unauthorized access) in real time. Built with Random Forest (98.17% accuracy), Logistic Regression baseline, and Isolation Forest for unsupervised anomaly detection. Deployed as a Flask REST API with SOC alerting. Stack: Python, scikit-learn, Flask, pandas, matplotlib, pytest."*

2. *"Built a full-stack ML-based SOC (Security Operations Center) pipeline for cybersecurity threat detection — from synthetic data generation mimicking CICIDS/NSL-KDD benchmarks, through preprocessing pipelines, model training with hyperparameter tuning, to a live REST API and self-contained HTML dashboard. Covers the complete ML lifecycle: data → model → API → alerts → visualization."*

3. *"Simulated real-world cyber threats including DoS floods, SSH brute-force credential stuffing, port reconnaissance, phishing gateway ingress, C2 malware beaconing, and off-hours privilege escalation. Each attack scenario feeds through a trained Random Forest classifier + Isolation Forest anomaly detector that triggers structured SOC alerts with severity ratings and automated response recommendations."*

---

## HR-Level Explanation

"I built an artificial intelligence system that helps protect computer networks by automatically detecting cyber attacks. The system works like a smart security guard — it analyses the pattern of network traffic (how much data is being sent, how many failed login attempts, how fast requests come in) and instantly classifies whether it looks like a normal user or an attacker. When it detects a threat like a hacking attempt or malware infection, it raises an alert just like a real security team would."

---

## Technical Explanation

"The system uses a Random Forest ensemble classifier trained on 52,000 synthetic network flow records with NSL-KDD/CICIDS-style features. A Stratified 80/20 split prevents class imbalance leakage. The model is wrapped in a sklearn Pipeline with StandardScaler, ensuring identical preprocessing at training and inference time. An Isolation Forest trained on benign-only traffic provides unsupervised anomaly detection as a second layer. All models are persisted with joblib and served via a Flask REST API. Input validation, structured JSON logging, and a rate-limited SOC alert engine complete the production-grade implementation."

---

## Industry Relevance Explanation

"Companies like Google (Chronicle SIEM), Microsoft (Defender for Endpoint), IBM Security (QRadar), Palo Alto Networks (Cortex XDR), and every major bank use exactly these techniques. They run supervised classifiers on network flow features to flag intrusions, unsupervised anomaly detectors for zero-day threats, and REST APIs to integrate detections into SIEM platforms. My system demonstrates this complete pipeline at a portfolio scale, showing I understand the production-ready implementation pattern."

---

## 10 Source Document Interview Q&As (Expanded)

**Q1: What ML algorithms did you use?**
Random Forest (primary — 100+ estimators, balanced class weights), Logistic Regression (baseline for comparison), and Isolation Forest (unsupervised anomaly detection trained on normal traffic only). Each serves a different role: RF for accurate classification, LR as an interpretable benchmark, IF to catch novel attacks not seen in training.

**Q2: What metrics did you use to evaluate the model?**
Accuracy (98.17%), Precision (98.17%), Recall/TPR (98.17%), F1-score (98.17%), ROC-AUC (0.9955), per-class precision/recall/F1 (classification_report), confusion matrix (binary and 7-class), and false positive rate. In cybersecurity, recall is prioritised over precision — a missed attack (false negative) is more dangerous than a false alarm.

**Q3: How did you handle imbalanced data?**
`class_weight="balanced"` in sklearn automatically adjusts sample weights inversely proportional to class frequency. The Stratified split ensures all 7 attack classes are represented in both train and test. Optionally, SMOTE (from imbalanced-learn) can be applied if installed.

**Q4: Why Random Forest over simpler models?**
RF handles non-linear relationships between features (e.g., burst_score × failed_logins interaction) that logistic regression misses. It's inherently resistant to outliers, provides native feature importance scores, and doesn't require extensive feature scaling.

**Q5: What features did you use?**
13 engineered features: `duration`, `src_bytes`, `dst_bytes`, `packet_size`, `failed_logins`, `request_frequency`, `num_connections`, `login_attempts`, `geo_risk`, `bytes_ratio` (src/dst ratio), `req_per_conn` (requests per connection), `failed_login_rate`, `burst_score` (packet_size × frequency). Plus categorical: `protocol_type`, `service`, `flag`.

**Q6: How do you handle categorical variables?**
OneHotEncoder inside a ColumnTransformer Pipeline. `handle_unknown="ignore"` prevents crashes on unseen categories at inference time. All encoding is done within the sklearn Pipeline so it's applied consistently at both training and prediction.

**Q7: What is Isolation Forest?**
An unsupervised anomaly detection algorithm. It randomly partitions features and measures how quickly a point gets isolated — anomalies are isolated faster (shorter path length). Trained on benign traffic only; anything flagged as an outlier at inference is classified as anomalous even if the supervised model says "normal".

**Q8: How would you deploy this in production?**
Replace Flask dev server with Gunicorn (`gunicorn -w 4 app:app`). Containerise with the provided Dockerfile. Deploy on AWS Lambda (serverless) via Zappa, Google Cloud Functions, or Azure Container Apps. For streaming: Kafka → consumer → predict() → Elasticsearch/SIEM.

**Q9: What is data leakage and did you prevent it?**
Data leakage occurs when test data information leaks into training (e.g., fitting scaler on all data before splitting). Prevention: all scalers and encoders are fitted only on training data, wrapped inside the sklearn Pipeline and applied to test data via `transform()` only.

**Q10: What's the difference between precision and recall in security?**
Precision = of all alerts raised, how many are real threats (low FP). Recall = of all real threats, how many were caught (low FN). Security prioritises **recall** — missing an attack is worse than a false alarm. This is why `class_weight="balanced"` and a threshold tunable via ROC curve are both used.

---

## 10 Additional Interview Questions

**Q11: What is model drift and how would you detect it?**
Model drift occurs when real traffic distribution shifts away from training data (e.g., new attack variants). Detect with statistical tests (PSI, KS test) on feature distributions, and monitor model accuracy/recall decay on labeled production samples. Retrain periodically with fresh data.

**Q12: What is a SIEM and how would your system integrate with one?**
SIEM (Security Information and Event Management) aggregates logs from network devices and runs correlation rules. This system integrates via its structured JSON alert output: pipe `alerts.jsonl` to Elasticsearch/Kibana (ELK Stack), Splunk (REST API), or IBM QRadar (Syslog/CEF format).

**Q13: How would you handle real-time streaming data?**
Replace file-based processing with Apache Kafka: producers push network flow records to a Kafka topic, consumers call `detector.predict_network_record()` on each message, and alerts are published to another Kafka topic or pushed to SIEM via webhooks.

**Q14: What is a false positive and why does it matter in security?**
False positive = flagging benign traffic as an attack. High FP rates cause SOC alert fatigue — analysts start ignoring alerts. Our model achieves 98.17% precision, reducing false alarms while maintaining high attack recall.

**Q15: How would you add deep learning to this system?**
Replace the RF with an LSTM autoencoder for time-series anomaly detection on sequential flows, or a 1D-CNN on raw packet byte sequences. The Flask API endpoint signature stays identical — only the `models/` artifact changes.

**Q16: What is feature importance and which features were most predictive?**
Gini-based feature importance from the Random Forest. Top features: `burst_score` (high for DoS/brute-force), `req_per_conn` (elevated for port scans), `num_connections` (DoS indicator), `bytes_ratio` (malware exfiltration = high src, low dst), `failed_login_rate` (brute force).

**Q17: How did you prevent overfitting?**
Stratified k-fold cross-validation (3-fold), `min_samples_split` constraints, `max_depth` limits in GridSearch, and evaluation on a completely held-out test set (20%). The synthetic data has intentional noise and overlap between classes to prevent artificially perfect boundaries.

**Q18: What is the ROC-AUC and what does it mean here?**
Area Under the ROC Curve measures how well the model separates threats from normal traffic across all confidence thresholds. AUC = 0.9955 means the model nearly perfectly ranks a threat above a benign flow 99.55% of the time.

**Q19: How would you explain this project to a bank CISO?**
"This system monitors every network connection entering your infrastructure and uses machine learning trained on historical attack patterns to instantly flag suspicious behaviour — brute-force login attempts, DDoS traffic, internal machines calling out to known C2 servers — before your security team even opens their laptop. Each alert includes the attack type, confidence level, source IP, and the recommended response action."

**Q20: What would you improve with more time?**
SHAP explainability (why was this flagged?), streaming with Kafka, LSTM autoencoder for temporal patterns, threat intelligence API enrichment (VirusTotal, AbuseIPDB), Grafana dashboard with live metrics, A/B model testing, and automated response playbooks (block IP via firewall API).
