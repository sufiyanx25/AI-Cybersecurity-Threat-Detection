# Architecture — AI-Powered Cybersecurity Threat Detection System

## High-Level Block Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DATA INGESTION LAYER                             │
│  data/raw/network_traffic.csv  |  phishing_urls.csv  |  malware.csv│
│  (Synthetic Generator OR user-dropped NSL-KDD / CICIDS2017)        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  PREPROCESSING PIPELINE                             │
│  src/preprocessing/pipeline.py                                      │
│  ├── Drop Timestamp → extract hour, day_of_week, unusual_hour       │
│  ├── Remove duplicates, impute NaN (median/mode), clip infinities   │
│  ├── Feature Engineering: bytes_ratio, req_per_conn, burst_score    │
│  ├── OneHotEncoder(protocol_type, service, flag)                    │
│  ├── StandardScaler(numeric columns)                                │
│  └── Stratified 80/20 train/test split (random_state=42)           │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
              ┌─────────────────┴──────────────────┐
              ▼                                    ▼
┌─────────────────────────┐          ┌─────────────────────────────┐
│ DEPLOYMENT MODEL        │          │  FULL MULTI-CLASS MODEL      │
│ (3 features only)       │          │  (all engineered features)   │
│                         │          │                              │
│ sklearn Pipeline:       │          │ sklearn Pipeline:            │
│  StandardScaler +       │          │  ColumnTransformer +         │
│  RandomForestClassifier │          │  RandomForestClassifier      │
│  (binary: Normal/Threat)│          │  (7-class: dos, brute_force  │
│                         │          │   port_scan, phishing,       │
│ Saved: cybersecurity_   │          │   malware, unauth, normal)   │
│        model.pkl        │          │ Saved: full_model.pkl        │
└─────────────────────────┘          └─────────────────────────────┘
                                                    │
                                                    ▼
                                    ┌─────────────────────────────┐
                                    │ ISOLATION FOREST            │
                                    │ (Unsupervised Anomaly)      │
                                    │ Trained on normal-only data │
                                    │ Saved: isolation_forest.pkl │
                                    └─────────────────────────────┘
              │                                     │
              └──────────────┬──────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  THREAT SCORING ENGINE                              │
│  src/detection/detector.py — ThreatDetector                        │
│  ├── Supervised classification (RF) → attack_type, confidence       │
│  ├── Unsupervised check (IF) → anomaly_score                        │
│  ├── Hybrid decision: if RF=normal AND IF=outlier → "anomaly"       │
│  └── Severity mapping: INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL│
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   SOC ALERTING ENGINE                               │
│  src/detection/alert_engine.py — AlertEngine                       │
│  ├── Deduplication / rate limiting (per src_ip:attack_type)         │
│  ├── Colored console output (colorama)                              │
│  ├── outputs/alerts/alerts.jsonl  (structured JSONL audit trail)    │
│  └── outputs/alerts/alerts.csv   (spreadsheet-friendly)            │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
              ┌─────────────────┴──────────────────┐
              ▼                                    ▼
┌─────────────────────────┐          ┌─────────────────────────────┐
│  FLASK REST API          │          │  VISUALIZATION LAYER         │
│  app.py                  │          │  src/visualization/          │
│  ├── POST /predict       │          │  ├── plots.py (10 charts)    │
│  ├── POST /predict_batch │          │  └── dashboard_gen.py        │
│  ├── POST /predict_phish │          │                              │
│  ├── POST /predict_malwr │          │  outputs/plots/*.png         │
│  ├── GET  /health        │          │  outputs/dashboard.html      │
│  ├── GET  /alerts        │          │  images/ (proof assets)      │
│  ├── GET  /metrics       │          └─────────────────────────────┘
│  └── GET  /dashboard     │
└─────────────────────────┘
```

## Module-by-Module Description

| Module | File | Responsibility |
|--------|------|----------------|
| Dataset Generator | `src/data/generate_dataset.py` | Creates 52K network + 5K phishing + 5K malware rows |
| Loader | `src/data/loader.py` | Auto-detects & normalises CICIDS/NSL-KDD schemas |
| Pipeline | `src/preprocessing/pipeline.py` | Cleaning, FE, encoders, splits |
| Train | `src/models/train.py` | RF, LR, IF, Phishing, Malware model training + tuning |
| Evaluate | `src/models/evaluate.py` | Feature importance, ROC, FPR analysis |
| Detector | `src/detection/detector.py` | Hybrid inference (supervised + unsupervised) |
| Alert Engine | `src/detection/alert_engine.py` | SOC alert generation + deduplication + audit logs |
| Simulator | `src/detection/simulate_attack_stream.py` | Live-stream replay of scripted attacks |
| Plots | `src/visualization/plots.py` | 10 diagnostic + operational charts |
| Dashboard | `src/visualization/dashboard_gen.py` | Static HTML SOC console |
| API | `app.py` | Flask REST endpoints |
| CLI | `main.py` | Argparse command-line interface |
| Runner | `run_all.py` | One-command full pipeline execution |
