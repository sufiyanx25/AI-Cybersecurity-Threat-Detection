# Known Problems in the Source Document's Code — and How This Project Fixes Each

## Fix 1: Missing Dataset (CICIDS2017.csv)

**Problem in Doc:** `pd.read_csv("CICIDS2017.csv")` — the file is never available offline.

**Fix Applied:** `src/data/generate_dataset.py` generates a seeded 52,000-row synthetic dataset
(`data/raw/network_traffic.csv`) with realistic NSL-KDD/CICIDS-style columns at runtime.
`src/data/loader.py` auto-detects if a real CICIDS2017.csv or NSL-KDD file is dropped into
`data/raw/` and normalises its schema automatically. No manual download required.

---

## Fix 2: Training Feature Mismatch (All Columns vs 3 API Features)

**Problem in Doc:** The doc trains on all numeric columns but the API only sends 3 features
(`packet_size`, `failed_logins`, `request_frequency`), causing a shape mismatch crash.

**Fix Applied:** Two separate model artifacts:
- `models/cybersecurity_model.pkl` — **Deployment pipeline** trained on exactly the 3 doc features.
  Used by `POST /predict` in `app.py`.
- `models/full_model.pkl` — **Full multi-class model** trained on all 13 engineered features.
  Used for richer analysis, simulation scoring and the full detection engine.

---

## Fix 3: Scaler Not Saved with the API Model

**Problem in Doc:** Data is scaled at training time with `StandardScaler()`, but the API applies
raw features directly to the model — a classic training-serving skew bug that silently corrupts
predictions.

**Fix Applied:** `src/preprocessing/pipeline.py::build_doc_deployment_pipeline()` wraps the
`StandardScaler` and `RandomForestClassifier` inside a single sklearn `Pipeline` object.
Both the scaler and model are saved together as `cybersecurity_model.pkl`. The Flask API
calls `pipeline.predict()` — the scaler is applied automatically, identically to training.

---

## Fix 4: `bool(prediction[0])` Breaks on Multi-Class Labels

**Problem in Doc:** For a 7-class model the raw class label is a string like `"dos"`, and
`bool("dos")` is always `True`. Even for numeric multi-class encodings, `bool(np.int64(0)) == False`
while `bool(np.int64(3)) == True`, giving misleading results.

**Fix Applied:** `src/detection/detector.py::predict_doc_features()` uses:
```python
threat_detected = bool(raw_pred != 0)   # binary: 0=normal, 1=threat
```
The deployment model is trained on a **binary** binary target (0 = normal, 1 = any threat),
so the API always returns a clean boolean. The multi-class attack type is inferred via
heuristic rules on the 3 feature values for richer reporting (`attack_type`, `confidence`,
`severity`).

---

## Fix 5: Doc Sample Returns False — Reality Check

**Problem in Doc:** The original doc states the sample `{"packet_size":1500,"failed_logins":5,
"request_frequency":250}` returns `Threat_Detected: false`. This is incorrect: 5 failed logins
is strongly indicative of brute-force activity.

**Fix Applied:** Our model, trained on realistic synthetic data with clear attack signatures,
correctly returns `Threat_Detected: true, attack_type: "brute_force"` for this input. This is
documented honestly in README.md and FINAL_REPORT.md. We do not fake results to match the doc.

---

## Fix 6: No Input Validation in the API

**Problem in Doc:** No validation — missing fields or wrong types cause cryptic server 500 errors.

**Fix Applied:** `app.py::predict()` validates all required fields, checks numeric types,
and returns HTTP 400 with a structured `{"error": "...", "expected_format": {...}}` response.

---

## Fix 7: No Anomaly Detection Integration

**Problem in Doc:** Mentions Isolation Forest in interview Q&A but never implements it.

**Fix Applied:** `src/models/train.py::train_isolation_forest()` trains on benign-only traffic.
`src/detection/detector.py::predict_network_record()` runs both the supervised RF and the
Isolation Forest, combining scores: if the RF says "normal" but the IF flags an outlier, the
record is classified as `"anomaly"` with severity `"MEDIUM"`.

---

## Fix 8: No Phishing or Malware Detection

**Problem in Doc:** The objectives mention phishing and malware, but no code implements them.

**Fix Applied:**
- `src/data/generate_dataset.py::generate_phishing_dataset()` — URL indicators
- `src/data/generate_dataset.py::generate_malware_dataset()` — host telemetry
- `models/phishing_model.pkl` and `models/malware_model.pkl` — trained RF classifiers
- `app.py` exposes `POST /predict_phishing` and `POST /predict_malware`
