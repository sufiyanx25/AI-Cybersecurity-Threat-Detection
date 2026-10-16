# Troubleshooting Guide

## Installation Issues

### `pip install -r requirements.txt` Fails — Dependency Conflict
**Reason:** Conflicting package versions or outdated pip.
**Solution:**
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### `ModuleNotFoundError: No module named 'src'`
**Reason:** Running scripts from the wrong directory.
**Solution:** Always run from the project root:
```bash
cd "AI-Powered Cybersecurity Threat Detection – Complete Project Execution Guide Final"
python run_all.py
```

### `numpy` / `scikit-learn` version incompatibility
**Reason:** Python 3.14 may not have prebuilt wheels for some packages.
**Solution:** Use Python 3.12 (the tested version):
```bash
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

---

## Dataset Issues

### `FileNotFoundError: No dataset found in data/raw`
**Reason:** Datasets not generated yet.
**Solution:**
```bash
.venv\Scripts\python.exe main.py generate-data
```

### Model predicts everything as normal after adding a real dataset
**Reason:** External dataset label column wasn't mapped. Check `loader.py` normalisation output.
**Solution:** Rename your label column to `Attack_Label` and standardise class names to:
`normal`, `dos`, `brute_force`, `port_scan`, `phishing`, `malware`, `unauthorized_access`

---

## Model Issues

### `models/cybersecurity_model.pkl` not found — API returns 500
**Reason:** `run_all.py` or `main.py train` not run yet.
**Solution:**
```bash
.venv\Scripts\python.exe run_all.py
```

### Model version mismatch (joblib/sklearn version error)
**Reason:** Model pickle was saved with a different sklearn version.
**Solution:** Retrain models with the current environment:
```bash
.venv\Scripts\python.exe main.py train
```

### Model accuracy suspiciously high (99%+) — data leakage?
**Reason:** With synthetic data, patterns are intentionally clear. The 80/20 stratified split
is done *before* any fitting. Check `prepare_training_data()` in `pipeline.py` — scalers are
fitted only on `X_train`. High accuracy on clean synthetic data is expected and not leakage.
See `docs/doc_fixes.md` for the full explanation.

---

## Flask API Issues

### `OSError: [Errno 10048] — Port 5000 already in use`
**Reason:** Another process is on port 5000.
**Solution (Windows):**
```bash
netstat -ano | findstr :5000
taskkill /PID <PID_NUMBER> /F
python app.py
```
Or use a different port:
```bash
python main.py serve --port 5001
```

### API returns HTTP 400 for valid request
**Reason:** Request `Content-Type` is not `application/json`.
**Solution:** Always include the header:
```bash
curl -X POST http://127.0.0.1:5000/predict \
  -H "Content-Type: application/json" \
  -d "{\"packet_size\":1500,\"failed_logins\":5,\"request_frequency\":250}"
```

### `predict_phishing` returns 400 — feature name mismatch
**Reason:** Old model (pre-fix) saved before `detector.py` column-ordering fix.
**Solution:** Retrain: `python main.py train`

---

## Test Issues

### `pytest` cannot find `src` module
**Reason:** `pytest` not run from project root.
**Solution:**
```bash
.venv\Scripts\python.exe -m pytest tests/ -v
```

### `test_isolation_forest_flags_anomalies` fails
**Reason:** Unsupervised Isolation Forest has non-deterministic behaviour on small datasets.
**Solution:** The test uses a 30% recall threshold which accommodates statistical variance.
If still failing, increase training data size: `python main.py generate-data --rows 80000`

---

## Notebook Issues

### nbconvert exits with code 1 but notebooks show output
**Reason:** Windows PowerShell treats stderr output (nbconvert logs) as errors.
The conversion succeeded. Check that notebook files have `"outputs"` populated.

### Kernel dies mid-execution with memory error
**Reason:** Dataset too large for the notebook kernel.
**Solution:** Use `num_rows=2000` in notebook data generation cells.

---

## Git Issues

### `fatal: remote origin already exists`
```bash
git remote remove origin
git remote add origin https://github.com/YOUR_USERNAME/AI-Cybersecurity-Threat-Detection.git
```

### `error: failed to push some refs`
```bash
git pull --rebase origin main
git push origin main
```
