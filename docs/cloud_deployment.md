# Cloud Deployment Guide (Doc Step 7)

## Option A — AWS Lambda with Zappa

```bash
pip install zappa gunicorn
# Create zappa_settings.json:
zappa init
# Deploy:
zappa deploy production
# Invoke:
curl -X POST https://YOUR_ID.execute-api.ap-south-1.amazonaws.com/production/predict \
  -H "Content-Type: application/json" \
  -d '{"packet_size":1500,"failed_logins":5,"request_frequency":250}'
```

**Key Steps:**
1. Store `models/` in S3 — load from `s3://bucket/models/cybersecurity_model.pkl` at cold start
2. Set Lambda memory to 512 MB, timeout 30 seconds
3. Configure API Gateway for POST /predict

---

## Option B — Google Cloud Functions

```python
# main.py (Cloud Function entry point)
import functions_framework, joblib, json
model = joblib.load("cybersecurity_model.pkl")  # Bundle in deployment zip

@functions_framework.http
def predict(request):
    data = request.get_json()
    import pandas as pd
    df = pd.DataFrame([data])[["packet_size","failed_logins","request_frequency"]]
    pred = model.predict(df)[0]
    return json.dumps({"Threat_Detected": bool(pred != 0)})
```

```bash
gcloud functions deploy threat-detector \
  --runtime python312 --trigger-http --allow-unauthenticated \
  --entry-point predict --memory 512MB
```

---

## Option C — Azure Container Apps with Docker

```bash
# Build Docker image using the project's Dockerfile:
docker build -t threat-detector:latest .
docker run -p 5000:5000 threat-detector

# Push to Azure Container Registry:
az acr login --name yourregistry
docker tag threat-detector yourregistry.azurecr.io/threat-detector:latest
docker push yourregistry.azurecr.io/threat-detector:latest

# Deploy as Container App:
az containerapp create \
  --name threat-detector-api \
  --resource-group myRG \
  --image yourregistry.azurecr.io/threat-detector:latest \
  --target-port 5000 --ingress external
```

---

## Production Gunicorn Deployment (Linux/VPS)

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app --timeout 120
```

## Environment Variables for Production

```bash
export FLASK_ENV=production
export MODEL_DIR=/opt/models
export ALERTS_DIR=/var/log/threat-detection/alerts
```
