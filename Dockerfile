FROM python:3.12-slim

LABEL maintainer="AI Cybersecurity Threat Detection System"
LABEL description="REST API for real-time network intrusion, phishing & malware detection using Random Forest + Isolation Forest"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==21.2.0

# Copy application code
COPY src/ ./src/
COPY app.py .
COPY models/ ./models/

# Create output directories
RUN mkdir -p outputs/alerts outputs/logs outputs/plots data/raw

# Expose the Flask port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5)" || exit 1

# Start production server with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]
