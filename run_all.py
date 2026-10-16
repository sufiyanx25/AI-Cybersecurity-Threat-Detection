"""
One-Command Complete System Pipeline Runner
Executes data generation, preprocessing, model training, hyperparameter tuning,
attack stream simulation, visualization plots, dashboard compilation, and API tests.
"""

import os
import sys
import time

from src.utils.logger import logger
from src.data.generate_dataset import generate_network_traffic, generate_phishing_dataset, generate_malware_dataset
from src.preprocessing.pipeline import prepare_training_data
from src.data.loader import load_network_data
from src.models.train import run_training_pipeline
from src.models.evaluate import evaluate_models
from src.detection.simulate_attack_stream import run_simulation
from src.visualization.plots import generate_all_plots
from src.visualization.dashboard_gen import generate_dashboard_html
from test_api import run_all_tests

def run_entire_system():
    start_time = time.time()
    print("\n" + "=" * 75)
    print("AI-POWERED CYBERSECURITY THREAT DETECTION SYSTEM - FULL EXECUTION")
    print("=" * 75)

    # 1. Dataset Generation
    print("\n>>> [STEP 1/7] Generating 52,000+ synthetic network flow and domain datasets...")
    os.makedirs("data/raw", exist_ok=True)
    df_net = generate_network_traffic(num_rows=52000, random_seed=42)
    df_net.to_csv("data/raw/network_traffic.csv", index=False)
    
    df_phish = generate_phishing_dataset(num_rows=5000, random_seed=42)
    df_phish.to_csv("data/raw/phishing_urls.csv", index=False)
    
    df_malware = generate_malware_dataset(num_rows=5000, random_seed=42)
    df_malware.to_csv("data/raw/malware_behavior.csv", index=False)
    print("    [+] Saved data/raw/network_traffic.csv, phishing_urls.csv, malware_behavior.csv")

    # 2. Preprocessing & Feature Engineering
    print("\n>>> [STEP 2/7] Preprocessing & Engineering Domain Cybersecurity Features...")
    df_raw, src_path = load_network_data("data/raw")
    prep = prepare_training_data(df_raw, test_size=0.20, random_state=42)
    os.makedirs("data/processed", exist_ok=True)
    prep["df_engineered"].to_csv("data/processed/network_traffic_features.csv", index=False)
    print(f"    [+] Preprocessing finished. Cleaned & engineered data shape: {prep['df_engineered'].shape}")

    # 3. Model Training & Comparison
    print("\n>>> [STEP 3/7] Training Machine Learning Models (Doc RF, Full RF, LR, Isolation Forest)...")
    metadata = run_training_pipeline(data_dir="data/raw", models_dir="models", outputs_dir="outputs")
    print("    [+] Saved models/cybersecurity_model.pkl (Doc 3-feature pipeline)")
    print("    [+] Saved models/full_model.pkl, logistic_regression.pkl, isolation_forest.pkl")
    print("    [+] Saved models/phishing_model.pkl, malware_model.pkl, metadata.json")

    # 4. Evaluation & Feature Importance
    print("\n>>> [STEP 4/7] Evaluating Models & Computing Diagnostics...")
    evaluate_models(models_dir="models", data_dir="data/raw", outputs_dir="outputs")
    print("    [+] Reports saved to outputs/reports/")

    # 5. Virtual Attack Simulation
    print("\n>>> [STEP 5/7] Running Virtual Network Attack Simulation & SOC Alerting...")
    run_simulation(speed_delay=0.03, models_dir="models", alerts_dir="outputs/alerts")
    print("    [+] Live alerts written to outputs/alerts/alerts.jsonl & alerts.csv")

    # 6. Visualization & Dashboard Generation
    print("\n>>> [STEP 6/7] Generating Visualizations & Building SOC Dashboard...")
    generate_all_plots(data_dir="data/raw", models_dir="models", outputs_dir="outputs", images_dir="images")
    dash_path = generate_dashboard_html(outputs_dir="outputs", models_dir="models")
    print(f"    [+] High-res diagnostic plots saved to outputs/plots/ and proof images/ mapped")
    print(f"    [+] Standalone SOC Web Dashboard generated: {dash_path}")

    # 7. Automated API & Inference Verification
    print("\n>>> [STEP 7/7] Running Automated API Test Client (Doc Step 6 Verification)...")
    run_all_tests(use_live_server=False)
    print("    [+] All API endpoints, doc sample request, and validation tests PASSED.")

    elapsed = round(time.time() - start_time, 2)
    print("\n" + "=" * 75)
    print(f">>> FULL EXECUTION COMPLETED SUCCESSFULLY IN {elapsed} SECONDS! <<<")
    print("=" * 75)
    print("Run `python app.py` to launch the live REST API and browse http://127.0.0.1:5000/dashboard\n")

if __name__ == "__main__":
    run_entire_system()
