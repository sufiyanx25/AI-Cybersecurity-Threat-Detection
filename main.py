"""
AI Cybersecurity Threat Detection System - Unified Command Line Interface
Usage:
  python main.py generate-data [--rows 52000]
  python main.py preprocess
  python main.py train
  python main.py evaluate
  python main.py detect --file <path_to_csv>
  python main.py simulate [--speed 0.1]
  python main.py plots
  python main.py serve [--port 5000]
  python main.py all
"""

import os
import sys
import argparse
import pandas as pd

from src.utils.logger import logger

def cmd_generate_data(rows: int = 52000):
    from src.data.generate_dataset import generate_network_traffic, generate_phishing_dataset, generate_malware_dataset
    os.makedirs("data/raw", exist_ok=True)
    df_net = generate_network_traffic(num_rows=rows)
    df_net.to_csv("data/raw/network_traffic.csv", index=False)
    
    df_phish = generate_phishing_dataset(num_rows=5000)
    df_phish.to_csv("data/raw/phishing_urls.csv", index=False)
    
    df_malware = generate_malware_dataset(num_rows=5000)
    df_malware.to_csv("data/raw/malware_behavior.csv", index=False)
    print(f"[OK] Generated {rows} network flow records and domain datasets in data/raw/")

def cmd_preprocess():
    from src.data.loader import load_network_data
    from src.preprocessing.pipeline import prepare_training_data
    df, path = load_network_data("data/raw")
    prep = prepare_training_data(df)
    os.makedirs("data/processed", exist_ok=True)
    prep["df_engineered"].to_csv("data/processed/network_traffic_features.csv", index=False)
    print(f"[OK] Preprocessed dataset from {path}. Cleaned & engineered features saved to data/processed/")

def cmd_train():
    from src.models.train import run_training_pipeline
    metadata = run_training_pipeline(data_dir="data/raw", models_dir="models", outputs_dir="outputs")
    print("[OK] Training complete. Artifacts saved to models/ and outputs/reports/")

def cmd_evaluate():
    from src.models.evaluate import evaluate_models
    evaluate_models(models_dir="models", data_dir="data/raw", outputs_dir="outputs")
    print("[OK] Evaluation complete.")

def cmd_detect_file(filepath: str):
    from src.detection.detector import ThreatDetector
    detector = ThreatDetector(models_dir="models")
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        return
    df = pd.read_csv(filepath)
    print(f"[*] Running threat detection on {len(df)} records from {filepath}...")
    threats = 0
    for idx, row in df.iterrows():
        rec = row.to_dict()
        res = detector.predict_network_record(rec)
        if res["Threat_Detected"]:
            threats += 1
            print(f"  [ALERT] Row {idx}: {res['attack_type']} (Severity: {res['severity']}, Conf: {res['confidence']:.2f})")
    print(f"[SUMMARY] Total records: {len(df)} | Threats flagged: {threats}")

def cmd_simulate(speed: float = 0.1):
    from src.detection.simulate_attack_stream import run_simulation
    run_simulation(speed_delay=speed, models_dir="models", alerts_dir="outputs/alerts")

def cmd_plots():
    from src.visualization.plots import generate_all_plots
    from src.visualization.dashboard_gen import generate_dashboard_html
    generate_all_plots(data_dir="data/raw", models_dir="models", outputs_dir="outputs", images_dir="images")
    generate_dashboard_html(outputs_dir="outputs", models_dir="models")
    print("[OK] Plots generated in outputs/plots/, images/ and dashboard in outputs/dashboard.html")

def cmd_serve(port: int = 5000):
    from app import app
    print(f"[*] Starting REST API on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)

def cmd_all():
    from run_all import run_entire_system
    run_entire_system()

def main():
    parser = argparse.ArgumentParser(description="AI Cybersecurity Threat Detection System CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    p_gen = subparsers.add_parser("generate-data", help="Generate synthetic datasets")
    p_gen.add_argument("--rows", type=int, default=52000, help="Number of flow records (default: 52000)")

    subparsers.add_parser("preprocess", help="Clean data and engineer cyber features")
    subparsers.add_parser("train", help="Train and benchmark all ML models")
    subparsers.add_parser("evaluate", help="Compute metrics and feature rankings")

    p_det = subparsers.add_parser("detect", help="Run detection on a CSV file")
    p_det.add_argument("--file", type=str, required=True, help="Path to CSV file with network records")

    p_sim = subparsers.add_parser("simulate", help="Run live attack simulation")
    p_sim.add_argument("--speed", type=float, default=0.1, help="Delay between packet events in seconds")

    subparsers.add_parser("plots", help="Generate all visualization charts and dashboard")

    p_srv = subparsers.add_parser("serve", help="Launch Flask REST API")
    p_srv.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")

    subparsers.add_parser("all", help="Execute complete lifecycle pipeline end-to-end")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate-data":
        cmd_generate_data(rows=args.rows)
    elif args.command == "preprocess":
        cmd_preprocess()
    elif args.command == "train":
        cmd_train()
    elif args.command == "evaluate":
        cmd_evaluate()
    elif args.command == "detect":
        cmd_detect_file(filepath=args.file)
    elif args.command == "simulate":
        cmd_simulate(speed=args.speed)
    elif args.command == "plots":
        cmd_plots()
    elif args.command == "serve":
        cmd_serve(port=args.port)
    elif args.command == "all":
        cmd_all()

if __name__ == "__main__":
    main()
