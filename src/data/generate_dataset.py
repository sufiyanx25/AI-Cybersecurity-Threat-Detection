"""
Realistic Synthetic Network Traffic & Cyber Threat Dataset Generator
Simulates NSL-KDD / CICIDS-2017 style flow records, phishing URL indicators,
and host-based malware execution telemetry.
"""

import os
import argparse
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from src.utils.logger import logger

SEED = 42

def generate_network_traffic(num_rows: int = 50000, random_seed: int = SEED) -> pd.DataFrame:
    """
    Generates realistic network flow records with NSL-KDD / CICIDS2017 features.
    Includes normal traffic and multiple cyber attack classes:
    dos, brute_force, port_scan, phishing, malware, unauthorized_access.
    """
    np.random.seed(random_seed)
    logger.info(f"Generating {num_rows} synthetic network traffic records (Seed={random_seed})...")

    # Define label distribution (~75% normal, 25% attacks)
    classes = [
        "normal", "dos", "brute_force", "port_scan", 
        "phishing", "malware", "unauthorized_access"
    ]
    probabilities = [0.75, 0.08, 0.05, 0.04, 0.03, 0.03, 0.02]
    labels = np.random.choice(classes, size=num_rows, p=probabilities)

    # Base timestamp: starting 7 days ago
    start_time = datetime.now() - timedelta(days=7)
    time_offsets_sec = np.sort(np.random.randint(0, 7 * 86400, size=num_rows))
    timestamps = [start_time + timedelta(seconds=int(offset)) for offset in time_offsets_sec]

    # IP pools
    internal_subnets = [f"192.168.1.{i}" for i in range(10, 250)] + [f"10.0.0.{i}" for i in range(10, 250)]
    external_ips = [
        f"203.0.113.{i}" for i in range(1, 100)
    ] + [
        f"198.51.100.{i}" for i in range(1, 100)
    ] + [
        f"45.33.32.{i}" for i in range(1, 50)
    ]
    attacker_subnets = [f"185.220.101.{i}" for i in range(1, 40)] + [f"194.26.29.{i}" for i in range(1, 30)]

    protocols = ["tcp", "udp", "icmp"]
    services = ["http", "https", "ssh", "ftp", "dns", "smtp", "rdp", "smb"]
    flags = ["SF", "S0", "REJ", "RSTO", "RSTR", "SH"]

    data = []

    for i in range(num_rows):
        lbl = labels[i]
        ts = timestamps[i]
        hour = ts.hour
        is_unusual_hour = 1 if (hour < 6 or hour >= 23) else 0

        # Defaults for normal traffic
        src_ip = np.random.choice(internal_subnets)
        dst_ip = np.random.choice(external_ips)
        protocol = np.random.choice(protocols, p=[0.75, 0.22, 0.03])
        service = np.random.choice(services, p=[0.40, 0.35, 0.05, 0.03, 0.12, 0.03, 0.01, 0.01])
        flag = np.random.choice(flags, p=[0.88, 0.05, 0.04, 0.01, 0.01, 0.01])
        duration = float(np.random.exponential(scale=2.5))
        src_bytes = int(np.random.exponential(scale=1200))
        dst_bytes = int(np.random.exponential(scale=4500))
        packet_size = int(np.clip(np.random.normal(loc=550, scale=250), 40, 1500))
        failed_logins = int(np.random.choice([0, 1], p=[0.985, 0.015]))
        request_frequency = int(np.clip(np.random.normal(loc=25, scale=12), 1, 90))
        num_connections = int(np.clip(np.random.poisson(lam=4), 1, 30))
        login_attempts = failed_logins + int(np.random.choice([0, 1], p=[0.7, 0.3]))
        geo_risk = float(np.clip(np.random.beta(a=1.5, b=8.0), 0.0, 1.0))

        # Distinct attack signatures
        if lbl == "dos":
            src_ip = np.random.choice(attacker_subnets)
            protocol = np.random.choice(["tcp", "udp", "icmp"], p=[0.6, 0.3, 0.1])
            service = np.random.choice(["http", "https", "dns"])
            flag = np.random.choice(["S0", "SF", "REJ"], p=[0.7, 0.2, 0.1])
            duration = float(np.random.uniform(0.01, 0.8))
            src_bytes = int(np.random.uniform(2000, 25000))
            dst_bytes = int(np.random.uniform(0, 500))
            packet_size = int(np.clip(np.random.normal(loc=1400, scale=100), 800, 1500))
            failed_logins = 0
            request_frequency = int(np.random.uniform(300, 1800))  # Extreme request burst
            num_connections = int(np.random.uniform(80, 500))
            login_attempts = 0
            geo_risk = float(np.clip(np.random.uniform(0.65, 0.98), 0.0, 1.0))

        elif lbl == "brute_force":
            src_ip = np.random.choice(attacker_subnets)
            protocol = "tcp"
            service = np.random.choice(["ssh", "ftp", "rdp"], p=[0.6, 0.25, 0.15])
            flag = np.random.choice(["SF", "REJ", "RSTO"], p=[0.4, 0.4, 0.2])
            duration = float(np.random.uniform(1.0, 15.0))
            src_bytes = int(np.random.uniform(300, 1800))
            dst_bytes = int(np.random.uniform(200, 1200))
            packet_size = int(np.clip(np.random.normal(loc=480, scale=120), 100, 1000))
            failed_logins = int(np.random.randint(4, 25))  # High failed logins
            request_frequency = int(np.random.uniform(150, 450))  # Rapid automated credential stuffing
            num_connections = int(np.random.randint(15, 60))
            login_attempts = failed_logins + int(np.random.randint(1, 3))
            geo_risk = float(np.clip(np.random.uniform(0.55, 0.95), 0.0, 1.0))

        elif lbl == "port_scan":
            src_ip = np.random.choice(attacker_subnets)
            protocol = np.random.choice(["tcp", "udp"], p=[0.85, 0.15])
            service = np.random.choice(["ssh", "http", "smb", "rdp", "ftp"])
            flag = np.random.choice(["REJ", "S0", "RSTO"], p=[0.55, 0.35, 0.10])
            duration = float(np.random.uniform(0.001, 0.05))
            src_bytes = int(np.random.uniform(40, 120))
            dst_bytes = 0
            packet_size = int(np.random.uniform(40, 120))
            failed_logins = 0
            request_frequency = int(np.random.uniform(180, 800))
            num_connections = int(np.random.uniform(100, 600))  # Probing hundreds of ports
            login_attempts = 0
            geo_risk = float(np.clip(np.random.uniform(0.40, 0.85), 0.0, 1.0))

        elif lbl == "phishing":
            dst_ip = np.random.choice(attacker_subnets)
            protocol = "tcp"
            service = np.random.choice(["http", "https"], p=[0.3, 0.7])
            flag = "SF"
            duration = float(np.random.uniform(2.0, 20.0))
            src_bytes = int(np.random.uniform(800, 3500))
            dst_bytes = int(np.random.uniform(4000, 25000))
            packet_size = int(np.clip(np.random.normal(loc=950, scale=200), 300, 1500))
            failed_logins = int(np.random.choice([0, 1, 2], p=[0.7, 0.2, 0.1]))
            request_frequency = int(np.random.uniform(20, 80))
            num_connections = int(np.random.randint(2, 10))
            login_attempts = failed_logins + 1
            geo_risk = float(np.clip(np.random.uniform(0.60, 0.95), 0.0, 1.0))

        elif lbl == "malware":
            src_ip = np.random.choice(internal_subnets[:10])  # Infected host
            dst_ip = np.random.choice(attacker_subnets)  # C2 server
            protocol = np.random.choice(["tcp", "udp"], p=[0.8, 0.2])
            service = np.random.choice(["https", "dns", "http"], p=[0.5, 0.3, 0.2])
            flag = "SF"
            duration = float(np.random.uniform(0.5, 8.0))
            src_bytes = int(np.random.uniform(1500, 12000))  # Exfiltrating data
            dst_bytes = int(np.random.uniform(500, 3000))
            packet_size = int(np.clip(np.random.normal(loc=1100, scale=250), 400, 1500))
            failed_logins = 0
            request_frequency = int(np.random.uniform(60, 220))  # Periodic beaconing
            num_connections = int(np.random.randint(10, 45))
            login_attempts = 0
            geo_risk = float(np.clip(np.random.uniform(0.70, 0.99), 0.0, 1.0))

        elif lbl == "unauthorized_access":
            src_ip = np.random.choice(external_ips)
            dst_ip = np.random.choice(internal_subnets[:5])  # Domain controller / database
            protocol = "tcp"
            service = np.random.choice(["ssh", "rdp", "smb"], p=[0.4, 0.4, 0.2])
            flag = "SF"
            duration = float(np.random.uniform(15.0, 120.0))
            src_bytes = int(np.random.uniform(2500, 18000))
            dst_bytes = int(np.random.uniform(5000, 40000))
            packet_size = int(np.clip(np.random.normal(loc=850, scale=200), 200, 1400))
            failed_logins = int(np.random.choice([1, 2, 3, 4], p=[0.2, 0.3, 0.3, 0.2]))
            request_frequency = int(np.random.uniform(40, 140))
            num_connections = int(np.random.randint(4, 20))
            login_attempts = failed_logins + 1
            is_unusual_hour = 1  # Often off-hours privilege escalation
            geo_risk = float(np.clip(np.random.uniform(0.65, 0.98), 0.0, 1.0))

        data.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol_type": protocol,
            "service": service,
            "flag": flag,
            "duration": round(duration, 4),
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "packet_size": packet_size,
            "failed_logins": failed_logins,
            "request_frequency": request_frequency,
            "num_connections": num_connections,
            "login_attempts": login_attempts,
            "unusual_hour": is_unusual_hour,
            "geo_risk": round(geo_risk, 4),
            "Attack_Label": lbl  # Exact label name expected
        })

    df = pd.DataFrame(data)

    # Introduce realistic imperfections: duplicates (~0.2%) and missing values (~0.1%)
    dup_indices = np.random.choice(df.index, size=int(num_rows * 0.002), replace=False)
    duplicates = df.loc[dup_indices].copy()
    df = pd.concat([df, duplicates], ignore_index=True)

    # Missing values in non-critical columns
    for col in ["src_bytes", "dst_bytes", "service"]:
        nan_indices = np.random.choice(df.index, size=int(len(df) * 0.001), replace=False)
        df.loc[nan_indices, col] = np.nan

    logger.info(f"Generated network dataset with shape {df.shape}.")
    return df


def generate_phishing_dataset(num_rows: int = 5000, random_seed: int = SEED) -> pd.DataFrame:
    """Generates synthetic dataset of URL indicators for phishing detection."""
    np.random.seed(random_seed)
    logger.info(f"Generating {num_rows} phishing URL indicators...")
    
    labels = np.random.choice(["normal", "phishing"], size=num_rows, p=[0.7, 0.3])
    records = []
    
    for lbl in labels:
        if lbl == "normal":
            url_length = int(np.random.normal(loc=35, scale=12))
            has_ip_in_url = 0
            num_special_chars = int(np.random.poisson(lam=3))
            https_flag = int(np.random.choice([1, 0], p=[0.92, 0.08]))
            domain_age_days = int(np.random.uniform(365, 5000))
            num_redirects = int(np.random.choice([0, 1], p=[0.90, 0.10]))
            suspicious_keywords = int(np.random.choice([0, 1], p=[0.97, 0.03]))
        else:
            url_length = int(np.random.normal(loc=85, scale=25))
            has_ip_in_url = int(np.random.choice([1, 0], p=[0.35, 0.65]))
            num_special_chars = int(np.random.poisson(lam=11))
            https_flag = int(np.random.choice([1, 0], p=[0.40, 0.60]))
            domain_age_days = int(np.random.uniform(1, 90))  # Freshly registered
            num_redirects = int(np.random.randint(1, 5))
            suspicious_keywords = int(np.random.randint(1, 4))
            
        records.append({
            "url_length": max(10, url_length),
            "has_ip_in_url": has_ip_in_url,
            "num_special_chars": max(0, num_special_chars),
            "https_flag": https_flag,
            "domain_age_days": max(1, domain_age_days),
            "num_redirects": num_redirects,
            "suspicious_keywords": suspicious_keywords,
            "Attack_Label": lbl
        })
        
    df = pd.DataFrame(records)
    logger.info(f"Phishing dataset generated: {df.shape}")
    return df


def generate_malware_dataset(num_rows: int = 5000, random_seed: int = SEED) -> pd.DataFrame:
    """Generates synthetic dataset of process/host telemetry for malware detection."""
    np.random.seed(random_seed)
    logger.info(f"Generating {num_rows} malware behavior indicators...")
    
    labels = np.random.choice(["normal", "malware"], size=num_rows, p=[0.7, 0.3])
    records = []
    
    for lbl in labels:
        if lbl == "normal":
            api_call_count = int(np.random.normal(loc=120, scale=40))
            registry_changes = int(np.random.poisson(lam=2))
            files_modified = int(np.random.poisson(lam=5))
            network_connections = int(np.random.poisson(lam=3))
            entropy = float(np.random.uniform(2.5, 5.5))
            memory_usage_mb = float(np.random.normal(loc=65, scale=20))
            execution_time_sec = float(np.random.uniform(5.0, 300.0))
        else:
            api_call_count = int(np.random.normal(loc=850, scale=200))
            registry_changes = int(np.random.poisson(lam=18))
            files_modified = int(np.random.poisson(lam=45))
            network_connections = int(np.random.poisson(lam=16))
            entropy = float(np.random.uniform(6.8, 7.99))  # Packed/encrypted binary
            memory_usage_mb = float(np.random.normal(loc=240, scale=60))
            execution_time_sec = float(np.random.uniform(0.5, 30.0))
            
        records.append({
            "api_call_count": max(10, api_call_count),
            "registry_changes": max(0, registry_changes),
            "files_modified": max(0, files_modified),
            "network_connections": max(0, network_connections),
            "entropy": round(min(8.0, max(1.0, entropy)), 4),
            "memory_usage_mb": round(max(5.0, memory_usage_mb), 2),
            "execution_time_sec": round(max(0.1, execution_time_sec), 2),
            "Attack_Label": lbl
        })
        
    df = pd.DataFrame(records)
    logger.info(f"Malware dataset generated: {df.shape}")
    return df


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic cybersecurity datasets.")
    parser.add_argument("--rows", type=int, default=52000, help="Number of network traffic rows to generate (default: 52000)")
    parser.add_argument("--outdir", type=str, default="data/raw", help="Output directory for raw CSVs")
    parser.add_argument("--seed", type=int, default=SEED, help="Random seed for reproducibility")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    net_df = generate_network_traffic(num_rows=args.rows, random_seed=args.seed)
    net_path = os.path.join(args.outdir, "network_traffic.csv")
    net_df.to_csv(net_path, index=False)
    logger.info(f"Saved primary network traffic to {net_path}")

    phish_df = generate_phishing_dataset(num_rows=5000, random_seed=args.seed)
    phish_path = os.path.join(args.outdir, "phishing_urls.csv")
    phish_df.to_csv(phish_path, index=False)
    logger.info(f"Saved phishing URL telemetry to {phish_path}")

    malware_df = generate_malware_dataset(num_rows=5000, random_seed=args.seed)
    malware_path = os.path.join(args.outdir, "malware_behavior.csv")
    malware_df.to_csv(malware_path, index=False)
    logger.info(f"Saved malware behavior telemetry to {malware_path}")
    print("[SUCCESS] All raw datasets generated successfully.")

if __name__ == "__main__":
    main()
