"""
Virtual Network Stream Simulation & Attack Injector
Replays synthetic and injected attack scenarios against the ThreatDetector,
generating real-time SOC alerts and simulating live enterprise security monitoring.
"""

import os
import time
import argparse
from datetime import datetime
from typing import List, Dict, Any

from src.utils.logger import logger
from src.detection.detector import ThreatDetector
from src.detection.alert_engine import AlertEngine

# Scripted Attack Scenarios
ATTACK_SCENARIOS = [
    {
        "name": "DoS SYN Flood Campaign",
        "description": "High-volume distributed SYN flood targeting internal web server",
        "records": [
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": "185.220.101.5",
                "dst_ip": "192.168.1.10",
                "protocol_type": "tcp",
                "service": "http",
                "flag": "S0",
                "duration": 0.02,
                "src_bytes": 15000,
                "dst_bytes": 0,
                "packet_size": 1450,
                "failed_logins": 0,
                "request_frequency": 1400,
                "num_connections": 350,
                "login_attempts": 0,
                "unusual_hour": 0,
                "geo_risk": 0.92
            } for _ in range(5)
        ]
    },
    {
        "name": "Automated SSH Brute-Force Credential Stuffing",
        "description": "Rapid password-guessing attack against perimeter bastion server",
        "records": [
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": "194.26.29.14",
                "dst_ip": "192.168.1.22",
                "protocol_type": "tcp",
                "service": "ssh",
                "flag": "REJ",
                "duration": 4.5,
                "src_bytes": 850,
                "dst_bytes": 450,
                "packet_size": 520,
                "failed_logins": 12,
                "request_frequency": 280,
                "num_connections": 45,
                "login_attempts": 13,
                "unusual_hour": 0,
                "geo_risk": 0.88
            } for _ in range(3)
        ]
    },
    {
        "name": "Aggressive Horizontal Port Reconnaissance",
        "description": "Scanning enterprise subnets for open vulnerable listening services",
        "records": [
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": "185.220.101.44",
                "dst_ip": f"192.168.1.{i*10}",
                "protocol_type": "tcp",
                "service": "rdp",
                "flag": "REJ",
                "duration": 0.01,
                "src_bytes": 60,
                "dst_bytes": 0,
                "packet_size": 60,
                "failed_logins": 0,
                "request_frequency": 450,
                "num_connections": 220,
                "login_attempts": 0,
                "unusual_hour": 0,
                "geo_risk": 0.76
            } for i in range(1, 4)
        ]
    },
    {
        "name": "Targeted Phishing Gateway Ingress",
        "description": "User clicked suspicious link redirecting to external credential harvest form",
        "records": [
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": "192.168.1.105",
                "dst_ip": "198.51.100.82",
                "protocol_type": "tcp",
                "service": "https",
                "flag": "SF",
                "duration": 12.0,
                "src_bytes": 2200,
                "dst_bytes": 14500,
                "packet_size": 1150,
                "failed_logins": 1,
                "request_frequency": 55,
                "num_connections": 6,
                "login_attempts": 2,
                "unusual_hour": 0,
                "geo_risk": 0.82
            }
        ]
    },
    {
        "name": "C2 Malware Beaconing & Exfiltration",
        "description": "Compromised internal host transmitting encrypted staging archive to command-and-control node",
        "records": [
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": "192.168.1.15",
                "dst_ip": "185.220.101.88",
                "protocol_type": "tcp",
                "service": "https",
                "flag": "SF",
                "duration": 6.2,
                "src_bytes": 9500,
                "dst_bytes": 1200,
                "packet_size": 1350,
                "failed_logins": 0,
                "request_frequency": 140,
                "num_connections": 28,
                "login_attempts": 0,
                "unusual_hour": 0,
                "geo_risk": 0.95
            }
        ]
    },
    {
        "name": "Off-Hours Unauthorized Privilege Escalation (03:15 AM)",
        "description": "Anomalous administrator logon session from external IP modifying database shares at 3:15 AM",
        "records": [
            {
                "timestamp": "2026-10-16 03:15:22",
                "src_ip": "203.0.113.89",
                "dst_ip": "192.168.1.5",
                "protocol_type": "tcp",
                "service": "smb",
                "flag": "SF",
                "duration": 48.0,
                "src_bytes": 14000,
                "dst_bytes": 32000,
                "packet_size": 1050,
                "failed_logins": 3,
                "request_frequency": 95,
                "num_connections": 12,
                "login_attempts": 4,
                "unusual_hour": 1,
                "geo_risk": 0.94
            }
        ]
    }
]

# Normal Baseline Traffic Samples
NORMAL_TRAFFIC = [
    {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.50",
        "dst_ip": "203.0.113.10",
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "duration": 1.5,
        "src_bytes": 450,
        "dst_bytes": 2200,
        "packet_size": 520,
        "failed_logins": 0,
        "request_frequency": 18,
        "num_connections": 3,
        "login_attempts": 0,
        "unusual_hour": 0,
        "geo_risk": 0.15
    },
    {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": "192.168.1.55",
        "dst_ip": "198.51.100.25",
        "protocol_type": "udp",
        "service": "dns",
        "flag": "SF",
        "duration": 0.05,
        "src_bytes": 80,
        "dst_bytes": 140,
        "packet_size": 110,
        "failed_logins": 0,
        "request_frequency": 8,
        "num_connections": 1,
        "login_attempts": 0,
        "unusual_hour": 0,
        "geo_risk": 0.10
    }
]

def run_simulation(speed_delay: float = 0.2, models_dir: str = "models", alerts_dir: str = "outputs/alerts"):
    """
    Executes live stream simulation replaying attacks and benign traffic.
    """
    print("\n" + "=" * 70)
    print("AI CYBERSECURITY THREAT DETECTION SYSTEM - LIVE TRAFFIC SIMULATOR")
    print("=" * 70)
    print("[*] Initializing AI Threat Detection Engine & SOC Alerting...")
    
    detector = ThreatDetector(models_dir=models_dir)
    engine = AlertEngine(alerts_dir=alerts_dir, dedup_window_sec=1.0)
    
    total_processed = 0
    total_alerts = 0

    print("[*] Streaming baseline benign traffic (normal operations)...")
    for rec in NORMAL_TRAFFIC:
        res = detector.predict_network_record(rec)
        total_processed += 1
        alert = engine.emit_alert(res, record=rec, print_console=True)
        if alert:
            total_alerts += 1
        time.sleep(speed_delay)

    print("\n[*] INJECTING SCRIPTED CYBER ATTACK SCENARIOS...")
    for idx, scenario in enumerate(ATTACK_SCENARIOS, 1):
        print(f"\n>>> [SCENARIO {idx}/{len(ATTACK_SCENARIOS)}] {scenario['name']}")
        print(f"    Details: {scenario['description']}")
        
        for record in scenario["records"]:
            res = detector.predict_network_record(record)
            total_processed += 1
            alert = engine.emit_alert(res, record=record, print_console=True)
            if alert:
                total_alerts += 1
            time.sleep(speed_delay)

    print("\n" + "=" * 70)
    print(f"[SUMMARY] Simulation Complete: {total_processed} packets processed, {total_alerts} security alerts triggered.")
    print(f"[OUTPUT] Audit trail saved to {os.path.join(alerts_dir, 'alerts.jsonl')} and alerts.csv")
    print("=" * 70 + "\n")
    return {"processed": total_processed, "alerts": total_alerts}

def main():
    parser = argparse.ArgumentParser(description="Live Cyber Threat Simulation")
    parser.add_argument("--speed", type=float, default=0.1, help="Delay between packet events in seconds")
    parser.add_argument("--models", type=str, default="models", help="Models directory")
    parser.add_argument("--alerts", type=str, default="outputs/alerts", help="Alerts output directory")
    args = parser.parse_args()

    run_simulation(speed_delay=args.speed, models_dir=args.models, alerts_dir=args.alerts)

if __name__ == "__main__":
    main()
