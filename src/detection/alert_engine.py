"""
SOC Alerting Engine
Formats security alerts, manages de-duplication/rate-limiting,
persists structured JSONL/CSV audit trails, and prints colored SOC terminal alerts.
"""

import os
import json
import time
from datetime import datetime
import pandas as pd
from typing import Dict, Any, Optional

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False

RECOMMENDED_ACTIONS = {
    "dos": "Rate-limit traffic and block source IP at edge firewall (Null-route / BGP Flowspec)",
    "brute_force": "Lock targeted account, enforce MFA challenge, and add IP to temporary fail2ban jail",
    "port_scan": "Drop reconnaissance packets and flag source IP in Threat Intelligence watch-list",
    "phishing": "Add malicious URL/domain to Secure Web Gateway blacklist and quarantine related emails",
    "malware": "Isolate compromised endpoint from corporate LAN, kill offending PID, dump memory for forensics",
    "unauthorized_access": "Terminate active session, revoke privileges, force password reset, escalate to Tier-3 SOC",
    "anomaly": "Initiate automated packet capture (PCAP) and route session through deep packet inspection (DPI)",
    "normal": "No remediation required. Logged to standard audit trail."
}

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT if COLOR_ENABLED else "",
    "HIGH": Fore.LIGHTRED_EX + Style.BRIGHT if COLOR_ENABLED else "",
    "MEDIUM": Fore.YELLOW + Style.BRIGHT if COLOR_ENABLED else "",
    "LOW": Fore.CYAN if COLOR_ENABLED else "",
    "INFORMATIONAL": Fore.GREEN if COLOR_ENABLED else ""
}
RESET = Style.RESET_ALL if COLOR_ENABLED else ""

class AlertEngine:
    """Manages alert generation, deduplication, formatting, and persistence."""
    
    def __init__(self, alerts_dir: str = "outputs/alerts", dedup_window_sec: float = 2.0):
        self.alerts_dir = alerts_dir
        self.dedup_window_sec = dedup_window_sec
        self.recent_alerts = {}
        os.makedirs(self.alerts_dir, exist_ok=True)
        self.jsonl_path = os.path.join(self.alerts_dir, "alerts.jsonl")
        self.csv_path = os.path.join(self.alerts_dir, "alerts.csv")

    def should_deduplicate(self, src_ip: str, attack_type: str) -> bool:
        """Rate-limits repeated identical alerts within dedup_window_sec."""
        key = f"{src_ip}:{attack_type}"
        now = time.time()
        last_time = self.recent_alerts.get(key)
        if last_time and (now - last_time < self.dedup_window_sec):
            return True
        self.recent_alerts[key] = now
        return False

    def emit_alert(self, detection_result: Dict[str, Any], record: Optional[Dict[str, Any]] = None, print_console: bool = True) -> Optional[Dict[str, Any]]:
        """Creates a standardized security incident alert if a threat is detected."""
        if not detection_result.get("Threat_Detected", False):
            return None

        src_ip = record.get("src_ip", detection_result.get("src_ip", "Unknown")) if record else detection_result.get("src_ip", "Unknown")
        dst_ip = record.get("dst_ip", detection_result.get("dst_ip", "Internal-Asset")) if record else detection_result.get("dst_ip", "Internal-Asset")
        attack_type = detection_result.get("attack_type", "anomaly")
        
        # Check rate-limiting
        if self.should_deduplicate(src_ip, attack_type):
            return None

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        severity = detection_result.get("severity", "MEDIUM")
        confidence = detection_result.get("confidence", 0.0)
        action = RECOMMENDED_ACTIONS.get(attack_type.lower(), "Investigate anomalous event in SIEM")

        alert = {
            "timestamp": timestamp,
            "severity": severity,
            "attack_type": attack_type.upper(),
            "confidence": confidence,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "recommended_action": action,
            "anomaly_score": detection_result.get("anomaly_score", 0.0),
            "threat_detected": True
        }

        # 1. Append to JSONL
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")

        # 2. Append to CSV
        df_alert = pd.DataFrame([alert])
        write_header = not os.path.exists(self.csv_path) or os.path.getsize(self.csv_path) == 0
        df_alert.to_csv(self.csv_path, mode="a", index=False, header=write_header)

        # 3. Print to Console with SOC formatting
        if print_console:
            sev_color = SEVERITY_COLORS.get(severity, "")
            print(f"{sev_color}[ALERT] [{timestamp}] [{severity}] {attack_type.upper()} detected from {src_ip} -> {dst_ip} (Conf: {confidence:.2f}){RESET}")
            print(f"        Action: {action}")

        return alert

    def get_recent_alerts(self, limit: int = 50) -> list:
        """Retrieves recent alerts from the JSONL log."""
        if not os.path.exists(self.jsonl_path):
            return []
        alerts = []
        with open(self.jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        alerts.append(json.loads(line))
                    except Exception:
                        pass
        return alerts[-limit:]
