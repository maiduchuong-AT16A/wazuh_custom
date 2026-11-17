#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sample Log Replayer for Wazuh AI Detection Module
Reads sample logs from ait_sample.xlsx and comiset_sample.xlsx
and injects them into wazuh-local-analysisd via its Unix DGRAM queue socket.
"""

import os
import sys
import json
import time
import socket
import argparse
import pandas as pd
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ANALYSISD_SOCK = "/tmp/test_analysisd_queue.sock"
AIT_SAMPLE = REPO_ROOT / "models-AI" / "samples" / "ait_sample.xlsx"
COMISET_SAMPLE = REPO_ROOT / "models-AI" / "samples" / "comiset_sample.xlsx"
ALERTS_JSON = REPO_ROOT / "logs" / "alerts" / "local_alerts.json"

TEXT_COLS = [
    "srcIp", "destIp", "deviceName", "deviceCategory",
    "eventName", "eventDescription", "domainName", "severity",
    "mPCEvent", "payloadAsUTF"
]


def format_row(row: pd.Series) -> str:
    """Format DataFrame row into JSON string for event payload"""
    d = {}
    for col in row.index:
        val = row[col]
        if pd.notna(val):
            d[str(col)] = str(val)
    return json.dumps(d)


def send_event(sock_path: str, location: str, payload: str):
    """Send formatted event to wazuh-local-analysisd unix dgram socket"""
    # Wazuh message format: 1:<location>:<log_message>
    wire_msg = f"1:{location}:{payload}"
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        client.sendto(wire_msg.encode("utf-8", errors="replace"), sock_path)
    finally:
        client.close()


def replay_samples(sock_path: str, count: int = 5, test_type: str = "both"):
    print(f"[*] Replaying samples to socket: {sock_path} (count={count}, type={test_type})")

    sent_events = []

    # 1. AIT (Linux) Samples
    if test_type in ("ait", "both") and AIT_SAMPLE.exists():
        df_ait = pd.read_excel(AIT_SAMPLE)
        print(f"[*] Loaded {len(df_ait)} rows from {AIT_SAMPLE.name}")
        for idx, row in df_ait.head(count).iterrows():
            payload = format_row(row)
            category = str(row.get("categoryDescription", "unknown"))
            send_event(sock_path, "/var/log/syslog", payload)
            sent_events.append({"idx": idx, "dataset": "ait", "expected": category})
            print(f"  -> Sent AIT [{idx}] expected label: '{category}'")
            time.sleep(0.05)

    # 2. COMISET (Windows) Samples
    if test_type in ("comiset", "both") and COMISET_SAMPLE.exists():
        df_comiset = pd.read_excel(COMISET_SAMPLE)
        print(f"[*] Loaded {len(df_comiset)} rows from {COMISET_SAMPLE.name}")
        for idx, row in df_comiset.head(count).iterrows():
            payload = format_row(row)
            category = str(row.get("categoryDescription", "unknown"))
            send_event(sock_path, "WinEvtLog:Security", payload)
            sent_events.append({"idx": idx, "dataset": "comiset", "expected": category})
            print(f"  -> Sent COMISET [{idx}] expected label: '{category}'")
            time.sleep(0.05)

    print(f"[+] Total events replayed: {len(sent_events)}")
    return sent_events


def verify_alerts(min_expected: int = 1, timeout_secs: float = 3.0):
    """Verify alerts produced in logs/alerts/local_alerts.json"""
    print(f"[*] Verifying alerts in {ALERTS_JSON}...")
    start_time = time.time()
    ai_alerts = []

    while time.time() - start_time < timeout_secs:
        if ALERTS_JSON.exists():
            with open(ALERTS_JSON, "r", encoding="utf-8") as f:
                lines = f.readlines()
            ai_alerts = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    rule_info = data.get("rule", {})
                    if str(rule_info.get("id")) == "99999":
                        ai_alerts.append(data)
                except Exception:
                    pass
            if len(ai_alerts) >= min_expected:
                break
        time.sleep(0.2)

    print(f"[+] Found {len(ai_alerts)} AI alerts (Rule ID 99999) in {ALERTS_JSON}")
    for idx, alert in enumerate(ai_alerts[-5:]):
        rule = alert.get("rule", {})
        print(f"  Alert #{idx+1}: ID={rule.get('id')} Level={rule.get('level')} Desc='{rule.get('description')}' Location='{alert.get('location')}'")

    return ai_alerts


def main():
    parser = argparse.ArgumentParser(description="Replay sample logs to wazuh-local-analysisd")
    parser.add_argument("--socket", default=DEFAULT_ANALYSISD_SOCK, help="Target socket path for analysisd")
    parser.add_argument("--count", type=int, default=5, help="Number of rows per dataset")
    parser.add_argument("--type", choices=["ait", "comiset", "both"], default="both", help="Sample dataset")
    parser.add_argument("--verify", action="store_true", help="Verify generated alerts in local_alerts.json")
    args = parser.parse_args()

    replay_samples(args.socket, args.count, args.type)
    if args.verify:
        alerts = verify_alerts(min_expected=1)
        if not alerts:
            print("[!] Warning: No AI alerts detected yet.")
            sys.exit(1)


if __name__ == "__main__":
    main()
