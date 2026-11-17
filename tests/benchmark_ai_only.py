#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI-Only Mode Benchmark Script for Wazuh Local Analysisd (-A)
Evaluates pure AI detection accuracy without static Wazuh rules by:
1. Launching wazuh-local-analysisd in AI-only mode (-A)
2. Streaming labeled Linux (AIT raw logs / ait_sample.xlsx) and Windows (comiset_sample.xlsx)
   events through the real C -> Unix Socket -> Python AI Daemon -> local_alerts.json pipeline
3. Computing Binary (Malicious vs Normal) and Multiclass accuracy metrics.
"""

import argparse
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
ANALYSISD_BIN = REPO_ROOT / "src" / "wazuh-local-analysisd"
AI_DAEMON_SCRIPT = REPO_ROOT / "src" / "daemon" / "ai_daemon.py"
AI_SOCKET = "/var/ossec/queue/ai/ai_inference.sock"
BENCH_QUEUE = "/tmp/bench_ai_only_queue.sock"
ALERTS_FILE = REPO_ROOT / "logs" / "alerts" / "local_alerts.json"

SAMPLE_LOGS_DIR = REPO_ROOT / "ait_attack_detector_Linux" / "ait_attack_detector" / "sample_input" / "logs"
SAMPLE_LABELS_DIR = REPO_ROOT / "ait_attack_detector_Linux" / "ait_attack_detector" / "sample_input" / "labels"
AIT_XLSX = REPO_ROOT / "models-AI" / "samples" / "ait_sample.xlsx"
COMISET_XLSX = REPO_ROOT / "models-AI" / "samples" / "comiset_sample.xlsx"


def map_ait_raw_label(raw_label: str) -> str:
    tok = raw_label.strip().split(",")[-1].strip().lower()
    if tok in ("", "0", "normal"):
        return "normal"
    if "eximsploit" in tok:
        return "privesc"
    if tok.startswith("webshell"):
        return "webshell"
    if tok in ("upload", "okay-upload-webshell", "mail-curl", "okay-curl"):
        return "upload"
    return tok


def load_ait_raw_samples(max_per_class: int = 25, seed: int = 42):
    """Load labeled raw Linux log lines from sample_input/logs + sample_input/labels"""
    if not SAMPLE_LOGS_DIR.exists() or not SAMPLE_LABELS_DIR.exists():
        return []

    rnd = random.Random(seed)
    buckets = defaultdict(list)

    for label_path in sorted(SAMPLE_LABELS_DIR.rglob("*")):
        if not label_path.is_file():
            continue
        rel = label_path.relative_to(SAMPLE_LABELS_DIR)
        log_path = SAMPLE_LOGS_DIR / rel
        if not log_path.exists():
            continue

        location = f"/var/log/{rel.as_posix()}"
        with open(log_path, "r", encoding="utf-8", errors="replace") as fl, \
             open(label_path, "r", encoding="utf-8", errors="replace") as fb:
            for log_line, lab_line in zip(fl, fb):
                log_line = log_line.rstrip("\r\n")
                if len(log_line) < 5:
                    continue
                cls = map_ait_raw_label(lab_line)
                item = {
                    "dataset": "ait_raw_linux",
                    "location": location,
                    "payload": log_line,
                    "true_label": cls,
                    "is_malicious_true": (cls != "normal"),
                }
                if len(buckets[cls]) < max_per_class * 4:
                    buckets[cls].append(item)

    samples = []
    for cls, items in sorted(buckets.items()):
        if len(items) > max_per_class:
            items = rnd.sample(items, max_per_class)
        samples.extend(items)
    rnd.shuffle(samples)
    return samples


def load_xlsx_samples(xlsx_path: Path, dataset_name: str, default_location: str, max_rows: int = 50):
    if not xlsx_path.exists():
        return []
    df = pd.read_excel(xlsx_path)
    samples = []
    for _, row in df.head(max_rows).iterrows():
        d = {str(col): str(row[col]) for col in row.index if pd.notna(row[col])}
        true_label = str(row.get("categoryDescription", "unknown")).strip()
        loc = default_location
        if dataset_name == "ait_xlsx_linux" and "eventName" in d:
            ev = d["eventName"]
            if ev == "apache_access":
                loc = "/var/log/apache2/access.log"
            elif ev == "apache_error":
                loc = "/var/log/apache2/error.log"
            elif ev == "auth":
                loc = "/var/log/auth.log"
            elif ev == "mail":
                loc = "/var/log/mail.log"
            elif ev == "exim_mainlog":
                loc = "/var/log/exim4/mainlog"
            else:
                loc = f"/var/log/{ev}"
        samples.append({
            "dataset": dataset_name,
            "location": loc,
            "payload": json.dumps(d),
            "true_label": true_label,
            "is_malicious_true": (true_label.lower() != "normal"),
        })
    return samples


def send_and_collect_alert(sock_path: str, location: str, payload: str, alerts_fp, wait_ms: int = 120):
    """Send 1 event to wazuh-local-analysisd -A and check if Rule 99999 alert is written"""
    wire_msg = f"1:{location}:{payload}"
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        client.sendto(wire_msg.encode("utf-8", errors="replace"), sock_path)
    finally:
        client.close()

    # Poll local_alerts.json briefly to see if AI generated an alert for this event
    deadline = time.time() + (wait_ms / 1000.0)
    while time.time() < deadline:
        line = alerts_fp.readline()
        if line:
            line = line.strip()
            if line:
                try:
                    alert = json.loads(line)
                    if str(alert.get("rule", {}).get("id")) == "99999":
                        return alert
                except json.JSONDecodeError:
                    pass
        time.sleep(0.01)
    return None


def parse_predicted_attack(alert: dict) -> str:
    if not alert:
        return "normal"
    desc = alert.get("rule", {}).get("description", "")
    m = re.search(r"AI Threat Detected:\s*(.+?)\s*\(Confidence:", desc)
    return m.group(1).strip() if m else "unknown"


def compute_and_print_metrics(title: str, results: list):
    if not results:
        print(f"\n[!] No results for {title}")
        return

    tp = fp = tn = fn = 0
    exact_attack_match = 0
    total_attack = 0
    pred_counter = Counter()
    true_counter = Counter()
    latencies = []

    for r in results:
        yt = r["true_malicious"]
        yp = r["pred_malicious"]
        latencies.append(r["latency_ms"])
        true_counter[r["true_label"]] += 1
        pred_counter[r["pred_label"]] += 1

        if yt and yp:
            tp += 1
        elif not yt and yp:
            fp += 1
        elif not yt and not yp:
            tn += 1
        else:
            fn += 1

        if yt:
            total_attack += 1
            if r["pred_label"].lower() == r["true_label"].lower():
                exact_attack_match += 1

    total = tp + fp + tn + fn
    acc = (tp + tn) / total if total else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
    avg_ms = sum(latencies) / len(latencies) if latencies else 0.0

    print(f"\n==================== {title} ====================")
    print(f"Total Samples : {total} (Attack: {tp + fn}, Normal: {tn + fp})")
    print(f"Confusion Mat : TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Binary Metrics: Accuracy={acc:.4f} | Precision={prec:.4f} | Recall={rec:.4f} | F1={f1:.4f}")
    if total_attack > 0:
        print(f"Multiclass Acc: {exact_attack_match}/{total_attack} ({exact_attack_match/total_attack:.2%}) exact attack-type match")
    print(f"Avg Latency   : {avg_ms:.2f} ms/event")
    print(f"True Labels   : {dict(true_counter)}")
    print(f"Pred Labels   : {dict(pred_counter)}")


def is_socket_alive(sock_path: str) -> bool:
    if not os.path.exists(sock_path):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(sock_path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser(description="Benchmark Wazuh AI-Only Mode (-A)")
    parser.add_argument("--dataset", choices=["ait-raw", "samples", "all"], default="all")
    parser.add_argument("--max-per-class", type=int, default=20, help="Max rows per class for AIT raw logs")
    parser.add_argument("--max-xlsx", type=int, default=40, help="Max rows per Excel sample file")
    args = parser.parse_args()

    if not ANALYSISD_BIN.exists():
        print(f"[!] Missing binary {ANALYSISD_BIN}. Build with: make TARGET=agent wazuh-local-analysisd")
        sys.exit(1)

    (REPO_ROOT / "logs" / "alerts").mkdir(parents=True, exist_ok=True)
    ALERTS_FILE.write_text("", encoding="utf-8")
    if os.path.exists(BENCH_QUEUE):
        os.unlink(BENCH_QUEUE)

    started_ai_daemon = None
    analysisd_proc = None

    try:
        # 1. Start AI Daemon only if socket is not already alive
        if not is_socket_alive(AI_SOCKET):
            print("[*] AI socket not active, launching ai_daemon.py...")
            started_ai_daemon = subprocess.Popen(
                [sys.executable, str(AI_DAEMON_SCRIPT), "--socket", AI_SOCKET],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(120):
                if is_socket_alive(AI_SOCKET):
                    break
                time.sleep(0.5)
            if not is_socket_alive(AI_SOCKET):
                print("[!] Failed to start ai_daemon.py")
                sys.exit(1)
            print(f"[+] AI Daemon started and listening on {AI_SOCKET}")
        else:
            print(f"[+] Using active AI Daemon socket: {AI_SOCKET}")

        # 2. Launch wazuh-local-analysisd in AI-ONLY mode (-A)
        print(f"[*] Launching wazuh-local-analysisd in AI-ONLY mode (-A) on {BENCH_QUEUE}...")
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = f"{REPO_ROOT / 'src'}:{env.get('LD_LIBRARY_PATH', '')}"
        analysisd_proc = subprocess.Popen(
            [str(ANALYSISD_BIN), "-A", "-D", str(REPO_ROOT), "-f", "-u", "root", "-g", "root", "-q", BENCH_QUEUE],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        for _ in range(50):
            if os.path.exists(BENCH_QUEUE):
                break
            time.sleep(0.1)

        if not os.path.exists(BENCH_QUEUE):
            print("[!] Failed to bind benchmark queue socket.")
            sys.exit(1)
        print("[+] wazuh-local-analysisd (-A) ready.")

        # 3. Collect datasets
        datasets = []
        if args.dataset in ("ait-raw", "all"):
            datasets.append(("AIT Raw Linux Logs (sample_input)", load_ait_raw_samples(args.max_per_class)))
        if args.dataset in ("samples", "all"):
            datasets.append(("AIT Sample Excel (Linux)", load_xlsx_samples(AIT_XLSX, "ait_xlsx_linux", "/var/log/syslog", args.max_xlsx)))
            datasets.append(("CoMiSet Sample Excel (Windows)", load_xlsx_samples(COMISET_XLSX, "comiset_xlsx_win", "WinEvtLog:Security", args.max_xlsx)))

        # 4. Run benchmark
        with open(ALERTS_FILE, "r", encoding="utf-8") as alerts_fp:
            alerts_fp.seek(0, os.SEEK_END)
            for title, items in datasets:
                if not items:
                    print(f"[!] Dataset '{title}' is empty or missing, skipping.")
                    continue
                print(f"\n[*] Running benchmark on '{title}' ({len(items)} events)...")
                res = []
                for idx, item in enumerate(items):
                    t0 = time.time()
                    alert = send_and_collect_alert(BENCH_QUEUE, item["location"], item["payload"], alerts_fp, wait_ms=450)
                    dt_ms = (time.time() - t0) * 1000.0
                    pred_label = parse_predicted_attack(alert)
                    res.append({
                        "true_label": item["true_label"],
                        "true_malicious": item["is_malicious_true"],
                        "pred_label": pred_label,
                        "pred_malicious": (alert is not None),
                        "latency_ms": dt_ms,
                    })
                compute_and_print_metrics(title, res)

    finally:
        if analysisd_proc and analysisd_proc.poll() is None:
            analysisd_proc.send_signal(signal.SIGTERM)
            try:
                analysisd_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                analysisd_proc.kill()
        if started_ai_daemon and started_ai_daemon.poll() is None:
            started_ai_daemon.send_signal(signal.SIGTERM)
            started_ai_daemon.wait(timeout=5)
        if os.path.exists(BENCH_QUEUE):
            os.unlink(BENCH_QUEUE)


if __name__ == "__main__":
    main()

