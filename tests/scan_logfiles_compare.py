#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compare Static Rules (only_rule) vs AI-Only (-A) on real IIS logs under LogFiles/
Outputs a per-log comparison table to stdout and saves full results to CSV.
"""

import argparse
import csv
import glob
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ANALYSISD_BIN = REPO_ROOT / "src" / "wazuh-local-analysisd"
AI_DAEMON_SCRIPT = REPO_ROOT / "src" / "daemon" / "ai_daemon.py"
AI_SOCKET = "/var/ossec/queue/ai/ai_inference.sock"
CMP_QUEUE = "/tmp/cmp_logfiles_queue.sock"
ALERTS_FILE = REPO_ROOT / "logs" / "alerts" / "local_alerts.json"
LOGFILES_DIR = REPO_ROOT / "LogFiles"
DEFAULT_OUT_CSV = REPO_ROOT / "logs" / "logfiles_rule_vs_ai.csv"

SUSPICIOUS_KEYWORDS = [
    "union+select", "union%20select", "../..", "etc/passwd", "cmd=", "syscmd",
    "jndi:", "ldap:", "wget+", "curl/", "<script", "%3cscript", "xp_cmdshell",
    "eval(", "base64", "sqlmap", "nikto", "nmap", "tomcatwar", "setup.cgi",
    "boaform", "wp-login", "phpmyadmin", "zgrab", "libwww-perl"
]


def collect_diverse_samples(max_suspicious: int = 40, max_normal: int = 20):
    files = sorted(glob.glob(str(LOGFILES_DIR / "*" / "*.log")))
    suspicious = []
    normal = []
    seen_patterns = set()

    for fpath in files:
        rel = os.path.relpath(fpath, LOGFILES_DIR)
        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
            for line_no, line in enumerate(fp, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                low = line.lower()
                # Deduplicate by (method, uri, status) to maximize diversity
                parts = line.split()
                sig = (parts[3] if len(parts) > 3 else "", parts[4] if len(parts) > 4 else "", parts[-4] if len(parts) > 4 else "")

                is_susp = any(k in low for k in SUSPICIOUS_KEYWORDS)
                if is_susp and len(suspicious) < max_suspicious and sig not in seen_patterns:
                    seen_patterns.add(sig)
                    suspicious.append({
                        "file": rel,
                        "line_no": line_no,
                        "category": "suspicious_or_error",
                        "location": f"/var/log/iis/{rel}",
                        "log": line,
                    })
                elif not is_susp and " 200 " in line and len(normal) < max_normal and sig not in seen_patterns:
                    seen_patterns.add(sig)
                    normal.append({
                        "file": rel,
                        "line_no": line_no,
                        "category": "normal_200",
                        "location": f"/var/log/iis/{rel}",
                        "log": line,
                    })
                if len(suspicious) >= max_suspicious and len(normal) >= max_normal:
                    return suspicious + normal
    return suspicious + normal


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


def run_pass(ai_only: bool, items: list) -> list:
    ALERTS_FILE.write_text("", encoding="utf-8")
    if os.path.exists(CMP_QUEUE):
        os.unlink(CMP_QUEUE)

    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{REPO_ROOT / 'src'}:{env.get('LD_LIBRARY_PATH', '')}"

    cmd = [str(ANALYSISD_BIN)]
    if ai_only:
        cmd.append("-A")
    cmd.extend(["-D", str(REPO_ROOT), "-f", "-u", "root", "-g", "root", "-q", CMP_QUEUE])

    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []

    try:
        for _ in range(450):
            if os.path.exists(CMP_QUEUE):
                break
            time.sleep(0.1)

        if not os.path.exists(CMP_QUEUE):
            raise RuntimeError(f"Failed to start wazuh-local-analysisd (ai_only={ai_only})")

        with open(ALERTS_FILE, "r", encoding="utf-8") as alerts_fp:
            alerts_fp.seek(0, os.SEEK_END)
            for item in items:
                wire_msg = f"1:{item['location']}:{item['log']}"
                client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    client.sendto(wire_msg.encode("utf-8", errors="replace"), CMP_QUEUE)
                finally:
                    client.close()

                matched = []
                deadline = time.time() + (0.40 if ai_only else 0.20)
                while time.time() < deadline:
                    line = alerts_fp.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                alert = json.loads(line)
                                matched.append(alert)
                                if ai_only or str(alert.get("rule", {}).get("id")) != "99999":
                                    break
                            except json.JSONDecodeError:
                                pass
                    time.sleep(0.01)

                static_alert = next((a for a in matched if str(a.get("rule", {}).get("id")) != "99999"), None)
                ai_alert = next((a for a in matched if str(a.get("rule", {}).get("id")) == "99999"), None)
                results.append({"static": static_alert, "ai": ai_alert})

    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if os.path.exists(CMP_QUEUE):
            os.unlink(CMP_QUEUE)

    return results


def parse_ai_desc(ai_alert: dict) -> str:
    if not ai_alert:
        return "-"
    desc = ai_alert.get("rule", {}).get("description", "")
    m = re.search(r"AI Threat Detected:\s*(.+?)\s*\(Confidence:\s*([\d.]+%)\)", desc)
    return f"{m.group(1)} ({m.group(2)})" if m else desc


def main():
    parser = argparse.ArgumentParser(description="Compare Static Rules vs AI-Only on LogFiles/")
    parser.add_argument("--max-suspicious", type=int, default=40)
    parser.add_argument("--max-normal", type=int, default=20)
    parser.add_argument("--out-csv", default=str(DEFAULT_OUT_CSV))
    args = parser.parse_args()

    samples = collect_diverse_samples(args.max_suspicious, args.max_normal)
    if not samples:
        print("[!] No log samples found in LogFiles/")
        sys.exit(1)

    print(f"[*] Collected {len(samples)} diverse IIS log lines from LogFiles/")
    (REPO_ROOT / "logs" / "alerts").mkdir(parents=True, exist_ok=True)
    started_ai_daemon = None

    try:
        if not is_socket_alive(AI_SOCKET):
            print("[*] Launching ai_daemon.py...")
            started_ai_daemon = subprocess.Popen(
                [sys.executable, str(AI_DAEMON_SCRIPT), "--socket", AI_SOCKET],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(120):
                if is_socket_alive(AI_SOCKET):
                    break
                time.sleep(0.5)
        else:
            print(f"[+] Using active AI Daemon socket: {AI_SOCKET}")

        print("[*] Pass 1 (only_rule): Running Static Rules...")
        p1_res = run_pass(ai_only=False, items=samples)

        print("[*] Pass 2 (only_AI): Running AI-Only (-A)...")
        p2_res = run_pass(ai_only=True, items=samples)

        rows = []
        counts = {"both": 0, "rule_only": 0, "ai_only": 0, "none": 0}

        print("\n" + "=" * 125)
        print(f"{'#':<3} | {'File':<26} | {'Cat':<10} | {'Rule (ID/Lvl)':<14} | {'AI (-A)':<22} | {'Status':<11} | {'Log Snippet'}")
        print("-" * 125)

        for idx, (item, r1, r2) in enumerate(zip(samples, p1_res, p2_res), 1):
            st = r1["static"]
            ai = r2["ai"]

            st_str = f"{st['rule']['id']} (L{st['rule']['level']})" if st else "-"
            ai_str = f"L{ai['rule']['level']} {parse_ai_desc(ai)}" if ai else "-"

            if st and ai:
                status = "BOTH"
                counts["both"] += 1
            elif st and not ai:
                status = "RULE_ONLY"
                counts["rule_only"] += 1
            elif not st and ai:
                status = "AI_ONLY"
                counts["ai_only"] += 1
            else:
                status = "NONE"
                counts["none"] += 1

            snippet = item["log"][:42]
            cat_short = "susp/err" if item["category"] == "suspicious_or_error" else "normal"
            print(f"{idx:<3} | {item['file']:<26} | {cat_short:<10} | {st_str:<14} | {ai_str:<22} | {status:<11} | {snippet}")

            rows.append({
                "index": idx,
                "file": item["file"],
                "line_no": item["line_no"],
                "category": item["category"],
                "only_rule_detected": bool(st),
                "rule_id": st["rule"]["id"] if st else "",
                "rule_level": st["rule"]["level"] if st else "",
                "rule_description": st["rule"]["description"] if st else "",
                "only_ai_detected": bool(ai),
                "ai_level": ai["rule"]["level"] if ai else "",
                "ai_description": parse_ai_desc(ai) if ai else "",
                "comparison_status": status,
                "log_line": item["log"],
            })

        with open(args.out_csv, "w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

        print("=" * 125)
        print(f"SUMMARY ({len(samples)} logs from LogFiles/):")
        print(f"  BOTH (Rule & AI detected) : {counts['both']}")
        print(f"  RULE_ONLY                 : {counts['rule_only']}")
        print(f"  AI_ONLY                   : {counts['ai_only']}")
        print(f"  NONE (Not flagged)        : {counts['none']}")
        print(f"  Full CSV saved to         : {args.out_csv}")

    finally:
        if started_ai_daemon and started_ai_daemon.poll() is None:
            started_ai_daemon.send_signal(signal.SIGTERM)
            started_ai_daemon.wait(timeout=5)


if __name__ == "__main__":
    main()

