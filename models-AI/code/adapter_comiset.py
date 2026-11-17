"""
COMISET (Comiset23 Lab, Windows event logs JSONL) adapter
-> QRadar-compatible CSV for the train_1 pipeline.

Streams the (huge, 160GB) JSON line-by-line from the zip, scanning only the
first MAX_LINES records (a small part). Attack-type multiclass target
(categoryDescription) = rule_technique_name (MITRE ATT&CK technique).
A 'normal' class is sampled from benign Sysmon process events.
Caps N rows per class (default 2000).
"""
import sys
import re
import csv
import json
import subprocess
import random
from collections import defaultdict, Counter

ZIP = "downloads/COMISET_Lab.zip"
MEMBER = "dataset_comillas2.json"
OUT = "runs/comiset/dataset/comiset_data.csv"
MAX_LINES = 5_000_000
N_PER_CLASS = 2000
SEED = 42

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def main():
    import os
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    rnd = random.Random(SEED)

    attacks = defaultdict(list)     # technique -> records
    normal = []                     # reservoir of benign sysmon records
    normal_seen = 0
    raw = Counter()

    proc = subprocess.Popen(["unzip", "-p", ZIP, MEMBER],
                            stdout=subprocess.PIPE, bufsize=1024 * 1024)
    n = 0
    for bline in proc.stdout:
        if n >= MAX_LINES:
            break
        n += 1
        try:
            line = bline.decode("utf-8", "ignore").strip().rstrip(",")
            if not line or line in "[]":
                continue
            o = json.loads(line)
        except Exception:
            continue
        s = o.get("_source", o)

        msg = s.get("event_original_message") or s.get("Message") or s.get("Operation") or ""
        msg = str(msg)
        ips = IP_RE.findall(msg)
        rec = {
            "deviceName": s.get("host_name", ""),
            "deviceCategory": "windows_endpoint",
            "eventName": s.get("log_name", "") or s.get("source_name", ""),
            "eventDescription": str(s.get("source_name", ""))[:120],
            "srcIp": ips[0] if ips else "",
            "destIp": ips[1] if len(ips) > 1 else "",
            "severity": s.get("Severity Name") or s.get("level", "info"),
            "payloadAsUTF": msg[:500],
            "categoryDescription": None,
        }

        tech = s.get("rule_technique_name")
        if tech:
            raw[tech] += 1
            if len(msg) < 5:
                continue
            rec["categoryDescription"] = str(tech)
            if len(attacks[tech]) < N_PER_CLASS * 4:
                attacks[tech].append(rec)
        else:
            # benign: prefer Sysmon process events as the 'normal' contrast class
            if s.get("log_name") == "Microsoft-Windows-Sysmon/Operational" and len(msg) >= 5:
                normal_seen += 1
                rec["categoryDescription"] = "normal"
                if len(normal) < N_PER_CLASS * 4:
                    normal.append(rec)
                else:
                    j = rnd.randint(0, normal_seen - 1)
                    if j < N_PER_CLASS * 4:
                        normal[j] = rec

    proc.stdout.close()
    proc.wait()

    print(f"Scanned {n:,} lines.")
    print("Raw technique counts (pre-cap):")
    for k, v in raw.most_common():
        print(f"  {v:6,d}  {k}")

    # assemble + cap
    buckets = dict(attacks)
    buckets["normal"] = normal
    fieldnames = ["deviceName", "deviceCategory", "eventName", "eventDescription",
                  "srcIp", "destIp", "severity", "payloadAsUTF", "categoryDescription"]
    final = Counter()
    with open(OUT, "w", newline="", encoding="utf-8") as fo:
        w = csv.DictWriter(fo, fieldnames=fieldnames)
        w.writeheader()
        for cls, recs in buckets.items():
            if len(recs) > N_PER_CLASS:
                recs = rnd.sample(recs, N_PER_CLASS)
            for r in recs:
                w.writerow(r)
            final[cls] = len(recs)

    print(f"\nWrote {OUT}")
    print("Final per-class (capped at %d):" % N_PER_CLASS)
    for k, v in final.most_common():
        print(f"  {v:6,d}  {k}")
    print("Total rows:", sum(final.values()), "| classes:", len(final))


if __name__ == "__main__":
    main()
