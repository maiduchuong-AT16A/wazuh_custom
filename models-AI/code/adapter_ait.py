"""
AIT-LDS-v1.1 adapter -> QRadar-compatible CSV for the train_1 pipeline.

Joins each text log file with its line-parallel label file under labels/.
Attack-type multiclass target (categoryDescription):
  0/''        -> normal
  webshell-*  -> webshell
  nikto/hydra/vrfy/upload/... -> kept as-is
Caps to N rows per class (default 2000).
"""
import os
import re
import glob
import csv
import sys
import random
from collections import defaultdict, Counter

EXTRACT = "downloads/ait_extract"
OUT_DIR = "runs/ait/dataset"
N_PER_CLASS = 2000
SEED = 42

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def event_name(fname):
    n = os.path.basename(fname)
    if "access.log" in n: return "apache_access"
    if "error.log" in n:  return "apache_error"
    if n == "auth.log":   return "auth"
    if n == "mainlog":    return "exim_mainlog"
    if n == "syslog":     return "syslog"
    if n == "messages":   return "messages"
    if n == "daemon.log": return "daemon"
    if n == "mail.log":   return "mail"
    if n == "mail.info":  return "mail_info"
    if n == "user.log":   return "user"
    return n


def map_label(raw):
    tok = raw.split(",")[0].strip().lower()
    if tok in ("", "0"):
        return "normal"
    if tok.startswith("webshell"):
        return "webshell"
    return tok


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    label_files = glob.glob(os.path.join(EXTRACT, "labels", "**", "*"), recursive=True)
    label_files = [f for f in label_files if os.path.isfile(f)]

    buckets = defaultdict(list)   # class -> list of record dicts
    raw_counts = Counter()
    rnd = random.Random(SEED)

    for lf in label_files:
        data_f = lf.replace(os.sep + "labels" + os.sep, os.sep + "data" + os.sep)
        if not os.path.isfile(data_f):
            continue
        host_m = re.search(r'mail\.[a-z]+\.com', lf)
        host = host_m.group(0) if host_m else "unknown_host"
        ev = event_name(data_f)
        try:
            with open(data_f, "r", encoding="utf-8", errors="ignore") as fd, \
                 open(lf, "r", encoding="utf-8", errors="ignore") as fl:
                for line, lab in zip(fd, fl):
                    cls = map_label(lab)
                    raw_counts[cls] += 1
                    line = line.rstrip("\n")
                    if len(line) < 5:
                        continue
                    ips = IP_RE.findall(line)
                    rec = {
                        "deviceName": host,
                        "deviceCategory": "linux_mailserver",
                        "eventName": ev,
                        "srcIp": ips[0] if ips else "",
                        "destIp": ips[1] if len(ips) > 1 else "",
                        "severity": "attack" if cls != "normal" else "info",
                        "payloadAsUTF": line[:500],
                        "categoryDescription": cls,
                    }
                    # reservoir-ish: keep all attacks, subsample normal on the fly to bound memory
                    if cls == "normal" and len(buckets[cls]) >= N_PER_CLASS * 20:
                        # replace randomly to keep a representative sample
                        j = rnd.randint(0, raw_counts[cls] - 1)
                        if j < N_PER_CLASS * 20:
                            buckets[cls][j] = rec
                    else:
                        buckets[cls].append(rec)
        except Exception as e:
            print(f"  ! skip {data_f}: {e}")

    print("Raw line label distribution:")
    for k, v in raw_counts.most_common():
        print(f"  {k:12s} {v:,}")

    # cap N per class
    fieldnames = ["deviceName", "deviceCategory", "eventName", "srcIp", "destIp",
                  "severity", "payloadAsUTF", "categoryDescription"]
    out_path = os.path.join(OUT_DIR, "ait_data.csv")
    final_counts = Counter()
    with open(out_path, "w", newline="", encoding="utf-8") as fo:
        w = csv.DictWriter(fo, fieldnames=fieldnames)
        w.writeheader()
        for cls, recs in buckets.items():
            if len(recs) > N_PER_CLASS:
                recs = rnd.sample(recs, N_PER_CLASS)
            for r in recs:
                w.writerow(r)
            final_counts[cls] = len(recs)

    print(f"\nWrote {out_path}")
    print("Final per-class (capped at %d):" % N_PER_CLASS)
    for k, v in final_counts.most_common():
        print(f"  {k:12s} {v:,}")
    print("Total rows:", sum(final_counts.values()), "| classes:", len(final_counts))


if __name__ == "__main__":
    main()
