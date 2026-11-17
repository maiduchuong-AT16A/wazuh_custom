#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modular LogFiles Scanner: Independent Only-Rule, Only-AI, or Both Modes
Low-RAM, Crash-Safe, Incremental-Save Edition (suitable for 3.7GB RAM machines & 13M+ lines):
- Saves detections incrementally per folder/chunk to CSV on disk immediately (never loses progress if interrupted).
- Uses chunked deduplication (max 50,000 unique lines per chunk) in run_only_ai() to keep RAM under ~1GB.
- Supports --resume to skip already completed folders.
- Automatically builds multi-sheet .xlsx (or keeps per-folder .csv) at the end or on Ctrl+C.
"""

import argparse
import csv
import gc
import glob
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd
import torch

REPO_ROOT = Path(__file__).resolve().parent.parent
DAEMON_DIR = REPO_ROOT / "src" / "daemon"
sys.path.insert(0, str(DAEMON_DIR))

from detector.model import TransformerScorer
from detector.pipeline import prior_correct
from detector.preprocess import Normalizer

ANALYSISD_BIN = REPO_ROOT / "src" / "wazuh-local-analysisd"
AIT_MODEL_DIR = REPO_ROOT / "models-AI" / "models" / "ait"
CMP_QUEUE = "/tmp/full_logfiles_rule_queue.sock"
ALERTS_FILE = REPO_ROOT / "logs" / "alerts" / "local_alerts.json"
DEFAULT_LOGFILES_DIR = REPO_ROOT / "LogFiles"
EXCEL_MAX_ROWS = 1_048_500


def confidence_to_level(conf: float) -> int:
    if conf >= 0.90:
        return 12
    if conf >= 0.80:
        return 10
    if conf >= 0.70:
        return 8
    if conf >= 0.60:
        return 6
    if conf >= 0.50:
        return 5
    return 3


class StaticRuleRunner:
    """Manages a single wazuh-local-analysisd (-R) instance for fast streaming Static Rule evaluation."""

    def __init__(self):
        self.proc = None
        self.alerts_fp = None

    def start(self):
        if not ANALYSISD_BIN.exists():
            raise FileNotFoundError(
                f"Missing binary {ANALYSISD_BIN}. Build first: cd src && make TARGET=agent wazuh-local-analysisd"
            )
        (REPO_ROOT / "logs" / "alerts").mkdir(parents=True, exist_ok=True)
        ALERTS_FILE.write_text("", encoding="utf-8")
        if os.path.exists(CMP_QUEUE):
            os.unlink(CMP_QUEUE)

        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = f"{REPO_ROOT / 'src'}:{env.get('LD_LIBRARY_PATH', '')}"
        cmd = [
            str(ANALYSISD_BIN),
            "-R",
            "-D", str(REPO_ROOT),
            "-f", "-u", "root", "-g", "root",
            "-q", CMP_QUEUE,
        ]
        self.proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for _ in range(600):
            if os.path.exists(CMP_QUEUE):
                break
            time.sleep(0.1)

        if not os.path.exists(CMP_QUEUE):
            raise RuntimeError("Failed to start wazuh-local-analysisd for Static Rules pass.")

        self.alerts_fp = open(ALERTS_FILE, "r", encoding="utf-8", errors="replace")
        self.alerts_fp.seek(0, os.SEEK_END)

    def _drain_alerts(self, writer, seen_count_ref, wait_idle: bool = False):
        """Read newly generated alerts from local_alerts.json and write immediately to CSV."""
        idle_rounds = 0
        max_idle = 15 if wait_idle else 1
        while idle_rounds < max_idle:
            got_new = False
            while True:
                aline = self.alerts_fp.readline()
                if not aline:
                    break
                got_new = True
                aline = aline.strip()
                if not aline:
                    continue
                try:
                    obj = json.loads(aline)
                    rid = str(obj.get("rule", {}).get("id", ""))
                    if rid and rid != "99999":
                        writer.writerow({
                            "file": obj.get("location", "").replace("/var/log/iis/", ""),
                            "line_no": "",
                            "rule_id": rid,
                            "rule_level": obj.get("rule", {}).get("level", ""),
                            "rule_description": obj.get("rule", {}).get("description", ""),
                            "log_line": obj.get("full_log", "")[:1000],
                        })
                        seen_count_ref[0] += 1
                except json.JSONDecodeError:
                    pass
            if not wait_idle:
                break
            if got_new:
                idle_rounds = 0
            else:
                idle_rounds += 1
                time.sleep(0.1)

    def stop(self):
        if self.alerts_fp:
            self.alerts_fp.close()
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if os.path.exists(CMP_QUEUE):
            os.unlink(CMP_QUEUE)


def run_only_rule(log_files: list, rule_runner: StaticRuleRunner, out_csv_path: Path):
    """
    Run ONLY Static Wazuh Rules on log_files, streaming detections directly to out_csv_path.
    Uses almost zero RAM and saves progress continuously on disk.
    """
    cols = ["file", "line_no", "rule_id", "rule_level", "rule_description", "log_line"]
    total_lines = 0
    flagged_ref = [0]
    total_files = len(log_files)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    with open(out_csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=cols)
        writer.writeheader()
        try:
            for fidx, (rel_path, full_path) in enumerate(log_files, 1):
                loc = f"/var/log/iis/{rel_path}"
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fp:
                    for line in fp:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        wire_msg = f"1:{loc}:{line}".encode("utf-8", errors="replace")
                        for _ in range(10):
                            try:
                                sock.sendto(wire_msg, CMP_QUEUE)
                                break
                            except OSError:
                                time.sleep(0.005)
                        total_lines += 1
                        if total_lines % 5000 == 0:
                            time.sleep(0.002)
                        if total_lines % 50000 == 0:
                            rule_runner._drain_alerts(writer, flagged_ref, wait_idle=False)
                            cf.flush()
                        if total_lines % 100000 == 0:
                            print(f"    [rule] streamed {total_lines:,} lines ({fidx}/{total_files} files) | flagged so far: {flagged_ref[0]:,}", flush=True)
        finally:
            sock.close()
            rule_runner._drain_alerts(writer, flagged_ref, wait_idle=True)
            cf.flush()

    return total_lines, flagged_ref[0]


def _flush_ai_chunk(chunk_lines: list, scorer: TransformerScorer, normalizer: Normalizer,
                    line_threshold: float, batch_size: int, src: str, writer, flagged_ref: list):
    """Deduplicate, infer batch, and write AI detections for a bounded chunk of lines."""
    if not chunk_lines:
        return 0
    unique_norms = list({norm_t for _, _, _, norm_t in chunk_lines})
    probs = scorer.predict(unique_norms, src=src, batch_size=batch_size)
    p_corr = prior_correct(probs, scorer.ratios[src])
    attack_scores = 1.0 - p_corr[:, 0]

    ai_hits = {}
    for idx, score in enumerate(attack_scores):
        if float(score) > line_threshold:
            cls_idx = int(p_corr[idx].argmax())
            if cls_idx == 0 and len(scorer.classes) > 1:
                cls_idx = int(p_corr[idx, 1:].argmax()) + 1
            ai_hits[unique_norms[idx]] = {
                "ai_attack_type": str(scorer.classes[cls_idx]),
                "ai_confidence": round(float(score), 4),
                "ai_level": confidence_to_level(float(score)),
            }

    if ai_hits:
        for rel_path, line_no, raw_line, norm_t in chunk_lines:
            a_info = ai_hits.get(norm_t)
            if a_info:
                writer.writerow({
                    "file": rel_path,
                    "line_no": line_no,
                    "ai_attack_type": a_info["ai_attack_type"],
                    "ai_level": a_info["ai_level"],
                    "ai_confidence": a_info["ai_confidence"],
                    "log_line": raw_line[:1000],
                })
                flagged_ref[0] += 1

    return len(unique_norms)


def run_only_ai(log_files: list, scorer: TransformerScorer, normalizer: Normalizer,
                line_threshold: float, out_csv_path: Path, batch_size: int = 256,
                chunk_size: int = 50000, src: str = "syslog"):
    """
    Run ONLY AI Model (AIT ByteTransformer) in bounded chunks (default 50,000 lines/chunk)
    so RAM usage stays low even on 7M+ line folders, flushing results to out_csv_path after every chunk.
    """
    cols = ["file", "line_no", "ai_attack_type", "ai_level", "ai_confidence", "log_line"]
    total_lines = 0
    total_unique = 0
    flagged_ref = [0]
    chunk_lines = []
    total_files = len(log_files)

    with open(out_csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=cols)
        writer.writeheader()
        try:
            for fidx, (rel_path, full_path) in enumerate(log_files, 1):
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fp:
                    for line_no, line in enumerate(fp, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        total_lines += 1
                        chunk_lines.append((rel_path, line_no, line, normalizer.text(line, audit=False)))

                        if len(chunk_lines) >= chunk_size:
                            total_unique += _flush_ai_chunk(
                                chunk_lines, scorer, normalizer, line_threshold,
                                batch_size, src, writer, flagged_ref
                            )
                            cf.flush()
                            chunk_lines.clear()
                            gc.collect()
                            print(f"    [ai] processed {total_lines:,} lines ({fidx}/{total_files} files) | flagged so far: {flagged_ref[0]:,}", flush=True)
        finally:
            if chunk_lines:
                total_unique += _flush_ai_chunk(
                    chunk_lines, scorer, normalizer, line_threshold,
                    batch_size, src, writer, flagged_ref
                )
                cf.flush()
                chunk_lines.clear()
                gc.collect()

    return total_lines, total_unique, flagged_ref[0]


def export_xlsx_from_csvs(summary_rows: list, csv_dir: Path, folders: list, xlsx_path: Path):
    """Build multi-sheet Excel workbook from saved per-folder CSV files."""
    if not summary_rows:
        return
    xlsx_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"\n[*] Exporting multi-sheet Excel report to {xlsx_path}...")
    with pd.ExcelWriter(xlsx_path, engine="openpyxl") as writer:
        pd.DataFrame(summary_rows).to_excel(writer, sheet_name="Summary", index=False)
        for folder in folders:
            cpath = csv_dir / f"{folder}.csv"
            if cpath.exists():
                df = pd.read_csv(cpath, nrows=EXCEL_MAX_ROWS)
                df.to_excel(writer, sheet_name=folder[:31], index=False)
    print(f"[+] Excel file saved: {xlsx_path}")


def main():
    parser = argparse.ArgumentParser(description="Crash-Safe Modular LogFiles Scanner (only_rule / only_ai)")
    parser.add_argument("--mode", choices=["rule", "ai"], required=True,
                        help="rule: run only_rule | ai: run only_ai")
    parser.add_argument("--format", choices=["xlsx", "csv"], default="xlsx",
                        help="Final output format: multi-sheet xlsx (default, CSVs also kept) or csv only")
    parser.add_argument("--logfiles-dir", default=str(DEFAULT_LOGFILES_DIR))
    parser.add_argument("--folders", nargs="*", default=None,
                        help="Optional subset of subfolders (e.g. W3SVC3 W3SVC5)")
    parser.add_argument("--out", default=None, help="Custom output .xlsx path")
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--chunk-size", type=int, default=50000, help="Lines per AI memory chunk (default: 50000)")
    parser.add_argument("--device", choices=["auto", "cuda", "cpu"], default="auto")
    parser.add_argument("--resume", action="store_true", help="Skip folders that already finished (.done marker)")
    args = parser.parse_args()

    logfiles_dir = Path(args.logfiles_dir)
    if not logfiles_dir.is_dir():
        print(f"[!] LogFiles directory not found: {logfiles_dir}")
        sys.exit(1)

    base_name = "only_rule_results" if args.mode == "rule" else "only_ai_results"
    csv_dir = REPO_ROOT / "logs" / f"{base_name}_csv"
    csv_dir.mkdir(parents=True, exist_ok=True)
    xlsx_path = Path(args.out) if args.out else (REPO_ROOT / "logs" / f"{base_name}.xlsx")

    subfolders = sorted([d.name for d in logfiles_dir.iterdir() if d.is_dir()])
    if args.folders:
        subfolders = [f for f in subfolders if f in args.folders]
    if not subfolders:
        print("[!] No target subfolders found.")
        sys.exit(1)

    rule_runner = None
    scorer = None
    normalizer = None
    line_threshold = 0.5

    if args.mode == "rule":
        rule_runner = StaticRuleRunner()
        print("[*] Starting wazuh-local-analysisd (-R) for ONLY-RULE pass...")
        rule_runner.start()
    else:
        device = ("cuda" if torch.cuda.is_available() else "cpu") if args.device == "auto" else args.device
        print(f"[*] Loading AIT ByteTransformer on device='{device}' for ONLY-AI pass...")
        cfg = json.loads((AIT_MODEL_DIR / "config.json").read_text(encoding="utf-8"))
        line_threshold = float(cfg.get("line_threshold", 0.5))
        scorer = TransformerScorer(str(AIT_MODEL_DIR / "tfbig.pt"), device=device)
        normalizer = Normalizer(["cup.com", "insect.com", "onion.com", "spiral.com"], default_year=2020)

    summary_csv = csv_dir / "Summary.csv"
    summary_rows = []
    if args.resume and summary_csv.exists():
        summary_rows = pd.read_csv(summary_csv).to_dict(orient="records")
    processed_folders = {r["folder"] for r in summary_rows}

    try:
        for folder in subfolders:
            done_marker = csv_dir / f"{folder}.done"
            out_csv = csv_dir / f"{folder}.csv"

            if args.resume and done_marker.exists() and folder in processed_folders:
                print(f"[*] Skipping {folder} (already completed).")
                continue

            folder_path = logfiles_dir / folder
            raw_files = sorted(glob.glob(str(folder_path / "*.log")))
            log_files = [(f"{folder}/{os.path.basename(p)}", p) for p in raw_files]
            if not log_files:
                continue

            t0 = time.time()
            print(f"\n[*] [{args.mode.upper()}] Processing {folder} ({len(log_files)} files) -> streaming to {out_csv}", flush=True)

            if args.mode == "rule":
                total_lines, flagged_cnt = run_only_rule(log_files, rule_runner, out_csv)
                elapsed = round(time.time() - t0, 2)
                print(f"    -> Done {folder}: {total_lines:,} lines | Rule flagged: {flagged_cnt:,} ({elapsed}s)", flush=True)
                row = {
                    "folder": folder, "total_files": len(log_files),
                    "total_log_lines": total_lines, "rule_flagged": flagged_cnt,
                    "elapsed_seconds": elapsed,
                }
            else:
                total_lines, unique_cnt, flagged_cnt = run_only_ai(
                    log_files, scorer, normalizer, line_threshold, out_csv,
                    batch_size=args.batch_size, chunk_size=args.chunk_size
                )
                elapsed = round(time.time() - t0, 2)
                print(f"    -> Done {folder}: {total_lines:,} lines ({unique_cnt:,} unique) | AI flagged: {flagged_cnt:,} ({elapsed}s)", flush=True)
                row = {
                    "folder": folder, "total_files": len(log_files),
                    "total_log_lines": total_lines, "unique_normalized_lines": unique_cnt,
                    "ai_flagged": flagged_cnt, "elapsed_seconds": elapsed,
                }

            summary_rows = [r for r in summary_rows if r["folder"] != folder]
            summary_rows.append(row)
            pd.DataFrame(summary_rows).to_csv(summary_csv, index=False)
            done_marker.write_text("ok", encoding="utf-8")
            gc.collect()

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Partial CSV results have already been saved on disk!")
    finally:
        if rule_runner:
            rule_runner.stop()
        if args.format == "xlsx" and summary_rows:
            export_xlsx_from_csvs(summary_rows, csv_dir, subfolders, xlsx_path)
        print(f"[+] Per-folder CSV files available in: {csv_dir}")


if __name__ == "__main__":
    main()
