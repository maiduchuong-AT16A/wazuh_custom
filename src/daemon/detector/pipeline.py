import csv
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer

from .model import TransformerScorer
from .preprocess import AuditTracker, Normalizer, detect_source


def coarse(label):
    if label == "0":
        return "normal"
    if "eximsploit" in label:
        return "privesc"
    if label.startswith("webshell"):
        return "webshell"
    if label in ("upload", "okay-upload-webshell", "mail-curl", "okay-curl"):
        return "upload"
    return label


class TfidfScorer:
    def __init__(self, path):
        m = joblib.load(path)
        self.tfidf, self.clf, self.ratios, self.classes = m["tfidf"], m["clf"], m["ratios"], m["classes"]
        self.vec = HashingVectorizer(analyzer="char_wb", ngram_range=(2, 5), n_features=2**20, alternate_sign=False)

    def predict(self, texts, src):
        p = np.zeros((len(texts), len(self.classes)))
        if texts:
            X = self.tfidf.transform(self.vec.transform([f"{src} | {t}" for t in texts]))
            p[:, self.clf.classes_] = self.clf.predict_proba(X)
        return p


def prior_correct(prob, ratio):
    p = prob * ratio
    return p / p.sum(1, keepdims=True)


def read_file(path, src, norm):
    tracker = AuditTracker() if src == "audit" else None
    texts, ts, last = [], [], None
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            t = norm.timestamp(line)
            t = t if t is not None else last
            last = t
            if tracker:
                texts.append(f"{tracker.annotate(line)} {norm.text(line, audit=True)}")
            else:
                texts.append(norm.text(line))
            ts.append(np.nan if t is None else t)
    return texts, np.asarray(ts, dtype=float)


def read_labels(path):
    with open(path) as f:
        return [coarse(l.rstrip("\n").split(",")[1]) for l in f]


def score_file(texts, src, tfidf, tfm):
    uniq, inv = np.unique(np.asarray(texts, dtype=object), return_inverse=True)
    uniq = list(uniq)
    p_lr = prior_correct(tfidf.predict(uniq, src), tfidf.ratios[src])
    p_tf = prior_correct(tfm.predict(uniq, src), tfm.ratios[src])
    return p_lr[inv], p_tf[inv]


def iso(t):
    return "" if np.isnan(t) else datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def metrics(y, pred):
    tp = int((y & pred).sum())
    fp = int((~y & pred).sum())
    fn = int((y & ~pred).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def run(input_dir, out_dir, models_dir, hostnames, year, labels_dir=None, mode="window", predictions="all",
        device=None):
    t0 = time.time()
    input_dir, out_dir, models_dir = Path(input_dir), Path(out_dir), Path(models_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg = json.loads((models_dir / "config.json").read_text())
    classes = cfg["classes"]
    tfidf = TfidfScorer(models_dir / "tfidf.joblib")
    tfm = TransformerScorer(models_dir / "tfbig.pt", device=device)
    norm = Normalizer(hostnames, year)
    win, line_thr, min_lines = cfg["window_seconds"], cfg["line_threshold"], cfg["min_alert_lines_per_window"]

    files = sorted(p for p in input_dir.rglob("*") if p.is_file() and detect_source(p.relative_to(input_dir)))
    if not files:
        raise SystemExit(f"no recognised log files under {input_dir}")

    frames = []
    fo = open(out_dir / "line_predictions.csv", "w", newline="") if mode == "line" else None
    w = csv.writer(fo) if fo else None
    if w:
        header = ["file", "source", "line_no", "timestamp", "predicted_class", "attack_score",
                  "attack_score_tfidf", "alert_line"]
        if labels_dir:
            header.append("true_class")
        w.writerow(header)
    for path in files:
        rel = path.relative_to(input_dir)
        src = detect_source(rel)
        texts, ts = read_file(path, src, norm)
        if not texts:
            continue
        p_lr, p_tf = score_file(texts, src, tfidf, tfm)
        s_lr, s_tf = 1.0 - p_lr[:, 0], 1.0 - p_tf[:, 0]
        cls = p_tf.argmax(1)
        hit_lr, hit_tf = s_lr > line_thr, s_tf > line_thr
        alert = hit_tf if mode == "line" else (hit_lr | hit_tf)
        truth = None
        if labels_dir:
            lp = Path(labels_dir) / rel
            truth = read_labels(lp) if lp.exists() else None
            if truth is not None and len(truth) != len(texts):
                raise SystemExit(f"label file {lp} has {len(truth)} lines, log has {len(texts)}")
        if w:
            for i in range(len(texts)):
                if predictions == "alerts" and not alert[i]:
                    continue
                row = [str(rel), src, i + 1, iso(ts[i]), classes[cls[i]] if alert[i] else "normal",
                       round(float(s_tf[i]), 6), round(float(s_lr[i]), 6), int(alert[i])]
                if labels_dir:
                    row.append(truth[i] if truth is not None else "")
                w.writerow(row)
        frames.append(pd.DataFrame({
            "source": src, "ts": ts, "cls": np.asarray(classes, dtype=object)[cls],
            "hits": hit_lr.astype(int) + hit_tf.astype(int), "alert": alert,
            "truth": truth if truth is not None else None,
        }))
        print(f"{rel} [{src}] {len(texts)} lines, {int(alert.sum())} flagged lines", flush=True)
    if fo:
        fo.close()

    df = pd.concat(frames, ignore_index=True)
    has_truth = labels_dir is not None and df.truth.notna().any()
    summary = {
        "mode": mode,
        "input_dir": str(input_dir),
        "files": len(files),
        "lines": int(len(df)),
        "flagged_lines": int(df.alert.sum()),
        "lines_by_source": df.source.value_counts().to_dict(),
        "flagged_lines_by_source": df[df.alert].source.value_counts().to_dict(),
        "predicted_class_counts_of_flagged_lines": df[df.alert & (df.cls != "normal")].cls.value_counts().to_dict(),
    }
    win_tab = None
    if mode == "window":
        win_tab = window_table(df, win, min_lines, has_truth)
        win_tab.to_csv(out_dir / "window_alerts.csv", index=False)
        summary.update({
            "window_seconds": win,
            "min_alert_lines_per_window": min_lines,
            "windows": int(len(win_tab)),
            "alert_windows": int(win_tab.alert.sum()),
            "alert_window_starts": win_tab[win_tab.alert].window_start.tolist(),
        })
    if has_truth:
        if mode == "line":
            lab = df.dropna(subset=["truth"])
            summary["evaluation"] = metrics((lab.truth != "normal").to_numpy(), lab.alert.to_numpy())
        else:
            summary["evaluation"] = metrics(win_tab.true_attack.fillna(False).to_numpy(bool),
                                            win_tab.alert.to_numpy(bool))
    summary["runtime_seconds"] = round(time.time() - t0, 1)
    summary["device"] = tfm.device
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    (out_dir / "summary.md").write_text(render_md(summary, win_tab))
    print(f"done in {summary['runtime_seconds']}s -> {out_dir}", flush=True)
    return summary


def window_table(df, win, min_lines, has_truth):
    df = df.assign(window=np.floor(df.ts / win)).dropna(subset=["window"])
    g = df.groupby("window")
    t = pd.DataFrame({"lines": g.size(), "alert_line_hits": g.hits.sum()})
    t["score"] = np.log1p(t.alert_line_hits)
    t["alert"] = t.alert_line_hits >= min_lines
    al = df[df.alert]
    t["alert_sources"] = al.groupby("window").source.agg(lambda x: ",".join(sorted(set(x))))
    t["top_attack_class"] = al[al.cls != "normal"].groupby("window").cls.agg(lambda x: x.value_counts().index[0])
    if has_truth:
        t["true_attack"] = df.assign(a=df.truth.fillna("normal") != "normal").groupby("window").a.any()
    t = t.reset_index()
    t.insert(0, "window_start", [iso(x * win) for x in t.window])
    return t.drop(columns="window").fillna({"alert_sources": "", "top_attack_class": ""})


def render_md(s, win_tab):
    title = "theo từng dòng log" if s["mode"] == "line" else "theo cửa sổ thời gian"
    lines = [
        f"# Kết quả phát hiện tấn công ({title})",
        "",
        f"- Thư mục input: `{s['input_dir']}`",
        f"- Số file log: {s['files']}, tổng số dòng: {s['lines']:,}",
        f"- Số dòng bị gắn cờ: {s['flagged_lines']:,}",
    ]
    if win_tab is not None:
        lines.append(f"- Số cửa sổ {s['window_seconds']}s: {s['windows']}, số cửa sổ cảnh báo: {s['alert_windows']} "
                     f"(ngưỡng: ít nhất {s['min_alert_lines_per_window']} lượt gắn cờ trong một cửa sổ)")
    lines += [f"- Thời gian chạy: {s['runtime_seconds']}s trên {s['device']}", "",
              "## Số dòng theo nguồn log", "", "| Nguồn | Số dòng | Số dòng bị gắn cờ |", "|---|---|---|"]
    for src, n in s["lines_by_source"].items():
        lines.append(f"| {src} | {n:,} | {s['flagged_lines_by_source'].get(src, 0):,} |")
    lines += ["", "## Lớp tấn công dự đoán của các dòng bị gắn cờ", "", "| Lớp | Số dòng |", "|---|---|"]
    for c, n in s["predicted_class_counts_of_flagged_lines"].items():
        lines.append(f"| {c} | {n:,} |")
    if win_tab is not None:
        lines += ["", "## Các cửa sổ cảnh báo", "", "| Bắt đầu (UTC) | Số lượt gắn cờ | Nguồn | Lớp chính |",
                  "|---|---|---|---|"]
        for _, r in win_tab[win_tab.alert].iterrows():
            lines.append(f"| {r.window_start} | {int(r.alert_line_hits):,} | {r.alert_sources} | {r.top_attack_class} |")
    if "evaluation" in s:
        m = s["evaluation"]
        unit = "dòng" if s["mode"] == "line" else "cửa sổ"
        lines += ["", f"## Đối chiếu với nhãn (theo {unit})", "", "| Precision | Recall | F1 | TP | FP | FN |",
                  "|---|---|---|---|---|---|",
                  f"| {m['precision']} | {m['recall']} | {m['f1']} | {m['tp']} | {m['fp']} | {m['fn']} |"]
    return "\n".join(lines) + "\n"
