# -*- coding: utf-8 -*-
"""
Suy luận (dự đoán) bằng mô hình đã huấn luyện, chạy trực tiếp bằng PyTorch
(KHÔNG cần Triton Server).

Cách dùng:
    python predict.py --model ait     --input ../data/ait/ait_data.csv         --output ait_pred.csv
    python predict.py --model comiset --input ../data/comiset/comiset_data.csv --output comiset_pred.csv
    python predict.py --model ../models/ait --input duong_dan_log.csv

Đầu vào là file CSV chứa các cột log (srcIp, destIp, deviceName, deviceCategory,
eventName, eventDescription, domainName, severity, mPCEvent, payloadAsUTF).
Script tự ghép các cột này thành chuỗi văn bản giống lúc huấn luyện rồi phân loại.
Nếu CSV có sẵn cột nhãn 'categoryDescription', script sẽ in thêm độ chính xác.
"""
import os
import sys
import argparse
import pandas as pd
import torch

# Cho phép import train_1 dù chạy từ thư mục nào
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from train_1 import B6Inference, Config

HERE = os.path.dirname(os.path.abspath(__file__))
TEXT_COLS = Config.TEXT_COLS


def build_text(row):
    """Ghép các cột văn bản thành một chuỗi, đúng định dạng lúc huấn luyện."""
    parts = []
    for col in TEXT_COLS:
        if col in row and pd.notna(row[col]):
            parts.append(f"{col}: {str(row[col])[:100]}")
    return " | ".join(parts) if parts else ""


def resolve_model_dir(name):
    if name in ("ait", "comiset"):
        return os.path.join(HERE, "..", "models", name)
    return name


def main():
    ap = argparse.ArgumentParser(description="Dự đoán tấn công/bất thường bằng mô hình đã huấn luyện")
    ap.add_argument("--model", required=True, help="ait | comiset | hoặc đường dẫn thư mục model")
    ap.add_argument("--input", required=True, help="file CSV log cần phân loại")
    ap.add_argument("--output", default="predictions.csv", help="file CSV kết quả")
    ap.add_argument("--text-col", default=None, help="(tùy chọn) tên cột đã ghép sẵn văn bản")
    ap.add_argument("--device", default="cpu", choices=["cpu", "cuda"],
                    help="thiết bị tính toán (mặc định cpu; dùng cuda nếu GPU hỗ trợ tốt)")
    a = ap.parse_args()

    model_dir = resolve_model_dir(a.model)
    if not os.path.isfile(os.path.join(model_dir, "best_model.pt")):
        sys.exit(f"Khong tim thay model tai: {model_dir}")

    detector = B6Inference(model_dir, device=torch.device(a.device))

    df = pd.read_csv(a.input)
    if a.text_col and a.text_col in df.columns:
        texts = df[a.text_col].astype(str).tolist()
    else:
        texts = df.apply(build_text, axis=1).tolist()

    preds = detector.predict(texts)
    proba = detector.predict_proba(texts)
    conf = proba.max(axis=1)

    df_out = df.copy()
    df_out["predicted_label"] = preds
    df_out["confidence"] = [round(float(c), 4) for c in conf]
    df_out.to_csv(a.output, index=False, encoding="utf-8-sig")
    print(f"Da ghi {len(df_out)} du doan vao: {a.output}")

    if "categoryDescription" in df.columns:
        import numpy as np
        y_true = df["categoryDescription"].astype(str).values
        acc = float((y_true == pd.Series(preds).astype(str).values).mean())
        print(f"Accuracy so voi nhan that (categoryDescription): {acc:.4f}")

    print("\nVi du 5 du doan dau:")
    for t, p, c in list(zip(texts, preds, conf))[:5]:
        print(f"  [{p}]  conf={c:.3f}  | {t[:80]}")


if __name__ == "__main__":
    main()
