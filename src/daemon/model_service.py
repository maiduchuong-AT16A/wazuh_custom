# -*- coding: utf-8 -*-
"""
Model Service for AI Inference Daemon
Integrates:
- ait (Linux): ByteTransformer + Prior Correction (ait_attack_detector_Linux, --mode line)
  with fallback support for legacy B6 Hybrid BiLSTM-Attention + CNN
- comiset (Windows): B6 Hybrid BiLSTM-Attention + CNN
"""

import os
import sys
import json
import pickle
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from detector.model import TransformerScorer
from detector.preprocess import Normalizer, AuditTracker, detect_source
from detector.pipeline import prior_correct

logger = logging.getLogger("model_service")

# Model Architecture matching train_1.py
class ModelConfig:
    CHUNK_SIZE = 100
    LSTM_UNITS = 128
    CNN_FILTERS = 128
    DENSE_UNITS = 256
    DROPOUT_RATE = 0.4
    TEXT_COLS = [
        "srcIp", "destIp", "deviceName", "deviceCategory",
        "eventName", "eventDescription", "domainName", "severity",
        "mPCEvent", "payloadAsUTF"
    ]


class AttentionLayer(nn.Module):
    """Attention mechanism matching train_1.py"""
    def __init__(self, hidden_dim: int):
        super(AttentionLayer, self).__init__()
        self.W = nn.Linear(hidden_dim, hidden_dim, bias=False)
        self.b = nn.Parameter(torch.zeros(hidden_dim))
        self.u = nn.Parameter(torch.randn(hidden_dim))
        nn.init.xavier_uniform_(self.W.weight)
        nn.init.xavier_uniform_(self.u.unsqueeze(0))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        uit = torch.tanh(self.W(x) + self.b)
        ait = torch.matmul(uit, self.u)
        a = F.softmax(ait, dim=1)
        a = a.unsqueeze(-1)
        weighted_input = x * a
        return torch.sum(weighted_input, dim=1)


class HybridBiLSTMCNN(nn.Module):
    """Hybrid BiLSTM-Attention + CNN model matching train_1.py"""
    def __init__(self, tfidf_dim: int, num_classes: int, config: ModelConfig = ModelConfig):
        super(HybridBiLSTMCNN, self).__init__()
        self.tfidf_dim = tfidf_dim
        self.chunk_size = config.CHUNK_SIZE
        self.num_chunks = tfidf_dim // self.chunk_size
        if tfidf_dim % self.chunk_size != 0:
            self.num_chunks += 1

        self.padded_dim = self.num_chunks * self.chunk_size
        if tfidf_dim % self.chunk_size != 0:
            self.padding_dense = nn.Linear(tfidf_dim, self.padded_dim)
        else:
            self.padding_dense = None

        # BiLSTM branch
        self.bilstm_1 = nn.LSTM(
            input_size=self.chunk_size,
            hidden_size=config.LSTM_UNITS,
            batch_first=True,
            bidirectional=True,
            dropout=0.2
        )
        self.bilstm_2 = nn.LSTM(
            input_size=config.LSTM_UNITS * 2,
            hidden_size=config.LSTM_UNITS // 2,
            batch_first=True,
            bidirectional=True,
            dropout=0.2
        )
        self.attention = AttentionLayer(config.LSTM_UNITS)

        # CNN branch
        self.filter_sizes = [3, 4, 5]
        self.convs = nn.ModuleList([
            nn.Conv1d(self.chunk_size, config.CNN_FILTERS, fs, padding='same')
            for fs in self.filter_sizes
        ])

        # Dense layers
        merged_dim = config.LSTM_UNITS + (config.CNN_FILTERS * len(self.filter_sizes))
        self.dense_1 = nn.Linear(merged_dim, config.DENSE_UNITS)
        self.dropout_1 = nn.Dropout(config.DROPOUT_RATE)
        self.dense_2 = nn.Linear(config.DENSE_UNITS, config.DENSE_UNITS // 2)
        self.dropout_2 = nn.Dropout(config.DROPOUT_RATE / 2)
        self.batch_norm = nn.BatchNorm1d(config.DENSE_UNITS // 2)
        self.output_layer = nn.Linear(config.DENSE_UNITS // 2, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        batch_size = x.size(0)
        if self.padding_dense is not None:
            x = self.padding_dense(x)

        x_seq = x.view(batch_size, self.num_chunks, self.chunk_size)

        # BiLSTM + Attention
        lstm_out_1, _ = self.bilstm_1(x_seq)
        lstm_out_2, _ = self.bilstm_2(lstm_out_1)
        attention_output = self.attention(lstm_out_2)

        # CNN
        x_cnn = x_seq.transpose(1, 2)
        conv_outputs = []
        for conv in self.convs:
            conv_out = F.relu(conv(x_cnn))
            pooled = F.max_pool1d(conv_out, kernel_size=conv_out.size(2))
            conv_outputs.append(pooled.squeeze(2))
        cnn_concat = torch.cat(conv_outputs, dim=1)

        # Merge and dense
        merged = torch.cat([attention_output, cnn_concat], dim=1)
        x = F.relu(self.dense_1(merged))
        x = self.dropout_1(x)
        x = F.relu(self.dense_2(x))
        x = self.dropout_2(x)
        x = self.batch_norm(x)
        return self.output_layer(x)


class B6Model:
    """Wrapper for trained PyTorch B6 model"""
    def __init__(self, model_dir: str, device: Optional[torch.device] = None):
        self.model_dir = model_dir
        self.device = device or torch.device('cpu')

        # Load TF-IDF vectorizer
        tfidf_path = os.path.join(model_dir, "tfidf_vectorizer.pkl")
        with open(tfidf_path, 'rb') as f:
            self.tfidf_vectorizer = pickle.load(f)

        # Load Label Encoder
        label_enc_path = os.path.join(model_dir, "label_encoder.pkl")
        with open(label_enc_path, 'rb') as f:
            self.label_encoder = pickle.load(f)

        # Load Metadata
        meta_path = os.path.join(model_dir, "metadata.json")
        with open(meta_path, 'r', encoding='utf-8') as f:
            self.metadata = json.load(f)

        # Build model and load checkpoint
        self.model = HybridBiLSTMCNN(
            self.metadata['tfidf_dim'],
            self.metadata['num_classes'],
            ModelConfig
        ).to(self.device)

        checkpoint_path = os.path.join(model_dir, "best_model.pt")
        checkpoint = torch.load(checkpoint_path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()

        logger.info(f"Model successfully loaded from {model_dir} ({self.metadata['num_classes']} classes)")

    def predict(self, texts: List[str]) -> List[str]:
        X_tfidf = self.tfidf_vectorizer.transform(texts).toarray()
        X_tensor = torch.FloatTensor(X_tfidf).to(self.device)
        with torch.no_grad():
            outputs = self.model(X_tensor)
            _, predicted = torch.max(outputs, 1)
        return self.label_encoder.inverse_transform(predicted.cpu().numpy()).tolist()

    def predict_proba(self, texts: List[str]) -> List[float]:
        X_tfidf = self.tfidf_vectorizer.transform(texts).toarray()
        X_tensor = torch.FloatTensor(X_tfidf).to(self.device)
        with torch.no_grad():
            outputs = self.model(X_tensor)
            proba = F.softmax(outputs, dim=1)
        return proba.cpu().numpy()


class AITDetectorModel:
    """Wrapper for ait_attack_detector_Linux ByteTransformer (--mode line)"""
    DEFAULT_HOSTNAMES = ["cup.com", "insect.com", "onion.com", "spiral.com"]
    SOURCE_ALIASES = {
        "exim_mainlog": "exim",
        "mail_info": "mail",
        "journald": "syslog",
    }

    def __init__(self, model_dir: str, device: Optional[torch.device] = None):
        self.model_dir = model_dir
        self.device_str = str(device) if device else "cpu"

        cfg_path = os.path.join(model_dir, "config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "classes": ["normal", "nmap", "nikto", "vrfy", "hydra", "upload", "webshell", "privesc"],
                "window_seconds": 60,
                "line_threshold": 0.5,
                "min_alert_lines_per_window": 148,
            }

        self.line_threshold = float(self.config.get("line_threshold", 0.5))
        tfbig_path = os.path.join(model_dir, "tfbig.pt")
        self.scorer = TransformerScorer(tfbig_path, device=self.device_str)
        self.classes = self.scorer.classes
        self.normalizer = Normalizer(self.DEFAULT_HOSTNAMES, default_year=2020)
        self.audit_tracker = AuditTracker()

        logger.info(
            f"AIT ByteTransformer loaded from {tfbig_path} "
            f"({len(self.classes)} classes, {len(self.scorer.srcs)} sources, mode=line, threshold={self.line_threshold})"
        )

    def _extract_raw_line_and_hint(self, log_content: str) -> tuple[str, str]:
        if not log_content:
            return "", ""

        content = log_content.strip()
        if content.startswith("{") and content.endswith("}"):
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    if "payloadAsUTF" in data and data["payloadAsUTF"]:
                        return str(data["payloadAsUTF"]), str(data.get("eventName", ""))
                    if "flow_id" in data or "event_type" in data:
                        return content, "suricata_eve"
            except Exception:
                pass

        if "payloadAsUTF:" in content:
            parts = content.split("payloadAsUTF:", 1)
            ev_hint = ""
            if "eventName:" in parts[0]:
                ev_hint = parts[0].split("eventName:", 1)[1].split("|")[0].strip()
            return parts[1].strip(), ev_hint

        return content, ""

    def _resolve_source(self, location: str, ev_hint: str, raw_line: str) -> str:
        # 1. Match location by filename rules (access.log, auth.log, syslog, audit.log, etc.)
        if location:
            src = detect_source(location)
            if src in self.scorer.srcs:
                return src
            loc_clean = location.strip().lower()
            if loc_clean in self.scorer.srcs:
                return loc_clean
            if loc_clean in self.SOURCE_ALIASES:
                return self.SOURCE_ALIASES[loc_clean]

        # 2. Match eventName hint from structured sample payloads
        if ev_hint:
            hint_clean = ev_hint.strip().lower()
            if hint_clean in self.scorer.srcs:
                return hint_clean
            if hint_clean in self.SOURCE_ALIASES:
                return self.SOURCE_ALIASES[hint_clean]
            src = detect_source(hint_clean)
            if src in self.scorer.srcs:
                return src

        # 3. Heuristic fallback from raw log line content
        if "type=SYSCALL" in raw_line or "msg=audit(" in raw_line:
            return "audit"
        if "HTTP/1." in raw_line and any(m in raw_line for m in ('"GET ', '"POST ', '"HEAD ', '"PUT ', '"DELETE ', 'GET /', 'POST /')):
            return "apache_access"
        if ("[error]" in raw_line or "PHP " in raw_line) and "[pid " in raw_line:
            return "apache_error"
        if any(k in raw_line for k in ("sshd[", "pam_unix", "sudo:", "Accepted password", "Failed password")):
            return "auth"
        if "dovecot:" in raw_line or "postfix/" in raw_line:
            return "mail"

        return "syslog"

    def classify_line(self, log_content: str, location: str = "") -> tuple[bool, str, float]:
        raw_line, ev_hint = self._extract_raw_line_and_hint(log_content)
        if not raw_line:
            return False, "", 0.0

        src = self._resolve_source(location, ev_hint, raw_line)
        if src == "audit":
            norm_text = f"{self.audit_tracker.annotate(raw_line)} {self.normalizer.text(raw_line, audit=True)}"
        else:
            norm_text = self.normalizer.text(raw_line, audit=False)

        raw_probs = self.scorer.predict([norm_text], src)
        p_tf = prior_correct(raw_probs, self.scorer.ratios[src])

        attack_score = float(1.0 - p_tf[0, 0])
        is_alert = bool(attack_score > self.line_threshold)

        if is_alert:
            cls_idx = int(p_tf[0].argmax())
            if cls_idx == 0 and len(self.classes) > 1:
                cls_idx = int(p_tf[0, 1:].argmax()) + 1
            predicted_class = str(self.classes[cls_idx])
            return True, predicted_class, round(attack_score, 4)

        return False, "", round(attack_score, 4)


class ModelService:
    """Manages AI inference across Linux (ait) and Windows (comiset) models"""

    def __init__(self, ait_model_dir: str, comiset_model_dir: str, device: str = "cpu"):
        self.device = torch.device(device)
        logger.info(f"Initializing ModelService on {self.device}")
        
        self.ait_model: Optional[ Any ] = None
        self.comiset_model: Optional[B6Model] = None

        if os.path.isdir(ait_model_dir):
            try:
                tfbig_path = os.path.join(ait_model_dir, "tfbig.pt")
                if os.path.exists(tfbig_path):
                    self.ait_model = AITDetectorModel(ait_model_dir, self.device)
                else:
                    self.ait_model = B6Model(ait_model_dir, self.device)
            except Exception as e:
                logger.error(f"Failed to load ait model: {e}")
        else:
            logger.warning(f"ait model directory not found: {ait_model_dir}")

        if os.path.isdir(comiset_model_dir):
            try:
                self.comiset_model = B6Model(comiset_model_dir, self.device)
            except Exception as e:
                logger.error(f"Failed to load comiset model: {e}")
        else:
            logger.warning(f"comiset model directory not found: {comiset_model_dir}")

        # Warmup models to prevent first-call JIT/allocation latency spikes
        try:
            if self.ait_model:
                self.classify_event("warmup-linux", "Linux", "warmup event", location="/var/log/syslog")
            if self.comiset_model:
                self.classify_event("warmup-win", "Windows", "warmup event")
            logger.info("AI models warmed up successfully.")
        except Exception as e:
            logger.warning(f"Model warmup failed: {e}")


    def format_log_content(self, log_content: str) -> str:
        """Sanitize or format log content for model inference"""
        if not log_content:
            return ""
        
        # Check if log_content is JSON with standard column keys
        try:
            if log_content.startswith("{") and log_content.endswith("}"):
                data = json.loads(log_content)
                parts = []
                for col in ModelConfig.TEXT_COLS:
                    if col in data and data[col]:
                        parts.append(f"{col}: {str(data[col])[:100]}")
                if parts:
                    return " | ".join(parts)
        except Exception:
            pass

        return log_content[:2048]

    def classify_event(self, event_id: str, os_type: str, log_content: str, location: str = "") -> Dict[str, Any]:
        """Classify a log event conforming to ipc-schema.md contract"""
        target_os = (os_type or "").strip().lower()
        if "win" in target_os:
            model = self.comiset_model
            model_name = "comiset"
        else:
            model = self.ait_model
            model_name = "ait"

        if model is None:
            return {
                "event_id": event_id,
                "is_malicious": False,
                "attack_type": "",
                "confidence_score": 0.0,
                "error": f"Model for {model_name} ({os_type}) is not available"
            }

        try:
            if not log_content or not log_content.strip():
                return {
                    "event_id": event_id,
                    "is_malicious": False,
                    "attack_type": "",
                    "confidence_score": 0.0,
                    "error": "Empty log content"
                }

            if isinstance(model, AITDetectorModel):
                is_malicious, attack_type, confidence = model.classify_line(log_content, location=location)
                return {
                    "event_id": event_id,
                    "is_malicious": is_malicious,
                    "attack_type": attack_type,
                    "confidence_score": confidence,
                    "error": None
                }

            formatted_text = self.format_log_content(log_content)
            if not formatted_text:
                return {
                    "event_id": event_id,
                    "is_malicious": False,
                    "attack_type": "",
                    "confidence_score": 0.0,
                    "error": "Empty log content"
                }

            preds = model.predict([formatted_text])
            probs = model.predict_proba([formatted_text])

            predicted_label = str(preds[0])
            confidence = float(probs[0].max())

            is_malicious = (predicted_label.strip().lower() != "normal")
            attack_type = predicted_label if is_malicious else ""

            return {
                "event_id": event_id,
                "is_malicious": is_malicious,
                "attack_type": attack_type,
                "confidence_score": round(confidence, 4),
                "error": None
            }
        except Exception as e:
            logger.exception(f"Inference error for event {event_id}: {e}")
            return {
                "event_id": event_id,
                "is_malicious": False,
                "attack_type": "",
                "confidence_score": 0.0,
                "error": str(e)
            }
