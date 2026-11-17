"""
Complete Pipeline: B6 TF-IDF + BiLSTM-Attention + CNN (PyTorch)
With Integrated Data Loader from Multiple CSV Files
Run: python main.py
"""

from tqdm import tqdm
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score, 
    precision_score, recall_score, confusion_matrix,
    roc_curve, auc, roc_auc_score
)

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import time
import os
import json
import pickle
import re
import warnings
from pathlib import Path
from datetime import datetime

warnings.filterwarnings('ignore')

# ================================================================
# CONFIGURATION
# ================================================================
class Config:
    # Data paths
    DATA_FOLDER = "./dataset"  # Folder chứa các file CSV
    OUTPUT_FOLDER = "outputs"
    MODELS_FOLDER = "saved_models"
    PLOTS_FOLDER = "plots"
    RESULTS_FOLDER = "results"
    
    # Data columns configuration
    SELECTED_COLUMNS = [
        "deviceDateTime", "stopDateTime", "srcIp", "destIp",
        "sourcePort", "destinationPort", "deviceName", "deviceCategory",
        "eventName", "eventDescription", "categoryDescription",
        "domainName", "severity", "magnitude", "relevance",
        "eventCount", "mPCEvent", "payloadAsUTF"
    ]
    TARGET_COL = 'categoryDescription'
    TEXT_COLS = [
        "srcIp", "destIp", "deviceName", "deviceCategory",
        "eventName", "eventDescription", "domainName", "severity",
        "mPCEvent", "payloadAsUTF"
    ]
    
    # Model hyperparameters
    MAX_FEATURES = 50000
    LSTM_UNITS = 128
    CNN_FILTERS = 128
    DENSE_UNITS = 256
    DROPOUT_RATE = 0.4
    CHUNK_SIZE = 100
    
    # Training parameters
    EPOCHS = 10
    BATCH_SIZE = 2048
    LEARNING_RATE = 0.001
    PATIENCE = 5
    
    # Data split
    TEST_SIZE = 0.3
    VALID_RATIO = 0.5  # Tỷ lệ valid trong test_size
    RANDOM_STATE = 42
    MIN_SAMPLES_PER_CLASS = 5
    
    # Device
    DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


# ================================================================
# ATTENTION LAYER
# ================================================================
class AttentionLayer(nn.Module):
    """Attention mechanism"""
    
    def __init__(self, hidden_dim):
        super(AttentionLayer, self).__init__()
        self.W = nn.Linear(hidden_dim, hidden_dim, bias=False)
        self.b = nn.Parameter(torch.zeros(hidden_dim))
        self.u = nn.Parameter(torch.randn(hidden_dim))
        
        nn.init.xavier_uniform_(self.W.weight)
        nn.init.xavier_uniform_(self.u.unsqueeze(0))
    
    def forward(self, x):
        uit = torch.tanh(self.W(x) + self.b)
        ait = torch.matmul(uit, self.u)
        a = F.softmax(ait, dim=1)
        a = a.unsqueeze(-1)
        weighted_input = x * a
        output = torch.sum(weighted_input, dim=1)
        return output


# ================================================================
# HYBRID MODEL
# ================================================================
class HybridBiLSTMCNN(nn.Module):
    """Hybrid BiLSTM-Attention + CNN model"""
    
    def __init__(self, tfidf_dim, num_classes, config):
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
    
    def forward(self, x):
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
        output = self.output_layer(x)
        
        return output


# ================================================================
# DATASET - SPARSE MATRIX SUPPORT
# ================================================================
class TfidfDataset(Dataset):
    def __init__(self, X_tfidf, y, is_sparse=True):
        """
        X_tfidf: sparse matrix or dense array
        y: labels array
        is_sparse: whether X_tfidf is sparse
        """
        self.is_sparse = is_sparse
        if is_sparse:
            # Keep as sparse for memory efficiency
            self.X = X_tfidf
        else:
            self.X = torch.FloatTensor(X_tfidf)
        self.y = torch.LongTensor(y)
    
    def __len__(self):
        return len(self.y)
    
    def __getitem__(self, idx):
        if self.is_sparse:
            # Convert single row from sparse to dense on-the-fly
            x_dense = self.X[idx].toarray().squeeze()
            return torch.FloatTensor(x_dense), self.y[idx]
        else:
            return self.X[idx], self.y[idx]


# ================================================================
# DATA LOADING - INTEGRATED VERSION
# ================================================================
def load_and_prepare_data(config):
    """Load và chuẩn bị dữ liệu từ nhiều file CSV"""
    
    print("\n" + "=" * 70)
    print("📂 LOADING DATA FROM MULTIPLE CSV FILES")
    print("=" * 70)
    
    # Tìm tất cả file CSV trong folder
    csv_files = []
    for root, dirs, files in os.walk(config.DATA_FOLDER):
        for file in files:
            if file.endswith(".csv"):
                csv_files.append(os.path.join(root, file))
    
    if not csv_files:
        raise ValueError(f"❌ Không tìm thấy file CSV nào trong {config.DATA_FOLDER}")
    
    print(f"📁 Tìm thấy {len(csv_files)} file CSV")
    
    # Load tất cả CSV files
    df_list = []
    for fp in csv_files:
        try:
            # Đọc header để check columns có sẵn
            available_cols = pd.read_csv(fp, nrows=0).columns.tolist()
            cols_to_read = [col for col in config.SELECTED_COLUMNS if col in available_cols]
            
            if not cols_to_read:
                print(f"  ⚠️ Bỏ qua {fp}: không có cột nào phù hợp")
                continue
            
            temp = pd.read_csv(
                fp, 
                usecols=cols_to_read,
                on_bad_lines='skip', 
                encoding_errors='ignore'
            )
            df_list.append(temp)
            print(f"  ✅ Loaded {len(temp):,} rows from {os.path.basename(fp)}")
        except Exception as e:
            print(f"  ⚠️ Lỗi khi đọc {fp}: {e}")
    
    if not df_list:
        raise ValueError("❌ Không có dữ liệu nào được tải thành công")
    
    # Merge tất cả dataframes
    df = pd.concat(df_list, ignore_index=True)
    print(f"\n✅ Tổng dữ liệu: {df.shape[0]:,} dòng, {df.shape[1]} cột")
    
    # Kiểm tra target column
    if config.TARGET_COL not in df.columns:
        raise ValueError(f"❌ Không tìm thấy cột target '{config.TARGET_COL}'!")
    
    # Lọc dữ liệu có target
    df_clean = df[df[config.TARGET_COL].notna()].copy()
    print(f"✅ Dữ liệu có nhãn: {len(df_clean):,} dòng")
    
    # Lọc các class có đủ samples
    label_counts = df_clean[config.TARGET_COL].value_counts()
    valid_labels = label_counts[label_counts >= config.MIN_SAMPLES_PER_CLASS].index
    df_filtered = df_clean[df_clean[config.TARGET_COL].isin(valid_labels)].copy()
    
    print(f"✅ Dữ liệu sau khi lọc (≥{config.MIN_SAMPLES_PER_CLASS} samples/class): {len(df_filtered):,} dòng")
    print(f"✅ Số lượng classes: {len(valid_labels)}")
    
    # Tạo text input từ nhiều cột
    def create_text_input(row):
        parts = []
        for col in config.TEXT_COLS:
            if col in row and pd.notna(row[col]):
                # Giới hạn độ dài mỗi field
                parts.append(f"{col}: {str(row[col])[:100]}")
        return " | ".join(parts) if parts else ""
    
    print("\n📝 Tạo text input từ các cột...")
    df_filtered['text'] = df_filtered.apply(create_text_input, axis=1)
    
    # Lọc các dòng có text rỗng
    df_filtered = df_filtered[df_filtered['text'].str.len() > 0].copy()
    print(f"✅ Dữ liệu có text hợp lệ: {len(df_filtered):,} dòng")
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df_filtered[config.TARGET_COL])
    X = df_filtered['text'].values
    
    print(f"\n📊 Thống kê nhãn:")
    print(f"   Số classes: {len(label_encoder.classes_)}")
    for i, cls in enumerate(label_encoder.classes_[:10]):
        count = (y == i).sum()
        print(f"   {i}: {cls} - {count:,} samples")
    if len(label_encoder.classes_) > 10:
        print(f"   ... và {len(label_encoder.classes_) - 10} classes khác")
    
    # Lưu label mapping
    label_mapping = {i: label for i, label in enumerate(label_encoder.classes_)}
    os.makedirs(config.OUTPUT_FOLDER, exist_ok=True)
    with open(f"{config.OUTPUT_FOLDER}/label_mapping.json", 'w', encoding='utf-8') as f:
        json.dump(label_mapping, f, ensure_ascii=False, indent=2)
    print(f"\n✅ Đã lưu label mapping: {config.OUTPUT_FOLDER}/label_mapping.json")
    
    # Split data: Train / Temp
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, 
        test_size=config.TEST_SIZE, 
        random_state=config.RANDOM_STATE, 
        stratify=y
    )
    
    # Split Temp: Valid / Test
    X_valid, X_test, y_valid, y_test = train_test_split(
        X_temp, y_temp, 
        test_size=config.VALID_RATIO,
        random_state=config.RANDOM_STATE, 
        stratify=y_temp
    )
    
    print(f"\n📊 Kích thước bộ dữ liệu:")
    print(f"   Train:      {len(X_train):,} samples ({len(X_train)/len(X)*100:.1f}%)")
    print(f"   Validation: {len(X_valid):,} samples ({len(X_valid)/len(X)*100:.1f}%)")
    print(f"   Test:       {len(X_test):,} samples ({len(X_test)/len(X)*100:.1f}%)")
    
    return X_train, X_valid, X_test, y_train, y_valid, y_test, label_encoder


# ================================================================
# TRAINING
# ================================================================
def train_model(X_train, y_train, X_valid, y_valid, label_encoder, config):
    """Train model B6"""
    
    print("\n" + "=" * 70)
    print("🚀 TRAINING MODEL B6")
    print("=" * 70)
    
    # TF-IDF
    print("\n📊 Step 1: TF-IDF Vectorization")
    tfidf_vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=config.MAX_FEATURES,
        sublinear_tf=True,
        min_df=2,
        max_df=0.95
    )
    
    # Keep as sparse matrix - DON'T convert to dense!
    X_train_tfidf_sparse = tfidf_vectorizer.fit_transform(X_train)
    X_valid_tfidf_sparse = tfidf_vectorizer.transform(X_valid)
    
    print(f"✅ TF-IDF shape: {X_train_tfidf_sparse.shape}")
    print(f"✅ Vocabulary size: {len(tfidf_vectorizer.vocabulary_):,}")
    print(f"✅ Sparsity: {100 * (1 - X_train_tfidf_sparse.nnz / (X_train_tfidf_sparse.shape[0] * X_train_tfidf_sparse.shape[1])):.2f}%")
    
    # DataLoaders with sparse support
    print("\n📦 Step 2: Creating DataLoaders")
    train_dataset = TfidfDataset(X_train_tfidf_sparse, y_train, is_sparse=True)
    valid_dataset = TfidfDataset(X_valid_tfidf_sparse, y_valid, is_sparse=True)
    
    train_loader = DataLoader(train_dataset, batch_size=config.BATCH_SIZE, shuffle=True)
    valid_loader = DataLoader(valid_dataset, batch_size=config.BATCH_SIZE, shuffle=False)
    print(f"✅ Train batches: {len(train_loader)}, Valid batches: {len(valid_loader)}")
    
    # Build model
    print("\n🏗️  Step 3: Building Model")
    num_classes = len(label_encoder.classes_)
    tfidf_dim = X_train_tfidf_sparse.shape[1]
    model = HybridBiLSTMCNN(tfidf_dim, num_classes, config).to(config.DEVICE)
    
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"✅ Total parameters: {total_params:,}")
    print(f"✅ Trainable parameters: {trainable_params:,}")
    print(f"✅ Device: {config.DEVICE}")
    
    # Training setup
    criterion = nn.CrossEntropyLoss()
    optimizer = Adam(model.parameters(), lr=config.LEARNING_RATE)
    scheduler = ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=3, min_lr=1e-6)
    
    # Create save directory
    model_dir = f"{config.MODELS_FOLDER}/b6_bilstm_cnn_pytorch"
    os.makedirs(model_dir, exist_ok=True)
    
    # Training loop
    print("\n🎯 Step 4: Training")
    history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}
    best_val_acc = -1.0
    patience_counter = 0
    start_time = time.time()
    
    for epoch in range(config.EPOCHS):
        # Train
        model.train()
        train_loss, train_correct, train_total = 0.0, 0, 0
        
        train_bar = tqdm(train_loader, desc=f"Epoch [{epoch+1}/{config.EPOCHS}] Train", leave=False)
        for batch_X, batch_y in train_bar:
            batch_X, batch_y = batch_X.to(config.DEVICE), batch_y.to(config.DEVICE)
            
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            _, predicted = torch.max(outputs, 1)
            train_correct += (predicted == batch_y).sum().item()
            train_total += batch_y.size(0)
            
            # Cập nhật tqdm realtime
            train_bar.set_postfix({
                'loss': f'{loss.item():.4f}',
                'acc': f'{train_correct/train_total:.4f}'
            })
        
        train_loss /= len(train_loader)
        train_acc = train_correct / train_total
        
        # Validate
        model.eval()
        val_loss, val_correct, val_total = 0.0, 0, 0
        
        val_bar = tqdm(valid_loader, desc=f"Epoch [{epoch+1}/{config.EPOCHS}] Valid", leave=False)
        with torch.no_grad():
            for batch_X, batch_y in val_bar:
                batch_X, batch_y = batch_X.to(config.DEVICE), batch_y.to(config.DEVICE)
                outputs = model(batch_X)
                loss = criterion(outputs, batch_y)
                
                val_loss += loss.item()
                _, predicted = torch.max(outputs, 1)
                val_correct += (predicted == batch_y).sum().item()
                val_total += batch_y.size(0)
                
                val_bar.set_postfix({
                    'loss': f'{loss.item():.4f}',
                    'acc': f'{val_correct/val_total:.4f}'
                })
        
        val_loss /= len(valid_loader)
        val_acc = val_correct / val_total
        
        # In kết quả sau mỗi epoch
        print(f"Epoch [{epoch+1}/{config.EPOCHS}] "
            f"Train Loss: {train_loss:.4f}, Acc: {train_acc:.4f} | "
            f"Val Loss: {val_loss:.4f}, Acc: {val_acc:.4f}")

        history['train_loss'].append(train_loss)
        history['train_acc'].append(train_acc)
        history['val_loss'].append(val_loss)
        history['val_acc'].append(val_acc)
        
        scheduler.step(val_loss)
        
        # Save best model
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            patience_counter = 0
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_acc': val_acc,
            }, f"{model_dir}/best_model.pt")
            print(f"   ✅ Saved best model (val_acc: {val_acc:.4f})")
        else:
            patience_counter += 1
            if patience_counter >= config.PATIENCE:
                print(f"\n⚠️  Early stopping at epoch {epoch+1}")
                break
    
    train_time = time.time() - start_time
    print(f"\n✅ Training completed in {train_time:.2f}s ({train_time/60:.2f} mins)")
    print(f"   Best validation accuracy: {best_val_acc:.4f}")
    
    # Load best model
    checkpoint = torch.load(f"{model_dir}/best_model.pt")
    model.load_state_dict(checkpoint['model_state_dict'])
    
    # Save components
    print("\n💾 Step 5: Saving Components")
    with open(f"{model_dir}/tfidf_vectorizer.pkl", 'wb') as f:
        pickle.dump(tfidf_vectorizer, f)
    with open(f"{model_dir}/label_encoder.pkl", 'wb') as f:
        pickle.dump(label_encoder, f)
    with open(f"{model_dir}/training_history.json", 'w') as f:
        json.dump(history, f, indent=2)
    
    metadata = {
        'model_name': 'B6_BiLSTM_Attention_CNN_PyTorch',
        'num_classes': num_classes,
        'tfidf_dim': tfidf_dim,
        'total_params': total_params,
        'trainable_params': trainable_params,
        'best_val_acc': best_val_acc,
        'train_time_sec': train_time,
        'saved_at': datetime.now().isoformat()
    }
    with open(f"{model_dir}/metadata.json", 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"✅ Saved to: {model_dir}")
    
    return model, tfidf_vectorizer, history, model_dir


# ================================================================
# EVALUATION
# ================================================================
def evaluate_model(model, tfidf_vectorizer, X, y, label_encoder, split_name, config):
    """Evaluate model with sparse matrix support"""
    
    print(f"\n📊 Evaluating {split_name} set...")
    
    # Transform to sparse matrix
    X_tfidf_sparse = tfidf_vectorizer.transform(X)
    print(f"   Shape: {X_tfidf_sparse.shape}, Sparsity: {100 * (1 - X_tfidf_sparse.nnz / (X_tfidf_sparse.shape[0] * X_tfidf_sparse.shape[1])):.2f}%")
    
    # Predict in batches (convert sparse to dense per batch)
    model.eval()
    all_preds = []
    all_probs = []
    
    batch_size = config.BATCH_SIZE
    num_samples = X_tfidf_sparse.shape[0]
    
    with torch.no_grad():
        for i in range(0, num_samples, batch_size):
            end_idx = min(i + batch_size, num_samples)
            
            # Convert batch from sparse to dense
            batch_dense = X_tfidf_sparse[i:end_idx].toarray()
            batch_tensor = torch.FloatTensor(batch_dense).to(config.DEVICE)
            
            outputs = model(batch_tensor)
            probs = F.softmax(outputs, dim=1)
            _, preds = torch.max(outputs, 1)
            
            all_preds.extend(preds.cpu().numpy())
            all_probs.extend(probs.cpu().numpy())
    
    y_pred = np.array(all_preds)
    y_proba = np.array(all_probs)
    
    # Metrics
    acc = accuracy_score(y, y_pred)
    f1 = f1_score(y, y_pred, average='weighted', zero_division=0)
    precision = precision_score(y, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y, y_pred, average='weighted', zero_division=0)
    
    print(f"✅ {split_name} Results:")
    print(f"   Accuracy:  {acc:.4f}")
    print(f"   F1-Score:  {f1:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall:    {recall:.4f}")
    
    # Confusion matrix
    cm = confusion_matrix(y, y_pred)
    
    # Save results
    results = {
        'split': split_name,
        'accuracy': float(acc),
        'f1_weighted': float(f1),
        'precision_weighted': float(precision),
        'recall_weighted': float(recall)
    }
    
    return results, cm, y_pred, y_proba


# ================================================================
# PLOTTING
# ================================================================
def plot_training_history(history, save_path):
    """Plot training history"""
    
    fig, axes = plt.subplots(1, 2, figsize=(15, 5))
    
    # Accuracy
    axes[0].plot(history['train_acc'], label='Train', linewidth=2)
    axes[0].plot(history['val_acc'], label='Validation', linewidth=2)
    axes[0].set_xlabel('Epoch')
    axes[0].set_ylabel('Accuracy')
    axes[0].set_title('Model Accuracy')
    axes[0].legend()
    axes[0].grid(alpha=0.3)
    
    # Loss
    axes[1].plot(history['train_loss'], label='Train', linewidth=2)
    axes[1].plot(history['val_loss'], label='Validation', linewidth=2)
    axes[1].set_xlabel('Epoch')
    axes[1].set_ylabel('Loss')
    axes[1].set_title('Model Loss')
    axes[1].legend()
    axes[1].grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✅ Training plot saved: {save_path}")


def plot_confusion_matrix(cm, class_names, split_name, save_path):
    """Plot confusion matrix với các class quan trọng + Others"""
    
    # Các class quan trọng cần highlight
    IMPORTANT_CLASSES = [
        "SQL Injection",
        "Cross Site Scripting", 
        "Admin Login Successful",
        "Remote Code Execution",
        "Misc Exploit",
        # Thêm các class khác nếu muốn
        "Buffer Overflow",
        "Code Injection",
        "Web Exploit",
    ]
    
    # Lọc ra các class thực sự có trong data
    selected_classes = [c for c in IMPORTANT_CLASSES if c in class_names]
    selected_indices = [list(class_names).index(c) for c in selected_classes]
    
    # Tính indices của "Others" (các class không được chọn)
    all_indices = list(range(len(class_names)))
    other_indices = [i for i in all_indices if i not in selected_indices]
    
    n = len(selected_classes)
    total_size = n + 1  # +1 cho "Others"
    
    # Xây dựng ma trận mới
    new_cm = np.zeros((total_size, total_size), dtype=np.int64)
    
    # Fill selected x selected
    for i, si in enumerate(selected_indices):
        for j, sj in enumerate(selected_indices):
            new_cm[i, j] = cm[si, sj]
        # Fill selected x Others (cột cuối)
        new_cm[i, n] = sum(cm[si, oj] for oj in other_indices)
    
    # Fill Others x selected (hàng cuối)
    for j, sj in enumerate(selected_indices):
        new_cm[n, j] = sum(cm[oi, sj] for oi in other_indices)
    
    # Fill Others x Others
    new_cm[n, n] = sum(cm[oi, oj] for oi in other_indices for oj in other_indices)
    
    # Labels
    display_labels = selected_classes + ["Others"]
    short_labels = [c[:18] + '..' if len(c) > 18 else c for c in display_labels]
    
    # Tính % theo hàng (recall-style) để dễ đọc
    row_sums = new_cm.sum(axis=1, keepdims=True)
    row_sums = np.where(row_sums == 0, 1, row_sums)  # tránh chia 0
    cm_pct = new_cm / row_sums * 100
    
    # Vẽ
    fig_size = max(10, total_size * 1.2)
    fig, ax = plt.subplots(figsize=(fig_size, fig_size * 0.85))
    
    # Annot: hiển thị cả % và số tuyệt đối
    annot = np.empty_like(new_cm, dtype=object)
    for i in range(total_size):
        for j in range(total_size):
            annot[i, j] = f"{cm_pct[i,j]:.1f}%\n({new_cm[i,j]:,})"
    
    sns.heatmap(
        cm_pct,
        annot=annot,
        fmt='',
        cmap='Blues',
        xticklabels=short_labels,
        yticklabels=short_labels,
        ax=ax,
        annot_kws={'size': 9},
        linewidths=0.5,
        linecolor='white',
        vmin=0,
        vmax=100
    )
    
    ax.set_xlabel('Predicted Label', fontsize=12, labelpad=10)
    ax.set_ylabel('True Label', fontsize=12, labelpad=10)
    ax.set_title(f'Confusion Matrix - {split_name}\n(Key Classes + Others)', fontsize=14)
    plt.xticks(rotation=45, ha='right', fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✅ Confusion matrix saved: {save_path}")
    print(f"   Classes shown: {selected_classes + ['Others']}")

# ================================================================
# MAIN PIPELINE
# ================================================================
def main():
    """Main execution pipeline"""
    
    print("\n" + "=" * 70)
    print("🚀 B6: TF-IDF + BiLSTM-Attention + CNN (PyTorch)")
    print("   Multi-CSV Data Loader Integrated")
    print("=" * 70)
    
    # Setup
    config = Config()
    
    # Create directories
    for folder in [config.OUTPUT_FOLDER, config.MODELS_FOLDER, 
                   config.PLOTS_FOLDER, config.RESULTS_FOLDER]:
        os.makedirs(folder, exist_ok=True)
    
    # Load data from multiple CSV files
    X_train, X_valid, X_test, y_train, y_valid, y_test, label_encoder = \
        load_and_prepare_data(config)
    
    # Train
    model, tfidf_vectorizer, history, model_dir = \
        train_model(X_train, y_train, X_valid, y_valid, label_encoder, config)
    
    # Plot training
    plot_training_history(history, f"{config.PLOTS_FOLDER}/training_history.png")
    
    # Evaluate
    all_results = []
    
    for X, y, split_name in [(X_train, y_train, 'Train'),
                              (X_valid, y_valid, 'Valid'),
                              (X_test, y_test, 'Test')]:
        results, cm, y_pred, y_proba = evaluate_model(
            model, tfidf_vectorizer, X, y, label_encoder, split_name, config
        )
        all_results.append(results)
        
        # Plot confusion matrix
        plot_confusion_matrix(
            cm, label_encoder.classes_, split_name,
            f"{config.PLOTS_FOLDER}/cm_{split_name.lower()}.png"
        )
        
        # Save classification report
        report = classification_report(
            y, y_pred, 
            target_names=label_encoder.classes_,
            zero_division=0,
            output_dict=True
        )
        with open(f"{config.RESULTS_FOLDER}/report_{split_name.lower()}.json", 'w') as f:
            json.dump(report, f, indent=2)
    
   
    # Save summary
    summary = {
        'model': 'B6_BiLSTM_Attention_CNN_PyTorch',
        'results': all_results,
        'model_dir': model_dir,
        'completed_at': datetime.now().isoformat()
    }
    with open(f"{config.RESULTS_FOLDER}/summary.json", 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "=" * 70)
    print("✅ PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    print(f"\n📁 Outputs saved to:")
    print(f"   Models: {config.MODELS_FOLDER}")
    print(f"   Plots:  {config.PLOTS_FOLDER}")
    print(f"   Results: {config.RESULTS_FOLDER}")
    
    # Print final results
    print(f"\n📊 Final Results:")
    for result in all_results:
        print(f"\n{result['split']}:")
        print(f"  Accuracy:  {result['accuracy']:.4f}")
        print(f"  F1-Score:  {result['f1_weighted']:.4f}")
        print(f"  Precision: {result['precision_weighted']:.4f}")
        print(f"  Recall:    {result['recall_weighted']:.4f}")


# ================================================================
# INFERENCE CLASS
# ================================================================
class B6Inference:
    """Inference class for trained model"""
    
    def __init__(self, model_dir, device=None):
        if device is None:
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = device
        
        # Load components
        with open(f"{model_dir}/tfidf_vectorizer.pkl", 'rb') as f:
            self.tfidf_vectorizer = pickle.load(f)
        with open(f"{model_dir}/label_encoder.pkl", 'rb') as f:
            self.label_encoder = pickle.load(f)
        with open(f"{model_dir}/metadata.json", 'r') as f:
            metadata = json.load(f)
        
        # Build model
        config = Config()
        self.model = HybridBiLSTMCNN(
            metadata['tfidf_dim'], 
            metadata['num_classes'], 
            config
        ).to(self.device)
        
        # Load weights
        checkpoint = torch.load(f"{model_dir}/best_model.pt", map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()
        
        print(f"✅ Model loaded from {model_dir}")
    
    def predict(self, texts):
        """Predict labels"""
        X_tfidf = self.tfidf_vectorizer.transform(texts).toarray()
        X_tensor = torch.FloatTensor(X_tfidf).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(X_tensor)
            _, predicted = torch.max(outputs, 1)
        
        return self.label_encoder.inverse_transform(predicted.cpu().numpy())
    
    def predict_proba(self, texts):
        """Predict probabilities"""
        X_tfidf = self.tfidf_vectorizer.transform(texts).toarray()
        X_tensor = torch.FloatTensor(X_tfidf).to(self.device)
        
        with torch.no_grad():
            outputs = self.model(X_tensor)
            proba = F.softmax(outputs, dim=1)
        
        return proba.cpu().numpy()


# ================================================================
# RUN
# ================================================================
if __name__ == "__main__":
    # Train and evaluate
    main()
    
    # Example inference
    print("\n" + "=" * 70)
    print("📝 INFERENCE EXAMPLE")
    print("=" * 70)
    
    # Load trained model
    inference_model = B6Inference("saved_models/b6_bilstm_cnn_pytorch")
    
    # Example texts (thay đổi theo dữ liệu của bạn)
    sample_texts = [
        "This is a sample security event",
        "Another example text for classification"
    ]
    
    predictions = inference_model.predict(sample_texts)
    probabilities = inference_model.predict_proba(sample_texts)
    
    print("\nPredictions:")
    for text, pred, proba in zip(sample_texts, predictions, probabilities):
        print(f"\nText: {text}")
        print(f"Predicted: {pred}")
        print(f"Confidence: {proba.max():.4f}")