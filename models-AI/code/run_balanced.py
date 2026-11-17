"""
Same train_1 pipeline + class balancing (RandomUnderSampler on majority +
SMOTE on minorities), applied ONLY to the training split. Valid/Test are left
untouched. Reports weighted AND macro F1 (macro is where balancing shows up).

Usage: python run_balanced.py <run_name> <dataset_dir> [epochs] [target_T]
"""
import os, sys, json, time, pickle
from collections import Counter
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
from torch.optim import Adam
from torch.optim.lr_scheduler import ReduceLROnPlateau
from torch.utils.data import DataLoader
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score, classification_report
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE

import train_1 as T
from run_external import plot_cm_generic


def balance(X, y, target_T):
    counts = Counter(y)
    under = {c: target_T for c, n in counts.items() if n > target_T}
    over = {c: target_T for c, n in counts.items() if n < target_T}
    if under:
        X, y = RandomUnderSampler(sampling_strategy=under, random_state=42).fit_resample(X, y)
        counts = Counter(y)
    if over:
        k = max(1, min(5, min(counts.values()) - 1))
        X, y = SMOTE(sampling_strategy=over, k_neighbors=k, random_state=42).fit_resample(X, y)
    return X, y


def main():
    run_name = sys.argv[1]
    dataset_dir = sys.argv[2]
    epochs = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    target_T = int(sys.argv[4]) if len(sys.argv) > 4 else 1000

    base = os.path.join("runs", run_name)
    cfg = T.Config
    cfg.DEVICE = torch.device("cpu")
    cfg.DATA_FOLDER = dataset_dir
    cfg.OUTPUT_FOLDER = os.path.join(base, "outputs")
    cfg.MODELS_FOLDER = os.path.join(base, "saved_models")
    cfg.PLOTS_FOLDER = os.path.join(base, "plots")
    cfg.RESULTS_FOLDER = os.path.join(base, "results")
    cfg.EPOCHS = epochs
    for d in [cfg.OUTPUT_FOLDER, cfg.MODELS_FOLDER, cfg.PLOTS_FOLDER, cfg.RESULTS_FOLDER]:
        os.makedirs(d, exist_ok=True)

    print(f"\n=== BALANCED RUN: {run_name} (target/class={target_T}) ===")
    X_train, X_valid, X_test, y_train, y_valid, y_test, le = T.load_and_prepare_data(cfg)

    # TF-IDF (identical settings to train_1)
    vec = TfidfVectorizer(ngram_range=(1, 2), max_features=cfg.MAX_FEATURES,
                          sublinear_tf=True, min_df=2, max_df=0.95)
    Xtr = vec.fit_transform(X_train)
    print("Train class dist BEFORE:", dict(sorted(Counter(y_train).items())))
    Xtr_b, ytr_b = balance(Xtr, y_train, target_T)
    print("Train class dist AFTER :", dict(sorted(Counter(ytr_b).items())))
    print(f"Train rows: {Xtr.shape[0]} -> {Xtr_b.shape[0]} (balanced)")

    # model + training (same architecture / loop as train_1)
    num_classes = len(le.classes_)
    model = T.HybridBiLSTMCNN(Xtr_b.shape[1], num_classes, cfg).to(cfg.DEVICE)
    crit = nn.CrossEntropyLoss()
    opt = Adam(model.parameters(), lr=cfg.LEARNING_RATE)
    sched = ReduceLROnPlateau(opt, mode='min', factor=0.5, patience=3, min_lr=1e-6)

    tr_loader = DataLoader(T.TfidfDataset(Xtr_b, ytr_b, True), batch_size=cfg.BATCH_SIZE, shuffle=True)
    Xva = vec.transform(X_valid)
    va_loader = DataLoader(T.TfidfDataset(Xva, y_valid, True), batch_size=cfg.BATCH_SIZE, shuffle=False)

    model_dir = f"{cfg.MODELS_FOLDER}/b6_bilstm_cnn_pytorch"
    os.makedirs(model_dir, exist_ok=True)
    history = {'train_loss': [], 'train_acc': [], 'val_loss': [], 'val_acc': []}
    best = -1.0; t0 = time.time()
    for ep in range(epochs):
        model.train(); tl=tc=tt=0
        for bx, by in tr_loader:
            bx, by = bx.to(cfg.DEVICE), by.to(cfg.DEVICE)
            opt.zero_grad(); out = model(bx); loss = crit(out, by); loss.backward(); opt.step()
            tl += loss.item(); tc += (out.argmax(1)==by).sum().item(); tt += by.size(0)
        model.eval(); vl=vc=vt=0
        with torch.no_grad():
            for bx, by in va_loader:
                bx, by = bx.to(cfg.DEVICE), by.to(cfg.DEVICE)
                out = model(bx); loss = crit(out, by)
                vl += loss.item(); vc += (out.argmax(1)==by).sum().item(); vt += by.size(0)
        tr_acc, va_acc = tc/tt, vc/vt
        history['train_acc'].append(tr_acc); history['val_acc'].append(va_acc)
        history['train_loss'].append(tl/len(tr_loader)); history['val_loss'].append(vl/max(1,len(va_loader)))
        sched.step(vl/max(1,len(va_loader)))
        print(f"  epoch {ep+1}/{epochs} train_acc={tr_acc:.4f} val_acc={va_acc:.4f}")
        if va_acc > best:
            best = va_acc
            torch.save({'model_state_dict': model.state_dict()}, f"{model_dir}/best_model.pt")
    print(f"trained in {time.time()-t0:.1f}s, best val_acc={best:.4f}")
    model.load_state_dict(torch.load(f"{model_dir}/best_model.pt")['model_state_dict'])

    with open(f"{model_dir}/tfidf_vectorizer.pkl",'wb') as f: pickle.dump(vec,f)
    with open(f"{model_dir}/label_encoder.pkl",'wb') as f: pickle.dump(le,f)
    with open(f"{model_dir}/metadata.json",'w') as f:
        json.dump({'model_name':'B6_BiLSTM_Attention_CNN_PyTorch','num_classes':num_classes,
                   'tfidf_dim':Xtr_b.shape[1],'balanced_target':target_T,
                   'saved_at':datetime.now().isoformat()}, f, indent=2)
    T.plot_training_history(history, f"{cfg.PLOTS_FOLDER}/training_history.png")

    # evaluate on ORIGINAL (unbalanced) splits
    all_results = []
    for X, y, split in [(X_train,y_train,'Train'),(X_valid,y_valid,'Valid'),(X_test,y_test,'Test')]:
        res, cm, y_pred, _ = T.evaluate_model(model, vec, X, y, le, split, cfg)
        res['f1_macro'] = float(f1_score(y, y_pred, average='macro', zero_division=0))
        all_results.append(res)
        plot_cm_generic(cm, le.classes_, split, f"{cfg.PLOTS_FOLDER}/cm_{split.lower()}.png")
        rep = classification_report(y, y_pred, target_names=le.classes_, zero_division=0, output_dict=True)
        with open(f"{cfg.RESULTS_FOLDER}/report_{split.lower()}.json",'w') as f: json.dump(rep,f,indent=2)

    summary = {'model':'B6_BiLSTM_Attention_CNN_PyTorch_SMOTE','dataset':run_name,
               'balancing':'RandomUnderSampler+SMOTE','target_per_class':target_T,
               'results':all_results,'completed_at':datetime.now().isoformat()}
    with open(f"{cfg.RESULTS_FOLDER}/summary.json",'w') as f: json.dump(summary,f,indent=2)

    print("\nFinal (balanced):")
    for r in all_results:
        print(f"  {r['split']:6s} acc={r['accuracy']:.4f} f1_w={r['f1_weighted']:.4f} f1_macro={r['f1_macro']:.4f}")


if __name__ == "__main__":
    main()
