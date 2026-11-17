"""
Generic runner that reuses the EXACT train_1.py pipeline
(TF-IDF + BiLSTM-Attention + CNN) on an external dataset folder,
emitting the same report artifacts into a per-dataset run directory.

Usage:
    python run_external.py <run_name> <dataset_dir> [epochs]

Expects <dataset_dir> to contain CSV file(s) with at least the
'categoryDescription' target column plus some of the TEXT_COLS used by
train_1 (eventName, eventDescription, payloadAsUTF, srcIp, destIp,
deviceCategory, severity, ...).
"""
import os
import sys
import json
from datetime import datetime

import numpy as np
from sklearn.metrics import classification_report

import train_1 as T


def plot_cm_generic(cm, class_names, split_name, save_path, top_k=12):
    """Same style as train_1.plot_confusion_matrix but highlights the
    dataset's own most-frequent classes (by support in cm) + Others."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns

    class_names = list(class_names)
    supports = cm.sum(axis=1)
    order = np.argsort(supports)[::-1]
    selected_indices = list(order[:top_k])
    selected_classes = [class_names[i] for i in selected_indices]

    all_indices = list(range(len(class_names)))
    other_indices = [i for i in all_indices if i not in selected_indices]

    n = len(selected_classes)
    has_others = len(other_indices) > 0
    total_size = n + (1 if has_others else 0)

    new_cm = np.zeros((total_size, total_size), dtype=np.int64)
    for i, si in enumerate(selected_indices):
        for j, sj in enumerate(selected_indices):
            new_cm[i, j] = cm[si, sj]
        if has_others:
            new_cm[i, n] = sum(cm[si, oj] for oj in other_indices)
    if has_others:
        for j, sj in enumerate(selected_indices):
            new_cm[n, j] = sum(cm[oi, sj] for oi in other_indices)
        new_cm[n, n] = sum(cm[oi, oj] for oi in other_indices for oj in other_indices)

    display_labels = selected_classes + (["Others"] if has_others else [])
    short_labels = [c[:18] + '..' if len(c) > 18 else c for c in display_labels]

    row_sums = new_cm.sum(axis=1, keepdims=True)
    row_sums = np.where(row_sums == 0, 1, row_sums)
    cm_pct = new_cm / row_sums * 100

    fig_size = max(10, total_size * 1.2)
    fig, ax = plt.subplots(figsize=(fig_size, fig_size * 0.85))
    annot = np.empty_like(new_cm, dtype=object)
    for i in range(total_size):
        for j in range(total_size):
            annot[i, j] = f"{cm_pct[i,j]:.1f}%\n({new_cm[i,j]:,})"
    sns.heatmap(cm_pct, annot=annot, fmt='', cmap='Blues',
                xticklabels=short_labels, yticklabels=short_labels, ax=ax,
                annot_kws={'size': 9}, linewidths=0.5, linecolor='white',
                vmin=0, vmax=100)
    ax.set_xlabel('Predicted Label', fontsize=12, labelpad=10)
    ax.set_ylabel('True Label', fontsize=12, labelpad=10)
    ax.set_title(f'Confusion Matrix - {split_name}\n(Top classes + Others)', fontsize=14)
    plt.xticks(rotation=45, ha='right', fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✅ Confusion matrix saved: {save_path}")


def main():
    run_name = sys.argv[1]
    dataset_dir = sys.argv[2]
    epochs = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    import torch
    base = os.path.join("runs", run_name)
    cfg = T.Config
    # Blackwell GPU + cu128 dev torch has broken cuBLAS here; data is tiny -> CPU.
    if os.environ.get("FORCE_CPU", "1") == "1":
        cfg.DEVICE = torch.device("cpu")
    cfg.DATA_FOLDER = dataset_dir
    cfg.OUTPUT_FOLDER = os.path.join(base, "outputs")
    cfg.MODELS_FOLDER = os.path.join(base, "saved_models")
    cfg.PLOTS_FOLDER = os.path.join(base, "plots")
    cfg.RESULTS_FOLDER = os.path.join(base, "results")
    cfg.EPOCHS = epochs

    for folder in [cfg.OUTPUT_FOLDER, cfg.MODELS_FOLDER, cfg.PLOTS_FOLDER, cfg.RESULTS_FOLDER]:
        os.makedirs(folder, exist_ok=True)

    print("\n" + "=" * 70)
    print(f"🚀 EXTERNAL RUN: {run_name}  (epochs={epochs})")
    print(f"   dataset: {dataset_dir}")
    print("=" * 70)

    # --- exactly the train_1 stages ---
    X_train, X_valid, X_test, y_train, y_valid, y_test, label_encoder = \
        T.load_and_prepare_data(cfg)

    model, tfidf_vectorizer, history, model_dir = \
        T.train_model(X_train, y_train, X_valid, y_valid, label_encoder, cfg)

    T.plot_training_history(history, f"{cfg.PLOTS_FOLDER}/training_history.png")

    all_results = []
    for X, y, split_name in [(X_train, y_train, 'Train'),
                             (X_valid, y_valid, 'Valid'),
                             (X_test, y_test, 'Test')]:
        results, cm, y_pred, y_proba = T.evaluate_model(
            model, tfidf_vectorizer, X, y, label_encoder, split_name, cfg)
        all_results.append(results)
        plot_cm_generic(cm, label_encoder.classes_, split_name,
                        f"{cfg.PLOTS_FOLDER}/cm_{split_name.lower()}.png")
        report = classification_report(
            y, y_pred, target_names=label_encoder.classes_,
            zero_division=0, output_dict=True)
        with open(f"{cfg.RESULTS_FOLDER}/report_{split_name.lower()}.json", 'w') as f:
            json.dump(report, f, indent=2)

    summary = {
        'model': 'B6_BiLSTM_Attention_CNN_PyTorch',
        'dataset': run_name,
        'results': all_results,
        'model_dir': model_dir,
        'completed_at': datetime.now().isoformat()
    }
    with open(f"{cfg.RESULTS_FOLDER}/summary.json", 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n📊 Final Results:")
    for r in all_results:
        print(f"  {r['split']:6s} acc={r['accuracy']:.4f} f1={r['f1_weighted']:.4f} "
              f"prec={r['precision_weighted']:.4f} rec={r['recall_weighted']:.4f}")
    print(f"\n📁 Artifacts in: {base}")


if __name__ == "__main__":
    main()
