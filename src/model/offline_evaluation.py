"""
offline_comparison.py

Offline evaluation script to compare:
- Rule-Based Only (with two thresholds)
- ML-Only (Random Forest from rf_model.joblib)
- Hybrid Fusion 

Uses preprocessed features_balanced.csv/test.csv and the trained model.
No re-training or scaling is performed.
"""

import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns

# === PATHS ===
PREPROCESSED_CSV = "../../data/processed/test_data.csv"     # balanced CSV
MODEL_PATH = "../../model/rf_model.joblib"        # Trained model

# === STEP 1: Load preprocessed data ===
print("Loading preprocessed dataset...")
df = pd.read_csv(PREPROCESSED_CSV)

LABEL_COL = "label"

print("Class distribution:\n", df[LABEL_COL].value_counts(normalize=True))

# === STEP 2: Load trained pipeline ===
print("\nLoading trained model...")
bundle = joblib.load(MODEL_PATH)

# Explicit check to guard against loading stale bundles containing old scaler objects
if "scaler" in bundle:
    raise KeyError("Detected a 'scaler' key in model bundle. You appear to be loading an older pipeline model.")

model = bundle["model"]
feature_order = bundle["features"]

print(f"Model expects {len(feature_order)} features:\n", feature_order)

# === STEP 3: Prepare X and y ===
missing_cols = [col for col in feature_order if col not in df.columns]
if missing_cols:
    print(f"Warning: Missing columns in CSV: {missing_cols}")
    print("Filling missing columns with 0")
    for col in missing_cols:
        df[col] = 0.0

X = df[feature_order]
y = df[LABEL_COL]

# === STEP 4: Define your rule_check function ===
def rule_check(row):
    score = 0
    
    # 1. High Packet Rate (Volumetric Flood Check)
    if row.get("packets_per_sec", 0) > 300:
        score += 1
        
    # 2. High Byte Rate (Bandwidth Saturation Check)
    if row.get("bytes_per_sec", 0) > 500000:
        score += 1
        
    # 3. Massive SYN Burst (Connection Request Flood Check)
    if row.get("syn_count", 0) > 150:
        score += 1 
        
    # 4. TCP Protocol Asymmetry (SYN Flood / Half-Open Connection Check)
    # Replaces 'ack_count < 10' to avoid misclassifying short benign flows
    syn = row.get("syn_count", 0)
    ack = row.get("ack_count", 0)
    
    if syn > 100 and (syn / (ack + 1)) > 10:
        score += 1
        
    return min(score / 4.0, 1.0)

# Compute rule_score for all rows
print("Computing rule_score...")
df["rule_score"] = X.apply(rule_check, axis=1)

# === STEP 5: Generate decisions ===
# ML-Only (Predictions directly on unscaled X)
y_pred_ml = model.predict(X)

# Rule-Based Only — two thresholds
df["rule_decision_any"]  = (df["rule_score"] > 0.0).astype(int)
df["rule_decision_full"] = (df["rule_score"] == 1.0).astype(int)

# Hybrid Fusion
fusion_weight_ml = 0.7
fusion_weight_rule = 0.3
threshold = 0.4

df["final_score"] = fusion_weight_ml * model.predict_proba(X)[:, 1] + fusion_weight_rule * df["rule_score"]
df["hybrid_decision"] = (df["final_score"] > threshold).astype(int)

# === STEP 6: Metrics function ===
def get_metrics(y_true, y_pred, name):
    return {
        "Approach": name,
        "Accuracy":  accuracy_score(y_true, y_pred),
        "Precision": precision_score(y_true, y_pred, zero_division=0),
        "Recall":    recall_score(y_true, y_pred, zero_division=0),
        "F1-Score":  f1_score(y_true, y_pred, zero_division=0),
    }

# === STEP 7: Build & print comparison table ===
results = [
    get_metrics(y, df["rule_decision_any"],  "Rule-Based Only (> 0.0)"),
    get_metrics(y, df["rule_decision_full"], "Rule-Based Only (≥ 1.0)"),
    get_metrics(y, y_pred_ml,                "ML-Only (Random Forest)"),
    get_metrics(y, df["hybrid_decision"],   "Hybrid Fusion (0.7 ML + 0.3 Rule)"),
]

comparison_table = pd.DataFrame(results)
comparison_table = comparison_table.round(4)

print("\n=== Offline Evaluation Comparison Table ===")
print(comparison_table.to_string(index=False))

# Save for thesis
comparison_table.to_csv("../../logs/offline_test_results/offline_comparison_results.csv", index=False)
print("\nResults saved to 'offline_comparison_results.csv'")

# === STEP 8: Plot Confusion Matrices ===
y_true = df[LABEL_COL]  # ground truth (0=benign, 1=attack)

y_pred_rule_any   = df["rule_decision_any"]
y_pred_rule_full  = df["rule_decision_full"]
y_pred_hybrid     = df["hybrid_decision"]

cm_rule_any   = confusion_matrix(y_true, y_pred_rule_any)
cm_rule_full  = confusion_matrix(y_true, y_pred_rule_full)
cm_ml         = confusion_matrix(y_true, y_pred_ml)
cm_hybrid     = confusion_matrix(y_true, y_pred_hybrid)

fig, axes = plt.subplots(2, 2, figsize=(10, 8), sharex=True, sharey=True)
fig.suptitle("Confusion Matrices - Offline Evaluation (Benign = 0, DDoS = 1)", fontsize=16, y=1.02)

titles = [
    "Rule-Based Only (> 0.0)",
    "Rule-Based Only (≥ 1.0)",
    "ML-Only (Random Forest)",
    "Hybrid Fusion (0.7 ML + 0.3 Rule)"
]

cms = [cm_rule_any, cm_rule_full, cm_ml, cm_hybrid]

for i, ax in enumerate(axes.flat):
    sns.heatmap(
        cms[i],
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=False,
        xticklabels=["Benign", "DDoS"],
        yticklabels=["Benign", "DDoS"],
        annot_kws={"size": 14},
        linewidths=0.5,
        linecolor="gray",
        ax=ax
    )
    ax.set_title(titles[i], fontsize=12, pad=10)
    ax.set_xlabel("Predicted Label" if i >= 2 else "")
    ax.set_ylabel("True Label" if i % 2 == 0 else "")

plt.tight_layout(rect=[0, 0, 1, 0.95])

plt.savefig("../../logs/offline_test_results/confusion_matrices_all_four.png", dpi=300, bbox_inches="tight")
plt.savefig("../../logs/offline_test_results/confusion_matrices_all_four.pdf", format="pdf", bbox_inches="tight")

plt.show()
print("Figure saved as confusion_matrices_all_four.png and .pdf")

# === STEP 9: ROC-AUC Evaluation ===
y_prob_ml = model.predict_proba(X)[:, 1]
fpr_ml, tpr_ml, _ = roc_curve(y, y_prob_ml)
roc_auc_ml = auc(fpr_ml, tpr_ml)

fpr_hybrid, tpr_hybrid, _ = roc_curve(y, df["final_score"])
roc_auc_hybrid = auc(fpr_hybrid, tpr_hybrid)

plt.figure(figsize=(8, 6))
plt.plot(fpr_ml, tpr_ml, color='darkorange', lw=2,
         label=f'ML-Only (AUC = {roc_auc_ml:.4f})')
plt.plot(fpr_hybrid, tpr_hybrid, color='darkgreen', lw=2,
         label=f'Hybrid Fusion (AUC = {roc_auc_hybrid:.4f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')

plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate', fontsize=12)
plt.ylabel('True Positive Rate', fontsize=12)
plt.title('ROC Curves - Offline Evaluation (CICIDS2019 Balanced Test Set)', fontsize=14)
plt.legend(loc="lower right")
plt.grid(True, linestyle='--', alpha=0.7)
plt.tight_layout()

plt.savefig("../../logs/offline_test_results/roc_curves_ml_hybrid.png", dpi=300, bbox_inches="tight")
plt.savefig("../../logs/offline_test_results/roc_curves_ml_hybrid.pdf", format="pdf", bbox_inches="tight")

plt.show()
print("ROC-AUC curves saved as roc_curves_ml_hybrid.png and .pdf")