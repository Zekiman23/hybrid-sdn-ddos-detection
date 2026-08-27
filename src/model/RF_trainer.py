import pandas as pd
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# =============== CONFIG ======================
DATA_PATH = "../../data/processed/features_balanced.csv"   # output of prepare_features_balanced_v1.py (no source_file)
MODEL_OUT = "../../model/rf_model.joblib"       # renamed from rf_pipeline.joblib - no scaler in this bundle anymore
TEST_DATA_OUT = "../../data/processed/test_data.csv"
TEST_SIZE = 0.2
RANDOM_STATE = 42
N_ESTIMATORS = 300
# ==============================================

print(f"Loading dataset: {DATA_PATH}")
df = pd.read_csv(DATA_PATH)

# Separate features and labels
X = df.drop(columns=['label'])
y = df['label']

# Train-test split (stratified preserves class ratio)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
)

print("Training class distribution:")
print(y_train.value_counts())

# --- SAVE HELD-OUT TEST DATA ---
# Saved unscaled (no scaler used anywhere in this pipeline - RandomForest
# doesn't need one) and with labels attached, for downstream evaluation
# scripts (e.g. offline_comparison.py) to consume directly.
os.makedirs(os.path.dirname(TEST_DATA_OUT), exist_ok=True)
test_df = X_test.copy()
test_df['label'] = y_test.values
test_df.to_csv(TEST_DATA_OUT, index=False)
print(f"Test dataset saved to: {TEST_DATA_OUT}")

# --- MODEL ---
# NOTE ON class_weight: the training data (features_balanced.csv) was
# already balanced upstream via undersampling, so it's already ~50/50.
# Adding class_weight='balanced' on top would double-correct for an
# imbalance that isn't there anymore, distorting the decision boundary
# more than necessary. Left as None.
#
# NOTE ON SCALING: RandomForestClassifier makes axis-aligned splits and is
# invariant to monotonic feature scaling, so no StandardScaler is used -
# it added no benefit and only a place for train/inference mismatches.
clf = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    class_weight=None,
    n_jobs=-1,
    random_state=RANDOM_STATE,
    max_depth=None,
)

print("\nTraining Random Forest model...")
clf.fit(X_train, y_train)


# --- SAVE MODEL ---
# Directory creation now targets the ACTUAL parent of MODEL_OUT, fixing a
# bug in the original script where os.makedirs("src/models") pointed at a
# different directory than MODEL_OUT ("models/..."), which would raise
# FileNotFoundError on a machine where "models/" didn't already exist.
os.makedirs(os.path.dirname(MODEL_OUT), exist_ok=True)
joblib.dump(
    {"model": clf, "features": list(X.columns)},
    MODEL_OUT
)
print(f"\nModel saved successfully to: {MODEL_OUT}")
