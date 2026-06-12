import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)

# =============================
# Load Dataset
# =============================

df = pd.read_csv("../datasets/final_clean_multiclass_dataset.csv")

print("\nDataset Shape:")
print(df.shape)

print("\nClass Distribution:")
print(df["label"].value_counts())

# =============================
# Protocol Encoding
# =============================

df = pd.get_dummies(
    df,
    columns=["protocol"],
    drop_first=True
)

# =============================
# Handle Infinite Values
# =============================

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(df.max(numeric_only=True), inplace=True)

# =============================
# Feature Selection
# =============================

X = df.drop(
    ["label", "src_port", "dst_port"],
    axis=1
)

y = df["label"]

print("\nFeatures Used:")
print(X.columns.tolist())

# =============================
# Train/Test Split
# =============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# =============================
# Scaling
# =============================

scaler = RobustScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# =============================
# Train Random Forest
# =============================

print("\nTraining Random Forest...\n")

rf_model = RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

rf_model.fit(
    X_train_scaled,
    y_train
)

# =============================
# Predictions
# =============================

y_pred = rf_model.predict(X_test_scaled)

# =============================
# Evaluation
# =============================

print("=" * 60)
print("MODEL EVALUATION")
print("=" * 60)

accuracy = accuracy_score(
    y_test,
    y_pred
)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "normal",
            "portscan",
            "ssh_bruteforce"
        ]
    )
)

print("\nConfusion Matrix:\n")
print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

# =============================
# Feature Importance
# =============================

importance_df = pd.DataFrame({
    "Feature": X.columns,
    "Importance": rf_model.feature_importances_
})

importance_df = importance_df.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 15 Important Features:\n")
print(
    importance_df.head(15)
)


# =============================
# Save Feature Names
# =============================

joblib.dump(
    list(X.columns),
    "../models/feature_columns.pkl"
)

print("\nFeature columns saved.")

# =============================
# Save Model
# =============================

joblib.dump(
    rf_model,
    "../models/random_forest_ids_multiclass.pkl"
)

joblib.dump(
    scaler,
    "../models/random_forest_scaler_multiclass.pkl"
)

print("\nModel saved successfully.")
