"""
=============================================================
Module 3: Machine Learning Model
=============================================================
Random Forest classifier for network traffic classification.
Handles training, evaluation, saving, and loading.
=============================================================
"""

import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)
from sklearn.preprocessing import StandardScaler
import joblib

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import (
    FEATURE_COLUMNS, MODEL_PATH, SCALER_PATH,
    RANDOM_FOREST_ESTIMATORS, RANDOM_FOREST_MAX_DEPTH,
    TEST_SPLIT_RATIO, RANDOM_SEED
)


class IPSModel:
    """
    Random Forest-based Intrusion Detection Model.
    
    Usage:
        model = IPSModel()
        model.train(data_path="data/training_data.csv")
        model.save()
        model.load()
        predictions = model.predict(features_df)
    """

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=RANDOM_FOREST_ESTIMATORS,
            max_depth=RANDOM_FOREST_MAX_DEPTH,
            random_state=RANDOM_SEED,
            n_jobs=-1,
            class_weight="balanced"
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_columns = FEATURE_COLUMNS

    def train(self, data_path=None, df=None):
        """Train the model on a labeled dataset."""
        if df is not None:
            data = df
        elif data_path:
            data = pd.read_csv(data_path)
        else:
            raise ValueError("Provide either data_path or df")

        print(f"[MLModel] Training on {len(data)} samples...")
        print(f"[MLModel] Class distribution:\n{data['label'].value_counts()}")

        X = data[self.feature_columns].values
        y = data["label"].values

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SPLIT_RATIO,
            random_state=RANDOM_SEED, stratify=y
        )

        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True

        y_pred = self.model.predict(X_test_scaled)
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1_score": f1_score(y_test, y_pred, zero_division=0),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "classification_report": classification_report(
                y_test, y_pred, target_names=["Normal", "Malicious"]
            ),
        }

        importances = dict(zip(self.feature_columns, self.model.feature_importances_))
        metrics["feature_importance"] = dict(
            sorted(importances.items(), key=lambda x: x[1], reverse=True)
        )

        print("\n" + "=" * 60)
        print("MODEL EVALUATION RESULTS")
        print("=" * 60)
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1-Score:  {metrics['f1_score']:.4f}")
        print(f"\n{metrics['classification_report']}")
        print("=" * 60)
        return metrics

    def predict(self, features_df):
        """Predict 0=Normal or 1=Malicious."""
        if not self.is_trained:
            raise RuntimeError("Model not loaded. Call train() or load() first.")
        X = features_df[self.feature_columns].values
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def predict_proba(self, features_df):
        """Get prediction probabilities [P(Normal), P(Malicious)]."""
        if not self.is_trained:
            raise RuntimeError("Model not loaded. Call train() or load() first.")
        X = features_df[self.feature_columns].values
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def save(self, model_path=None, scaler_path=None):
        """Save model and scaler to disk."""
        model_path = model_path or MODEL_PATH
        scaler_path = scaler_path or SCALER_PATH
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)
        print(f"[MLModel] Saved to {model_path}")

    def load(self, model_path=None, scaler_path=None):
        """Load model and scaler from disk."""
        model_path = model_path or MODEL_PATH
        scaler_path = scaler_path or SCALER_PATH
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.is_trained = True
        print(f"[MLModel] Loaded from {model_path}")
