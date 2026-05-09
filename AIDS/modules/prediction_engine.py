"""
=============================================================
Module 4: Real-Time Prediction Engine
=============================================================
Loads the trained model and runs predictions on live
feature DataFrames produced by the Feature Engineering module.
=============================================================
"""

import os
import sys
import pandas as pd
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import FEATURE_COLUMNS, ML_CONFIDENCE_THRESHOLD
from modules.ml_model import IPSModel


class PredictionEngine:
    """
    Real-time prediction engine.
    Wraps the trained model and applies confidence thresholding.
    """

    def __init__(self):
        self.model = IPSModel()
        self._loaded = False

    def load_model(self):
        """Load the trained model from disk."""
        self.model.load()
        self._loaded = True

    @property
    def is_ready(self):
        return self._loaded

    def predict(self, features_df):
        """
        Run predictions on a feature DataFrame.
        
        Args:
            features_df: DataFrame with FEATURE_COLUMNS
            
        Returns:
            DataFrame with added columns:
                - prediction:  0 (Normal) or 1 (Malicious)
                - confidence:  probability of the predicted class
        """
        if not self._loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        if features_df.empty:
            return features_df.copy()

        # Ensure correct columns exist, fill missing with 0
        for col in FEATURE_COLUMNS:
            if col not in features_df.columns:
                features_df[col] = 0.0

        # Replace NaN/inf values
        feature_data = features_df[FEATURE_COLUMNS].replace(
            [np.inf, -np.inf], 0
        ).fillna(0)

        # Get predictions and probabilities
        predictions = self.model.predict(feature_data)
        probabilities = self.model.predict_proba(feature_data)

        # Build result DataFrame
        result = features_df.copy()
        result["prediction"] = predictions

        # Confidence = probability of the predicted class
        result["confidence"] = [
            probabilities[i][pred] for i, pred in enumerate(predictions)
        ]

        # Apply confidence threshold — if below threshold, mark as Normal
        result.loc[
            (result["prediction"] == 1) &
            (result["confidence"] < ML_CONFIDENCE_THRESHOLD),
            "prediction"
        ] = 0

        return result


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    engine = PredictionEngine()
    engine.load_model()

    # Create test features
    test_data = pd.DataFrame([{
        "src_ip": "192.168.1.100",
        "packet_count": 100,
        "unique_dst_ips": 5,
        "unique_dst_ports": 50,
        "avg_packet_length": 64,
        "std_packet_length": 10,
        "tcp_ratio": 0.9,
        "udp_ratio": 0.1,
        "icmp_ratio": 0.0,
        "syn_count": 45,
        "packet_rate": 150,
    }])

    result = engine.predict(test_data)
    print(result[["src_ip", "prediction", "confidence"]])
