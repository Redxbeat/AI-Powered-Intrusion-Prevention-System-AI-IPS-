"""
=============================================================
Model Training Script
=============================================================
Generates dataset (if needed) and trains the Random Forest
model. Saves model + scaler to the models/ directory.
=============================================================
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import TRAINING_DATA_PATH, MODEL_PATH
from data.generate_dataset import generate_dataset
from modules.ml_model import IPSModel


def main():
    print("=" * 60)
    print("  AI-IPS  —  Model Training Pipeline")
    print("=" * 60)

    # Step 1: Generate dataset if not exists
    if not os.path.exists(TRAINING_DATA_PATH):
        print("\n[Step 1] Generating training dataset...")
        generate_dataset()
    else:
        print(f"\n[Step 1] Dataset found at {TRAINING_DATA_PATH}")

    # Step 2: Train model
    print("\n[Step 2] Training Random Forest model...")
    model = IPSModel()
    metrics = model.train(data_path=TRAINING_DATA_PATH)

    # Step 3: Save model
    print("\n[Step 3] Saving model...")
    model.save()

    # Step 4: Display feature importance
    print("\n[Step 4] Feature Importance:")
    print("-" * 40)
    for feature, importance in metrics["feature_importance"].items():
        bar = "█" * int(importance * 50)
        print(f"  {feature:25s} {importance:.4f} {bar}")

    print("\n" + "=" * 60)
    print("  Training Complete! Model saved to:")
    print(f"    {MODEL_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    main()
