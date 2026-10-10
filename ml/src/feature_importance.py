
from pathlib import Path

import joblib
import pandas as pd

MODEL_FILE = Path("models/random_forest_baseline.joblib")
TRAIN_FILE = Path("data/processed/splits/train.csv")
OUTPUT_FILE = Path("reports/feature_importance.csv")


def main():
    print("Loading model and feature names...")

    model = joblib.load(MODEL_FILE)
    train_df = pd.read_csv(TRAIN_FILE, nrows=1)
    feature_names = train_df.drop(columns=["Category"]).columns

    importance = pd.DataFrame({
        "Feature": feature_names,
        "Importance": model.feature_importances_,
    }).sort_values("Importance", ascending=False)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    importance.to_csv(OUTPUT_FILE, index=False)

    print("\nTop 15 important features:")
    print(importance.head(15).to_string(index=False))
    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
