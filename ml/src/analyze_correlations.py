
from pathlib import Path

import numpy as np
import pandas as pd

INPUT_FILE = Path("data/processed/splits/train.csv")
OUTPUT_FILE = Path("reports/top_feature_correlations.csv")


def main():
    print("Loading training data...")
    df = pd.read_csv(INPUT_FILE)
    X = df.drop(columns=["Category"])

    correlations = X.corr().abs()
    upper = correlations.where(
        np.triu(np.ones(correlations.shape, dtype=bool), k=1)
    )

    top_pairs = (
        upper.stack()
        .sort_values(ascending=False)
        .head(30)
        .rename("Absolute Correlation")
        .reset_index()
    )

    top_pairs.columns = [
        "Feature 1",
        "Feature 2",
        "Absolute Correlation",
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    top_pairs.to_csv(OUTPUT_FILE, index=False)

    print("\nTop 10 feature pairs:")
    print(top_pairs.head(10).to_string(index=False))
    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

