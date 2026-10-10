from pathlib import Path

import numpy as np
import pandas as pd


INPUT_FILE = Path("data/processed/cic_ids2017_combined.csv")
OUTPUT_FILE = Path("data/processed/cic_ids2017_model_ready.csv")


LABEL_MAP = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS/DDoS",
    "DDoS": "DoS/DDoS",
    "DoS GoldenEye": "DoS/DDoS",
    "DoS slowloris": "DoS/DDoS",
    "DoS Slowhttptest": "DoS/DDoS",
    "PortScan": "Port Scan",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Web Attack � Brute Force": "Web Attack",
    "Web Attack � XSS": "Web Attack",
    "Web Attack � Sql Injection": "Web Attack",
    "Bot": "Botnet",
}


def main():
    print("Loading dataset...")
    df = pd.read_csv(INPUT_FILE)

    # Clean column names and labels.
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].astype(str).str.strip()

    print(f"Original rows: {len(df):,}")

    # Keep only the 7 main classification categories.
    df["Category"] = df["Label"].map(LABEL_MAP)
    df = df.dropna(subset=["Category"]).copy()

    print(f"Rows after selecting main classes: {len(df):,}")

    # Remove exact duplicate rows.
    df = df.drop_duplicates().reset_index(drop=True)

    print(f"Rows after exact deduplication: {len(df):,}")

    # Convert numeric columns to numeric values.
    feature_columns = [
        column for column in df.columns
        if column not in {"Label", "Category"}
    ]

    df[feature_columns] = df[feature_columns].apply(
        pd.to_numeric,
        errors="coerce",
    )

    # Replace positive/negative infinity with missing values.
    df[feature_columns] = df[feature_columns].replace(
        [np.inf, -np.inf],
        np.nan,
    )

    # Remove rows where all feature values are missing.
    df = df.dropna(
        subset=feature_columns,
        how="all",
    ).reset_index(drop=True)

    # Fill remaining missing numeric values with column medians.
    for column in feature_columns:
        if df[column].isna().any():
            median = df[column].median()

            if pd.isna(median):
                median = 0

            df[column] = df[column].fillna(median)

    # Remove the original detailed label.
    df = df.drop(columns=["Label"])

    # Save the model-ready dataset.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nFinal rows: {len(df):,}")
    print(f"Features: {len(feature_columns):,}")

    print("\nClass distribution:")
    print(df["Category"].value_counts())

    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
    