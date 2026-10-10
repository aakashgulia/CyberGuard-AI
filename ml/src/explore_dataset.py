from pathlib import Path

import pandas as pd


DATA_FILE = Path("data/processed/cic_ids2017_combined.csv")


def main():
    print("Loading dataset...")

    df = pd.read_csv(DATA_FILE)

    print(f"\nRows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    print("\nLabel distribution:")
    print(df["Label"].value_counts())

    print("\nDataset information:")
    print(df.info())

    print("\nMissing values:")
    missing = df.isna().sum()
    print(missing[missing > 0])

    print("\nDuplicate rows:")
    print(f"{df.duplicated().sum():,}")

    print("\nNumeric columns:")
    print(len(df.select_dtypes(include="number").columns))

    print("\nNon-numeric columns:")
    print(df.select_dtypes(exclude="number").columns.tolist())


if __name__ == "__main__":
    main()