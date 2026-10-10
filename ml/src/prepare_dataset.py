from pathlib import Path
import pandas as pd


DATA_DIR = Path("data/raw/CIC-IDS2017/MachineLearningCVE")
OUTPUT_FILE = Path("data/processed/cic_ids2017_combined.csv")


def main():
    files = sorted(DATA_DIR.glob("*.csv"))

    if not files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

    print(f"Found {len(files)} CSV files.")

    frames = []

    for file in files:
        print(f"Reading: {file.name}")
        df = pd.read_csv(file)
        df.columns = df.columns.str.strip()
        df["Label"] = df["Label"].astype(str).str.strip()
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)

    print(f"\nCombined rows: {len(combined):,}")
    print(f"Columns: {len(combined.columns)}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUTPUT_FILE, index=False)

    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()