
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

INPUT_FILE = Path("data/processed/cic_ids2017_training_sample.csv")
OUTPUT_DIR = Path("data/processed/splits")
RANDOM_STATE = 42


def main():
    print("Loading training sample...")
    df = pd.read_csv(INPUT_FILE)

    X = df.drop(columns=["Category"])
    y = df["Category"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    train_df = X_train.copy()
    train_df["Category"] = y_train
    test_df = X_test.copy()
    test_df["Category"] = y_test

    train_df.to_csv(OUTPUT_DIR / "train.csv", index=False)
    test_df.to_csv(OUTPUT_DIR / "test.csv", index=False)

    print(f"\nTraining rows: {len(train_df):,}")
    print(f"Testing rows: {len(test_df):,}")
    print("\nTraining class distribution:")
    print(train_df["Category"].value_counts().to_string())
    print("\nTesting class distribution:")
    print(test_df["Category"].value_counts().to_string())
    print(f"\nSaved splits to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
