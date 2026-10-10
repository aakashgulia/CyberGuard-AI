
from pathlib import Path
import pandas as pd

INPUT_FILE = Path("data/processed/cic_ids2017_model_ready.csv")
OUTPUT_FILE = Path("data/processed/cic_ids2017_training_sample.csv")

CHUNK_SIZE = 100_000
MAX_PER_CLASS = 100_000
SAMPLE_PER_CLASS_PER_CHUNK = 5_000
RANDOM_STATE = 42


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {INPUT_FILE}")

    print("Creating a memory-conscious training sample...")
    candidates = []

    for chunk in pd.read_csv(INPUT_FILE, chunksize=CHUNK_SIZE):
        for _, group in chunk.groupby("Category"):
            size = min(len(group), SAMPLE_PER_CLASS_PER_CHUNK)
            candidates.append(
                group.sample(n=size, random_state=RANDOM_STATE)
            )

    sampled = pd.concat(candidates, ignore_index=True)
    balanced_groups = []

    for _, group in sampled.groupby("Category"):
        size = min(len(group), MAX_PER_CLASS)
        balanced_groups.append(
            group.sample(n=size, random_state=RANDOM_STATE)
        )

    sampled = pd.concat(balanced_groups, ignore_index=True)
    sampled = sampled.sample(frac=1, random_state=RANDOM_STATE)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    sampled.to_csv(OUTPUT_FILE, index=False)

    print(f"\nSample rows: {len(sampled):,}")
    print(f"Features: {len(sampled.columns) - 1}")
    print("\nClass distribution:")
    print(sampled["Category"].value_counts().to_string())
    print(f"\nSaved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
