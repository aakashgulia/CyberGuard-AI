
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score

MODEL_FILE = Path("models/random_forest_baseline.joblib")
ENCODER_FILE = Path("models/label_encoder.joblib")
TEST_FILE = Path("data/processed/splits/test.csv")


def main():
    print("Loading model and test data...")

    model = joblib.load(MODEL_FILE)
    encoder = joblib.load(ENCODER_FILE)
    test_df = pd.read_csv(TEST_FILE)

    # Select up to 100 records per category for a quick diagnostic.
    sample_df = (
        test_df.groupby("Category", group_keys=False)
        .sample(n=100, random_state=42, replace=False)
        .reset_index(drop=True)
    )

    X = sample_df.drop(columns=["Category"])
    y_actual = sample_df["Category"]
    predictions = encoder.inverse_transform(model.predict(X))

    print(f"\nRecords evaluated: {len(sample_df)}")
    print(f"Accuracy: {accuracy_score(y_actual, predictions):.4f}")

    print("\nClassification report:")
    print(
        classification_report(
            y_actual,
            predictions,
            labels=encoder.classes_,
            target_names=encoder.classes_,
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()
