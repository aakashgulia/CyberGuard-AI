
from pathlib import Path
import json

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

MODEL_FILE = Path("models/random_forest_baseline.joblib")
ENCODER_FILE = Path("models/label_encoder.joblib")
TEST_FILE = Path("data/processed/splits/test.csv")
REPORT_DIR = Path("reports")
REPORT_FILE = REPORT_DIR / "baseline_evaluation.json"


def main():
    print("Loading model and full test set...")

    model = joblib.load(MODEL_FILE)
    encoder = joblib.load(ENCODER_FILE)
    test_df = pd.read_csv(TEST_FILE)

    X_test = test_df.drop(columns=["Category"])
    y_test = test_df["Category"]
    predictions = encoder.inverse_transform(model.predict(X_test))

    report = classification_report(
        y_test,
        predictions,
        labels=encoder.classes_,
        target_names=encoder.classes_,
        output_dict=True,
        zero_division=0,
    )

    results = {
        "model": "RandomForestClassifier",
        "test_records": len(test_df),
        "feature_count": X_test.shape[1],
        "accuracy": accuracy_score(y_test, predictions),
        "classification_report": report,
        "confusion_matrix": confusion_matrix(
            y_test,
            predictions,
            labels=encoder.classes_,
        ).tolist(),
        "class_order": encoder.classes_.tolist(),
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"Full test accuracy: {results['accuracy']:.4%}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
