
from pathlib import Path
import time

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.preprocessing import LabelEncoder

TRAIN_FILE = Path("data/processed/splits/train.csv")
TEST_FILE = Path("data/processed/splits/test.csv")
MODEL_DIR = Path("models")
MODEL_FILE = MODEL_DIR / "random_forest_baseline.joblib"
LABELS_FILE = MODEL_DIR / "label_encoder.joblib"


def main():
    print("Loading training and testing data...")
    train_df = pd.read_csv(TRAIN_FILE)
    test_df = pd.read_csv(TEST_FILE)

    X_train = train_df.drop(columns=["Category"])
    y_train = train_df["Category"]
    X_test = test_df.drop(columns=["Category"])
    y_test = test_df["Category"]

    encoder = LabelEncoder()
    y_train_encoded = encoder.fit_transform(y_train)
    y_test_encoded = encoder.transform(y_test)

    print(f"Training rows: {len(X_train):,}")
    print(f"Testing rows: {len(X_test):,}")
    print(f"Features: {X_train.shape[1]}")
    print("\nTraining Random Forest baseline...")

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    start = time.time()
    model.fit(X_train, y_train_encoded)
    print(f"Training time: {time.time() - start:.1f} seconds")

    print("\nEvaluating on the test set...")
    predictions = model.predict(X_test)

    print(f"Accuracy: {accuracy_score(y_test_encoded, predictions):.4f}")
    print("\nClassification report:")
    print(
        classification_report(
            y_test_encoded,
            predictions,
            labels=range(len(encoder.classes_)),
            target_names=encoder.classes_,
            zero_division=0,
        )
    )

    print("Confusion matrix (rows=actual, columns=predicted):")
    print(confusion_matrix(y_test_encoded, predictions))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    joblib.dump(encoder, LABELS_FILE)

    print(f"\nModel saved to: {MODEL_FILE}")
    print(f"Label encoder saved to: {LABELS_FILE}")


if __name__ == "__main__":
    main()
