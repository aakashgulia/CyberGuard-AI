
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

INPUT_FILE = Path("reports/feature_importance.csv")
OUTPUT_FILE = Path("reports/feature_importance.png")


def main():
    importance = pd.read_csv(INPUT_FILE)
    top_features = importance.head(15).sort_values("Importance")

    plt.figure(figsize=(10, 7))
    plt.barh(top_features["Feature"], top_features["Importance"])
    plt.xlabel("Feature Importance")
    plt.ylabel("Network Traffic Feature")
    plt.title("CyberGuard AI — Top 15 Feature Importances")
    plt.tight_layout()

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUTPUT_FILE, dpi=200, bbox_inches="tight")
    plt.close()

    print(f"Chart saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
