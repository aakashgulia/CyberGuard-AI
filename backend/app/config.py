from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = PROJECT_ROOT / "models" / "random_forest_baseline.joblib"
ENCODER_PATH = PROJECT_ROOT / "models" / "label_encoder.joblib"

APP_NAME = "CyberGuard AI"
APP_VERSION = "1.0.0"