import joblib

from backend.app.config import ENCODER_PATH, MODEL_PATH


class ModelService:
    def __init__(self):
        self.model = None
        self.encoder = None

    def load(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Trained model not found: {MODEL_PATH}"
            )

        if not ENCODER_PATH.exists():
            raise FileNotFoundError(
                f"Label encoder not found: {ENCODER_PATH}"
            )

        self.model = joblib.load(MODEL_PATH)
        self.encoder = joblib.load(ENCODER_PATH)

    def predict(self, features):
        if self.model is None or self.encoder is None:
            raise RuntimeError("Model service has not been loaded.")

        prediction = self.model.predict(features)[0]
        probabilities = self.model.predict_proba(features)[0]

        confidence = float(probabilities.max())
        predicted_category = str(
            self.encoder.inverse_transform([prediction])[0]
        )

        return {
            "predicted_category": predicted_category,
            "confidence": confidence,
        }


model_service = ModelService()
