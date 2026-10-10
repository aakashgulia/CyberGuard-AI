from contextlib import asynccontextmanager
from backend.app.schemas import PredictionResponse
from backend.app.database import initialize_database

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.app.model_service import model_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    model_service.load()
    yield


app = FastAPI(
    title="CyberGuard AI API",
    description="AI-powered network threat classification API.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class PredictionRequest(BaseModel):
    features: dict[str, float] = Field(
        ...,
        description="Network-flow features using the trained model's feature names.",
    )


@app.get("/")
def root():
    return {
        "name": "CyberGuard AI",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": model_service.model is not None,
    }


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest):
    if model_service.model is None:
        raise HTTPException(status_code=503, detail="Model is not loaded.")

    expected_features = list(model_service.model.feature_names_in_)
    received_features = set(request.features)
    expected_set = set(expected_features)

    missing = sorted(expected_set - received_features)
    unexpected = sorted(received_features - expected_set)

    if missing or unexpected:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Feature names do not match the trained model.",
                "missing_features": missing,
                "unexpected_features": unexpected,
            },
        )

    try:
        import pandas as pd

        feature_frame = pd.DataFrame(
            [[request.features[name] for name in expected_features]],
            columns=expected_features,
        )

        result = model_service.predict(feature_frame)
        return {
            **result,
            "confidence_percent": round(result["confidence"] * 100, 2),
            "disclaimer": (
                "This is a model prediction, not a guarantee that "
                "network activity is malicious or safe."
            ),
        }

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid feature values: {exc}",
        ) from exc