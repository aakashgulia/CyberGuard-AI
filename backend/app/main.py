from contextlib import asynccontextmanager
from backend.app.schemas import PredictionResponse
from backend.app.database import get_connection, initialize_database, save_prediction
from backend.app.database import initialize_database, save_prediction

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
        save_prediction(
        predicted_category=result["predicted_category"],
        confidence=result["confidence"],
        features=request.features,
)
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
    from backend.app.database import get_connection


@app.get("/history")
def get_prediction_history(limit: int = 50):
    if not 1 <= limit <= 500:
        raise HTTPException(
            status_code=422,
            detail="Limit must be between 1 and 500.",
        )

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, predicted_category, confidence
            FROM prediction_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return {
        "count": len(rows),
        "predictions": [dict(row) for row in rows],
    }
@app.get("/stats")
def get_prediction_stats():
    with get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM prediction_history"
        ).fetchone()[0]

        categories = connection.execute(
            """
            SELECT predicted_category, COUNT(*) AS count
            FROM prediction_history
            GROUP BY predicted_category
            ORDER BY count DESC
            """
        ).fetchall()

        average_confidence = connection.execute(
            "SELECT AVG(confidence) FROM prediction_history"
        ).fetchone()[0]

    return {
        "total_predictions": total,
        "category_counts": {
            row["predicted_category"]: row["count"]
            for row in categories
        },
        "average_confidence": (
            round(average_confidence, 4)
            if average_confidence is not None
            else None
        ),
    }
