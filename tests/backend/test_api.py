
import math

from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.app.main import PredictionRequest, app, predict
from backend.app.model_service import model_service
from backend.app.risk_engine import calculate_risk


def test_api_info():
    with TestClient(app) as client:
        response = client.get("/api-info")

    assert response.status_code == 200
    assert response.json()["application"] == "CyberGuard AI"


def test_health():
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["model_loaded"] is True


def test_predict_rejects_missing_features():
    with TestClient(app) as client:
        response = client.post(
            "/predict",
            json={"features": {"Destination Port": 443}},
        )

    assert response.status_code == 422
    assert "missing_features" in response.json()["detail"]


def test_predict_rejects_non_finite_values():
    with TestClient(app):
        feature_names = list(model_service.model.feature_names_in_)

        for invalid_value in (math.nan, math.inf, -math.inf):
            features = {name: 0.0 for name in feature_names}
            features["Flow Bytes/s"] = invalid_value

            try:
                predict(PredictionRequest(features=features))
                assert False, "Expected HTTP 422 for non-finite feature"
            except HTTPException as exc:
                assert exc.status_code == 422
                assert "Flow Bytes/s" in exc.detail["invalid_features"]


def test_risk_scoring_returns_expected_fields():
    result = calculate_risk("Botnet", 0.95)

    assert result["risk_score"] == 90
    assert result["risk_level"] == "Critical"
    assert "Botnet" in result["risk_reason"]
