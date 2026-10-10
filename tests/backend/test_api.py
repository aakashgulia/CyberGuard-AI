from fastapi.testclient import TestClient

from backend.app.main import app


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
