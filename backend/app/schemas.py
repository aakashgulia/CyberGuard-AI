
from pydantic import BaseModel, Field


class PredictionResponse(BaseModel):
    predicted_category: str = Field(
        description="Predicted network traffic category."
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Model confidence between 0 and 1."
    )
    confidence_percent: float = Field(
        ge=0.0,
        le=100.0,
        description="Model confidence expressed as a percentage."
    )
    risk_score: int = Field(
        ge=0,
        le=100,
        description="Rule-based risk score between 0 and 100."
    )
    risk_level: str = Field(
        description="Risk priority: Low, Medium, High, or Critical."
    )
    risk_reason: str = Field(
        description="Explanation of the assigned risk level."
    )
    disclaimer: str
