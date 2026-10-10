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
    disclaimer: str