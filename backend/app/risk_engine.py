
def calculate_risk(predicted_category: str, confidence: float) -> dict:
    """Assign a rule-based risk score to a network traffic prediction."""

    category = predicted_category.strip().lower()

    # Higher base scores represent categories that deserve more attention.
    category_scores = {
        "normal": 5,
        "dos/ddos": 85,
        "port scan": 60,
        "brute force": 75,
        "web attack": 80,
        "botnet": 95,
    }

    base_score = category_scores.get(category, 50)

    # Adjust the score according to model confidence.
    confidence = max(0.0, min(1.0, float(confidence)))
    adjusted_score = round(base_score * confidence)

    if adjusted_score >= 85:
        risk_level = "Critical"
    elif adjusted_score >= 65:
        risk_level = "High"
    elif adjusted_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if category == "normal":
        reason = "Traffic was classified as normal; continue routine monitoring."
    else:
        reason = (
            f"Traffic was classified as {predicted_category} "
            f"with {confidence:.1%} model confidence."
        )

    return {
        "risk_score": adjusted_score,
        "risk_level": risk_level,
        "risk_reason": reason,
    }
