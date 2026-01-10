CRITICAL_THRESHOLD = 0.85
HIGH_THRESHOLD = 0.65
MEDIUM_THRESHOLD = 0.35

CATEGORY_RISK_MULTIPLIER = {
    "Flooding": 1.2,
    "Exploitation": 1.15,
    "Reconnaissance": 1.0,
    "Unknown": 0.9
}

def _adjust_confidence(confidence, category):
    multiplier = CATEGORY_RISK_MULTIPLIER.get(category, 1.0)
    adjusted = confidence * multiplier
    return min(round(adjusted, 3), 1.0)

def get_severity(confidence, category="Unknown"):
    adj = _adjust_confidence(confidence, category)

    if adj >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if adj >= HIGH_THRESHOLD:
        return "HIGH"
    if adj >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"

def get_decision(confidence, category="Unknown"):
    adj = _adjust_confidence(confidence, category)

    if adj >= CRITICAL_THRESHOLD:
        return "BLOCK"
    if adj >= MEDIUM_THRESHOLD:
        return "ALERT"
    return "OBSERVE"
