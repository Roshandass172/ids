def get_severity(confidence):
    if confidence >= 0.85:
        return "CRITICAL"
    if confidence >= 0.65:
        return "HIGH"
    if confidence >= 0.35:
        return "MEDIUM"
    return "LOW"


def get_decision(confidence):
    if confidence >= 0.85:
        return "BLOCK"
    if confidence >= 0.35:
        return "ALERT"
    return "OBSERVE"
