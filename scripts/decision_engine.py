def get_severity(score):
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"

def get_decision(score):
    if score >= 5:
        return "BLOCK"
    if score >= 4:
        return "ALERT"
    return "OBSERVE"
