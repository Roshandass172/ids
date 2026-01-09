import json
import sys

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

if len(sys.argv) != 2:
    print("Usage: python replay_attack.py <session_file>")
    sys.exit(1)

with open(sys.argv[1], "r") as f:
    events = json.load(f)

print("\n🎥 ATTACK REPLAY")
print("-" * 50)

for e in events:
    ts = e.get("timestamp", "N/A")
    event = e.get("event", "Unknown event")
    confidence = e.get("score")

    line = f"[{ts}] {event}"

    if confidence is not None:
        try:
            confidence = float(confidence)
            severity = get_severity(confidence)
            decision = get_decision(confidence)
            line += (
                f" | Confidence: {confidence:.2f}"
                f" | Severity: {severity}"
                f" | Decision: {decision}"
            )
        except ValueError:
            line += f" | Score: {confidence}"

    print(line)
