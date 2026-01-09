import json
import time
from collections import defaultdict

_sessions = defaultdict(list)

def log_event(ip, event, confidence=None, severity=None, decision=None):
    _sessions[ip].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "confidence": confidence,
        "severity": severity,
        "decision": decision
    })

def save_session(ip):
    if ip not in _sessions or not _sessions[ip]:
        return

    filename = f"attack_session_{ip.replace('.', '_')}.json"
    with open(filename, "w") as f:
        json.dump(_sessions[ip], f, indent=2)
