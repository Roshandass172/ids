import json
import time
from collections import defaultdict

_sessions = defaultdict(list)
_last_session_file = None

def log_event(
    ip,
    event,
    confidence=None,
    severity=None,
    decision=None,
    category=None
):
    _sessions[ip].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "confidence": confidence,
        "severity": severity,
        "decision": decision,
        "category": category
    })

def save_session(ip):
    global _last_session_file
    filename = f"attack_session_{ip.replace('.', '_')}.json"
    with open(filename, "w") as f:
        json.dump(_sessions[ip], f, indent=2)
    _last_session_file = filename

def get_last_session_file():
    return _last_session_file
