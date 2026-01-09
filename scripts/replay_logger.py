import json
import time
from collections import defaultdict

_sessions = defaultdict(list)

def log_event(ip, event, score=None):
    _sessions[ip].append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "score": score
    })

def save_session(ip):
    filename = f"attack_session_{ip.replace('.', '_')}.json"
    with open(filename, "w") as f:
        json.dump(_sessions[ip], f, indent=2)
