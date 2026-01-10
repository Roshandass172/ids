from collections import defaultdict
import time
import math

CONFIRMATION_CONFIDENCE = 0.85
DECAY_HALF_LIFE = 60
REPEAT_WINDOW = 10

confidence = defaultdict(float)
last_update = defaultdict(float)
behavior_history = defaultdict(lambda: defaultdict(int))
category_scores = defaultdict(lambda: defaultdict(float))

BEHAVIOR_EVIDENCE = {
    "honeypot_hit": 0.10,
    "repeat_honeypot_hit": 0.20,
    "port_scan": 0.35,
    "dos": 0.55
}

BEHAVIOR_CATEGORY = {
    "honeypot_hit": "Reconnaissance",
    "repeat_honeypot_hit": "Reconnaissance",
    "port_scan": "Reconnaissance",
    "dos": "Flooding"
}

def _decay(ip: str):
    now = time.time()
    last = last_update[ip]
    if last == 0:
        return

    elapsed = now - last
    decay_factor = 0.5 ** (elapsed / DECAY_HALF_LIFE)

    confidence[ip] *= decay_factor

    for cat in category_scores[ip]:
        category_scores[ip][cat] *= decay_factor

def update_behavior(ip: str, behavior: str) -> float:
    now = time.time()
    _decay(ip)

    if now - last_update[ip] <= REPEAT_WINDOW:
        behavior_history[ip][behavior] += 1
    else:
        behavior_history[ip][behavior] = 1

    last_update[ip] = now

    if behavior_history[ip][behavior] > 1 and behavior == "honeypot_hit":
        evidence = BEHAVIOR_EVIDENCE["repeat_honeypot_hit"]
        category = BEHAVIOR_CATEGORY["repeat_honeypot_hit"]
    else:
        evidence = BEHAVIOR_EVIDENCE.get(behavior, 0.0)
        category = BEHAVIOR_CATEGORY.get(behavior, "Unknown")

    prior = confidence[ip]
    confidence[ip] = 1 - (1 - prior) * (1 - evidence)

    category_scores[ip][category] += evidence

    return round(confidence[ip], 3)

def should_block(ip: str) -> bool:
    _decay(ip)
    return confidence[ip] >= CONFIRMATION_CONFIDENCE

def get_score(ip: str) -> float:
    _decay(ip)
    return round(confidence[ip], 3)

def get_category(ip: str) -> str:
    if not category_scores[ip]:
        return "Unknown"
    return max(category_scores[ip], key=category_scores[ip].get)

def get_category_breakdown(ip: str):
    return {
        cat: round(score, 3)
        for cat, score in category_scores[ip].items()
    }

def reset_ip(ip: str):
    confidence.pop(ip, None)
    last_update.pop(ip, None)
    behavior_history.pop(ip, None)
    category_scores.pop(ip, None)

def snapshot():
    return {
        ip: {
            "confidence": round(confidence[ip], 3),
            "category": get_category(ip)
        }
        for ip in confidence
    }
