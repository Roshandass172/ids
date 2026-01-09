# deception_engine.py
"""
Deception Engine
----------------
Tracks attacker behavior over time and decides whether to
continue observation (honeynet) or escalate to blocking.

This module is STATEFUL and INTENT-AWARE.
"""

from collections import defaultdict
import time

# -------------------------------
# Configuration
# -------------------------------

# Score required to confirm malicious intent
BLOCK_THRESHOLD = 7

# Time window (seconds) to consider repeated behavior
REPEAT_WINDOW = 10

# -------------------------------
# Internal State
# -------------------------------

# Stores cumulative score per IP
ip_scores = defaultdict(int)

# Stores last behavior timestamp per IP
last_seen = defaultdict(float)

# Stores how many times behavior was seen recently
behavior_count = defaultdict(lambda: defaultdict(int))


# -------------------------------
# Scoring Rules
# -------------------------------

BEHAVIOR_SCORES = {
    "honeypot_hit": 1,
    "repeat_honeypot_hit": 2,
    "port_scan": 3,
    "dos": 5
}


# -------------------------------
# Core Functions
# -------------------------------

def update_behavior(ip: str, behavior: str) -> int:
    """
    Update behavior score for a source IP.

    Args:
        ip (str): Source IP address
        behavior (str): Type of behavior observed

    Returns:
        int: Current cumulative deception score for the IP
    """

    now = time.time()

    # Check if behavior is repeated in short time
    if now - last_seen[ip] <= REPEAT_WINDOW:
        behavior_count[ip][behavior] += 1
    else:
        behavior_count[ip][behavior] = 1

    last_seen[ip] = now

    # Determine score increment
    if behavior_count[ip][behavior] > 1 and behavior == "honeypot_hit":
        score = BEHAVIOR_SCORES["repeat_honeypot_hit"]
    else:
        score = BEHAVIOR_SCORES.get(behavior, 0)

    ip_scores[ip] += score

    return ip_scores[ip]


def should_block(ip: str) -> bool:
    """
    Decide whether the IP should be blocked.

    Args:
        ip (str): Source IP address

    Returns:
        bool: True if block threshold exceeded
    """
    return ip_scores[ip] >= BLOCK_THRESHOLD


def get_score(ip: str) -> int:
    """
    Get current deception score of an IP.
    """
    return ip_scores[ip]


def reset_ip(ip: str):
    """
    Reset tracking for an IP (optional use).
    """
    ip_scores.pop(ip, None)
    last_seen.pop(ip, None)
    behavior_count.pop(ip, None)


def snapshot():
    """
    Get full snapshot of tracked IPs (for debugging / dashboard).
    """
    return dict(ip_scores)
