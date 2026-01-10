import json
import sys

with open(sys.argv[1]) as f:
    events = json.load(f)

print("\n🎥 ATTACK REPLAY\n" + "-" * 50)
for e in events:
    print(f"[{e['timestamp']}]")
    print(f" Event     : {e['event']}")
    if e.get("category"):
        print(f" Category  : {e['category']}")
    if e.get("severity"):
        print(f" Severity  : {e['severity']}")
    if e.get("confidence") is not None:
        print(f" Confidence: {e['confidence']}")
    if e.get("decision"):
        print(f" Decision  : {e['decision']}")
    print()
