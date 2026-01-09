import json
import sys

if len(sys.argv) != 2:
    print("Usage: python replay_attack.py <session_file>")
    sys.exit(1)

with open(sys.argv[1], "r") as f:
    events = json.load(f)

print("\n🎥 ATTACK REPLAY\n" + "-" * 40)
for e in events:
    line = f"[{e['timestamp']}] {e['event']}"
    if e["score"] is not None:
        line += f" | Score: {e['score']}"
    print(line)
