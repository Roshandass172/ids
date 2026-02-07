from collections import defaultdict
import time

STAGES = ["Recon", "Exploit", "Persist", "Exfil"]

class CampaignEngine:
    """
    Infers multi-stage attack campaigns from temporal ML output.
    """

    def __init__(self):
        self.stage_history = defaultdict(list)
        self.last_seen = defaultdict(float)

    def update(self, ip, attack_prob, stage, window=60):
        """
        Update campaign state for an IP.
        """
        now = time.time()
        self.last_seen[ip] = now

        self.stage_history[ip].append((now, stage, attack_prob))

        # Keep only recent history
        self.stage_history[ip] = [
            (t, s, p)
            for (t, s, p) in self.stage_history[ip]
            if now - t <= window
        ]

    def infer_campaign(self, ip):
        """
        Returns:
        - current stage
        - campaign confidence
        """
        if ip not in self.stage_history or not self.stage_history[ip]:
            return "None", 0.0

        stages = [s for (_, s, _) in self.stage_history[ip]]
        probs = [p for (_, _, p) in self.stage_history[ip]]

        # Detect stage progression
        unique_stages = []
        for s in stages:
            if s not in unique_stages:
                unique_stages.append(s)

        # Campaign if multiple stages observed
        if len(unique_stages) >= 2:
            confidence = sum(probs) / len(probs)
            return "Campaign", round(confidence, 3)

        # Otherwise current stage
        return unique_stages[-1], round(sum(probs) / len(probs), 3)

    def reset(self, ip):
        self.stage_history.pop(ip, None)
        self.last_seen.pop(ip, None)
