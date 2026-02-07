from graph_engine import GraphEngine
from gnn_engine import GNNEngine
from temporal_engine import TemporalEngine
from campaign_engine import CampaignEngine
import decision_engine as decision

class CryptonPipeline:
    def __init__(self, device="cpu"):
        self.graph_engine = GraphEngine()
        self.gnn_engine = GNNEngine(device=device)
        self.temporal_engine = TemporalEngine(device=device)
        self.campaign_engine = CampaignEngine()

    def process_packet(self, src_ip, dst_ip, packet_size=0):
        """
        Full spatio-temporal pipeline.
        """

        # 1. Update graph
        self.graph_engine.update(src_ip, dst_ip, packet_size)

        graph = self.graph_engine.get_graph()

        # 2. Run GNN (spatial)
        embeddings, threat_scores = self.gnn_engine.infer(graph)

        if src_ip not in embeddings:
            return None

        emb = embeddings[src_ip]

        # 3. Update temporal sequence
        self.temporal_engine.update_sequence(src_ip, emb)

        # 4. Run Transformer (temporal)
        attack_prob, stage = self.temporal_engine.infer(src_ip)

        if attack_prob is None:
            return None

        # 5. Campaign reasoning
        campaign_stage, campaign_conf = self.campaign_engine.infer_campaign(src_ip)

        # 6. Decision
        severity = decision.get_severity(attack_prob, campaign_stage, stage, src_ip)
        action = decision.get_decision(attack_prob, campaign_stage, stage, src_ip)

        return {
            "ip": src_ip,
            "attack_prob": attack_prob,
            "stage": stage,
            "campaign_stage": campaign_stage,
            "severity": severity,
            "action": action
        }
