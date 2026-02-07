import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv
from torch_geometric.utils import from_networkx

class GNNModel(nn.Module):
    """
    Graph Neural Network for spatial attack detection.
    Produces node embeddings and threat scores.
    """
    def __init__(self, in_channels=2, hidden_channels=16, out_channels=8):
        super().__init__()
        self.conv1 = GATConv(in_channels, hidden_channels)
        self.conv2 = GATConv(hidden_channels, out_channels)
        self.classifier = nn.Linear(out_channels, 1)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        scores = torch.sigmoid(self.classifier(x))
        return x, scores  # embeddings, threat scores


class GNNEngine:
    def __init__(self, model_path=None, device="cpu"):
        self.device = torch.device(device)
        self.model = GNNModel().to(self.device)

        if model_path:
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))

        self.model.eval()

    def infer(self, nx_graph):
        """
        Convert NetworkX graph → PyTorch Geometric → run GNN.
        """
        if nx_graph.number_of_nodes() == 0:
            return {}, {}

        # Ensure node features exist
        for node in nx_graph.nodes:
            nx_graph.nodes[node].setdefault("packet_rate", 0)
            nx_graph.nodes[node].setdefault("confidence", 0)

        data = from_networkx(nx_graph)

        # Build feature tensor: [packet_rate, confidence]
        x = []
        node_list = list(nx_graph.nodes)
        for node in node_list:
            feat = [
                nx_graph.nodes[node]["packet_rate"],
                nx_graph.nodes[node]["confidence"]
            ]
            x.append(feat)

        data.x = torch.tensor(x, dtype=torch.float).to(self.device)
        data.edge_index = data.edge_index.to(self.device)

        with torch.no_grad():
            embeddings, scores = self.model(data.x, data.edge_index)

        # Map back to IPs
        threat_scores = {
            node_list[i]: float(scores[i].item())
            for i in range(len(node_list))
        }

        embeddings_map = {
            node_list[i]: embeddings[i].cpu()
            for i in range(len(node_list))
        }

        return embeddings_map, threat_scores
