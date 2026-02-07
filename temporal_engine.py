import torch
import torch.nn as nn

class TemporalTransformer(nn.Module):
    """
    Transformer model for temporal attack detection.
    Input: sequence of node embeddings over time
    Output: attack probability + stage score
    """
    def __init__(self, embed_dim=8, nhead=2, num_layers=2):
        super().__init__()

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=nhead,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers
        )

        self.attack_head = nn.Linear(embed_dim, 1)
        self.stage_head = nn.Linear(embed_dim, 4)  # Recon, Exploit, Persist, Exfil

    def forward(self, seq):
        """
        seq shape: [batch, time, embed_dim]
        """
        out = self.transformer(seq)

        last_state = out[:, -1, :]

        attack_prob = torch.sigmoid(self.attack_head(last_state))
        stage_logits = self.stage_head(last_state)

        return attack_prob, stage_logits


class TemporalEngine:
    def __init__(self, model_path=None, device="cpu"):
        self.device = torch.device(device)
        self.model = TemporalTransformer().to(self.device)

        if model_path:
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))

        self.model.eval()

        # Store past embeddings per IP
        self.history = {}

    def update_sequence(self, ip, embedding, max_len=10):
        """
        Add new embedding to time sequence for IP.
        """
        if ip not in self.history:
            self.history[ip] = []

        self.history[ip].append(embedding)

        if len(self.history[ip]) > max_len:
            self.history[ip] = self.history[ip][-max_len:]

    def infer(self, ip):
        """
        Run transformer on IP history.
        """
        if ip not in self.history or len(self.history[ip]) < 2:
            return None, None

        seq = torch.stack(self.history[ip]).unsqueeze(0).to(self.device)

        with torch.no_grad():
            attack_prob, stage_logits = self.model(seq)

        stage_idx = torch.argmax(stage_logits, dim=1).item()
        stage_map = ["Recon", "Exploit", "Persist", "Exfil"]

        return float(attack_prob.item()), stage_map[stage_idx]
