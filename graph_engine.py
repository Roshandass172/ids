import networkx as nx
import time
from collections import defaultdict

class GraphEngine:
    def __init__(self):
        self.graph = nx.Graph()
        self.last_seen = defaultdict(float)

    def update(self, src_ip, dst_ip, packet_size=0, protocol="IP"):
        now = time.time()

        if not self.graph.has_node(src_ip):
            self.graph.add_node(src_ip, packet_rate=0, protocol=protocol)

        if not self.graph.has_node(dst_ip):
            self.graph.add_node(dst_ip, packet_rate=0, protocol=protocol)

        if self.graph.has_edge(src_ip, dst_ip):
            self.graph[src_ip][dst_ip]["count"] += 1
            self.graph[src_ip][dst_ip]["bytes"] += packet_size
        else:
            self.graph.add_edge(src_ip, dst_ip, count=1, bytes=packet_size)

        self.graph.nodes[src_ip]["packet_rate"] += 1
        self.last_seen[src_ip] = now
        self.last_seen[dst_ip] = now

    def get_graph(self):
        return self.graph

    def reset(self):
        self.graph.clear()
        self.last_seen.clear()
