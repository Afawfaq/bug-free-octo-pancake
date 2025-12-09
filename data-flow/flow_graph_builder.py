#!/usr/bin/env python3
"""
Flow Graph Builder
Generates visual network topology and data flow graphs
"""

import sys
import json
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, List

class FlowGraphBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.anomalous_connections = set()
    
    def build_graph(self, baselines: Dict, anomalies: List[Dict]):
        """Build network graph from baseline data."""
        # Add nodes for each device
        for device_ip, baseline in baselines.items():
            self.graph.add_node(device_ip, 
                               packets=baseline.get('total_packets', 0),
                               bytes_sent=baseline.get('bytes_sent', 0))
        
        # Add edges for communication relationships
        for device_ip, baseline in baselines.items():
            destinations = baseline.get('top_destinations', {})
            for dest_ip, packet_count in destinations.items():
                if dest_ip in self.graph.nodes:
                    self.graph.add_edge(device_ip, dest_ip, weight=packet_count)
        
        # Mark anomalous connections
        for anomaly in anomalies:
            if anomaly['type'] == 'NEW_DESTINATION':
                device_ip = anomaly['device_ip']
                new_dests = anomaly['details'].get('new_destinations', [])
                for dest in new_dests:
                    self.anomalous_connections.add((device_ip, dest))
    
    def generate_static_graph(self, output_file: str):
        """Generate static PNG visualization."""
        if len(self.graph.nodes) == 0:
            print("[!] No nodes in graph, skipping visualization")
            return
        
        plt.figure(figsize=(16, 12))
        
        # Layout
        try:
            pos = nx.spring_layout(self.graph, k=2, iterations=50)
        except:
            pos = nx.circular_layout(self.graph)
        
        # Draw nodes
        nx.draw_networkx_nodes(self.graph, pos,
                              node_color='lightblue',
                              node_size=1000,
                              alpha=0.8)
        
        # Draw normal edges
        normal_edges = [(u, v) for u, v in self.graph.edges() 
                       if (u, v) not in self.anomalous_connections]
        nx.draw_networkx_edges(self.graph, pos,
                              edgelist=normal_edges,
                              edge_color='gray',
                              alpha=0.5,
                              arrows=True,
                              arrowsize=15)
        
        # Draw anomalous edges in red
        anomalous_edges = [(u, v) for u, v in self.graph.edges() 
                          if (u, v) in self.anomalous_connections]
        if anomalous_edges:
            nx.draw_networkx_edges(self.graph, pos,
                                  edgelist=anomalous_edges,
                                  edge_color='red',
                                  alpha=0.8,
                                  width=2,
                                  arrows=True,
                                  arrowsize=20)
        
        # Draw labels
        nx.draw_networkx_labels(self.graph, pos,
                               font_size=8,
                               font_weight='bold')
        
        plt.title('Network Data Flow Graph\n(Red edges indicate anomalous connections)',
                 fontsize=14, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        plt.close()
        
        print(f"[+] Static graph saved to {output_file}")
    
    def generate_graph_data(self) -> Dict:
        """Generate graph data structure for JSON export."""
        nodes = []
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            nodes.append({
                'id': node,
                'packets': node_data.get('packets', 0),
                'bytes_sent': node_data.get('bytes_sent', 0)
            })
        
        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                'source': u,
                'target': v,
                'weight': data.get('weight', 1),
                'anomalous': (u, v) in self.anomalous_connections
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'statistics': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'anomalous_edges': len(self.anomalous_connections)
            }
        }

def main():
    if len(sys.argv) < 4:
        print("Usage: flow_graph_builder.py <baseline_file> <anomalies_file> <output_prefix>")
        sys.exit(1)
    
    baseline_file = sys.argv[1]
    anomalies_file = sys.argv[2]
    output_prefix = sys.argv[3]
    
    try:
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
            baselines = baseline_data.get('baselines', {})
        
        with open(anomalies_file, 'r') as f:
            anomaly_data = json.load(f)
            anomalies = anomaly_data.get('anomalies', [])
    except Exception as e:
        print(f"[!] Error loading data: {e}")
        sys.exit(1)
    
    print(f"[*] Building flow graph for {len(baselines)} devices...")
    
    builder = FlowGraphBuilder()
    builder.build_graph(baselines, anomalies)
    
    # Generate static visualization
    builder.generate_static_graph(f"{output_prefix}_flow_graph.png")
    
    # Generate JSON data
    graph_data = builder.generate_graph_data()
    graph_data['timestamp'] = datetime.now().isoformat()
    
    with open(f"{output_prefix}_flow_graph.json", 'w') as f:
        json.dump(graph_data, f, indent=2)
    
    print(f"\n[+] Flow graph generation complete.")
    print(f"[+] Nodes: {graph_data['statistics']['total_nodes']}")
    print(f"[+] Edges: {graph_data['statistics']['total_edges']}")
    print(f"[+] Anomalous edges: {graph_data['statistics']['anomalous_edges']}")
    print(f"[+] Results saved with prefix: {output_prefix}_flow_graph")

if __name__ == "__main__":
    main()
