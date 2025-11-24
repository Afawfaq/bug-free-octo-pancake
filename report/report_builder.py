#!/usr/bin/env python3

import json
import os
import sys
from datetime import datetime
from jinja2 import Template
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def load_data(output_dir):
    """Load all reconnaissance data"""
    data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "passive": {},
        "discovery": {},
        "fingerprint": {},
        "iot": {},
        "nuclei": {},
        "webshot": {}
    }
    
    # Load passive recon data
    passive_dir = os.path.join(output_dir, "passive")
    if os.path.exists(passive_dir):
        ips_file = os.path.join(passive_dir, "discovered_ips.txt")
        if os.path.exists(ips_file):
            with open(ips_file) as f:
                data["passive"]["discovered_ips"] = f.read().splitlines()
    
    # Load discovery data
    discovery_file = os.path.join(output_dir, "discovery", "discovered_hosts.json")
    if os.path.exists(discovery_file):
        with open(discovery_file) as f:
            data["discovery"]["hosts"] = json.load(f)
    
    # Load fingerprint data
    fingerprint_dir = os.path.join(output_dir, "fingerprint")
    if os.path.exists(fingerprint_dir):
        httpx_file = os.path.join(fingerprint_dir, "httpx_results.json")
        if os.path.exists(httpx_file):
            try:
                with open(httpx_file) as f:
                    data["fingerprint"]["httpx"] = [json.loads(line) for line in f]
            except:
                pass
    
    # Load IoT data
    iot_dir = os.path.join(output_dir, "iot")
    if os.path.exists(iot_dir):
        for filename in os.listdir(iot_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(iot_dir, filename)
                try:
                    with open(filepath) as f:
                        data["iot"][filename] = json.load(f)
                except:
                    pass
    
    # Load Nuclei data
    nuclei_file = os.path.join(output_dir, "nuclei", "nuclei_results.json")
    if os.path.exists(nuclei_file):
        try:
            with open(nuclei_file) as f:
                data["nuclei"]["findings"] = [json.loads(line) for line in f]
        except:
            data["nuclei"]["findings"] = []
    
    return data

def build_network_graph(data, output_file):
    """Build network topology graph"""
    G = nx.Graph()
    
    # Add router as central node
    G.add_node("Router\n192.168.68.1", node_type="router")
    
    # Add discovered hosts
    if "hosts" in data.get("discovery", {}):
        for ip, ports in data["discovery"]["hosts"].items():
            node_label = f"{ip}\nPorts: {len(ports)}"
            G.add_node(node_label, node_type="host")
            G.add_edge("Router\n192.168.68.1", node_label)
    
    # Draw graph
    plt.figure(figsize=(12, 10))
    pos = nx.spring_layout(G, k=2, iterations=50)
    
    # Color nodes by type
    colors = []
    for node in G.nodes():
        if G.nodes[node].get("node_type") == "router":
            colors.append("red")
        else:
            colors.append("lightblue")
    
    nx.draw(G, pos, node_color=colors, with_labels=True, 
            node_size=3000, font_size=8, font_weight="bold")
    
    plt.title("Network Topology", fontsize=16, fontweight="bold")
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()

def generate_html_report(data, template_file, output_file):
    """Generate HTML report"""
    with open(template_file) as f:
        template = Template(f.read())
    
    html = template.render(data=data)
    
    with open(output_file, 'w') as f:
        f.write(html)

def generate_json_report(data, output_file):
    """Generate machine-readable JSON report"""
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/output"
    report_dir = os.path.join(output_dir, "report")
    os.makedirs(report_dir, exist_ok=True)
    
    print("[*] Loading reconnaissance data...")
    data = load_data(output_dir)
    
    print("[*] Building network graph...")
    graph_file = os.path.join(report_dir, "network_topology.png")
    build_network_graph(data, graph_file)
    
    print("[*] Generating HTML report...")
    template_file = "/templates/report_template.html"
    html_file = os.path.join(report_dir, "recon_report.html")
    generate_html_report(data, template_file, html_file)
    
    print("[*] Generating JSON report...")
    json_file = os.path.join(report_dir, "recon_report.json")
    generate_json_report(data, json_file)
    
    print(f"[+] Reports generated in {report_dir}")
    print(f"    - HTML Report: {html_file}")
    print(f"    - JSON Report: {json_file}")
    print(f"    - Network Graph: {graph_file}")

if __name__ == "__main__":
    main()
