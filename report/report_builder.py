#!/usr/bin/env python3
"""
Report Builder for LAN Reconnaissance Framework
===============================================

Generates comprehensive HTML, JSON, and CSV reports from scan data.
Includes executive summary, severity breakdown, and network topology visualization.

Version: 2.0.0
"""

import json
import os
import sys
import csv
from datetime import datetime
from jinja2 import Template
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


# Constants
DEFAULT_ROUTER_IP = "192.168.68.1"
DESCRIPTION_MAX_LENGTH = 200


def load_json_lines(filepath):
    """Load JSON lines file efficiently, yielding one record at a time."""
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def load_data(output_dir):
    """Load all reconnaissance data from output directories."""
    data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_timestamp": datetime.now().isoformat(),
        "passive": {},
        "discovery": {},
        "fingerprint": {},
        "iot": {},
        "nuclei": {},
        "webshot": {},
        "advanced": {},
        "attack_surface": {},
        "statistics": {}
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
                data["fingerprint"]["httpx"] = list(load_json_lines(httpx_file))
            except Exception:
                data["fingerprint"]["httpx"] = []
    
    # Load IoT data
    iot_dir = os.path.join(output_dir, "iot")
    if os.path.exists(iot_dir):
        for filename in os.listdir(iot_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(iot_dir, filename)
                try:
                    with open(filepath) as f:
                        data["iot"][filename] = json.load(f)
                except Exception:
                    pass
    
    # Load Nuclei data
    nuclei_file = os.path.join(output_dir, "nuclei", "nuclei_results.json")
    if os.path.exists(nuclei_file):
        try:
            data["nuclei"]["findings"] = list(load_json_lines(nuclei_file))
        except Exception:
            data["nuclei"]["findings"] = []
    
    # Load advanced monitoring data
    advanced_dir = os.path.join(output_dir, "advanced")
    if os.path.exists(advanced_dir):
        for filename in os.listdir(advanced_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(advanced_dir, filename)
                try:
                    with open(filepath) as f:
                        data["advanced"][filename] = json.load(f)
                except Exception:
                    pass
    
    # Load attack surface data
    attack_surface_dir = os.path.join(output_dir, "attack-surface")
    if os.path.exists(attack_surface_dir):
        for filename in os.listdir(attack_surface_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(attack_surface_dir, filename)
                try:
                    with open(filepath) as f:
                        data["attack_surface"][filename] = json.load(f)
                except Exception:
                    pass
    
    # Calculate statistics
    data["statistics"] = calculate_statistics(data)
    
    return data


def calculate_statistics(data):
    """Calculate summary statistics from scan data."""
    stats = {
        "total_hosts": 0,
        "total_ports": 0,
        "total_vulnerabilities": 0,
        "severity_breakdown": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "device_types": {},
        "top_open_ports": {},
        "risk_score": 0
    }
    
    # Count hosts and ports
    if "hosts" in data.get("discovery", {}):
        stats["total_hosts"] = len(data["discovery"]["hosts"])
        for ip, ports in data["discovery"]["hosts"].items():
            stats["total_ports"] += len(ports)
            for port in ports:
                port_num = str(port) if isinstance(port, int) else port.get("port", "unknown")
                stats["top_open_ports"][port_num] = stats["top_open_ports"].get(port_num, 0) + 1
    
    # Count vulnerabilities by severity
    if "findings" in data.get("nuclei", {}):
        stats["total_vulnerabilities"] = len(data["nuclei"]["findings"])
        for finding in data["nuclei"]["findings"]:
            severity = finding.get("info", {}).get("severity", "info").lower()
            if severity in stats["severity_breakdown"]:
                stats["severity_breakdown"][severity] += 1
    
    # Calculate risk score (0-100)
    stats["risk_score"] = calculate_risk_score(stats)
    
    # Sort top open ports
    stats["top_open_ports"] = dict(
        sorted(stats["top_open_ports"].items(), key=lambda x: x[1], reverse=True)[:10]
    )
    
    return stats


def calculate_risk_score(stats):
    """Calculate overall risk score based on findings."""
    score = 0
    
    # Weight by severity
    weights = {
        "critical": 25,
        "high": 15,
        "medium": 5,
        "low": 2,
        "info": 0
    }
    
    for severity, count in stats["severity_breakdown"].items():
        score += count * weights.get(severity, 0)
    
    # Cap at 100
    return min(score, 100)


def get_risk_level(score):
    """Convert risk score to level string."""
    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def build_network_graph(data, output_file):
    """Build network topology graph with improved visualization."""
    G = nx.Graph()
    
    # Get router IP from environment or use default
    router_ip = os.getenv("ROUTER_IP", DEFAULT_ROUTER_IP)
    
    # Add router as central node
    G.add_node(f"Router\n{router_ip}", node_type="router")
    
    # Add discovered hosts
    if "hosts" in data.get("discovery", {}):
        for ip, ports in data["discovery"]["hosts"].items():
            port_count = len(ports) if isinstance(ports, list) else len(ports.keys())
            node_label = f"{ip}\n{port_count} ports"
            
            # Determine node type based on ports
            node_type = classify_device_type(ports)
            G.add_node(node_label, node_type=node_type, ip=ip)
            G.add_edge(f"Router\n{router_ip}", node_label)
    
    
    # Draw graph
    plt.figure(figsize=(14, 12))
    pos = nx.spring_layout(G, k=2.5, iterations=50)
    
    # Color nodes by type
    color_map = {
        "router": "#e74c3c",
        "server": "#3498db",
        "workstation": "#2ecc71",
        "iot": "#9b59b6",
        "printer": "#f39c12",
        "unknown": "#95a5a6"
    }
    
    colors = [color_map.get(G.nodes[node].get("node_type", "unknown"), "#95a5a6") for node in G.nodes()]
    
    # Draw
    nx.draw(G, pos, node_color=colors, with_labels=True, 
            node_size=3500, font_size=8, font_weight="bold",
            edge_color="#bdc3c7", width=2, alpha=0.9)
    
    # Add legend
    legend_elements = [
        plt.scatter([], [], c=color, s=100, label=name.title())
        for name, color in color_map.items()
    ]
    plt.legend(handles=legend_elements, loc="upper left", fontsize=10)
    
    plt.title("Network Topology", fontsize=16, fontweight="bold", pad=20)
    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()


def classify_device_type(ports):
    """Classify device type based on open ports."""
    port_list = []
    if isinstance(ports, list):
        port_list = [str(p) if isinstance(p, int) else str(p.get("port", "")) for p in ports]
    elif isinstance(ports, dict):
        port_list = list(ports.keys())
    
    # Server indicators
    server_ports = {"22", "80", "443", "3306", "5432", "8080", "8443"}
    if server_ports & set(port_list):
        return "server"
    
    # Printer indicators
    printer_ports = {"631", "9100", "515"}
    if printer_ports & set(port_list):
        return "printer"
    
    # IoT indicators
    iot_ports = {"8008", "8009", "1883", "5353", "49152"}
    if iot_ports & set(port_list):
        return "iot"
    
    return "workstation"


def generate_html_report(data, template_file, output_file):
    """Generate comprehensive HTML report."""
    # Load or use default template
    if os.path.exists(template_file):
        with open(template_file) as f:
            template = Template(f.read())
    else:
        template = Template(get_default_template())
    
    # Add extra data for template
    data["risk_level"] = get_risk_level(data["statistics"]["risk_score"])
    
    html = template.render(data=data)
    
    with open(output_file, 'w') as f:
        f.write(html)


def generate_json_report(data, output_file):
    """Generate machine-readable JSON report."""
    # Create clean export data
    export_data = {
        "metadata": {
            "generated_at": data["scan_timestamp"],
            "framework_version": "2.0.0",
            "report_type": "full_scan"
        },
        "summary": {
            "total_hosts": data["statistics"]["total_hosts"],
            "total_ports": data["statistics"]["total_ports"],
            "total_vulnerabilities": data["statistics"]["total_vulnerabilities"],
            "risk_score": data["statistics"]["risk_score"],
            "risk_level": get_risk_level(data["statistics"]["risk_score"])
        },
        "severity_breakdown": data["statistics"]["severity_breakdown"],
        "findings": data.get("nuclei", {}).get("findings", []),
        "hosts": data.get("discovery", {}).get("hosts", {}),
        "iot_devices": data.get("iot", {}),
        "advanced_analysis": data.get("advanced", {}),
        "attack_surface": data.get("attack_surface", {})
    }
    
    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2)


def generate_csv_report(data, output_file):
    """Generate CSV report of findings for spreadsheet analysis."""
    findings = data.get("nuclei", {}).get("findings", [])
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Name", "Severity", "Description", "Matched At"])
        
        for finding in findings:
            description = finding.get("info", {}).get("description", "")
            truncated_desc = description[:DESCRIPTION_MAX_LENGTH] if description else ""
            writer.writerow([
                finding.get("host", ""),
                finding.get("port", ""),
                finding.get("info", {}).get("name", ""),
                finding.get("info", {}).get("severity", ""),
                truncated_desc,
                finding.get("matched-at", "")
            ])


def get_default_template():
    """Return default HTML template if template file not found."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAN Reconnaissance Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px; border-radius: 10px; margin-bottom: 30px; }
        h1 { font-size: 2.5rem; margin-bottom: 10px; }
        h2 { color: #667eea; margin: 30px 0 20px; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #252540; padding: 25px; border-radius: 10px; text-align: center; }
        .stat-value { font-size: 2.5rem; font-weight: bold; color: #667eea; }
        .stat-label { color: #888; margin-top: 5px; }
        .severity-critical { color: #e74c3c; }
        .severity-high { color: #e67e22; }
        .severity-medium { color: #f1c40f; }
        .severity-low { color: #2ecc71; }
        .severity-info { color: #3498db; }
        .risk-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .risk-CRITICAL { background: #e74c3c; }
        .risk-HIGH { background: #e67e22; }
        .risk-MEDIUM { background: #f1c40f; color: #333; }
        .risk-LOW { background: #2ecc71; }
        .risk-NONE { background: #95a5a6; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #252540; color: #667eea; }
        tr:hover { background: #252540; }
        .finding { background: #252540; padding: 20px; border-radius: 10px; margin: 15px 0; border-left: 4px solid; }
        .finding.critical { border-color: #e74c3c; }
        .finding.high { border-color: #e67e22; }
        .finding.medium { border-color: #f1c40f; }
        .finding.low { border-color: #2ecc71; }
        .finding.info { border-color: #3498db; }
        footer { text-align: center; padding: 30px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 LAN Reconnaissance Report</h1>
            <p>Generated: {{ data.scan_time }}</p>
            <p>Risk Level: <span class="risk-badge risk-{{ data.risk_level }}">{{ data.risk_level }}</span></p>
        </header>
        
        <h2>📊 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ data.statistics.total_hosts }}</div>
                <div class="stat-label">Hosts Discovered</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ data.statistics.total_ports }}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ data.statistics.total_vulnerabilities }}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ data.statistics.risk_score }}/100</div>
                <div class="stat-label">Risk Score</div>
            </div>
        </div>
        
        <h2>⚠️ Severity Breakdown</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value severity-critical">{{ data.statistics.severity_breakdown.critical }}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-high">{{ data.statistics.severity_breakdown.high }}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-medium">{{ data.statistics.severity_breakdown.medium }}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card">
                <div class="stat-value severity-low">{{ data.statistics.severity_breakdown.low }}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        {% if data.nuclei.findings %}
        <h2>🛡️ Security Findings</h2>
        {% for finding in data.nuclei.findings %}
        <div class="finding {{ finding.info.severity | default('info') }}">
            <h3>{{ finding.info.name | default('Unknown Finding') }}</h3>
            <p><strong>Severity:</strong> {{ finding.info.severity | default('info') | upper }}</p>
            <p><strong>Host:</strong> {{ finding.host | default('Unknown') }}</p>
            <p>{{ finding.info.description | default('No description') }}</p>
        </div>
        {% endfor %}
        {% endif %}
        
        {% if data.discovery.hosts %}
        <h2>🖥️ Discovered Hosts</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Open Ports</th>
                </tr>
            </thead>
            <tbody>
            {% for ip, ports in data.discovery.hosts.items() %}
                <tr>
                    <td>{{ ip }}</td>
                    <td>{{ ports | length }} ports</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
        {% endif %}
        
        <footer>
            <p>Generated by LAN Reconnaissance Framework v2.0.0</p>
            <p>⚠️ Use responsibly and only on authorized networks</p>
        </footer>
    </div>
</body>
</html>
    """


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
    
    print("[*] Generating CSV report...")
    csv_file = os.path.join(report_dir, "findings.csv")
    generate_csv_report(data, csv_file)
    
    # Print summary
    stats = data["statistics"]
    print(f"\n{'='*60}")
    print("SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"Total Hosts:         {stats['total_hosts']}")
    print(f"Total Open Ports:    {stats['total_ports']}")
    print(f"Vulnerabilities:     {stats['total_vulnerabilities']}")
    print(f"Risk Score:          {stats['risk_score']}/100 ({get_risk_level(stats['risk_score'])})")
    print(f"\nSeverity Breakdown:")
    print(f"  Critical: {stats['severity_breakdown']['critical']}")
    print(f"  High:     {stats['severity_breakdown']['high']}")
    print(f"  Medium:   {stats['severity_breakdown']['medium']}")
    print(f"  Low:      {stats['severity_breakdown']['low']}")
    print(f"{'='*60}\n")
    
    print(f"[+] Reports generated in {report_dir}")
    print(f"    - HTML Report: {html_file}")
    print(f"    - JSON Report: {json_file}")
    print(f"    - CSV Report:  {csv_file}")
    print(f"    - Network Graph: {graph_file}")


if __name__ == "__main__":
    main()
