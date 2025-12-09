#!/usr/bin/env python3
"""
Windows Trust Graph Builder
Maps Windows domain relationships, trust boundaries, and authentication flows.
"""

import json
import subprocess
import re
import sys
from collections import defaultdict
from datetime import datetime


class WindowsTrustGraphBuilder:
    """Build trust graphs for Windows environments."""
    
    def __init__(self):
        self.trust_relationships = []
        self.domain_controllers = []
        self.workstations = []
        self.servers = []
        
    def scan_for_windows_hosts(self, network_range):
        """
        Identify Windows hosts on the network.
        
        Args:
            network_range: Network range to scan (e.g., "192.168.1.0/24")
        
        Returns:
            List of Windows hosts with details
        """
        windows_hosts = []
        
        try:
            # Use nmap to identify Windows hosts
            cmd = [
                'nmap', '-sV', '-O', '--script', 'smb-os-discovery',
                '-p', '445,139,135', network_range
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse nmap output for Windows hosts
            current_host = None
            for line in result.stdout.split('\n'):
                if 'Nmap scan report for' in line:
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                    if ip_match:
                        current_host = {'ip': ip_match.group(0), 'ports': [], 'os': 'Unknown', 'hostname': ''}
                
                elif current_host and 'open' in line:
                    port_match = re.search(r'(\d+)/tcp', line)
                    if port_match:
                        current_host['ports'].append(int(port_match.group(1)))
                
                elif current_host and 'OS:' in line:
                    if 'Windows' in line:
                        current_host['os'] = line.split('OS:')[1].strip()
                        
                elif current_host and 'Computer name:' in line:
                    current_host['hostname'] = line.split(':')[1].strip()
                
                elif current_host and 'Domain name:' in line:
                    current_host['domain'] = line.split(':')[1].strip()
                    
                elif current_host and current_host.get('os', '').startswith('Windows'):
                    windows_hosts.append(current_host)
                    current_host = None
                    
        except subprocess.TimeoutExpired:
            print("Warning: Nmap scan timed out", file=sys.stderr)
        except Exception as e:
            print(f"Error scanning for Windows hosts: {e}", file=sys.stderr)
        
        return windows_hosts
    
    def identify_domain_controllers(self, windows_hosts):
        """
        Identify domain controllers from Windows hosts.
        
        Args:
            windows_hosts: List of Windows hosts
        
        Returns:
            List of identified domain controllers
        """
        domain_controllers = []
        
        for host in windows_hosts:
            # Check for common DC indicators
            is_dc = False
            
            # Port 389 (LDAP) and 88 (Kerberos) indicate DC
            if 389 in host.get('ports', []) or 88 in host.get('ports', []):
                is_dc = True
            
            # Check DNS for DC records
            hostname = host.get('hostname', '')
            if hostname and ('dc' in hostname.lower() or 'domain' in hostname.lower()):
                is_dc = True
            
            if is_dc:
                host['role'] = 'Domain Controller'
                domain_controllers.append(host)
                self.domain_controllers.append(host)
            elif any(p in host.get('ports', []) for p in [3389, 135, 445]):
                if 'server' in host.get('os', '').lower():
                    host['role'] = 'Server'
                    self.servers.append(host)
                else:
                    host['role'] = 'Workstation'
                    self.workstations.append(host)
        
        return domain_controllers
    
    def map_smb_relationships(self, windows_hosts):
        """
        Map SMB share relationships between hosts.
        
        Args:
            windows_hosts: List of Windows hosts
        
        Returns:
            Dictionary of SMB relationships
        """
        smb_relationships = defaultdict(list)
        
        for host in windows_hosts:
            ip = host['ip']
            
            try:
                # List SMB shares (requires null session or credentials)
                cmd = ['smbclient', '-L', ip, '-N']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    shares = []
                    for line in result.stdout.split('\n'):
                        if 'Disk' in line or 'IPC' in line:
                            share_match = re.search(r'(\S+)\s+(Disk|IPC)', line)
                            if share_match:
                                shares.append(share_match.group(1))
                    
                    if shares:
                        smb_relationships[ip] = shares
                        
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                print(f"Error mapping SMB for {ip}: {e}", file=sys.stderr)
        
        return dict(smb_relationships)
    
    def analyze_trust_boundaries(self, windows_hosts):
        """
        Analyze trust boundaries and authentication flows.
        
        Args:
            windows_hosts: List of Windows hosts
        
        Returns:
            Dictionary of trust boundary analysis
        """
        analysis = {
            'domains': set(),
            'workgroups': set(),
            'trust_relationships': [],
            'authentication_flows': [],
            'security_boundaries': []
        }
        
        for host in windows_hosts:
            domain = host.get('domain', '')
            if domain:
                analysis['domains'].add(domain)
            
            # Identify trust relationships between DCs
            if host.get('role') == 'Domain Controller':
                for other_host in windows_hosts:
                    if (other_host.get('role') == 'Domain Controller' and 
                        other_host['ip'] != host['ip']):
                        
                        # Check if domains are different (potential trust)
                        other_domain = other_host.get('domain', '')
                        if domain != other_domain and domain and other_domain:
                            trust = {
                                'source_domain': domain,
                                'target_domain': other_domain,
                                'source_dc': host['ip'],
                                'target_dc': other_host['ip'],
                                'trust_type': 'potential_cross_domain'
                            }
                            analysis['trust_relationships'].append(trust)
        
        # Identify security boundaries
        if len(analysis['domains']) > 1:
            analysis['security_boundaries'].append({
                'type': 'domain_boundary',
                'domains': list(analysis['domains']),
                'risk': 'Cross-domain trust may enable lateral movement'
            })
        
        # Convert sets to lists for JSON serialization
        analysis['domains'] = list(analysis['domains'])
        analysis['workgroups'] = list(analysis['workgroups'])
        
        return analysis
    
    def build_attack_paths(self, windows_hosts, trust_analysis):
        """
        Synthesize potential attack paths for lateral movement.
        
        Args:
            windows_hosts: List of Windows hosts
            trust_analysis: Trust boundary analysis
        
        Returns:
            List of potential attack paths
        """
        attack_paths = []
        
        # Path 1: Workstation -> DC via SMB
        for workstation in self.workstations:
            for dc in self.domain_controllers:
                path = {
                    'path_id': f"path_{len(attack_paths) + 1}",
                    'source': workstation['ip'],
                    'target': dc['ip'],
                    'method': 'SMB authentication',
                    'risk_level': 'HIGH',
                    'description': 'Compromised workstation can authenticate to DC',
                    'mitigation': 'Implement network segmentation and least privilege'
                }
                attack_paths.append(path)
        
        # Path 2: Server -> Server via trust relationships
        for i, server1 in enumerate(self.servers):
            for server2 in self.servers[i+1:]:
                path = {
                    'path_id': f"path_{len(attack_paths) + 1}",
                    'source': server1['ip'],
                    'target': server2['ip'],
                    'method': 'Server-to-server trust',
                    'risk_level': 'MEDIUM',
                    'description': 'Lateral movement between servers',
                    'mitigation': 'Implement micro-segmentation'
                }
                attack_paths.append(path)
        
        # Path 3: Cross-domain attacks via trust relationships
        for trust in trust_analysis.get('trust_relationships', []):
            path = {
                'path_id': f"path_{len(attack_paths) + 1}",
                'source': trust['source_domain'],
                'target': trust['target_domain'],
                'method': 'Domain trust exploitation',
                'risk_level': 'CRITICAL',
                'description': 'Cross-domain trust can be exploited for privilege escalation',
                'mitigation': 'Review and minimize trust relationships, implement SID filtering'
            }
            attack_paths.append(path)
        
        return attack_paths
    
    def generate_trust_graph(self, windows_hosts, smb_relationships, trust_analysis):
        """
        Generate graph data structure for visualization.
        
        Args:
            windows_hosts: List of Windows hosts
            smb_relationships: SMB relationship mapping
            trust_analysis: Trust boundary analysis
        
        Returns:
            Dictionary with graph nodes and edges
        """
        nodes = []
        edges = []
        
        # Create nodes for each host
        for host in windows_hosts:
            node = {
                'id': host['ip'],
                'label': host.get('hostname', host['ip']),
                'type': host.get('role', 'Unknown'),
                'domain': host.get('domain', 'Unknown'),
                'os': host.get('os', 'Unknown')
            }
            nodes.append(node)
        
        # Create edges for SMB relationships
        for source, shares in smb_relationships.items():
            for host in windows_hosts:
                if host['ip'] != source and 445 in host.get('ports', []):
                    edge = {
                        'source': source,
                        'target': host['ip'],
                        'type': 'smb_share',
                        'shares': len(shares)
                    }
                    edges.append(edge)
        
        # Create edges for trust relationships
        for trust in trust_analysis.get('trust_relationships', []):
            edge = {
                'source': trust['source_dc'],
                'target': trust['target_dc'],
                'type': 'domain_trust',
                'risk': 'CRITICAL'
            }
            edges.append(edge)
        
        return {
            'nodes': nodes,
            'edges': edges,
            'statistics': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'domain_controllers': len(self.domain_controllers),
                'servers': len(self.servers),
                'workstations': len(self.workstations)
            }
        }


def main():
    """Main execution function."""
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <output_dir> <network_range>")
        sys.exit(1)
    
    output_dir = sys.argv[1]
    network_range = sys.argv[2]
    
    builder = WindowsTrustGraphBuilder()
    
    print(f"[*] Scanning for Windows hosts on {network_range}...")
    windows_hosts = builder.scan_for_windows_hosts(network_range)
    
    print(f"[*] Found {len(windows_hosts)} Windows hosts")
    
    print("[*] Identifying domain controllers...")
    domain_controllers = builder.identify_domain_controllers(windows_hosts)
    print(f"[*] Found {len(domain_controllers)} domain controllers")
    
    print("[*] Mapping SMB relationships...")
    smb_relationships = builder.map_smb_relationships(windows_hosts)
    
    print("[*] Analyzing trust boundaries...")
    trust_analysis = builder.analyze_trust_boundaries(windows_hosts)
    
    print("[*] Building attack paths...")
    attack_paths = builder.build_attack_paths(windows_hosts, trust_analysis)
    
    print("[*] Generating trust graph...")
    trust_graph = builder.generate_trust_graph(windows_hosts, smb_relationships, trust_analysis)
    
    # Save results
    results = {
        'timestamp': datetime.now().isoformat(),
        'network_range': network_range,
        'windows_hosts': windows_hosts,
        'domain_controllers': domain_controllers,
        'smb_relationships': smb_relationships,
        'trust_analysis': trust_analysis,
        'attack_paths': attack_paths,
        'trust_graph': trust_graph
    }
    
    output_file = f"{output_dir}/windows_trust_graph.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Results saved to {output_file}")
    
    # Print summary
    print("\n=== Windows Trust Graph Summary ===")
    print(f"Windows Hosts: {len(windows_hosts)}")
    print(f"Domain Controllers: {len(domain_controllers)}")
    print(f"Servers: {len(builder.servers)}")
    print(f"Workstations: {len(builder.workstations)}")
    print(f"Domains: {len(trust_analysis['domains'])}")
    print(f"Trust Relationships: {len(trust_analysis['trust_relationships'])}")
    print(f"Attack Paths Identified: {len(attack_paths)}")


if __name__ == '__main__':
    main()
