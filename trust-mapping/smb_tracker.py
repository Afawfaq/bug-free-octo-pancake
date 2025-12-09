#!/usr/bin/env python3
"""
SMB Relationship Tracker
Tracks SMB connections and share access patterns for lateral movement analysis.
"""

import json
import sys
import subprocess
import re
from collections import defaultdict
from datetime import datetime


class SMBRelationshipTracker:
    """Track SMB relationships and share access patterns."""
    
    def __init__(self):
        self.smb_sessions = []
        self.share_access = defaultdict(list)
        self.authentication_attempts = []
        
    def enumerate_smb_shares(self, target_ip):
        """
        Enumerate SMB shares on a target host.
        
        Args:
            target_ip: Target IP address
        
        Returns:
            List of discovered shares
        """
        shares = []
        
        try:
            # Try null session enumeration
            cmd = ['smbclient', '-L', target_ip, '-N']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                # Parse share names
                if '\t' in line and ('Disk' in line or 'IPC' in line or 'Printer' in line):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        share_name = parts[0].strip()
                        share_type = parts[1].strip()
                        
                        share = {
                            'name': share_name,
                            'type': share_type,
                            'ip': target_ip,
                            'accessible_null_session': True
                        }
                        shares.append(share)
                        
        except subprocess.TimeoutExpired:
            print(f"Timeout enumerating shares on {target_ip}", file=sys.stderr)
        except Exception as e:
            print(f"Error enumerating shares on {target_ip}: {e}", file=sys.stderr)
        
        return shares
    
    def analyze_share_permissions(self, shares):
        """
        Analyze share permissions and access patterns.
        
        Args:
            shares: List of shares to analyze
        
        Returns:
            Dictionary of permission analysis
        """
        analysis = {
            'total_shares': len(shares),
            'accessible_shares': 0,
            'administrative_shares': [],
            'public_shares': [],
            'suspicious_shares': [],
            'risk_assessment': []
        }
        
        for share in shares:
            share_name = share['name']
            
            # Identify administrative shares (ending with $)
            if share_name.endswith('$'):
                analysis['administrative_shares'].append(share)
                analysis['risk_assessment'].append({
                    'share': share_name,
                    'ip': share['ip'],
                    'risk': 'HIGH',
                    'reason': 'Administrative share accessible'
                })
            
            # Identify public/guest shares
            elif share_name.lower() in ['public', 'share', 'data', 'files']:
                analysis['public_shares'].append(share)
                analysis['risk_assessment'].append({
                    'share': share_name,
                    'ip': share['ip'],
                    'risk': 'MEDIUM',
                    'reason': 'Public share may contain sensitive data'
                })
            
            # Flag suspicious share names
            suspicious_keywords = ['backup', 'password', 'confidential', 'finance', 'hr']
            if any(keyword in share_name.lower() for keyword in suspicious_keywords):
                analysis['suspicious_shares'].append(share)
                analysis['risk_assessment'].append({
                    'share': share_name,
                    'ip': share['ip'],
                    'risk': 'HIGH',
                    'reason': 'Share name suggests sensitive content'
                })
            
            if share.get('accessible_null_session'):
                analysis['accessible_shares'] += 1
        
        return analysis
    
    def map_lateral_movement_paths(self, smb_analysis, hosts):
        """
        Map potential lateral movement paths using SMB.
        
        Args:
            smb_analysis: SMB share analysis
            hosts: List of hosts with SMB
        
        Returns:
            List of lateral movement paths
        """
        lateral_paths = []
        
        # Identify pivot hosts (hosts with access to multiple shares)
        pivot_hosts = []
        for host in hosts:
            accessible_shares = [s for s in smb_analysis.get('accessible_shares', []) 
                               if s.get('accessible_null_session')]
            if len(accessible_shares) >= 2:
                pivot_hosts.append(host)
        
        # Create path entries
        for pivot in pivot_hosts:
            path = {
                'pivot_host': pivot,
                'accessible_targets': len([s for s in smb_analysis.get('accessible_shares', [])]),
                'risk_level': 'HIGH' if len([s for s in smb_analysis.get('accessible_shares', [])]) > 3 else 'MEDIUM',
                'attack_vector': 'SMB relay or credential reuse',
                'mitigation': 'Disable SMB1, enable SMB signing, enforce strong authentication'
            }
            lateral_paths.append(path)
        
        # Identify common vulnerabilities
        for risk in smb_analysis.get('risk_assessment', []):
            if risk['risk'] == 'HIGH':
                path = {
                    'vulnerability': risk['share'],
                    'target': risk['ip'],
                    'risk_level': 'HIGH',
                    'attack_vector': f"Access {risk['share']} for credential harvesting",
                    'mitigation': risk.get('reason', '')
                }
                lateral_paths.append(path)
        
        return lateral_paths
    
    def generate_smb_graph(self, hosts, shares, lateral_paths):
        """
        Generate SMB relationship graph.
        
        Args:
            hosts: List of hosts
            shares: List of shares
            lateral_paths: Lateral movement paths
        
        Returns:
            Dictionary with graph structure
        """
        nodes = []
        edges = []
        
        # Create nodes for hosts
        host_ips = set(share['ip'] for share in shares)
        for ip in host_ips:
            node = {
                'id': ip,
                'type': 'host',
                'shares_count': len([s for s in shares if s['ip'] == ip])
            }
            nodes.append(node)
        
        # Create nodes for shares
        for share in shares:
            node = {
                'id': f"{share['ip']}:{share['name']}",
                'type': 'share',
                'name': share['name'],
                'share_type': share['type'],
                'risk': 'high' if share['name'].endswith('$') else 'medium'
            }
            nodes.append(node)
            
            # Create edge from host to share
            edge = {
                'source': share['ip'],
                'target': f"{share['ip']}:{share['name']}",
                'type': 'hosts_share'
            }
            edges.append(edge)
        
        # Add edges for lateral movement paths
        for path in lateral_paths:
            if 'pivot_host' in path and 'target' in path:
                edge = {
                    'source': path['pivot_host'],
                    'target': path['target'],
                    'type': 'lateral_movement',
                    'risk': path['risk_level']
                }
                edges.append(edge)
        
        return {
            'nodes': nodes,
            'edges': edges,
            'statistics': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'host_count': len(host_ips),
                'share_count': len(shares)
            }
        }


def main():
    """Main execution function."""
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <output_dir> <target_ips_file>")
        sys.exit(1)
    
    output_dir = sys.argv[1]
    target_ips_file = sys.argv[2]
    
    # Read target IPs
    try:
        with open(target_ips_file, 'r') as f:
            target_ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Target IPs file not found: {target_ips_file}")
        sys.exit(1)
    
    tracker = SMBRelationshipTracker()
    
    all_shares = []
    
    print(f"[*] Enumerating SMB shares on {len(target_ips)} targets...")
    for ip in target_ips:
        print(f"[*] Scanning {ip}...")
        shares = tracker.enumerate_smb_shares(ip)
        all_shares.extend(shares)
        print(f"    Found {len(shares)} shares")
    
    print(f"\n[*] Total shares found: {len(all_shares)}")
    
    print("[*] Analyzing share permissions...")
    smb_analysis = tracker.analyze_share_permissions(all_shares)
    
    print("[*] Mapping lateral movement paths...")
    lateral_paths = tracker.map_lateral_movement_paths(smb_analysis, target_ips)
    
    print("[*] Generating SMB graph...")
    smb_graph = tracker.generate_smb_graph(target_ips, all_shares, lateral_paths)
    
    # Save results
    results = {
        'timestamp': datetime.now().isoformat(),
        'targets_scanned': len(target_ips),
        'shares': all_shares,
        'smb_analysis': smb_analysis,
        'lateral_paths': lateral_paths,
        'smb_graph': smb_graph
    }
    
    output_file = f"{output_dir}/smb_relationships.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Results saved to {output_file}")
    
    # Print summary
    print("\n=== SMB Relationship Analysis Summary ===")
    print(f"Total Shares: {smb_analysis['total_shares']}")
    print(f"Accessible Shares: {smb_analysis['accessible_shares']}")
    print(f"Administrative Shares: {len(smb_analysis['administrative_shares'])}")
    print(f"Public Shares: {len(smb_analysis['public_shares'])}")
    print(f"Suspicious Shares: {len(smb_analysis['suspicious_shares'])}")
    print(f"Lateral Movement Paths: {len(lateral_paths)}")
    print(f"High Risk Issues: {len([r for r in smb_analysis['risk_assessment'] if r['risk'] == 'HIGH'])}")


if __name__ == '__main__':
    main()
