#!/usr/bin/env python3
"""
Enhanced Attack Path Synthesizer
Integrates reconnaissance data from all modules to generate prioritized attack chains
with MITRE ATT&CK mapping and automated exploit recommendations.
"""

import json
import os
from typing import Dict, List, Any
from datetime import datetime


class AttackPathSynthesizer:
    """
    Synthesizes attack paths by integrating data from multiple reconnaissance modules.
    Generates prioritized, multi-step attack chains with MITRE ATT&CK techniques.
    """
    
    def __init__(self, output_dir: str = '/output'):
        self.output_dir = output_dir
        self.entry_points = []
        self.attack_chains = []
        self.mitre_techniques = {
            'T1078': 'Valid Accounts',
            'T1190': 'Exploit Public-Facing Application',
            'T1021.002': 'SMB/Windows Admin Shares',
            'T1003': 'OS Credential Dumping',
            'T1021': 'Remote Services',
            'T1068': 'Exploitation for Privilege Escalation',
            'T1053': 'Scheduled Task/Job'
        }
    
    def load_reconnaissance_data(self) -> Dict[str, Any]:
        """Load data from all reconnaissance modules."""
        recon_data = {
            'credential_attacks': self._load_json('credential-attacks/default_creds_results.json'),
            'cleartext_creds': self._load_json('credential-attacks/cleartext_creds.json'),
            'patch_cadence': self._load_json('patch-cadence/cve_matches.json'),
            'aging_scores': self._load_json('patch-cadence/aging_scores.json'),
            'data_flow_anomalies': self._load_json('data-flow/anomalies.json'),
            'wifi_analysis': self._load_json('wifi-attacks/spectrum_analysis.json'),
            'wps_analysis': self._load_json('wifi-attacks/wps_analysis.json'),
            'smb_relationships': self._load_json('trust-mapping/smb_relationships.json'),
            'windows_trust': self._load_json('trust-mapping/windows_trust_graph.json'),
            'deception_alerts': self._load_json('deception/alerts.json')
        }
        return recon_data
    
    def _load_json(self, rel_path: str) -> Dict[str, Any]:
        """Load JSON file from output directory."""
        path = os.path.join(self.output_dir, rel_path)
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load {path}: {e}")
        return {}
    
    def identify_entry_points(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential entry points from reconnaissance data."""
        entry_points = []
        
        # Entry Point 1: Default Credentials
        cred_data = recon_data.get('credential_attacks', {})
        if cred_data and isinstance(cred_data, dict):
            successful_creds = cred_data.get('successful_logins', [])
            for cred in successful_creds:
                entry_points.append({
                    'type': 'default_credential',
                    'target': cred.get('target', 'unknown'),
                    'service': cred.get('service', 'unknown'),
                    'username': cred.get('username', 'unknown'),
                    'risk': 'CRITICAL',
                    'difficulty': 'LOW',
                    'technique': 'T1078',
                    'description': f"Default credential on {cred.get('service', 'service')}"
                })
        
        # Entry Point 2: Known Vulnerabilities (CVEs)
        cve_data = recon_data.get('patch_cadence', {})
        if cve_data and isinstance(cve_data, dict):
            cves = cve_data.get('matches', [])
            for cve in cves:
                if cve.get('cvss_score', 0) >= 7.0:  # High/Critical only
                    entry_points.append({
                        'type': 'known_vulnerability',
                        'target': cve.get('device', 'unknown'),
                        'cve': cve.get('cve_id', 'unknown'),
                        'cvss': cve.get('cvss_score', 0),
                        'risk': 'HIGH' if cve.get('cvss_score', 0) < 9.0 else 'CRITICAL',
                        'difficulty': 'MEDIUM',
                        'technique': 'T1190',
                        'description': f"Exploitable {cve.get('cve_id', 'CVE')}"
                    })
        
        # Entry Point 3: Open SMB Shares
        smb_data = recon_data.get('smb_relationships', {})
        if smb_data and isinstance(smb_data, dict):
            shares = smb_data.get('shares', [])
            for share in shares:
                if share.get('accessible', False) and share.get('risk', '') in ['HIGH', 'CRITICAL']:
                    entry_points.append({
                        'type': 'open_smb_share',
                        'target': share.get('host', 'unknown'),
                        'share': share.get('name', 'unknown'),
                        'risk': share.get('risk', 'MEDIUM'),
                        'difficulty': 'LOW',
                        'technique': 'T1021.002',
                        'description': f"Accessible SMB share: {share.get('name', 'share')}"
                    })
        
        # Entry Point 4: Weak WiFi Security
        wifi_data = recon_data.get('wifi_analysis', {})
        if wifi_data and isinstance(wifi_data, dict):
            networks = wifi_data.get('networks', [])
            for network in networks:
                if network.get('encryption', '').upper() in ['OPEN', 'WEP']:
                    entry_points.append({
                        'type': 'weak_wifi',
                        'target': network.get('ssid', 'unknown'),
                        'bssid': network.get('bssid', 'unknown'),
                        'risk': 'HIGH' if network.get('encryption') == 'OPEN' else 'MEDIUM',
                        'difficulty': 'LOW',
                        'technique': 'T1190',
                        'description': f"Weak WiFi security: {network.get('encryption', 'unknown')}"
                    })
        
        # Entry Point 5: Cleartext Credentials
        cleartext_data = recon_data.get('cleartext_creds', {})
        if cleartext_data and isinstance(cleartext_data, dict):
            captures = cleartext_data.get('captures', [])
            for capture in captures:
                entry_points.append({
                    'type': 'cleartext_credential',
                    'target': capture.get('target', 'unknown'),
                    'protocol': capture.get('protocol', 'unknown'),
                    'username': capture.get('username', 'unknown'),
                    'risk': 'HIGH',
                    'difficulty': 'LOW',
                    'technique': 'T1078',
                    'description': f"Cleartext credential captured via {capture.get('protocol', 'protocol')}"
                })
        
        self.entry_points = entry_points
        return entry_points
    
    def build_attack_chains(self, entry_points: List[Dict[str, Any]], 
                           recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build multi-step attack chains from entry points."""
        chains = []
        
        for entry in entry_points:
            chain = {
                'chain_id': f"chain_{len(chains) + 1}",
                'entry_point': entry,
                'steps': [],
                'risk_level': entry['risk'],
                'difficulty': entry['difficulty'],
                'mitre_techniques': [entry['technique']]
            }
            
            # Step 1: Initial Access
            chain['steps'].append({
                'step_number': 1,
                'action': f"Exploit {entry['type']} on {entry['target']}",
                'technique': entry['technique'],
                'technique_name': self.mitre_techniques.get(entry['technique'], 'Unknown'),
                'success_probability': 'HIGH' if entry['difficulty'] == 'LOW' else 'MEDIUM'
            })
            
            # Step 2: Credential Harvesting
            chain['steps'].append({
                'step_number': 2,
                'action': 'Harvest credentials from memory or disk',
                'technique': 'T1003',
                'technique_name': self.mitre_techniques['T1003'],
                'success_probability': 'MEDIUM'
            })
            chain['mitre_techniques'].append('T1003')
            
            # Step 3: Lateral Movement
            smb_data = recon_data.get('smb_relationships', {})
            lateral_targets = self._identify_lateral_targets(entry['target'], smb_data)
            if lateral_targets:
                chain['steps'].append({
                    'step_number': 3,
                    'action': f"Move laterally to {len(lateral_targets)} targets",
                    'targets': lateral_targets[:5],  # Top 5
                    'technique': 'T1021',
                    'technique_name': self.mitre_techniques['T1021'],
                    'success_probability': 'MEDIUM'
                })
                chain['mitre_techniques'].append('T1021')
            
            # Step 4: Privilege Escalation
            aging_data = recon_data.get('aging_scores', {})
            if self._has_privilege_escalation_opportunity(entry['target'], aging_data):
                chain['steps'].append({
                    'step_number': 4,
                    'action': 'Escalate privileges using local vulnerability',
                    'technique': 'T1068',
                    'technique_name': self.mitre_techniques['T1068'],
                    'success_probability': 'MEDIUM'
                })
                chain['mitre_techniques'].append('T1068')
            
            # Step 5: Persistence
            chain['steps'].append({
                'step_number': 5,
                'action': 'Establish persistence mechanism',
                'technique': 'T1053',
                'technique_name': self.mitre_techniques['T1053'],
                'success_probability': 'HIGH'
            })
            chain['mitre_techniques'].append('T1053')
            
            # Calculate priority score
            chain['priority_score'] = self._calculate_priority(chain)
            chain['impact'] = self._assess_impact(chain, recon_data)
            
            chains.append(chain)
        
        # Sort by priority score
        chains.sort(key=lambda x: x['priority_score'], reverse=True)
        self.attack_chains = chains
        return chains
    
    def _identify_lateral_targets(self, source: str, smb_data: Dict[str, Any]) -> List[str]:
        """Identify potential lateral movement targets."""
        targets = []
        if smb_data and isinstance(smb_data, dict):
            lateral_paths = smb_data.get('lateral_paths', [])
            for path in lateral_paths:
                if path.get('source') == source:
                    targets.extend(path.get('targets', []))
        return list(set(targets))[:10]  # Unique, max 10
    
    def _has_privilege_escalation_opportunity(self, target: str, aging_data: Dict[str, Any]) -> bool:
        """Check if target has known privilege escalation vulnerabilities."""
        if aging_data and isinstance(aging_data, dict):
            scores = aging_data.get('scores', [])
            for score in scores:
                if score.get('device') == target and score.get('score', 0) > 70:
                    return True
        return False
    
    def _calculate_priority(self, chain: Dict[str, Any]) -> int:
        """Calculate attack chain priority score (0-100)."""
        risk_scores = {'LOW': 10, 'MEDIUM': 30, 'HIGH': 60, 'CRITICAL': 90}
        difficulty_scores = {'LOW': 30, 'MEDIUM': 20, 'HIGH': 10}
        
        risk_score = risk_scores.get(chain['risk_level'], 30)
        difficulty_score = difficulty_scores.get(chain['difficulty'], 20)
        step_penalty = max(0, 30 - (len(chain['steps']) * 2))
        
        return min(100, risk_score + difficulty_score + step_penalty)
    
    def _assess_impact(self, chain: Dict[str, Any], recon_data: Dict[str, Any]) -> str:
        """Assess potential impact of successful attack chain."""
        windows_data = recon_data.get('windows_trust', {})
        target = chain['entry_point'].get('target', '')
        
        # Check if target is domain controller
        if windows_data and isinstance(windows_data, dict):
            dcs = windows_data.get('domain_controllers', [])
            if target in dcs:
                return "Domain admin compromise possible"
        
        # Check for high-value targets
        if 'server' in target.lower() or 'dc' in target.lower():
            return "Critical infrastructure compromise"
        
        # Default impact
        return "Workstation or device compromise"
    
    def generate_recommendations(self, chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate prioritized security recommendations."""
        recommendations = []
        
        # Group chains by entry point type
        by_type = {}
        for chain in chains:
            entry_type = chain['entry_point']['type']
            if entry_type not in by_type:
                by_type[entry_type] = []
            by_type[entry_type].append(chain)
        
        # Generate recommendations
        priority_order = ['default_credential', 'known_vulnerability', 'open_smb_share', 
                         'cleartext_credential', 'weak_wifi']
        
        for entry_type in priority_order:
            if entry_type in by_type:
                chains_of_type = by_type[entry_type]
                severity = chains_of_type[0]['risk_level']
                
                if entry_type == 'default_credential':
                    recommendations.append({
                        'severity': severity,
                        'title': 'Change all default credentials immediately',
                        'affected_chains': len(chains_of_type),
                        'mitigation': 'Enforce strong password policy and disable default accounts',
                        'priority': 1
                    })
                elif entry_type == 'known_vulnerability':
                    recommendations.append({
                        'severity': severity,
                        'title': 'Apply security patches to vulnerable systems',
                        'affected_chains': len(chains_of_type),
                        'mitigation': 'Implement regular patch management and vulnerability scanning',
                        'priority': 2
                    })
                elif entry_type == 'open_smb_share':
                    recommendations.append({
                        'severity': severity,
                        'title': 'Restrict SMB share access and disable null sessions',
                        'affected_chains': len(chains_of_type),
                        'mitigation': 'Implement principle of least privilege for share permissions',
                        'priority': 3
                    })
                elif entry_type == 'cleartext_credential':
                    recommendations.append({
                        'severity': severity,
                        'title': 'Eliminate cleartext protocols and enforce encryption',
                        'affected_chains': len(chains_of_type),
                        'mitigation': 'Replace FTP/Telnet/HTTP with SFTP/SSH/HTTPS',
                        'priority': 4
                    })
                elif entry_type == 'weak_wifi':
                    recommendations.append({
                        'severity': severity,
                        'title': 'Secure wireless networks with WPA3 and strong passphrases',
                        'affected_chains': len(chains_of_type),
                        'mitigation': 'Disable WPS, use WPA3, implement 802.11w PMF',
                        'priority': 5
                    })
        
        # Add general recommendation for network segmentation
        if len(chains) > 5:
            recommendations.append({
                'severity': 'MEDIUM',
                'title': 'Implement network segmentation to prevent lateral movement',
                'affected_chains': len(chains),
                'mitigation': 'Deploy microsegmentation and monitor east-west traffic',
                'priority': 6
            })
        
        return recommendations
    
    def synthesize(self) -> Dict[str, Any]:
        """Main method to synthesize complete attack path analysis."""
        print("[*] Loading reconnaissance data from all modules...")
        recon_data = self.load_reconnaissance_data()
        
        print("[*] Identifying entry points...")
        entry_points = self.identify_entry_points(recon_data)
        print(f"[+] Found {len(entry_points)} potential entry points")
        
        print("[*] Building attack chains...")
        chains = self.build_attack_chains(entry_points, recon_data)
        print(f"[+] Generated {len(chains)} attack chains")
        
        print("[*] Generating security recommendations...")
        recommendations = self.generate_recommendations(chains)
        print(f"[+] Generated {len(recommendations)} recommendations")
        
        # Compile results
        results = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_entry_points': len(entry_points),
                'total_attack_chains': len(chains),
                'total_recommendations': len(recommendations)
            },
            'entry_points': entry_points,
            'attack_chains': chains,
            'recommendations': recommendations,
            'statistics': {
                'by_risk': self._count_by_risk(chains),
                'by_entry_type': self._count_by_type(entry_points),
                'high_priority_chains': len([c for c in chains if c['priority_score'] > 70])
            }
        }
        
        return results
    
    def _count_by_risk(self, chains: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count chains by risk level."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for chain in chains:
            risk = chain.get('risk_level', 'MEDIUM')
            counts[risk] = counts.get(risk, 0) + 1
        return counts
    
    def _count_by_type(self, entry_points: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count entry points by type."""
        counts = {}
        for entry in entry_points:
            entry_type = entry.get('type', 'unknown')
            counts[entry_type] = counts.get(entry_type, 0) + 1
        return counts
    
    def save_results(self, results: Dict[str, Any], output_path: str):
        """Save results to JSON file."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {output_path}")


def main():
    """Main execution function."""
    import sys
    
    output_dir = sys.argv[1] if len(sys.argv) > 1 else '/output'
    
    synthesizer = AttackPathSynthesizer(output_dir)
    results = synthesizer.synthesize()
    
    # Save detailed results
    output_path = os.path.join(output_dir, 'trust-mapping', 'attack_paths.json')
    synthesizer.save_results(results, output_path)
    
    # Print summary
    print("\n" + "="*60)
    print("ATTACK PATH SYNTHESIS SUMMARY")
    print("="*60)
    print(f"Entry Points Found: {results['metadata']['total_entry_points']}")
    print(f"Attack Chains Generated: {results['metadata']['total_attack_chains']}")
    print(f"High Priority Chains: {results['statistics']['high_priority_chains']}")
    print(f"\nBy Risk Level:")
    for risk, count in results['statistics']['by_risk'].items():
        if count > 0:
            print(f"  {risk}: {count}")
    print(f"\nTop 3 Recommendations:")
    for i, rec in enumerate(results['recommendations'][:3], 1):
        print(f"  {i}. [{rec['severity']}] {rec['title']}")
    print("="*60)


if __name__ == '__main__':
    main()
