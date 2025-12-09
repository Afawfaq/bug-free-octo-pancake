#!/usr/bin/env python3
"""
Evil Twin Analyzer
Analyzes WiFi environment for rogue AP placement opportunities
Note: Passive analysis only, does not create rogue APs
"""

import sys
import json
from datetime import datetime
from typing import Dict, List

class EvilTwinAnalyzer:
    def __init__(self):
        self.analysis = {}
    
    def analyze_channel_utilization(self, networks: List[Dict]) -> Dict:
        """Analyze channel utilization for optimal rogue AP placement."""
        channel_usage = {}
        
        for network in networks:
            channel = network.get('channel', 'Unknown')
            if channel != 'Unknown':
                channel_usage[channel] = channel_usage.get(channel, 0) + 1
        
        # Find least congested channels
        if channel_usage:
            sorted_channels = sorted(channel_usage.items(), key=lambda x: x[1])
            optimal_24ghz = [ch for ch, _ in sorted_channels if isinstance(ch, int) and ch <= 14][:3]
            optimal_5ghz = [ch for ch, _ in sorted_channels if isinstance(ch, int) and ch > 14][:3]
        else:
            optimal_24ghz = [1, 6, 11]  # Default non-overlapping channels
            optimal_5ghz = [36, 44, 149]
        
        return {
            'channel_utilization': channel_usage,
            'optimal_24ghz_channels': optimal_24ghz,
            'optimal_5ghz_channels': optimal_5ghz,
            'recommendation': 'Use least congested channels for better signal quality'
        }
    
    def analyze_signal_strength(self, networks: List[Dict]) -> Dict:
        """Analyze signal strengths to identify weak coverage areas."""
        strong_signals = 0
        weak_signals = 0
        
        for network in networks:
            signal = network.get('signal_strength', 'Unknown')
            if signal != 'Unknown':
                try:
                    # Parse signal strength (e.g., "-45 dBm")
                    signal_val = int(signal.split()[0]) if ' ' in signal else int(signal)
                    
                    if signal_val > -50:
                        strong_signals += 1
                    elif signal_val < -70:
                        weak_signals += 1
                except:
                    pass
        
        return {
            'strong_signal_networks': strong_signals,
            'weak_signal_networks': weak_signals,
            'analysis': 'Weak signals indicate coverage gaps or distance from AP',
            'security_implication': 'Users may connect to rogue APs offering stronger signals'
        }
    
    def analyze_encryption(self, networks: List[Dict]) -> Dict:
        """Analyze encryption types for downgrade attack opportunities."""
        encryption_types = {}
        
        for network in networks:
            enc = network.get('encryption', 'Unknown')
            encryption_types[enc] = encryption_types.get(enc, 0) + 1
        
        vulnerabilities = []
        if 'Open' in encryption_types:
            vulnerabilities.append('Open networks detected - users may accept unencrypted connections')
        if 'WPA' in encryption_types or 'WEP' in encryption_types:
            vulnerabilities.append('Legacy encryption detected - users may be familiar with weak security')
        
        return {
            'encryption_distribution': encryption_types,
            'potential_vulnerabilities': vulnerabilities,
            'recommendation': 'Users should verify network encryption before connecting'
        }
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        return [
            'Always verify network names before connecting',
            'Check for valid SSL certificates on sensitive sites',
            'Use VPN on public/untrusted networks',
            'Enable "forget network" for networks no longer in use',
            'Disable automatic WiFi connection',
            'Monitor for networks with similar names to legitimate ones',
            'Use WPA3 networks when available',
            'Educate users about evil twin attacks'
        ]

def main():
    if len(sys.argv) < 3:
        print("Usage: evil_twin_analyzer.py <networks_file> <output_file>")
        sys.exit(1)
    
    networks_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        with open(networks_file, 'r') as f:
            data = json.load(f)
            networks = data.get('networks', [])
    except Exception as e:
        print(f"[!] Error loading networks file: {e}")
        networks = []
    
    print(f"[*] Analyzing {len(networks)} networks for evil twin opportunities...")
    print(f"[*] Note: This is a defensive analysis tool")
    
    analyzer = EvilTwinAnalyzer()
    
    channel_analysis = analyzer.analyze_channel_utilization(networks)
    signal_analysis = analyzer.analyze_signal_strength(networks)
    encryption_analysis = analyzer.analyze_encryption(networks)
    recommendations = analyzer.generate_recommendations()
    
    output_data = {
        'timestamp': datetime.now().isoformat(),
        'networks_analyzed': len(networks),
        'channel_analysis': channel_analysis,
        'signal_analysis': signal_analysis,
        'encryption_analysis': encryption_analysis,
        'security_recommendations': recommendations,
        'note': 'This analysis identifies potential evil twin attack vectors for defensive purposes'
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Evil twin analysis complete.")
    print(f"[+] Analyzed {len(networks)} networks")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
