#!/usr/bin/env python3
"""
Device Chatter Fingerprinter
Identifies unique communication patterns for each device
"""

import sys
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict

class ChatterFingerprinter:
    def __init__(self):
        self.patterns = {}
    
    def analyze_time_patterns(self, baseline: Dict) -> Dict:
        """Analyze time-based communication patterns."""
        first_seen = baseline.get('first_seen')
        last_seen = baseline.get('last_seen')
        
        time_patterns = {
            'active_hours': 'unknown',
            'activity_type': 'continuous'
        }
        
        if first_seen and last_seen:
            first_dt = datetime.fromisoformat(first_seen)
            last_dt = datetime.fromisoformat(last_seen)
            
            first_hour = first_dt.hour
            last_hour = last_dt.hour
            
            # Classify activity patterns
            if 2 <= first_hour <= 5 or 2 <= last_hour <= 5:
                time_patterns['suspicious_hours'] = True
                time_patterns['3am_activity'] = True
            
            # Determine activity type
            if baseline.get('packets_per_second', 0) > 10:
                time_patterns['activity_type'] = 'high_frequency'
            elif baseline.get('packets_per_second', 0) < 0.1:
                time_patterns['activity_type'] = 'periodic'
            else:
                time_patterns['activity_type'] = 'moderate'
        
        return time_patterns
    
    def analyze_destination_patterns(self, baseline: Dict) -> Dict:
        """Analyze destination communication patterns."""
        top_destinations = baseline.get('top_destinations', {})
        destination_diversity = baseline.get('destination_diversity', 0)
        
        patterns = {
            'communication_style': 'unknown',
            'primary_destinations': list(top_destinations.keys())[:3] if top_destinations else [],
            'destination_count': len(top_destinations)
        }
        
        # Classify communication style
        if destination_diversity < 0.3:
            patterns['communication_style'] = 'focused'
            patterns['behavior'] = 'Single-purpose device or IoT'
        elif destination_diversity > 0.7:
            patterns['communication_style'] = 'diverse'
            patterns['behavior'] = 'General-purpose device or scanner'
        else:
            patterns['communication_style'] = 'moderate'
            patterns['behavior'] = 'Normal device usage'
        
        return patterns
    
    def analyze_protocol_behavior(self, baseline: Dict) -> Dict:
        """Analyze protocol usage patterns."""
        protocol_mix = baseline.get('protocol_mix', {})
        top_ports = baseline.get('top_ports', {})
        
        behavior = {
            'primary_protocol': max(protocol_mix.items(), key=lambda x: x[1])[0] if protocol_mix else 'unknown',
            'protocol_diversity': len(protocol_mix),
            'common_services': []
        }
        
        # Identify common services
        service_map = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 53: 'DNS', 139: 'NetBIOS', 445: 'SMB',
            3389: 'RDP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            631: 'IPP', 9100: 'JetDirect', 5353: 'mDNS',
            1900: 'SSDP', 8008: 'Chromecast'
        }
        
        for port, count in top_ports.items():
            if port in service_map:
                behavior['common_services'].append(service_map[port])
        
        # Classify device type
        if 'IPP' in behavior['common_services'] or 'JetDirect' in behavior['common_services']:
            behavior['likely_device_type'] = 'printer'
        elif 'Chromecast' in behavior['common_services'] or 'SSDP' in behavior['common_services']:
            behavior['likely_device_type'] = 'media_device'
        elif 'SMB' in behavior['common_services'] or 'NetBIOS' in behavior['common_services']:
            behavior['likely_device_type'] = 'file_server_or_nas'
        elif 'HTTPS' in behavior['common_services'] and 'HTTP' in behavior['common_services']:
            behavior['likely_device_type'] = 'general_purpose'
        else:
            behavior['likely_device_type'] = 'unknown'
        
        return behavior
    
    def create_fingerprint(self, device_ip: str, baseline: Dict) -> Dict:
        """Create a unique fingerprint for a device."""
        time_patterns = self.analyze_time_patterns(baseline)
        destination_patterns = self.analyze_destination_patterns(baseline)
        protocol_behavior = self.analyze_protocol_behavior(baseline)
        
        chatter_signature = {
            'device_ip': device_ip,
            'fingerprint_timestamp': datetime.now().isoformat(),
            'time_patterns': time_patterns,
            'destination_patterns': destination_patterns,
            'protocol_behavior': protocol_behavior,
            'traffic_characteristics': {
                'packets_per_second': baseline.get('packets_per_second', 0),
                'avg_packet_size': baseline.get('avg_packet_size', 0),
                'bytes_sent': baseline.get('bytes_sent', 0),
                'bytes_received': baseline.get('bytes_received', 0),
                'traffic_ratio': baseline.get('bytes_sent', 0) / max(baseline.get('bytes_received', 1), 1)
            },
            'anomaly_indicators': []
        }
        
        # Flag potential anomalies
        if time_patterns.get('3am_activity'):
            chatter_signature['anomaly_indicators'].append('Activity during unusual hours (2-5 AM)')
        
        if destination_patterns.get('communication_style') == 'diverse':
            chatter_signature['anomaly_indicators'].append('High destination diversity (potential scanning)')
        
        if baseline.get('packets_per_second', 0) > 100:
            chatter_signature['anomaly_indicators'].append('Very high packet rate')
        
        return chatter_signature
    
    def fingerprint_all_devices(self, baselines: Dict) -> Dict:
        """Create fingerprints for all devices."""
        fingerprints = {}
        
        for device_ip, baseline in baselines.items():
            fingerprints[device_ip] = self.create_fingerprint(device_ip, baseline)
        
        return fingerprints

def main():
    if len(sys.argv) < 3:
        print("Usage: chatter_fingerprinter.py <baseline_file> <output_file>")
        sys.exit(1)
    
    baseline_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
            baselines = baseline_data.get('baselines', {})
    except Exception as e:
        print(f"[!] Error loading baseline data: {e}")
        sys.exit(1)
    
    print(f"[*] Fingerprinting {len(baselines)} devices...")
    
    fingerprinter = ChatterFingerprinter()
    fingerprints = fingerprinter.fingerprint_all_devices(baselines)
    
    # Calculate summary
    devices_with_anomalies = sum(1 for fp in fingerprints.values() if fp['anomaly_indicators'])
    device_types = defaultdict(int)
    for fp in fingerprints.values():
        device_type = fp['protocol_behavior'].get('likely_device_type', 'unknown')
        device_types[device_type] += 1
    
    output_data = {
        'total_devices': len(fingerprints),
        'devices_with_anomalies': devices_with_anomalies,
        'device_type_distribution': dict(device_types),
        'fingerprints': fingerprints,
        'analysis_timestamp': datetime.now().isoformat()
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Chatter fingerprinting complete.")
    print(f"[+] Fingerprinted {len(fingerprints)} devices")
    print(f"[+] Found {devices_with_anomalies} devices with anomaly indicators")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
