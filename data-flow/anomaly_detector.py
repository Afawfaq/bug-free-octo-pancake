#!/usr/bin/env python3
"""
Anomaly Detector
Detects deviations from baseline behavior patterns
"""

import sys
import json
from datetime import datetime
from typing import Dict, List, Tuple

class AnomalyDetector:
    def __init__(self, baseline_data: Dict):
        self.baselines = baseline_data.get('baselines', {})
        self.anomalies = []
    
    def detect_new_destinations(self, current_fingerprint: Dict, device_ip: str) -> List[Dict]:
        """Detect communication with new, unexpected destinations."""
        anomalies = []
        
        baseline = self.baselines.get(device_ip)
        if not baseline:
            return anomalies
        
        baseline_destinations = set(baseline.get('top_destinations', {}).keys())
        current_destinations = set(current_fingerprint.get('destination_patterns', {}).get('primary_destinations', []))
        
        new_destinations = current_destinations - baseline_destinations
        
        if new_destinations:
            anomalies.append({
                'type': 'NEW_DESTINATION',
                'severity': 'MEDIUM',
                'device_ip': device_ip,
                'description': f'Device communicating with {len(new_destinations)} new destination(s)',
                'details': {
                    'new_destinations': list(new_destinations),
                    'baseline_destinations': list(baseline_destinations)
                }
            })
        
        return anomalies
    
    def detect_traffic_volume_anomaly(self, current_fingerprint: Dict, device_ip: str) -> List[Dict]:
        """Detect unusual traffic volume."""
        anomalies = []
        
        baseline = self.baselines.get(device_ip)
        if not baseline:
            return anomalies
        
        baseline_pps = baseline.get('packets_per_second', 0)
        current_pps = current_fingerprint.get('traffic_characteristics', {}).get('packets_per_second', 0)
        
        # Check for significant increase (>3x baseline)
        if baseline_pps > 0 and current_pps > baseline_pps * 3:
            anomalies.append({
                'type': 'TRAFFIC_SPIKE',
                'severity': 'HIGH',
                'device_ip': device_ip,
                'description': f'Traffic volume increased by {(current_pps/baseline_pps):.1f}x',
                'details': {
                    'baseline_pps': baseline_pps,
                    'current_pps': current_pps,
                    'increase_factor': current_pps / baseline_pps
                }
            })
        
        # Check for unusual silence (>80% decrease)
        if baseline_pps > 0 and current_pps < baseline_pps * 0.2:
            anomalies.append({
                'type': 'TRAFFIC_DROP',
                'severity': 'MEDIUM',
                'device_ip': device_ip,
                'description': f'Traffic volume decreased by {(1 - current_pps/baseline_pps)*100:.0f}%',
                'details': {
                    'baseline_pps': baseline_pps,
                    'current_pps': current_pps
                }
            })
        
        return anomalies
    
    def detect_protocol_shift(self, current_fingerprint: Dict, device_ip: str) -> List[Dict]:
        """Detect change in protocol usage patterns."""
        anomalies = []
        
        baseline = self.baselines.get(device_ip)
        if not baseline:
            return anomalies
        
        baseline_protocol = max(baseline.get('protocol_mix', {}).items(), 
                               key=lambda x: x[1])[0] if baseline.get('protocol_mix') else None
        current_protocol = current_fingerprint.get('protocol_behavior', {}).get('primary_protocol')
        
        if baseline_protocol and current_protocol and baseline_protocol != current_protocol:
            anomalies.append({
                'type': 'PROTOCOL_SHIFT',
                'severity': 'MEDIUM',
                'device_ip': device_ip,
                'description': f'Primary protocol changed from {baseline_protocol} to {current_protocol}',
                'details': {
                    'baseline_protocol': baseline_protocol,
                    'current_protocol': current_protocol
                }
            })
        
        return anomalies
    
    def detect_time_anomalies(self, current_fingerprint: Dict, device_ip: str) -> List[Dict]:
        """Detect unusual activity times."""
        anomalies = []
        
        time_patterns = current_fingerprint.get('time_patterns', {})
        
        if time_patterns.get('3am_activity'):
            anomalies.append({
                'type': 'UNUSUAL_HOURS',
                'severity': 'MEDIUM',
                'device_ip': device_ip,
                'description': 'Device active during unusual hours (2-5 AM)',
                'details': time_patterns
            })
        
        if time_patterns.get('activity_type') == 'high_frequency':
            anomalies.append({
                'type': 'HIGH_FREQUENCY',
                'severity': 'LOW',
                'device_ip': device_ip,
                'description': 'Very high frequency communication detected',
                'details': time_patterns
            })
        
        return anomalies
    
    def detect_data_exfiltration_patterns(self, current_fingerprint: Dict, device_ip: str) -> List[Dict]:
        """Detect patterns indicative of data exfiltration."""
        anomalies = []
        
        traffic_chars = current_fingerprint.get('traffic_characteristics', {})
        traffic_ratio = traffic_chars.get('traffic_ratio', 1)
        bytes_sent = traffic_chars.get('bytes_sent', 0)
        
        # High outbound traffic ratio
        if traffic_ratio > 10 and bytes_sent > 1000000:  # More than 1MB sent
            anomalies.append({
                'type': 'POSSIBLE_EXFILTRATION',
                'severity': 'HIGH',
                'device_ip': device_ip,
                'description': f'High outbound traffic ratio ({traffic_ratio:.1f}:1) with large volume',
                'details': {
                    'traffic_ratio': traffic_ratio,
                    'bytes_sent': bytes_sent,
                    'bytes_received': traffic_chars.get('bytes_received', 0)
                }
            })
        
        return anomalies
    
    def detect_beaconing_pattern(self, current_fingerprint: Dict, device_ip: str) -> List[Dict]:
        """Detect potential beaconing behavior (C2 communication)."""
        anomalies = []
        
        # Check for periodic, low-volume traffic to single destination
        dest_patterns = current_fingerprint.get('destination_patterns', {})
        traffic_chars = current_fingerprint.get('traffic_characteristics', {})
        
        if (dest_patterns.get('communication_style') == 'focused' and 
            traffic_chars.get('packets_per_second', 0) < 1 and
            traffic_chars.get('avg_packet_size', 0) < 200):
            
            anomalies.append({
                'type': 'POSSIBLE_BEACONING',
                'severity': 'CRITICAL',
                'device_ip': device_ip,
                'description': 'Potential C2 beaconing pattern detected',
                'details': {
                    'pattern': 'Low-volume periodic traffic to single destination',
                    'destination_patterns': dest_patterns,
                    'traffic_characteristics': traffic_chars
                }
            })
        
        return anomalies
    
    def analyze_device(self, device_ip: str, current_fingerprint: Dict) -> List[Dict]:
        """Run all anomaly detection checks on a device."""
        all_anomalies = []
        
        # Run all detection methods
        all_anomalies.extend(self.detect_new_destinations(current_fingerprint, device_ip))
        all_anomalies.extend(self.detect_traffic_volume_anomaly(current_fingerprint, device_ip))
        all_anomalies.extend(self.detect_protocol_shift(current_fingerprint, device_ip))
        all_anomalies.extend(self.detect_time_anomalies(current_fingerprint, device_ip))
        all_anomalies.extend(self.detect_data_exfiltration_patterns(current_fingerprint, device_ip))
        all_anomalies.extend(self.detect_beaconing_pattern(current_fingerprint, device_ip))
        
        return all_anomalies
    
    def analyze_all_devices(self, fingerprints: Dict) -> List[Dict]:
        """Analyze all devices for anomalies."""
        all_anomalies = []
        
        for device_ip, fingerprint in fingerprints.items():
            device_anomalies = self.analyze_device(device_ip, fingerprint)
            all_anomalies.extend(device_anomalies)
        
        return all_anomalies

def main():
    if len(sys.argv) < 4:
        print("Usage: anomaly_detector.py <baseline_file> <fingerprints_file> <output_file>")
        sys.exit(1)
    
    baseline_file = sys.argv[1]
    fingerprints_file = sys.argv[2]
    output_file = sys.argv[3]
    
    # Load baseline and fingerprints
    try:
        with open(baseline_file, 'r') as f:
            baseline_data = json.load(f)
        
        with open(fingerprints_file, 'r') as f:
            fingerprint_data = json.load(f)
            fingerprints = fingerprint_data.get('fingerprints', {})
    except Exception as e:
        print(f"[!] Error loading data: {e}")
        sys.exit(1)
    
    print(f"[*] Analyzing {len(fingerprints)} devices for anomalies...")
    
    detector = AnomalyDetector(baseline_data)
    anomalies = detector.analyze_all_devices(fingerprints)
    
    # Categorize by severity
    severity_counts = {
        'CRITICAL': sum(1 for a in anomalies if a['severity'] == 'CRITICAL'),
        'HIGH': sum(1 for a in anomalies if a['severity'] == 'HIGH'),
        'MEDIUM': sum(1 for a in anomalies if a['severity'] == 'MEDIUM'),
        'LOW': sum(1 for a in anomalies if a['severity'] == 'LOW')
    }
    
    # Group by device
    devices_with_anomalies = set(a['device_ip'] for a in anomalies)
    
    # Save results
    output_data = {
        'total_anomalies': len(anomalies),
        'devices_with_anomalies': len(devices_with_anomalies),
        'severity_breakdown': severity_counts,
        'anomalies': sorted(anomalies, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}[x['severity']]),
        'analysis_timestamp': datetime.now().isoformat(),
        'recommendations': [
            'Investigate all CRITICAL anomalies immediately',
            'Review HIGH severity anomalies within 24 hours',
            'Monitor devices with beaconing patterns for C2 activity',
            'Check new destinations against threat intelligence feeds',
            'Correlate traffic spikes with legitimate business activities'
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Anomaly detection complete.")
    print(f"[+] Found {len(anomalies)} anomalies across {len(devices_with_anomalies)} devices")
    print(f"[+] Severity breakdown: {severity_counts}")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
