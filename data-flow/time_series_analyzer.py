#!/usr/bin/env python3
"""
Time Series Analyzer
Analyzes traffic patterns over time
"""

import sys
import json
from datetime import datetime
from typing import Dict, List

class TimeSeriesAnalyzer:
    def __init__(self):
        self.time_series_data = []
    
    def analyze_temporal_patterns(self, baseline: Dict, device_ip: str) -> Dict:
        """Analyze temporal patterns for a device."""
        first_seen = baseline.get('first_seen')
        last_seen = baseline.get('last_seen')
        
        analysis = {
            'device_ip': device_ip,
            'activity_window': {},
            'patterns': []
        }
        
        if first_seen and last_seen:
            first_dt = datetime.fromisoformat(first_seen)
            last_dt = datetime.fromisoformat(last_seen)
            
            analysis['activity_window'] = {
                'start': first_seen,
                'end': last_seen,
                'duration_seconds': (last_dt - first_dt).total_seconds()
            }
            
            # Detect unusual time patterns
            start_hour = first_dt.hour
            end_hour = last_dt.hour
            
            if 2 <= start_hour <= 5 or 2 <= end_hour <= 5:
                analysis['patterns'].append({
                    'type': 'UNUSUAL_HOURS',
                    'description': 'Activity during 2-5 AM window',
                    'severity': 'MEDIUM'
                })
            
            # Check for continuous activity
            pps = baseline.get('packets_per_second', 0)
            if pps > 0:
                total_packets = baseline.get('total_packets', 0)
                duration = analysis['activity_window']['duration_seconds']
                
                if duration > 0:
                    utilization = (total_packets / pps) / duration
                    
                    if utilization > 0.8:
                        analysis['patterns'].append({
                            'type': 'CONTINUOUS_ACTIVITY',
                            'description': f'High activity utilization ({utilization:.1%})',
                            'severity': 'LOW'
                        })
        
        return analysis
    
    def analyze_all_devices(self, baselines: Dict) -> List[Dict]:
        """Analyze temporal patterns for all devices."""
        analyses = []
        
        for device_ip, baseline in baselines.items():
            analysis = self.analyze_temporal_patterns(baseline, device_ip)
            if analysis['patterns']:
                analyses.append(analysis)
        
        return analyses

def main():
    if len(sys.argv) < 3:
        print("Usage: time_series_analyzer.py <baseline_file> <output_file>")
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
    
    print(f"[*] Analyzing temporal patterns for {len(baselines)} devices...")
    
    analyzer = TimeSeriesAnalyzer()
    analyses = analyzer.analyze_all_devices(baselines)
    
    output_data = {
        'total_devices_analyzed': len(baselines),
        'devices_with_patterns': len(analyses),
        'temporal_analyses': analyses,
        'analysis_timestamp': datetime.now().isoformat()
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Time series analysis complete.")
    print(f"[+] Found patterns in {len(analyses)} devices")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
