#!/usr/bin/env python3
"""
Centralized Alert Management System
Aggregates and correlates alerts from all honeypots.
"""

import json
import os
import sys
from datetime import datetime
from collections import defaultdict

class AlertSystem:
    """Manages alerts from all honeypots"""
    
    def __init__(self, output_dir="/output/deception"):
        self.output_dir = output_dir
        self.all_alerts = []
        self.by_severity = defaultdict(list)
        self.by_source = defaultdict(list)
        self.patterns = []
        
    def load_honeypot_data(self, honeypot_name):
        """Load alerts from a honeypot JSON file"""
        filepath = os.path.join(self.output_dir, f"{honeypot_name}_honeypot.json")
        
        if not os.path.exists(filepath):
            print(f"[Alert] No data file for {honeypot_name}")
            return []
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                return data.get('alerts', [])
        except Exception as e:
            print(f"[Alert] Error loading {honeypot_name}: {e}")
            return []
    
    def aggregate_alerts(self):
        """Aggregate alerts from all honeypots"""
        honeypots = ['smb', 'ipp', 'chromecast', 'ssdp']
        
        for honeypot in honeypots:
            alerts = self.load_honeypot_data(honeypot)
            self.all_alerts.extend(alerts)
        
        # Group by severity
        for alert in self.all_alerts:
            severity = alert.get('severity', 'UNKNOWN')
            self.by_severity[severity].append(alert)
            
            # Group by source IP
            source_ip = alert.get('source_ip', 'unknown')
            self.by_source[source_ip].append(alert)
        
        print(f"[Alert] Aggregated {len(self.all_alerts)} total alerts")
        print(f"[Alert] CRITICAL: {len(self.by_severity['CRITICAL'])}")
        print(f"[Alert] HIGH: {len(self.by_severity['HIGH'])}")
        print(f"[Alert] MEDIUM: {len(self.by_severity['MEDIUM'])}")
        print(f"[Alert] LOW: {len(self.by_severity['LOW'])}")
    
    def detect_patterns(self):
        """Detect attack patterns"""
        # Pattern 1: Coordinated attacks (same source, multiple honeypots)
        for source_ip, alerts in self.by_source.items():
            if source_ip == 'unknown':
                continue
                
            honeypots = set(alert.get('honeypot') for alert in alerts)
            if len(honeypots) > 2:
                pattern = {
                    'pattern_type': 'coordinated_lateral_movement',
                    'severity': 'CRITICAL',
                    'source_ip': source_ip,
                    'description': f"Source {source_ip} triggered {len(honeypots)} different honeypots",
                    'honeypots': list(honeypots),
                    'alert_count': len(alerts)
                }
                self.patterns.append(pattern)
                print(f"[Pattern] CRITICAL: Coordinated attack from {source_ip}")
        
        # Pattern 2: Rapid enumeration (many alerts in short time)
        for source_ip, alerts in self.by_source.items():
            if source_ip == 'unknown':
                continue
                
            if len(alerts) > 10:
                pattern = {
                    'pattern_type': 'rapid_enumeration',
                    'severity': 'HIGH',
                    'source_ip': source_ip,
                    'description': f"Rapid enumeration detected: {len(alerts)} events",
                    'alert_count': len(alerts)
                }
                self.patterns.append(pattern)
                print(f"[Pattern] HIGH: Rapid enumeration from {source_ip}")
        
        # Pattern 3: Credential testing (multiple authentication attempts)
        auth_sources = defaultdict(int)
        for alert in self.all_alerts:
            if 'authentication' in alert.get('alert_type', ''):
                source_ip = alert.get('source_ip')
                auth_sources[source_ip] += 1
        
        for source_ip, count in auth_sources.items():
            if count > 3:
                pattern = {
                    'pattern_type': 'credential_spraying',
                    'severity': 'HIGH',
                    'source_ip': source_ip,
                    'description': f"Multiple authentication attempts: {count}",
                    'attempt_count': count
                }
                self.patterns.append(pattern)
                print(f"[Pattern] HIGH: Credential testing from {source_ip}")
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        # Recommendation based on CRITICAL alerts
        if len(self.by_severity['CRITICAL']) > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Immediate Action',
                'description': 'Investigate and isolate sources with CRITICAL alerts immediately',
                'affected_sources': list(set(a.get('source_ip') for a in self.by_severity['CRITICAL'])),
                'action': 'Isolate hosts and conduct forensic analysis'
            })
        
        # Recommendation based on coordinated attacks
        coordinated = [p for p in self.patterns if p['pattern_type'] == 'coordinated_lateral_movement']
        if coordinated:
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Lateral Movement',
                'description': 'Coordinated lateral movement detected',
                'affected_sources': [p['source_ip'] for p in coordinated],
                'action': 'Enable network segmentation and monitor east-west traffic'
            })
        
        # Recommendation based on HIGH alerts
        if len(self.by_severity['HIGH']) > 5:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Authentication',
                'description': 'Multiple high-severity authentication attempts detected',
                'action': 'Review credential policies and enable MFA'
            })
        
        # General recommendation
        if len(self.all_alerts) > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Monitoring',
                'description': 'Honeypot activity indicates reconnaissance',
                'action': 'Deploy additional monitoring and logging'
            })
        
        return recommendations
    
    def save_results(self):
        """Save aggregated alert data"""
        recommendations = self.generate_recommendations()
        
        results = {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'all_alerts': self.all_alerts,
            'by_severity': dict(self.by_severity),
            'by_source': dict(self.by_source),
            'patterns': self.patterns,
            'recommendations': recommendations,
            'statistics': {
                'total_alerts': len(self.all_alerts),
                'unique_sources': len([k for k in self.by_source.keys() if k != 'unknown']),
                'critical_alerts': len(self.by_severity['CRITICAL']),
                'high_alerts': len(self.by_severity['HIGH']),
                'medium_alerts': len(self.by_severity['MEDIUM']),
                'low_alerts': len(self.by_severity['LOW']),
                'patterns_detected': len(self.patterns)
            }
        }
        
        output_file = os.path.join(self.output_dir, 'alerts.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[Alert] Aggregated results saved to {output_file}")
        
        # Generate summary report
        self.generate_summary(results)
    
    def generate_summary(self, results):
        """Generate human-readable summary"""
        summary = []
        summary.append("Deception & Honeypot Analysis Summary")
        summary.append(f"Generated: {results['generated_at']}")
        summary.append("")
        
        summary.append("=== Alert Statistics ===")
        stats = results['statistics']
        summary.append(f"Total Alerts: {stats['total_alerts']}")
        summary.append(f"Unique Sources: {stats['unique_sources']}")
        summary.append(f"CRITICAL: {stats['critical_alerts']}")
        summary.append(f"HIGH: {stats['high_alerts']}")
        summary.append(f"MEDIUM: {stats['medium_alerts']}")
        summary.append(f"LOW: {stats['low_alerts']}")
        summary.append("")
        
        if results['patterns']:
            summary.append("=== Detected Attack Patterns ===")
            for i, pattern in enumerate(results['patterns'], 1):
                summary.append(f"{i}. [{pattern['severity']}] {pattern['pattern_type']}")
                summary.append(f"   Source: {pattern['source_ip']}")
                summary.append(f"   {pattern['description']}")
                summary.append("")
        
        if results['recommendations']:
            summary.append("=== Security Recommendations ===")
            for i, rec in enumerate(results['recommendations'], 1):
                summary.append(f"{i}. [{rec['priority']}] {rec['category']}")
                summary.append(f"   {rec['description']}")
                summary.append(f"   Action: {rec['action']}")
                summary.append("")
        
        summary_text = '\n'.join(summary)
        summary_file = os.path.join(self.output_dir, 'deception_summary.txt')
        with open(summary_file, 'w') as f:
            f.write(summary_text)
        
        print(f"[Alert] Summary saved to {summary_file}")
        print("\n" + summary_text)

def main():
    """Main function"""
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/output/deception"
    
    alert_system = AlertSystem(output_dir)
    alert_system.aggregate_alerts()
    alert_system.detect_patterns()
    alert_system.save_results()

if __name__ == "__main__":
    main()
