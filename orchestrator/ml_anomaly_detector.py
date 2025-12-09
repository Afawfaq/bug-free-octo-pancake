#!/usr/bin/env python3
"""
ML-Based Anomaly Detection Module
Implements behavioral analysis and anomaly detection based on research papers:
- Machine Learning and Deep Learning Models for Anomaly Intrusion Detection (2025)
- Behavioral Analysis of Network Traffic for Anomaly Detection Using AI (2024)
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import os


class NetworkBehaviorProfile:
    """Profile of normal network behavior for baseline comparison."""
    
    def __init__(self):
        self.port_frequencies = defaultdict(int)
        self.protocol_frequencies = defaultdict(int)
        self.connection_patterns = defaultdict(list)
        self.temporal_patterns = defaultdict(int)
        self.service_patterns = defaultdict(set)
        self.total_observations = 0
        
    def update(self, observation: Dict):
        """Update profile with new observation."""
        self.total_observations += 1
        
        # Track port usage
        if 'port' in observation:
            self.port_frequencies[observation['port']] += 1
            
        # Track protocols
        if 'protocol' in observation:
            self.protocol_frequencies[observation['protocol']] += 1
            
        # Track temporal patterns (hour of day)
        if 'timestamp' in observation:
            try:
                ts = datetime.fromisoformat(observation['timestamp'].replace('Z', '+00:00'))
                hour = ts.hour
                self.temporal_patterns[hour] += 1
            except:
                pass
                
        # Track connection patterns
        if 'source_ip' in observation and 'dest_ip' in observation:
            pattern = f"{observation['source_ip']}->{observation['dest_ip']}"
            self.connection_patterns[pattern].append(observation.get('timestamp'))
            
        # Track service patterns
        if 'service' in observation and 'ip' in observation:
            self.service_patterns[observation['ip']].add(observation['service'])
    
    def get_port_probability(self, port: int) -> float:
        """Get probability of seeing a specific port."""
        if self.total_observations == 0:
            return 0.0
        return self.port_frequencies.get(port, 0) / self.total_observations
    
    def get_protocol_probability(self, protocol: str) -> float:
        """Get probability of seeing a specific protocol."""
        if self.total_observations == 0:
            return 0.0
        return self.protocol_frequencies.get(protocol, 0) / self.total_observations


class AnomalyDetector:
    """
    ML-based anomaly detection using statistical methods and behavioral analysis.
    Implements concepts from recent research on network intrusion detection.
    """
    
    def __init__(self, sensitivity: float = 0.7):
        self.sensitivity = sensitivity  # 0.0 (low) to 1.0 (high)
        self.baseline_profile = NetworkBehaviorProfile()
        self.anomalies = []
        self.thresholds = {
            'port_rarity': 0.001,  # Ports seen < 0.1% of time
            'connection_rate': 10,  # Max connections per minute
            'service_diversity': 5,  # Max unique services per host
            'temporal_deviation': 0.1,  # Unusual time of day activity
        }
        
    def train_baseline(self, historical_data: List[Dict]):
        """Train baseline profile from historical network data."""
        print(f"[ML] Training baseline profile with {len(historical_data)} observations...")
        
        for observation in historical_data:
            self.baseline_profile.update(observation)
            
        print(f"[ML] Baseline trained: {self.baseline_profile.total_observations} observations")
        print(f"[ML] Tracked {len(self.baseline_profile.port_frequencies)} unique ports")
        print(f"[ML] Tracked {len(self.baseline_profile.protocol_frequencies)} protocols")
    
    def calculate_anomaly_score(self, observation: Dict) -> Tuple[float, List[str]]:
        """
        Calculate anomaly score for an observation.
        Returns (score, list of reasons).
        Score: 0.0 (normal) to 1.0 (highly anomalous)
        """
        score = 0.0
        reasons = []
        
        # Check port rarity
        if 'port' in observation:
            port_prob = self.baseline_profile.get_port_probability(observation['port'])
            if port_prob < self.thresholds['port_rarity'] and port_prob > 0:
                score += 0.3
                reasons.append(f"Rare port: {observation['port']} (seen {port_prob:.1%} of time)")
            elif port_prob == 0:
                score += 0.5
                reasons.append(f"Unknown port: {observation['port']} (never seen in baseline)")
        
        # Check protocol anomaly
        if 'protocol' in observation:
            proto_prob = self.baseline_profile.get_protocol_probability(observation['protocol'])
            if proto_prob < self.thresholds['port_rarity'] and proto_prob > 0:
                score += 0.2
                reasons.append(f"Unusual protocol: {observation['protocol']}")
            elif proto_prob == 0:
                score += 0.4
                reasons.append(f"Unknown protocol: {observation['protocol']}")
        
        # Check connection rate anomalies
        if 'source_ip' in observation:
            ip = observation['source_ip']
            recent_connections = len([
                t for pattern, times in self.baseline_profile.connection_patterns.items()
                if ip in pattern and times
            ])
            if recent_connections > self.thresholds['connection_rate']:
                score += 0.3
                reasons.append(f"High connection rate from {ip}: {recent_connections} connections")
        
        # Check service diversity
        if 'ip' in observation and 'service' in observation:
            ip = observation['ip']
            services = self.baseline_profile.service_patterns.get(ip, set())
            if len(services) > self.thresholds['service_diversity']:
                score += 0.2
                reasons.append(f"High service diversity on {ip}: {len(services)} services")
        
        # Normalize score
        score = min(score, 1.0)
        
        # Apply sensitivity adjustment
        score = score * (0.5 + self.sensitivity * 0.5)
        
        return score, reasons
    
    def detect_anomaly(self, observation: Dict) -> Optional[Dict]:
        """
        Detect if observation is anomalous.
        Returns anomaly dict if detected, None otherwise.
        """
        score, reasons = self.calculate_anomaly_score(observation)
        
        # Threshold varies with sensitivity
        threshold = 0.5 * (2.0 - self.sensitivity)
        
        if score >= threshold:
            anomaly = {
                'timestamp': observation.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
                'observation': observation,
                'anomaly_score': round(score, 3),
                'reasons': reasons,
                'severity': self._classify_severity(score),
                'recommended_actions': self._get_recommendations(reasons)
            }
            self.anomalies.append(anomaly)
            return anomaly
        
        # Update baseline with normal observations
        self.baseline_profile.update(observation)
        return None
    
    def _classify_severity(self, score: float) -> str:
        """Classify anomaly severity based on score."""
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_recommendations(self, reasons: List[str]) -> List[str]:
        """Get recommended actions based on anomaly reasons."""
        recommendations = []
        
        for reason in reasons:
            if 'port' in reason.lower():
                recommendations.append("Investigate unusual port activity")
                recommendations.append("Check for port scanning attempts")
            if 'protocol' in reason.lower():
                recommendations.append("Verify legitimate protocol usage")
            if 'connection rate' in reason.lower():
                recommendations.append("Check for DoS/DDoS attempts")
                recommendations.append("Review firewall rules")
            if 'service diversity' in reason.lower():
                recommendations.append("Investigate potential lateral movement")
                recommendations.append("Check for unauthorized service installations")
        
        return list(set(recommendations))  # Remove duplicates
    
    def get_anomaly_report(self) -> Dict:
        """Generate comprehensive anomaly report."""
        report = {
            'detection_summary': {
                'total_anomalies': len(self.anomalies),
                'by_severity': defaultdict(int),
                'detection_timestamp': datetime.utcnow().isoformat() + 'Z'
            },
            'anomalies': self.anomalies,
            'baseline_stats': {
                'total_observations': self.baseline_profile.total_observations,
                'unique_ports': len(self.baseline_profile.port_frequencies),
                'unique_protocols': len(self.baseline_profile.protocol_frequencies),
                'tracked_hosts': len(self.baseline_profile.service_patterns)
            }
        }
        
        # Count by severity
        for anomaly in self.anomalies:
            severity = anomaly.get('severity', 'UNKNOWN')
            report['detection_summary']['by_severity'][severity] += 1
        
        return report
    
    def save_report(self, output_dir: str = '/output'):
        """Save anomaly detection report to file."""
        os.makedirs(f"{output_dir}/ml-detection", exist_ok=True)
        
        report = self.get_anomaly_report()
        output_file = f"{output_dir}/ml-detection/anomaly_report.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"[ML] Anomaly report saved to {output_file}")
        print(f"[ML] Detected {len(self.anomalies)} anomalies")
        
        if self.anomalies:
            print("\n[ML] Anomaly Summary:")
            severities = report['detection_summary']['by_severity']
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = severities.get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")


def main():
    """Example usage and testing."""
    detector = AnomalyDetector(sensitivity=0.7)
    
    # Example: Train on historical data
    historical_data = [
        {'port': 80, 'protocol': 'HTTP', 'ip': '192.168.1.10', 'service': 'web'},
        {'port': 443, 'protocol': 'HTTPS', 'ip': '192.168.1.10', 'service': 'web'},
        {'port': 22, 'protocol': 'SSH', 'ip': '192.168.1.20', 'service': 'ssh'},
        {'port': 80, 'protocol': 'HTTP', 'ip': '192.168.1.30', 'service': 'web'},
    ]
    
    detector.train_baseline(historical_data)
    
    # Example: Detect anomalies
    test_observations = [
        {'port': 8080, 'protocol': 'HTTP', 'ip': '192.168.1.40', 'service': 'unknown'},
        {'port': 31337, 'protocol': 'TCP', 'ip': '192.168.1.50', 'service': 'backdoor'},
    ]
    
    for obs in test_observations:
        anomaly = detector.detect_anomaly(obs)
        if anomaly:
            print(f"\n[ANOMALY DETECTED] Score: {anomaly['anomaly_score']}")
            print(f"Severity: {anomaly['severity']}")
            print(f"Reasons: {', '.join(anomaly['reasons'])}")
    
    detector.save_report()


if __name__ == '__main__':
    main()
