#!/usr/bin/env python3
"""
Audit Log Analyzer - Foundational IDS Concepts
Implements concepts from pioneering intrusion detection research:
- James Anderson's "Computer Security Threat Monitoring and Surveillance" (1980)
- Dorothy Denning's "An Intrusion-Detection Model" (1987)
- SRI International's IDES (Intrusion Detection Expert System, 1985)

Features:
- Statistical anomaly detection based on historical baselines
- Rule-based detection for known attack patterns
- Behavioral profile analysis
- Audit trail correlation
"""

import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import os


class AuditLogAnalyzer:
    """
    Implements foundational intrusion detection concepts from the 1980s.
    Based on Anderson's threat monitoring and Denning's intrusion detection model.
    """
    
    def __init__(self, output_dir: str = '/output/continuous-monitor'):
        self.output_dir = output_dir
        self.baselines = defaultdict(lambda: defaultdict(int))
        self.anomalies = []
        self.profiles = {}
        
        # Denning's intrusion detection model components
        self.subjects = set()  # Users, processes
        self.objects = set()   # Files, resources
        self.audit_records = []
        
        # Rule-based signatures (IDES concept)
        self.attack_rules = {
            'failed_login_sequence': {
                'pattern': r'failed.*login',
                'threshold': 5,
                'time_window': 300,  # 5 minutes
                'severity': 'HIGH',
                'description': 'Multiple failed login attempts'
            },
            'privilege_escalation': {
                'pattern': r'(sudo|su|admin|root)',
                'threshold': 3,
                'time_window': 60,
                'severity': 'CRITICAL',
                'description': 'Unusual privilege escalation attempts'
            },
            'suspicious_file_access': {
                'pattern': r'(passwd|shadow|private|key|certificate)',
                'threshold': 10,
                'time_window': 600,
                'severity': 'HIGH',
                'description': 'Excessive access to sensitive files'
            },
            'unusual_time_activity': {
                'hours': [0, 1, 2, 3, 4, 5],  # Midnight to 6 AM
                'threshold': 10,
                'severity': 'MEDIUM',
                'description': 'Unusual activity during off-hours'
            }
        }
    
    def build_baseline(self, historical_logs: List[Dict]):
        """
        Build statistical baseline from historical audit logs.
        Implements Anderson's "normal activity" profiling concept.
        """
        print(f"[Audit Analyzer] Building baseline from {len(historical_logs)} records...")
        
        for log in historical_logs:
            subject = log.get('user', 'unknown')
            action = log.get('action', 'unknown')
            obj = log.get('object', 'unknown')
            timestamp = log.get('timestamp', '')
            
            # Track subjects and objects (Denning's model)
            self.subjects.add(subject)
            self.objects.add(obj)
            
            # Build statistical profile
            self.baselines[subject]['total_actions'] += 1
            self.baselines[subject][f'action_{action}'] += 1
            self.baselines[subject][f'object_{obj}'] += 1
            
            # Track time-of-day patterns
            try:
                ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = ts.hour
                self.baselines[subject][f'hour_{hour}'] += 1
            except:
                pass
        
        print(f"[Audit Analyzer] Baseline built:")
        print(f"  Tracked subjects: {len(self.subjects)}")
        print(f"  Tracked objects: {len(self.objects)}")
        print(f"  Profiles created: {len(self.baselines)}")
    
    def calculate_anomaly_score(self, log: Dict) -> Tuple[float, List[str]]:
        """
        Calculate anomaly score using statistical deviation.
        Based on IDES statistical anomaly detection approach.
        """
        score = 0.0
        reasons = []
        
        subject = log.get('user', 'unknown')
        action = log.get('action', 'unknown')
        obj = log.get('object', 'unknown')
        timestamp = log.get('timestamp', '')
        
        # Check if subject is in baseline
        if subject not in self.baselines:
            score += 0.5
            reasons.append(f"Unknown subject: {subject}")
        else:
            profile = self.baselines[subject]
            total_actions = profile['total_actions']
            
            # Check action frequency
            action_count = profile.get(f'action_{action}', 0)
            action_freq = action_count / total_actions if total_actions > 0 else 0
            
            if action_freq < 0.01:  # Rare action (< 1%)
                score += 0.3
                reasons.append(f"Rare action for {subject}: {action}")
            
            # Check object access frequency
            object_count = profile.get(f'object_{obj}', 0)
            object_freq = object_count / total_actions if total_actions > 0 else 0
            
            if object_freq < 0.01:  # Rare object access
                score += 0.3
                reasons.append(f"Rare object access: {obj}")
            
            # Check time-of-day anomaly
            try:
                ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = ts.hour
                hour_count = profile.get(f'hour_{hour}', 0)
                hour_freq = hour_count / total_actions if total_actions > 0 else 0
                
                if hour_freq < 0.05:  # Unusual time (< 5%)
                    score += 0.2
                    reasons.append(f"Unusual time of activity: {hour}:00")
            except:
                pass
        
        return min(score, 1.0), reasons
    
    def apply_rule_based_detection(self, logs: List[Dict]) -> List[Dict]:
        """
        Apply rule-based detection for known attack patterns.
        Implements expert system approach from IDES.
        """
        detections = []
        
        # Group logs by time window for pattern matching
        for rule_name, rule in self.attack_rules.items():
            if rule_name == 'unusual_time_activity':
                # Check for off-hours activity
                off_hours_count = 0
                for log in logs:
                    try:
                        ts = datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00'))
                        if ts.hour in rule['hours']:
                            off_hours_count += 1
                    except:
                        pass
                
                if off_hours_count > rule['threshold']:
                    detections.append({
                        'rule': rule_name,
                        'severity': rule['severity'],
                        'description': rule['description'],
                        'event_count': off_hours_count,
                        'threshold': rule['threshold'],
                        'historical_context': 'Off-hours activity identified in Anderson 1980 as anomaly indicator'
                    })
            else:
                # Pattern-based detection
                pattern = rule.get('pattern', '')
                matches = []
                
                for log in logs:
                    log_str = json.dumps(log).lower()
                    if re.search(pattern, log_str, re.IGNORECASE):
                        matches.append(log)
                
                if len(matches) > rule['threshold']:
                    detections.append({
                        'rule': rule_name,
                        'severity': rule['severity'],
                        'description': rule['description'],
                        'matches': len(matches),
                        'threshold': rule['threshold'],
                        'time_window': rule['time_window'],
                        'sample_logs': matches[:3],  # Include sample logs
                        'historical_context': 'Rule-based detection from IDES expert system (1985)'
                    })
        
        return detections
    
    def analyze_log(self, log: Dict) -> Optional[Dict]:
        """
        Analyze a single audit log entry.
        Returns anomaly if detected.
        """
        score, reasons = self.calculate_anomaly_score(log)
        
        # Threshold for anomaly (configurable)
        if score >= 0.5:
            anomaly = {
                'timestamp': log.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
                'log_entry': log,
                'anomaly_score': round(score, 3),
                'reasons': reasons,
                'severity': self._classify_severity(score),
                'detection_method': 'Statistical Anomaly Detection (Denning 1987)',
                'recommended_actions': self._get_recommendations(reasons)
            }
            self.anomalies.append(anomaly)
            return anomaly
        
        # Update baseline with normal behavior
        subject = log.get('user', 'unknown')
        action = log.get('action', 'unknown')
        obj = log.get('object', 'unknown')
        
        self.baselines[subject]['total_actions'] += 1
        self.baselines[subject][f'action_{action}'] += 1
        self.baselines[subject][f'object_{obj}'] += 1
        
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
            if 'unknown subject' in reason.lower():
                recommendations.append("Investigate unauthorized user account")
                recommendations.append("Review account creation logs")
            if 'rare action' in reason.lower():
                recommendations.append("Verify legitimacy of unusual action")
                recommendations.append("Check for privilege abuse")
            if 'unusual time' in reason.lower():
                recommendations.append("Investigate off-hours activity")
                recommendations.append("Verify user location and context")
            if 'sensitive' in reason.lower() or 'privilege' in reason.lower():
                recommendations.append("Immediate security review required")
                recommendations.append("Consider temporary access restriction")
        
        return list(set(recommendations))  # Remove duplicates
    
    def generate_report(self) -> Dict:
        """Generate comprehensive intrusion detection report."""
        report = {
            'analysis_timestamp': datetime.utcnow().isoformat() + 'Z',
            'analyzer': 'Audit Log Intrusion Detection System',
            'foundational_research': [
                'James Anderson - Computer Security Threat Monitoring (1980)',
                'Dorothy Denning - An Intrusion-Detection Model (1987)',
                'SRI International - IDES (1985)'
            ],
            'methodology': {
                'statistical_profiling': 'Anderson baseline approach',
                'behavioral_analysis': 'Denning intrusion detection model',
                'rule_based_detection': 'IDES expert system approach'
            },
            'statistics': {
                'total_subjects': len(self.subjects),
                'total_objects': len(self.objects),
                'baseline_profiles': len(self.baselines),
                'anomalies_detected': len(self.anomalies)
            },
            'anomalies': self.anomalies,
            'baseline_summary': {
                subject: {
                    'total_actions': profile['total_actions'],
                    'unique_actions': len([k for k in profile.keys() if k.startswith('action_')]),
                    'unique_objects': len([k for k in profile.keys() if k.startswith('object_')])
                }
                for subject, profile in list(self.baselines.items())[:10]  # Top 10
            }
        }
        
        return report
    
    def save_report(self):
        """Save intrusion detection report."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        report = self.generate_report()
        output_file = f"{self.output_dir}/audit_log_ids_report.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n[Audit Analyzer] Report saved to {output_file}")
        print(f"[Audit Analyzer] Anomalies detected: {len(self.anomalies)}")
        
        if self.anomalies:
            print("\n[Audit Analyzer] Anomaly Summary:")
            severity_count = defaultdict(int)
            for anomaly in self.anomalies:
                severity_count[anomaly['severity']] += 1
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = severity_count.get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")


def main():
    """Example usage."""
    analyzer = AuditLogAnalyzer()
    
    # Build baseline from historical logs
    historical_logs = [
        {'user': 'alice', 'action': 'read', 'object': '/home/alice/doc.txt', 'timestamp': '2025-12-09T14:30:00Z'},
        {'user': 'alice', 'action': 'write', 'object': '/home/alice/doc.txt', 'timestamp': '2025-12-09T14:35:00Z'},
        {'user': 'bob', 'action': 'read', 'object': '/var/log/system.log', 'timestamp': '2025-12-09T15:00:00Z'},
        {'user': 'alice', 'action': 'read', 'object': '/home/alice/notes.txt', 'timestamp': '2025-12-09T15:30:00Z'},
    ] * 25  # Repeat for baseline
    
    analyzer.build_baseline(historical_logs)
    
    # Analyze new logs for anomalies
    test_logs = [
        {'user': 'charlie', 'action': 'read', 'object': '/etc/shadow', 'timestamp': '2025-12-09T02:00:00Z'},  # Unknown user, sensitive file, off-hours
        {'user': 'alice', 'action': 'execute', 'object': '/usr/bin/sudo', 'timestamp': '2025-12-09T16:00:00Z'},  # Unusual action
    ]
    
    print("\n[Audit Analyzer] Analyzing test logs...")
    for log in test_logs:
        anomaly = analyzer.analyze_log(log)
        if anomaly:
            print(f"\n[ANOMALY] Score: {anomaly['anomaly_score']}")
            print(f"  Severity: {anomaly['severity']}")
            print(f"  Reasons: {', '.join(anomaly['reasons'])}")
    
    # Test rule-based detection
    failed_login_logs = [
        {'user': 'admin', 'action': 'failed login', 'timestamp': f'2025-12-09T16:{i:02d}:00Z'}
        for i in range(10)
    ]
    
    print("\n[Audit Analyzer] Testing rule-based detection...")
    detections = analyzer.apply_rule_based_detection(failed_login_logs)
    for detection in detections:
        print(f"\n[DETECTION] Rule: {detection['rule']}")
        print(f"  Severity: {detection['severity']}")
        print(f"  Description: {detection['description']}")
    
    analyzer.save_report()


if __name__ == '__main__':
    main()
