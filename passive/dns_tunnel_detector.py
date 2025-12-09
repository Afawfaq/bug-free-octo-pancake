#!/usr/bin/env python3
"""
DNS Tunneling and Covert Channel Detector
Based on modern research (2020-2024):
- DNS tunneling detection using payload and traffic analysis
- Covert channel identification
- Deep packet inspection concepts
- Machine learning-based anomaly detection

Detection Methods:
- High entropy domain analysis
- Unusual query patterns and volumes
- Suspicious DNS record types (TXT, NULL, CNAME abuse)
- Query length anomalies
- Timing pattern analysis
- Subdomain randomness detection
"""

import json
import re
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, Counter
import os


class DNSTunnelDetector:
    """
    Detects DNS tunneling and covert channels.
    Implements modern detection techniques from CTI research.
    """
    
    def __init__(self, output_dir: str = '/output/passive'):
        self.output_dir = output_dir
        self.dns_queries = []
        self.domain_stats = defaultdict(lambda: defaultdict(int))
        self.detections = []
        
        # Detection thresholds based on research
        # References: Fidelis Security DNS Tunneling Detection, arXiv:2507.10267v1
        self.thresholds = {
            'query_length': 52,  # Suspicious if > 52 chars (typical legitimate max ~40 chars)
            'max_length': 200,   # Very suspicious if > 200 chars (approaching 255 char DNS limit)
            'entropy_threshold': 3.5,  # Shannon entropy (random English ~4.1, encoded data >3.5)
            'query_rate': 10,    # Queries per minute per domain
            'subdomain_count': 5,  # Unique subdomains per minute
            'txt_record_size': 100,  # Bytes in TXT record (typical legitimate <100 bytes)
        }
        
        # Suspicious record types often used for tunneling
        self.suspicious_types = {'TXT', 'NULL', 'CNAME', 'MX', 'AAAA', 'SRV'}
        
        # Known legitimate high-entropy domains (to reduce false positives)
        self.whitelist = {
            'google-analytics.com', 'doubleclick.net', 'googletagmanager.com',
            'cloudfront.net', 'amazonaws.com', 's3.amazonaws.com'
        }
    
    def calculate_shannon_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy to detect random/encoded data.
        High entropy indicates potential tunneling.
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        freq = Counter(data.lower())
        length = len(data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_domain_structure(self, domain: str) -> Dict:
        """
        Analyze domain structure for tunneling indicators.
        Returns analysis results.
        """
        analysis = {
            'domain': domain,
            'length': len(domain),
            'subdomain_count': domain.count('.'),
            'has_numbers': bool(re.search(r'\d', domain)),
            'has_hyphens': '-' in domain,
            'entropy': self.calculate_shannon_entropy(domain),
            'suspicious_patterns': []
        }
        
        # Check for base64-like patterns
        if re.search(r'[A-Za-z0-9+/=]{20,}', domain):
            analysis['suspicious_patterns'].append('base64-like')
        
        # Check for hex encoding
        if re.search(r'[0-9a-fA-F]{32,}', domain):
            analysis['suspicious_patterns'].append('hex-encoded')
        
        # Check for excessive subdomain depth
        if analysis['subdomain_count'] > 3:
            analysis['suspicious_patterns'].append('deep-subdomain')
        
        # Check for random-looking subdomains
        parts = domain.split('.')
        for part in parts[:-2]:  # Exclude TLD and root domain
            if len(part) > 15 and self.calculate_shannon_entropy(part) > 3.8:
                analysis['suspicious_patterns'].append('random-subdomain')
                break
        
        return analysis
    
    def detect_query_anomalies(self, query: Dict) -> List[Dict]:
        """
        Detect anomalies in a DNS query.
        Returns list of detected issues.
        """
        anomalies = []
        domain = query.get('domain', '')
        qtype = query.get('type', 'A')
        response_size = query.get('response_size', 0)
        
        # Check if domain is whitelisted
        if any(wl in domain for wl in self.whitelist):
            return anomalies
        
        # Analyze domain structure
        domain_analysis = self.analyze_domain_structure(domain)
        
        # Check 1: Excessive query length
        if domain_analysis['length'] > self.thresholds['query_length']:
            severity = 'HIGH' if domain_analysis['length'] > self.thresholds['max_length'] else 'MEDIUM'
            anomalies.append({
                'type': 'EXCESSIVE_QUERY_LENGTH',
                'severity': severity,
                'domain': domain,
                'length': domain_analysis['length'],
                'description': f"DNS query length ({domain_analysis['length']} chars) exceeds threshold",
                'technique': 'DNS tunneling often uses long queries to encode data',
                'remediation': ['Investigate domain owner', 'Block if confirmed malicious', 'Monitor for pattern']
            })
        
        # Check 2: High entropy (encoded/random data)
        if domain_analysis['entropy'] > self.thresholds['entropy_threshold']:
            anomalies.append({
                'type': 'HIGH_ENTROPY_DOMAIN',
                'severity': 'HIGH',
                'domain': domain,
                'entropy': round(domain_analysis['entropy'], 2),
                'description': f"High entropy ({domain_analysis['entropy']:.2f}) suggests encoded data",
                'technique': 'Attackers encode data in DNS queries to bypass detection',
                'remediation': ['Analyze query patterns', 'Check for C2 communication', 'Capture and decode samples']
            })
        
        # Check 3: Suspicious record types
        if qtype in self.suspicious_types:
            anomalies.append({
                'type': 'SUSPICIOUS_RECORD_TYPE',
                'severity': 'MEDIUM',
                'domain': domain,
                'record_type': qtype,
                'description': f"Query type {qtype} commonly used for tunneling",
                'technique': f'{qtype} records can carry larger payloads than standard A records',
                'remediation': ['Monitor all queries to this domain', 'Analyze response payloads']
            })
        
        # Check 4: Large TXT record responses
        if qtype == 'TXT' and response_size > self.thresholds['txt_record_size']:
            anomalies.append({
                'type': 'LARGE_TXT_RESPONSE',
                'severity': 'HIGH',
                'domain': domain,
                'size': response_size,
                'description': f"Large TXT response ({response_size} bytes) may contain exfiltrated data",
                'technique': 'TXT records used for data exfiltration in DNS tunneling',
                'remediation': ['Capture and analyze response content', 'Block domain', 'Alert SOC']
            })
        
        # Check 5: Suspicious patterns in domain
        if domain_analysis['suspicious_patterns']:
            anomalies.append({
                'type': 'SUSPICIOUS_DOMAIN_PATTERN',
                'severity': 'MEDIUM',
                'domain': domain,
                'patterns': domain_analysis['suspicious_patterns'],
                'description': f"Domain contains suspicious patterns: {', '.join(domain_analysis['suspicious_patterns'])}",
                'technique': 'Encoded data in subdomains indicates tunneling',
                'remediation': ['Decode and analyze subdomain content', 'Check query frequency']
            })
        
        return anomalies
    
    def analyze_traffic_patterns(self, queries: List[Dict], time_window: int = 60) -> List[Dict]:
        """
        Analyze DNS traffic patterns over time.
        Detects tunneling based on query frequency and timing.
        """
        pattern_anomalies = []
        domain_queries = defaultdict(list)
        
        # Group queries by domain
        for query in queries:
            domain = query.get('domain', '')
            timestamp = query.get('timestamp', '')
            domain_queries[domain].append(timestamp)
        
        # Analyze each domain
        for domain, timestamps in domain_queries.items():
            query_count = len(timestamps)
            
            # Check 1: High query rate
            if query_count > self.thresholds['query_rate'] * (time_window / 60):
                pattern_anomalies.append({
                    'type': 'HIGH_QUERY_RATE',
                    'severity': 'HIGH',
                    'domain': domain,
                    'query_count': query_count,
                    'time_window': time_window,
                    'queries_per_minute': query_count / (time_window / 60),
                    'description': f"Excessive query rate: {query_count} queries in {time_window}s",
                    'technique': 'Tunneling tools send frequent queries to maintain C2 channel',
                    'remediation': [
                        'Rate limit DNS queries to this domain',
                        'Investigate source hosts',
                        'Consider blocking if confirmed malicious'
                    ]
                })
            
            # Check 2: Regular timing intervals (beaconing)
            if len(timestamps) >= 5:
                # Calculate intervals between queries
                try:
                    # Normalize timestamps - handle both Z suffix and explicit timezone
                    times = []
                    for ts in timestamps:
                        if not ts:
                            continue
                        # Remove Z and add explicit UTC if needed
                        normalized = ts.replace('Z', '+00:00') if ts.endswith('Z') else ts
                        try:
                            times.append(datetime.fromisoformat(normalized))
                        except ValueError:
                            continue
                    
                    if len(times) < 5:
                        continue
                    times.sort()
                    intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
                    
                    # Check for regular intervals (standard deviation)
                    if intervals and len(intervals) > 3:
                        mean_interval = sum(intervals) / len(intervals)
                        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                        std_dev = variance ** 0.5
                        
                        # Low standard deviation indicates regular beaconing
                        if std_dev < mean_interval * 0.2 and mean_interval > 1:
                            pattern_anomalies.append({
                                'type': 'REGULAR_BEACONING',
                                'severity': 'CRITICAL',
                                'domain': domain,
                                'mean_interval': round(mean_interval, 2),
                                'std_deviation': round(std_dev, 2),
                                'description': f"Regular query intervals ({mean_interval:.1f}s ± {std_dev:.1f}s) indicate C2 beaconing",
                                'technique': 'C2 malware often beacons at regular intervals',
                                'remediation': [
                                    'IMMEDIATE: Isolate affected hosts',
                                    'Analyze all traffic to/from domain',
                                    'Check for lateral movement',
                                    'Incident response activation'
                                ]
                            })
                except (ValueError, AttributeError):
                    pass
        
        return pattern_anomalies
    
    def process_query(self, query: Dict) -> Optional[List[Dict]]:
        """
        Process a DNS query and detect tunneling.
        Returns list of detections if any found.
        """
        self.dns_queries.append(query)
        domain = query.get('domain', '')
        
        # Update domain statistics
        self.domain_stats[domain]['query_count'] += 1
        self.domain_stats[domain]['last_seen'] = query.get('timestamp', '')
        
        # Detect query-level anomalies
        anomalies = self.detect_query_anomalies(query)
        
        if anomalies:
            for anomaly in anomalies:
                anomaly['timestamp'] = query.get('timestamp', datetime.utcnow().isoformat() + 'Z')
                anomaly['source_ip'] = query.get('source_ip', 'unknown')
                self.detections.append(anomaly)
            
            return anomalies
        
        return None
    
    def generate_report(self) -> Dict:
        """Generate comprehensive DNS tunneling detection report."""
        # Analyze traffic patterns
        pattern_detections = self.analyze_traffic_patterns(self.dns_queries[-1000:])  # Last 1000 queries
        self.detections.extend(pattern_detections)
        
        report = {
            'report_timestamp': datetime.utcnow().isoformat() + 'Z',
            'detection_methods': [
                'Shannon entropy analysis',
                'Query length anomalies',
                'Suspicious record types',
                'Traffic pattern analysis',
                'Beaconing detection'
            ],
            'statistics': {
                'total_queries': len(self.dns_queries),
                'unique_domains': len(self.domain_stats),
                'detections': len(self.detections),
                'by_severity': {
                    'CRITICAL': len([d for d in self.detections if d.get('severity') == 'CRITICAL']),
                    'HIGH': len([d for d in self.detections if d.get('severity') == 'HIGH']),
                    'MEDIUM': len([d for d in self.detections if d.get('severity') == 'MEDIUM']),
                }
            },
            'detections': self.detections,
            'top_suspicious_domains': sorted(
                [
                    {'domain': d, 'query_count': stats['query_count']}
                    for d, stats in self.domain_stats.items()
                ],
                key=lambda x: x['query_count'],
                reverse=True
            )[:20]
        }
        
        return report
    
    def save_report(self):
        """Save DNS tunneling detection report."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        report = self.generate_report()
        output_file = f"{self.output_dir}/dns_tunnel_detection.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[DNS Detector] Report saved to {output_file}")
        print(f"[DNS Detector] Queries analyzed: {len(self.dns_queries)}")
        print(f"[DNS Detector] Detections: {len(self.detections)}")
        
        if self.detections:
            print("\n[DNS Detector] Detection Summary:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                count = report['statistics']['by_severity'].get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")


def main():
    """Example usage."""
    detector = DNSTunnelDetector()
    
    # Example: Test high entropy domain
    test_queries = [
        {
            'domain': 'dGVzdGRhdGExMjM0NTY3ODkw.evil.com',  # Base64-like
            'type': 'A',
            'timestamp': '2025-12-09T20:00:00Z',
            'source_ip': '192.168.1.100'
        },
        {
            'domain': 'a' * 150 + '.malware.net',  # Very long
            'type': 'TXT',
            'response_size': 250,
            'timestamp': '2025-12-09T20:00:10Z',
            'source_ip': '192.168.1.100'
        },
    ]
    
    # Add regular queries for beaconing detection
    for i in range(10):
        test_queries.append({
            'domain': 'c2.attacker.com',
            'type': 'A',
            'timestamp': f'2025-12-09T20:{i:02d}:00Z',
            'source_ip': '192.168.1.101'
        })
    
    print("[DNS Detector] Processing test queries...")
    for query in test_queries:
        detections = detector.process_query(query)
        if detections:
            print(f"\n[DETECTION] Found {len(detections)} anomaly(ies):")
            for detection in detections:
                print(f"  Type: {detection['type']}")
                print(f"  Severity: {detection['severity']}")
                print(f"  Domain: {detection.get('domain', 'N/A')}")
    
    detector.save_report()


if __name__ == '__main__':
    main()
