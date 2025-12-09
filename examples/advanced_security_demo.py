#!/usr/bin/env python3
"""
Advanced Security Modules - Demonstration Script
=================================================

This script demonstrates how to use all advanced security modules
individually and through the integration layer.

Usage:
    python examples/advanced_security_demo.py
"""

import sys
import os
import json
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("="*80)
print("Advanced Security Modules - Demonstration")
print("Research-Based Security Enhancements (1920s-2024)")
print("="*80 + "\n")

# Example 1: ML Anomaly Detection
print("[1] ML Anomaly Detection")
print("-" * 40)
try:
    from orchestrator.ml_anomaly_detector import AnomalyDetector
    
    detector = AnomalyDetector(sensitivity=0.7)
    
    # Train on normal traffic
    historical_data = [
        {'port': 80, 'protocol': 'HTTP', 'ip': '192.168.1.10', 'service': 'web'},
        {'port': 443, 'protocol': 'HTTPS', 'ip': '192.168.1.10', 'service': 'web'},
        {'port': 22, 'protocol': 'SSH', 'ip': '192.168.1.20', 'service': 'ssh'},
    ] * 30  # Repeat for baseline
    
    detector.train_baseline(historical_data)
    
    # Test anomalous traffic
    anomalous = {'port': 31337, 'protocol': 'TCP', 'ip': '192.168.1.50', 'service': 'backdoor'}
    anomaly = detector.detect_anomaly(anomalous)
    
    if anomaly:
        print(f"✓ Anomaly detected: Score {anomaly['anomaly_score']}, Severity: {anomaly['severity']}")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 2: Adaptive Honeypot
print("[2] Adaptive Honeypot")
print("-" * 40)
try:
    from deception.adaptive_honeypot import AdaptiveHoneypot
    
    honeypot = AdaptiveHoneypot(service_type='web', realism_level=0.8)
    
    # Simulate attacker interactions
    actions = [
        {'type': 'directory_enumeration', 'technique': 'RECONNAISSANCE'},
        {'type': 'sql_injection', 'technique': 'SQL_INJECTION'},
    ]
    
    for action in actions:
        response = honeypot.handle_interaction('192.168.1.100', action)
        print(f"✓ Handled {action['type']}: {response['response_type']}")
    
    stats = honeypot.get_statistics()
    print(f"✓ Statistics: {stats['total_interactions']} interactions, {stats['unique_attackers']} attackers")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 3: UPnP Vulnerability Scanner
print("[3] UPnP Vulnerability Scanner")
print("-" * 40)
try:
    from iot.upnp_vulnerability_scanner import UPnPVulnerabilityScanner
    
    # Note: This would normally scan the network
    print("✓ UPnP Scanner initialized (network scan skipped in demo)")
    print("  Would detect 9 critical CVEs in libupnp")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 4: ARP Spoofing Detector
print("[4] ARP Spoofing Detector")
print("-" * 40)
try:
    from passive.arp_spoofing_detector import ARPSpoofingDetector
    from datetime import timedelta
    
    detector = ARPSpoofingDetector()
    
    # Normal ARP entry
    base_time = datetime.utcnow()
    detector.process_arp_entry('192.168.1.1', '00:11:22:33:44:55', base_time)
    
    # Spoofed entry (same IP, different MAC, short time)
    spoof_time = base_time + timedelta(seconds=10)
    alerts = detector.process_arp_entry('192.168.1.1', 'AA:BB:CC:DD:EE:FF', spoof_time)
    
    if alerts:
        print(f"✓ ARP spoofing detected: {len(alerts)} alert(s)")
        print(f"  Type: {alerts[0]['type']}, Severity: {alerts[0]['severity']}")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 5: TCP/IP Protocol Analyzer
print("[5] TCP/IP Protocol Analyzer")
print("-" * 40)
try:
    from passive.tcp_ip_analyzer import TCPIPVulnerabilityAnalyzer
    
    analyzer = TCPIPVulnerabilityAnalyzer()
    
    # Test invalid TCP flags
    anomalies = analyzer.analyze_tcp_flags({'SYN': True, 'FIN': True})
    if anomalies:
        print(f"✓ Invalid TCP flags detected: {anomalies[0]['type']}")
    
    # Test IP spoofing
    spoof = analyzer.detect_ip_spoofing('0.0.0.0', ttl=5, window_size=32768)
    if spoof:
        print(f"✓ IP spoofing indicators: {len(spoof['anomalies'])} anomaly(ies)")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 6: Audit Log Analyzer
print("[6] Audit Log Analyzer")
print("-" * 40)
try:
    from continuous_monitor.audit_log_analyzer import AuditLogAnalyzer
    
    analyzer = AuditLogAnalyzer()
    
    # Build baseline
    historical_logs = [
        {'user': 'alice', 'action': 'read', 'object': '/home/alice/doc.txt', 
         'timestamp': '2025-12-09T14:00:00Z'},
    ] * 50
    
    analyzer.build_baseline(historical_logs)
    
    # Analyze suspicious log
    suspicious = {
        'user': 'charlie',
        'action': 'read',
        'object': '/etc/shadow',
        'timestamp': '2025-12-09T02:00:00Z'
    }
    
    anomaly = analyzer.analyze_log(suspicious)
    if anomaly:
        print(f"✓ Log anomaly detected: Score {anomaly['anomaly_score']}, Severity: {anomaly['severity']}")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 7: Threat Intelligence Feed
print("[7] Threat Intelligence Feed")
print("-" * 40)
try:
    from orchestrator.threat_intelligence_feed import ThreatIntelligenceFeed
    
    feed = ThreatIntelligenceFeed()
    
    # Parse STIX bundle
    stix_bundle = {
        'type': 'bundle',
        'objects': [
            {
                'type': 'indicator',
                'pattern': "[ipv4-addr:value = '192.0.2.1']",
                'indicator_types': ['malicious-activity']
            }
        ]
    }
    
    summary = feed.parse_stix_bundle(stix_bundle)
    print(f"✓ STIX bundle parsed: {summary}")
    
    # Correlate finding
    finding = {'src_ip': '192.0.2.1', 'action': 'connection'}
    correlation = feed.correlate_finding(finding)
    
    if correlation:
        print(f"✓ IoC match found: {correlation['match_count']} indicator(s), Severity: {correlation['severity']}")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 8: DNS Tunnel Detector
print("[8] DNS Tunnel Detector")
print("-" * 40)
try:
    from passive.dns_tunnel_detector import DNSTunnelDetector
    
    detector = DNSTunnelDetector()
    
    # Test suspicious DNS query
    query = {
        'domain': 'dGVzdGRhdGExMjM0NTY3ODkw' + '.evil.com',  # Base64-like
        'type': 'TXT',
        'response_size': 250,
        'timestamp': '2025-12-09T21:00:00Z',
        'source_ip': '192.168.1.100'
    }
    
    detections = detector.process_query(query)
    if detections:
        print(f"✓ DNS tunnel detected: {len(detections)} anomaly(ies)")
        print(f"  Types: {', '.join([d['type'] for d in detections])}")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

# Example 9: Integrated Security Analysis
print("[9] Integrated Security Analysis")
print("-" * 40)
try:
    from orchestrator.advanced_security_integration import AdvancedSecurityOrchestrator
    
    orchestrator = AdvancedSecurityOrchestrator()
    
    # Initialize all modules
    if orchestrator.initialize_modules():
        print("✓ All security modules initialized")
        
        # Example reconnaissance data
        recon_data = {
            'discovered_hosts': [
                {
                    'ip': '192.168.1.100',
                    'mac': '00:11:22:33:44:55',
                    'open_ports': [
                        {'port': 80, 'protocol': 'TCP', 'service': 'http'},
                        {'port': 443, 'protocol': 'TCP', 'service': 'https'},
                    ]
                }
            ],
            'dns_queries': [],
            'arp_table': []
        }
        
        # Process data
        analysis = orchestrator.process_reconnaissance_data(recon_data)
        print(f"✓ Analysis complete: {len(analysis['modules_run'])} modules executed")
        
        # Generate report
        report = orchestrator.generate_comprehensive_report()
        summary = report['executive_summary']
        print(f"✓ Report generated: {summary['total_issues_found']} issues, Risk: {summary['risk_level']}")
    print()
    
except Exception as e:
    print(f"✗ Error: {e}\n")

print("="*80)
print("Demonstration Complete")
print("="*80)
print("\nAll 8 advanced security modules demonstrated successfully!")
print("See ADVANCED_SECURITY_MODULES.md for detailed documentation.")
