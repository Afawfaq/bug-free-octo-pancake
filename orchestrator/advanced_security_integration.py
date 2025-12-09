#!/usr/bin/env python3
"""
Advanced Security Integration Module
=====================================

Integrates all research-based security modules into the main reconnaissance framework.
Provides unified interface for:
- ML Anomaly Detection
- Adaptive Honeypots
- UPnP Vulnerability Scanner
- ARP Spoofing Detector
- TCP/IP Protocol Analyzer
- Audit Log Analyzer
- Threat Intelligence Feed
- DNS Tunnel Detector

Version: 1.0.0
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class AdvancedSecurityOrchestrator:
    """
    Orchestrates all advanced security modules in the reconnaissance framework.
    """
    
    def __init__(self, output_dir: str = './data/advanced-security'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        self.modules = {}
        self.results = {}
        self.enabled_modules = {
            'ml_anomaly': True,
            'adaptive_honeypot': True,
            'upnp_vuln': True,
            'arp_spoof': True,
            'tcpip_analyzer': True,
            'audit_log': True,
            'threat_intel': True,
            'dns_tunnel': True,
        }
    
    def initialize_modules(self, config: Optional[Dict] = None):
        """Initialize all security modules."""
        print("[Advanced Security] Initializing modules...")
        
        try:
            # ML Anomaly Detection
            if self.enabled_modules.get('ml_anomaly'):
                from orchestrator.ml_anomaly_detector import AnomalyDetector
                self.modules['ml_anomaly'] = AnomalyDetector(sensitivity=0.7)
                print("  ✓ ML Anomaly Detector initialized")
            
            # Adaptive Honeypot
            if self.enabled_modules.get('adaptive_honeypot'):
                from deception.adaptive_honeypot import AdaptiveHoneypot
                self.modules['adaptive_honeypot'] = AdaptiveHoneypot(
                    service_type='web',
                    realism_level=0.8
                )
                print("  ✓ Adaptive Honeypot initialized")
            
            # UPnP Vulnerability Scanner
            if self.enabled_modules.get('upnp_vuln'):
                from iot.upnp_vulnerability_scanner import UPnPVulnerabilityScanner
                self.modules['upnp_vuln'] = UPnPVulnerabilityScanner(
                    output_dir=f"{self.output_dir}/upnp"
                )
                print("  ✓ UPnP Vulnerability Scanner initialized")
            
            # ARP Spoofing Detector
            if self.enabled_modules.get('arp_spoof'):
                from passive.arp_spoofing_detector import ARPSpoofingDetector
                self.modules['arp_spoof'] = ARPSpoofingDetector(
                    output_dir=f"{self.output_dir}/arp"
                )
                print("  ✓ ARP Spoofing Detector initialized")
            
            # TCP/IP Protocol Analyzer
            if self.enabled_modules.get('tcpip_analyzer'):
                from passive.tcp_ip_analyzer import TCPIPVulnerabilityAnalyzer
                self.modules['tcpip_analyzer'] = TCPIPVulnerabilityAnalyzer(
                    output_dir=f"{self.output_dir}/tcpip"
                )
                print("  ✓ TCP/IP Protocol Analyzer initialized")
            
            # Audit Log Analyzer
            if self.enabled_modules.get('audit_log'):
                # Import with importlib to handle hyphenated directory name
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "audit_log_analyzer",
                    os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                 "continuous-monitor", "audit_log_analyzer.py")
                )
                if spec and spec.loader:
                    audit_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(audit_module)
                    self.modules['audit_log'] = audit_module.AuditLogAnalyzer(
                        output_dir=f"{self.output_dir}/audit"
                    )
                    print("  ✓ Audit Log Analyzer initialized")
            
            # Threat Intelligence Feed
            if self.enabled_modules.get('threat_intel'):
                from orchestrator.threat_intelligence_feed import ThreatIntelligenceFeed
                self.modules['threat_intel'] = ThreatIntelligenceFeed(
                    output_dir=f"{self.output_dir}/threat-intel"
                )
                print("  ✓ Threat Intelligence Feed initialized")
            
            # DNS Tunnel Detector
            if self.enabled_modules.get('dns_tunnel'):
                from passive.dns_tunnel_detector import DNSTunnelDetector
                self.modules['dns_tunnel'] = DNSTunnelDetector(
                    output_dir=f"{self.output_dir}/dns"
                )
                print("  ✓ DNS Tunnel Detector initialized")
            
            print(f"[Advanced Security] Initialized {len(self.modules)} modules\n")
            return True
            
        except Exception as e:
            print(f"[Advanced Security] Error initializing modules: {e}")
            return False
    
    def process_reconnaissance_data(self, recon_data: Dict) -> Dict:
        """
        Process reconnaissance data through all security modules.
        Returns consolidated security analysis.
        """
        print("[Advanced Security] Processing reconnaissance data...")
        analysis = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'modules_run': [],
            'findings': {},
            'statistics': {}
        }
        
        # Extract discovered hosts
        hosts = recon_data.get('discovered_hosts', [])
        dns_queries = recon_data.get('dns_queries', [])
        arp_table = recon_data.get('arp_table', [])
        
        # Run ML Anomaly Detection on network traffic
        if 'ml_anomaly' in self.modules and hosts:
            print("  Running ML Anomaly Detection...")
            detector = self.modules['ml_anomaly']
            
            # Convert hosts to observations
            observations = []
            for host in hosts:
                for port in host.get('open_ports', []):
                    obs = {
                        'ip': host.get('ip'),
                        'port': port.get('port'),
                        'protocol': port.get('protocol', 'TCP'),
                        'service': port.get('service', 'unknown')
                    }
                    observations.append(obs)
            
            # Train baseline and detect anomalies
            if observations:
                detector.train_baseline(observations[:len(observations)//2])
                for obs in observations[len(observations)//2:]:
                    anomaly = detector.detect_anomaly(obs)
                    if anomaly:
                        analysis['findings'].setdefault('anomalies', []).append(anomaly)
            
            analysis['modules_run'].append('ml_anomaly')
            analysis['statistics']['anomalies_detected'] = len(detector.anomalies)
        
        # Run ARP Spoofing Detection
        if 'arp_spoof' in self.modules and arp_table:
            print("  Running ARP Spoofing Detection...")
            detector = self.modules['arp_spoof']
            
            for entry in arp_table:
                ip = entry.get('ip')
                mac = entry.get('mac')
                if ip and mac:
                    alerts = detector.process_arp_entry(ip, mac)
                    if alerts:
                        analysis['findings'].setdefault('arp_spoofing', []).extend(alerts)
            
            analysis['modules_run'].append('arp_spoof')
            analysis['statistics']['arp_alerts'] = len(detector.alerts)
        
        # Run DNS Tunnel Detection
        if 'dns_tunnel' in self.modules and dns_queries:
            print("  Running DNS Tunnel Detection...")
            detector = self.modules['dns_tunnel']
            
            for query in dns_queries:
                detections = detector.process_query(query)
                if detections:
                    analysis['findings'].setdefault('dns_tunneling', []).extend(detections)
            
            analysis['modules_run'].append('dns_tunnel')
            analysis['statistics']['dns_detections'] = len(detector.detections)
        
        # Run UPnP Vulnerability Scan
        if 'upnp_vuln' in self.modules:
            print("  Running UPnP Vulnerability Scan...")
            scanner = self.modules['upnp_vuln']
            
            # Discover UPnP devices
            devices = scanner.scan_ssdp_multicast(timeout=5)
            
            # Check each device for vulnerabilities
            for device in devices:
                vulns = scanner.check_device_vulnerabilities(device)
                if vulns:
                    analysis['findings'].setdefault('upnp_vulnerabilities', []).extend(vulns)
            
            analysis['modules_run'].append('upnp_vuln')
            analysis['statistics']['upnp_vulnerabilities'] = len(scanner.vulnerabilities)
        
        # Correlate with Threat Intelligence
        if 'threat_intel' in self.modules:
            print("  Running Threat Intelligence Correlation...")
            feed = self.modules['threat_intel']
            
            for host in hosts:
                correlation = feed.correlate_finding(host)
                if correlation:
                    analysis['findings'].setdefault('threat_intel_matches', []).append(correlation)
            
            analysis['modules_run'].append('threat_intel')
            analysis['statistics']['ioc_matches'] = len(feed.correlations)
        
        print(f"[Advanced Security] Analysis complete: {len(analysis['modules_run'])} modules run\n")
        self.results = analysis
        return analysis
    
    def generate_comprehensive_report(self) -> Dict:
        """Generate comprehensive security report."""
        print("[Advanced Security] Generating comprehensive report...")
        
        report = {
            'report_metadata': {
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'framework_version': '1.0.0',
                'modules_enabled': [k for k, v in self.enabled_modules.items() if v]
            },
            'executive_summary': self._generate_executive_summary(),
            'detailed_findings': self.results.get('findings', {}),
            'statistics': self.results.get('statistics', {}),
            'recommendations': self._generate_recommendations(),
            'module_reports': {}
        }
        
        # Collect individual module reports
        for name, module in self.modules.items():
            if hasattr(module, 'generate_report'):
                try:
                    report['module_reports'][name] = module.generate_report()
                except:
                    pass
        
        # Save consolidated report
        output_file = f"{self.output_dir}/advanced_security_report.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"[Advanced Security] Report saved to {output_file}\n")
        return report
    
    def _generate_executive_summary(self) -> Dict:
        """Generate executive summary of findings."""
        findings = self.results.get('findings', {})
        stats = self.results.get('statistics', {})
        
        total_issues = sum([
            len(findings.get('anomalies', [])),
            len(findings.get('arp_spoofing', [])),
            len(findings.get('dns_tunneling', [])),
            len(findings.get('upnp_vulnerabilities', [])),
            len(findings.get('threat_intel_matches', []))
        ])
        
        # Count by severity
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for category in findings.values():
            if isinstance(category, list):
                for item in category:
                    severity = item.get('severity', 'UNKNOWN')
                    if severity in severity_counts:
                        severity_counts[severity] += 1
        
        return {
            'total_issues_found': total_issues,
            'severity_breakdown': severity_counts,
            'modules_executed': len(self.results.get('modules_run', [])),
            'risk_level': self._calculate_risk_level(severity_counts)
        }
    
    def _calculate_risk_level(self, severity_counts: Dict) -> str:
        """Calculate overall risk level."""
        if severity_counts['CRITICAL'] > 0:
            return 'CRITICAL'
        elif severity_counts['HIGH'] > 2:
            return 'HIGH'
        elif severity_counts['HIGH'] > 0 or severity_counts['MEDIUM'] > 5:
            return 'MEDIUM'
        elif severity_counts['MEDIUM'] > 0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        findings = self.results.get('findings', {})
        
        if findings.get('anomalies'):
            recommendations.append("Investigate anomalous network behavior detected by ML analysis")
        
        if findings.get('arp_spoofing'):
            recommendations.append("Enable port security on network switches to prevent ARP spoofing")
            recommendations.append("Deploy ARP inspection on network infrastructure")
        
        if findings.get('dns_tunneling'):
            recommendations.append("Implement DNS query monitoring and filtering")
            recommendations.append("Block suspicious domains identified in DNS tunnel detection")
        
        if findings.get('upnp_vulnerabilities'):
            recommendations.append("Update all UPnP-enabled devices to latest firmware")
            recommendations.append("Disable UPnP on WAN-facing interfaces")
            recommendations.append("Consider disabling UPnP if not required")
        
        if findings.get('threat_intel_matches'):
            recommendations.append("URGENT: Block all IoCs matched against threat intelligence")
            recommendations.append("Investigate systems communicating with known malicious indicators")
            recommendations.append("Activate incident response procedures")
        
        if not recommendations:
            recommendations.append("No critical issues detected - maintain current security posture")
            recommendations.append("Continue regular security monitoring and updates")
        
        return recommendations


def main():
    """Example usage of the advanced security orchestrator."""
    print("="*70)
    print("Advanced Security Integration Module")
    print("Research-Based Security Enhancements for LAN Reconnaissance")
    print("="*70 + "\n")
    
    # Initialize orchestrator
    orchestrator = AdvancedSecurityOrchestrator(output_dir='./data/advanced-security')
    
    # Initialize all modules
    if not orchestrator.initialize_modules():
        print("[Error] Failed to initialize modules")
        return 1
    
    # Example reconnaissance data
    example_recon_data = {
        'discovered_hosts': [
            {
                'ip': '192.168.1.100',
                'mac': '00:11:22:33:44:55',
                'open_ports': [
                    {'port': 80, 'protocol': 'TCP', 'service': 'http'},
                    {'port': 443, 'protocol': 'TCP', 'service': 'https'},
                ]
            },
            {
                'ip': '192.168.1.101',
                'mac': 'AA:BB:CC:DD:EE:FF',
                'open_ports': [
                    {'port': 22, 'protocol': 'TCP', 'service': 'ssh'},
                    {'port': 8080, 'protocol': 'TCP', 'service': 'http-proxy'},
                ]
            }
        ],
        'dns_queries': [
            {
                'domain': 'example.com',
                'type': 'A',
                'timestamp': '2025-12-09T21:00:00Z',
                'source_ip': '192.168.1.100'
            }
        ],
        'arp_table': [
            {'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55'},
            {'ip': '192.168.1.101', 'mac': 'AA:BB:CC:DD:EE:FF'},
        ]
    }
    
    # Process reconnaissance data
    analysis = orchestrator.process_reconnaissance_data(example_recon_data)
    
    # Generate comprehensive report
    report = orchestrator.generate_comprehensive_report()
    
    # Print summary
    summary = report['executive_summary']
    print("="*70)
    print("EXECUTIVE SUMMARY")
    print("="*70)
    print(f"Total Issues Found: {summary['total_issues_found']}")
    print(f"Risk Level: {summary['risk_level']}")
    print(f"Modules Executed: {summary['modules_executed']}")
    print("\nSeverity Breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    print("\n" + "="*70)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
