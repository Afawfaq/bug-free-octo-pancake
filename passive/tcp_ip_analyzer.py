#!/usr/bin/env python3
"""
TCP/IP Protocol Vulnerability Analyzer
Based on foundational research from the 1970s-2000s:
- Anderson's "Computer Security Threat Monitoring" (1980)
- Denning's "Intrusion Detection Model" (1987)
- TCP/IP vulnerability research (Purdue, Stanford)
- Morris Worm exploitation techniques (1988)

Detects classic TCP/IP protocol vulnerabilities:
- IP spoofing susceptibility
- TCP SYN flooding potential
- Fragment reassembly vulnerabilities
- Session hijacking risks
- Protocol implementation flaws
"""

import json
import struct
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import os


class TCPIPVulnerabilityAnalyzer:
    """
    Analyzer for classic TCP/IP protocol vulnerabilities.
    Implements concepts from foundational security research.
    """
    
    def __init__(self, output_dir: str = '/output/passive'):
        self.output_dir = output_dir
        self.vulnerabilities = []
        self.traffic_patterns = defaultdict(int)
        self.connection_states = {}
        
        # Known attack signatures based on Morris Worm and early research
        self.attack_signatures = {
            'syn_flood': {'description': 'TCP SYN flood DoS attack', 'threshold': 100},
            'ip_spoof': {'description': 'IP address spoofing attempt', 'severity': 'HIGH'},
            'fragment_attack': {'description': 'IP fragmentation exploit', 'severity': 'MEDIUM'},
            'session_hijack': {'description': 'TCP session hijacking', 'severity': 'CRITICAL'},
            'port_scan': {'description': 'Port scanning activity', 'severity': 'MEDIUM'},
        }
    
    def analyze_tcp_flags(self, flags: Dict[str, bool]) -> List[Dict]:
        """
        Analyze TCP flags for suspicious patterns.
        Based on TCP vulnerability research from the 1980s-90s.
        """
        anomalies = []
        
        # Check for SYN flood indicators
        if flags.get('SYN') and not flags.get('ACK'):
            self.traffic_patterns['syn_packets'] += 1
            
            if self.traffic_patterns['syn_packets'] > self.attack_signatures['syn_flood']['threshold']:
                anomalies.append({
                    'type': 'SYN_FLOOD_DETECTED',
                    'severity': 'HIGH',
                    'description': 'Possible SYN flood DoS attack detected',
                    'packet_count': self.traffic_patterns['syn_packets'],
                    'historical_context': 'SYN flood attacks exploit TCP three-way handshake, documented since mid-1990s',
                    'remediation': [
                        'Enable SYN cookies on the server',
                        'Configure firewall rate limiting',
                        'Implement TCP backlog queue management'
                    ]
                })
        
        # Check for NULL scan (all flags off)
        if not any(flags.values()):
            anomalies.append({
                'type': 'NULL_SCAN',
                'severity': 'MEDIUM',
                'description': 'NULL scan detected - all TCP flags are zero',
                'historical_context': 'NULL scans used for stealth port scanning, documented in early Nmap research',
                'remediation': ['Log and investigate source IP', 'Consider blocking if confirmed malicious']
            })
        
        # Check for XMAS scan (FIN, PSH, URG all set)
        if flags.get('FIN') and flags.get('PSH') and flags.get('URG'):
            anomalies.append({
                'type': 'XMAS_SCAN',
                'severity': 'MEDIUM',
                'description': 'XMAS scan detected - FIN, PSH, URG flags set',
                'historical_context': 'XMAS scans exploit RFC violations for stealthy reconnaissance',
                'remediation': ['Investigate scanning source', 'Update IDS signatures']
            })
        
        # Check for invalid flag combinations
        if flags.get('SYN') and flags.get('FIN'):
            anomalies.append({
                'type': 'INVALID_FLAGS',
                'severity': 'HIGH',
                'description': 'Invalid TCP flag combination (SYN + FIN)',
                'historical_context': 'Invalid flags can indicate evasion attempts or malformed packets',
                'remediation': ['Drop packets with invalid flag combinations', 'Log for analysis']
            })
        
        return anomalies
    
    def detect_ip_spoofing(self, src_ip: str, ttl: int, window_size: int) -> Optional[Dict]:
        """
        Detect potential IP spoofing based on anomalies.
        Based on IP spoofing research from the 1980s.
        """
        anomalies = []
        
        # Check for suspicious TTL values
        if ttl < 10 or ttl > 255:
            anomalies.append({
                'type': 'SUSPICIOUS_TTL',
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'ttl': ttl,
                'description': f'Suspicious TTL value: {ttl}',
                'historical_context': 'TTL anomalies can indicate spoofed packets or routing issues',
            })
        
        # Check for invalid source IPs (more comprehensive check)
        if (src_ip.startswith('0.') or 
            src_ip.startswith('127.') or 
            src_ip == '255.255.255.255' or
            src_ip.startswith('224.') or  # Multicast range
            src_ip.startswith('240.')):   # Reserved range
            anomalies.append({
                'type': 'INVALID_SOURCE_IP',
                'severity': 'HIGH',
                'src_ip': src_ip,
                'description': f'Invalid/suspicious source IP address: {src_ip}',
                'historical_context': 'Invalid IPs often indicate spoofing or misconfiguration',
                'note': 'Covers loopback, multicast, reserved, and broadcast ranges'
            })
        
        # Check for unusual window sizes (can indicate OS fingerprinting or spoofing)
        if window_size == 0 or window_size > 65535:
            anomalies.append({
                'type': 'SUSPICIOUS_WINDOW_SIZE',
                'severity': 'LOW',
                'src_ip': src_ip,
                'window_size': window_size,
                'description': f'Unusual TCP window size: {window_size}',
            })
        
        if anomalies:
            return {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'anomalies': anomalies,
                'recommended_actions': [
                    'Verify source IP legitimacy',
                    'Check routing tables',
                    'Enable egress filtering (RFC 2827)',
                    'Implement source address validation'
                ]
            }
        
        return None
    
    def analyze_fragmentation(self, fragments: List[Dict]) -> List[Dict]:
        """
        Analyze IP fragmentation for potential exploits.
        Based on fragment reassembly vulnerability research.
        """
        vulnerabilities = []
        
        # Check for fragment overlap attacks (Teardrop, Bonk, etc.)
        if len(fragments) > 1:
            for i, frag in enumerate(fragments[:-1]):
                next_frag = fragments[i + 1]
                
                # Check for overlapping fragments
                frag_end = frag.get('offset', 0) + frag.get('length', 0)
                next_start = next_frag.get('offset', 0)
                
                if frag_end > next_start:
                    vulnerabilities.append({
                        'type': 'FRAGMENT_OVERLAP',
                        'severity': 'HIGH',
                        'description': 'Overlapping IP fragments detected',
                        'historical_context': 'Teardrop attack (1997) exploited fragment overlap bugs',
                        'fragment_info': {
                            'fragment_1': {'offset': frag.get('offset'), 'length': frag.get('length')},
                            'fragment_2': {'offset': next_frag.get('offset'), 'length': next_frag.get('length')}
                        },
                        'remediation': [
                            'Update IP stack to handle overlapping fragments correctly',
                            'Enable fragment filtering on firewall',
                            'Apply OS security patches'
                        ]
                    })
        
        # Check for excessive fragmentation (possible DoS)
        if len(fragments) > 20:
            vulnerabilities.append({
                'type': 'EXCESSIVE_FRAGMENTATION',
                'severity': 'MEDIUM',
                'description': f'Excessive fragmentation detected: {len(fragments)} fragments',
                'historical_context': 'Fragment floods used for DoS attacks since 1990s',
                'remediation': [
                    'Set fragment reassembly timeout',
                    'Limit maximum fragments per packet',
                    'Monitor fragment reassembly queue size'
                ]
            })
        
        return vulnerabilities
    
    def detect_port_scan(self, src_ip: str, dest_ports: List[int], time_window: float) -> Optional[Dict]:
        """
        Detect port scanning activity.
        Based on early IDS research and Nmap detection techniques.
        """
        # Multiple ports accessed in short time indicates scanning
        unique_ports = len(set(dest_ports))
        
        if unique_ports > 10 and time_window < 60:
            scan_type = 'HORIZONTAL_SCAN'
            if len(dest_ports) > 100:
                scan_type = 'FAST_SCAN'
            
            return {
                'type': scan_type,
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'unique_ports': unique_ports,
                'total_attempts': len(dest_ports),
                'time_window_seconds': time_window,
                'scan_rate': len(dest_ports) / time_window if time_window > 0 else 0,
                'description': f'Port scan detected: {unique_ports} ports in {time_window:.1f} seconds',
                'historical_context': 'Port scanning fundamental reconnaissance technique since 1980s',
                'common_tools': ['Nmap', 'Masscan', 'Zmap'],
                'remediation': [
                    'Block source IP if confirmed malicious',
                    'Enable port scan detection on IDS',
                    'Configure firewall to rate-limit connection attempts',
                    'Review exposed services'
                ]
            }
        
        return None
    
    def check_session_hijack_vulnerability(self, connection: Dict) -> Optional[Dict]:
        """
        Check for TCP session hijacking vulnerability.
        Based on Mitnick attack (1994) and earlier research.
        """
        vulnerabilities = []
        
        # Check if sequence numbers are predictable
        if connection.get('seq_predictable', False):
            vulnerabilities.append({
                'type': 'PREDICTABLE_SEQUENCE_NUMBERS',
                'severity': 'CRITICAL',
                'description': 'TCP sequence numbers are predictable',
                'historical_context': 'Kevin Mitnick attack (1994) exploited predictable TCP sequences',
                'connection_info': {
                    'src': connection.get('src_ip'),
                    'dst': connection.get('dst_ip'),
                    'port': connection.get('port')
                },
                'remediation': [
                    'Enable TCP sequence number randomization',
                    'Use IPsec or TLS for sensitive connections',
                    'Implement stronger session management',
                    'Apply RFC 6528 recommendations'
                ]
            })
        
        # Check for lack of encryption
        if not connection.get('encrypted', False) and connection.get('sensitive', False):
            vulnerabilities.append({
                'type': 'UNENCRYPTED_SENSITIVE_CONNECTION',
                'severity': 'HIGH',
                'description': 'Sensitive data transmitted without encryption',
                'historical_context': 'Plaintext protocols vulnerable to sniffing since inception',
                'remediation': [
                    'Migrate to TLS/SSL encrypted protocols',
                    'Disable unencrypted services',
                    'Implement VPN for sensitive communications'
                ]
            })
        
        if vulnerabilities:
            return {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'vulnerabilities': vulnerabilities
            }
        
        return None
    
    def generate_report(self) -> Dict:
        """Generate comprehensive TCP/IP vulnerability analysis report."""
        report = {
            'analysis_timestamp': datetime.utcnow().isoformat() + 'Z',
            'analyzer': 'TCP/IP Protocol Vulnerability Analyzer',
            'based_on_research': [
                'Anderson - Computer Security Threat Monitoring (1980)',
                'Denning - Intrusion Detection Model (1986)',
                'Morris Worm exploitation techniques (1988)',
                'TCP/IP vulnerability research (1970s-2000s)'
            ],
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities,
            'traffic_patterns': dict(self.traffic_patterns),
            'recommendations': {
                'immediate': [
                    'Enable TCP SYN cookies',
                    'Configure egress filtering (RFC 2827)',
                    'Implement sequence number randomization',
                    'Enable fragment reassembly protections'
                ],
                'long_term': [
                    'Migrate to IPv6 with IPsec',
                    'Deploy modern IDS/IPS systems',
                    'Regular security audits and updates',
                    'Network segmentation and zero-trust architecture'
                ]
            }
        }
        
        return report
    
    def save_report(self):
        """Save vulnerability analysis report."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        report = self.generate_report()
        output_file = f"{self.output_dir}/tcpip_vulnerability_analysis.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n[TCP/IP Analyzer] Report saved to {output_file}")
        print(f"[TCP/IP Analyzer] Vulnerabilities found: {len(self.vulnerabilities)}")


def main():
    """Example usage."""
    analyzer = TCPIPVulnerabilityAnalyzer()
    
    # Example: Test SYN flood detection
    print("[TCP/IP Analyzer] Testing SYN flood detection...")
    for i in range(150):
        anomalies = analyzer.analyze_tcp_flags({'SYN': True, 'ACK': False})
        if anomalies:
            analyzer.vulnerabilities.extend(anomalies)
            print(f"  Detected: {anomalies[0]['type']}")
            break
    
    # Example: Test invalid flags
    print("[TCP/IP Analyzer] Testing invalid flag combinations...")
    invalid_flags = analyzer.analyze_tcp_flags({'SYN': True, 'FIN': True})
    if invalid_flags:
        analyzer.vulnerabilities.extend(invalid_flags)
        print(f"  Detected: {invalid_flags[0]['type']}")
    
    # Example: Test IP spoofing detection
    print("[TCP/IP Analyzer] Testing IP spoofing detection...")
    spoof = analyzer.detect_ip_spoofing('0.0.0.0', 5, 32768)
    if spoof:
        analyzer.vulnerabilities.append(spoof)
        print(f"  Detected: {len(spoof['anomalies'])} anomalies")
    
    # Example: Test port scan detection
    print("[TCP/IP Analyzer] Testing port scan detection...")
    ports = list(range(1, 101))
    scan = analyzer.detect_port_scan('192.168.1.100', ports, 30.0)
    if scan:
        analyzer.vulnerabilities.append(scan)
        print(f"  Detected: {scan['type']}")
    
    analyzer.save_report()


if __name__ == '__main__':
    main()
