#!/usr/bin/env python3
"""
ARP Spoofing Detection Module
Implements passive network monitoring for ARP spoofing/poisoning attacks.

Based on research:
- ARP spoofing detection techniques (various security research 2000-2024)
- Man-in-the-middle attack detection methodologies
- Network anomaly detection for layer 2 attacks

Features:
- Passive ARP table monitoring
- Detection of duplicate IP/MAC mappings
- Identification of ARP reply anomalies
- Detection of gratuitous ARP abuse
- Vendor OUI validation
"""

import json
import time
import re
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
import os


class ARPEntry:
    """Represents an ARP table entry."""
    
    def __init__(self, ip: str, mac: str, timestamp: datetime):
        self.ip = ip
        self.mac = mac.upper()
        self.first_seen = timestamp
        self.last_seen = timestamp
        self.update_count = 1
        
    def update(self, timestamp: datetime):
        """Update last seen timestamp."""
        self.last_seen = timestamp
        self.update_count += 1
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'first_seen': self.first_seen.isoformat() + 'Z',
            'last_seen': self.last_seen.isoformat() + 'Z',
            'update_count': self.update_count
        }


class ARPSpoofingDetector:
    """Detector for ARP spoofing and poisoning attacks."""
    
    def __init__(self, output_dir: str = '/output/passive'):
        self.output_dir = output_dir
        self.arp_table = {}  # ip -> ARPEntry
        self.mac_to_ips = defaultdict(set)  # mac -> set of IPs
        self.ip_mac_history = defaultdict(list)  # ip -> list of (mac, timestamp)
        self.alerts = []
        
        # Known vendor OUIs (first 3 bytes of MAC) for validation
        self.vendor_ouis = self._load_common_ouis()
        
        # Detection thresholds
        self.thresholds = {
            'ip_change_frequency': timedelta(minutes=5),  # Suspicious if IP changes MAC within 5 min
            'mac_change_frequency': timedelta(minutes=10),  # Suspicious if MAC serves multiple IPs
            'gratuitous_arp_rate': 10,  # Max gratuitous ARPs per minute
        }
    
    def _load_common_ouis(self) -> Dict[str, str]:
        """Load common vendor OUIs for MAC address validation."""
        return {
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            '00:1C:42': 'Parallels',
            '08:00:27': 'VirtualBox',
            '00:15:5D': 'Hyper-V',
            '52:54:00': 'QEMU/KVM',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            '00:1B:63': 'Apple',
            '00:0D:93': 'Apple',
            '28:6A:BA': 'Apple',
            '00:1A:11': 'Google',
            '00:E0:4C': 'Realtek',
            '00:50:F2': 'Microsoft',
        }
    
    def get_vendor(self, mac: str) -> Optional[str]:
        """Get vendor name from MAC address OUI."""
        # Normalize MAC address format (handle colons, dashes, or no separators)
        mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').upper()
        if len(mac_clean) < 6:
            return None
        
        # Extract OUI (first 6 characters) and format with colons
        oui = ':'.join([mac_clean[i:i+2] for i in range(0, 6, 2)])
        return self.vendor_ouis.get(oui)
    
    def process_arp_entry(self, ip: str, mac: str, timestamp: Optional[datetime] = None) -> List[Dict]:
        """
        Process an ARP entry and detect anomalies.
        Returns list of alerts generated.
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        mac = mac.upper()
        alerts = []
        
        # Check for duplicate IP with different MAC
        if ip in self.arp_table:
            existing_entry = self.arp_table[ip]
            if existing_entry.mac != mac:
                time_diff = timestamp - existing_entry.last_seen
                
                # Alert if MAC changed recently (potential ARP spoofing)
                if time_diff < self.thresholds['ip_change_frequency']:
                    alert = {
                        'alert_id': f"arp_spoof_{len(self.alerts):04d}",
                        'timestamp': timestamp.isoformat() + 'Z',
                        'type': 'ARP_SPOOFING_SUSPECTED',
                        'severity': 'HIGH',
                        'ip': ip,
                        'old_mac': existing_entry.mac,
                        'new_mac': mac,
                        'time_difference_seconds': time_diff.total_seconds(),
                        'description': f"IP {ip} changed from MAC {existing_entry.mac} to {mac} within {time_diff.total_seconds():.0f} seconds",
                        'old_vendor': self.get_vendor(existing_entry.mac),
                        'new_vendor': self.get_vendor(mac),
                        'recommended_actions': [
                            'Investigate the source of the conflicting ARP entries',
                            'Check for ARP poisoning tools on the network',
                            'Verify legitimate device ownership',
                            'Enable port security on switches if available',
                        ]
                    }
                    alerts.append(alert)
                    self.alerts.append(alert)
                
                # Update history
                self.ip_mac_history[ip].append((existing_entry.mac, existing_entry.last_seen))
        
        # Update or create ARP entry
        if ip in self.arp_table:
            self.arp_table[ip].mac = mac
            self.arp_table[ip].update(timestamp)
        else:
            self.arp_table[ip] = ARPEntry(ip, mac, timestamp)
        
        # Track MAC to IP mapping
        self.mac_to_ips[mac].add(ip)
        
        # Check if one MAC is serving multiple IPs (potential MITM)
        if len(self.mac_to_ips[mac]) > 1:
            alert = {
                'alert_id': f"arp_multi_{len(self.alerts):04d}",
                'timestamp': timestamp.isoformat() + 'Z',
                'type': 'MULTIPLE_IPS_SINGLE_MAC',
                'severity': 'MEDIUM',
                'mac': mac,
                'ips': list(self.mac_to_ips[mac]),
                'ip_count': len(self.mac_to_ips[mac]),
                'description': f"MAC {mac} is associated with {len(self.mac_to_ips[mac])} different IPs",
                'vendor': self.get_vendor(mac),
                'possible_causes': [
                    'ARP spoofing/poisoning attack (MITM)',
                    'Network device with multiple interfaces',
                    'Proxy or gateway device',
                    'Misconfigured network device'
                ],
                'recommended_actions': [
                    'Verify if device is a legitimate router/gateway',
                    'Check for ARP poisoning tools',
                    'Inspect traffic patterns from this MAC address'
                ]
            }
            
            # Only alert if it's a new condition
            if not any(a.get('mac') == mac and a.get('type') == 'MULTIPLE_IPS_SINGLE_MAC' 
                      for a in self.alerts[-10:]):
                alerts.append(alert)
                self.alerts.append(alert)
        
        # Check for gratuitous ARP abuse
        if ip in self.ip_mac_history:
            recent_changes = [
                ts for _, ts in self.ip_mac_history[ip]
                if timestamp - ts < timedelta(minutes=1)
            ]
            if len(recent_changes) > self.thresholds['gratuitous_arp_rate']:
                alert = {
                    'alert_id': f"arp_flood_{len(self.alerts):04d}",
                    'timestamp': timestamp.isoformat() + 'Z',
                    'type': 'GRATUITOUS_ARP_FLOOD',
                    'severity': 'HIGH',
                    'ip': ip,
                    'mac': mac,
                    'change_count': len(recent_changes),
                    'description': f"Excessive ARP updates for {ip}: {len(recent_changes)} changes in 1 minute",
                    'recommended_actions': [
                        'Investigate source device for malware',
                        'Check for ARP flooding attack',
                        'Verify device configuration'
                    ]
                }
                alerts.append(alert)
                self.alerts.append(alert)
        
        return alerts
    
    def analyze_mac_patterns(self) -> List[Dict]:
        """Analyze MAC address patterns for anomalies."""
        anomalies = []
        
        # Check for potentially fake MAC addresses
        for mac, ips in self.mac_to_ips.items():
            vendor = self.get_vendor(mac)
            
            # Check for locally administered MAC (bit 1 of first byte is 1)
            first_byte = int(mac.split(':')[0], 16)
            if first_byte & 0x02:  # Locally administered
                anomalies.append({
                    'type': 'LOCALLY_ADMINISTERED_MAC',
                    'severity': 'LOW',
                    'mac': mac,
                    'ips': list(ips),
                    'description': f"MAC {mac} is locally administered (potentially spoofed)",
                    'note': 'Locally administered MACs are sometimes used in virtualization or can be manually set'
                })
            
            # Check for unknown vendor
            if not vendor and len(ips) > 1:
                anomalies.append({
                    'type': 'UNKNOWN_VENDOR_MULTIPLE_IPS',
                    'severity': 'MEDIUM',
                    'mac': mac,
                    'ips': list(ips),
                    'description': f"Unknown vendor MAC {mac} serving {len(ips)} IPs",
                    'note': 'Could indicate spoofed MAC or unregistered vendor'
                })
        
        return anomalies
    
    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        stats = {
            'total_arp_entries': len(self.arp_table),
            'unique_macs': len(self.mac_to_ips),
            'alerts_by_type': defaultdict(int),
            'alerts_by_severity': defaultdict(int),
            'ips_with_mac_changes': len([ip for ip in self.ip_mac_history if len(self.ip_mac_history[ip]) > 0])
        }
        
        for alert in self.alerts:
            stats['alerts_by_type'][alert['type']] += 1
            stats['alerts_by_severity'][alert['severity']] += 1
        
        return stats
    
    def generate_report(self) -> Dict:
        """Generate comprehensive ARP spoofing detection report."""
        report = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'statistics': self.get_statistics(),
            'alerts': self.alerts,
            'arp_table': [entry.to_dict() for entry in self.arp_table.values()],
            'mac_patterns': self.analyze_mac_patterns(),
            'suspicious_macs': [
                {
                    'mac': mac,
                    'ips': list(ips),
                    'vendor': self.get_vendor(mac)
                }
                for mac, ips in self.mac_to_ips.items()
                if len(ips) > 1
            ]
        }
        
        return report
    
    def save_report(self):
        """Save detection report to file."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        report = self.generate_report()
        output_file = f"{self.output_dir}/arp_spoofing_detection.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n[ARP Detector] Report saved to {output_file}")
        print(f"[ARP Detector] ARP entries monitored: {len(self.arp_table)}")
        print(f"[ARP Detector] Alerts generated: {len(self.alerts)}")
        
        stats = report['statistics']
        if stats['alerts_by_severity']:
            print("\n[ARP Detector] Alerts by Severity:")
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                count = stats['alerts_by_severity'].get(severity, 0)
                if count > 0:
                    print(f"  {severity}: {count}")


def main():
    """Example usage and testing."""
    detector = ARPSpoofingDetector()
    
    # Simulate normal ARP entries
    base_time = datetime.utcnow()
    detector.process_arp_entry('192.168.1.1', '00:11:22:33:44:55', base_time)
    detector.process_arp_entry('192.168.1.10', '00:0C:29:AA:BB:CC', base_time)
    detector.process_arp_entry('192.168.1.20', 'B8:27:EB:11:22:33', base_time)
    
    # Simulate ARP spoofing
    spoof_time = base_time + timedelta(seconds=30)
    alerts = detector.process_arp_entry('192.168.1.1', 'AA:BB:CC:DD:EE:FF', spoof_time)
    
    if alerts:
        print("\n[ALERT] ARP Spoofing Detected!")
        for alert in alerts:
            print(f"  Type: {alert['type']}")
            print(f"  Severity: {alert['severity']}")
            print(f"  Description: {alert['description']}")
    
    # Simulate MITM (one MAC for multiple IPs)
    mitm_time = base_time + timedelta(seconds=60)
    detector.process_arp_entry('192.168.1.100', '11:22:33:44:55:66', mitm_time)
    detector.process_arp_entry('192.168.1.101', '11:22:33:44:55:66', mitm_time)
    detector.process_arp_entry('192.168.1.102', '11:22:33:44:55:66', mitm_time)
    
    detector.save_report()


if __name__ == '__main__':
    main()
