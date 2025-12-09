#!/usr/bin/env python3
"""
CVE Matcher
Matches device firmware versions to known CVEs (uses local database or API)
"""

import sys
import json
from datetime import datetime
from typing import Dict, List

class CVEMatcher:
    def __init__(self):
        # Sample CVE database (in production, this would query NVD or local CVE DB)
        self.cve_database = {
            "printers": [
                {
                    "cve_id": "CVE-2023-1234",
                    "description": "Buffer overflow in printer firmware",
                    "affected_versions": ["<3.0"],
                    "cvss_score": 8.8,
                    "severity": "HIGH"
                },
                {
                    "cve_id": "CVE-2023-5678",
                    "description": "Authentication bypass in web interface",
                    "affected_versions": ["<2.5"],
                    "cvss_score": 9.1,
                    "severity": "CRITICAL"
                }
            ],
            "routers": [
                {
                    "cve_id": "CVE-2023-9999",
                    "description": "Remote code execution via UPnP",
                    "affected_versions": ["<4.1"],
                    "cvss_score": 9.8,
                    "severity": "CRITICAL"
                },
                {
                    "cve_id": "CVE-2023-8888",
                    "description": "Default credentials vulnerability",
                    "affected_versions": ["all"],
                    "cvss_score": 7.5,
                    "severity": "HIGH"
                }
            ],
            "iot": [
                {
                    "cve_id": "CVE-2023-7777",
                    "description": "Insecure firmware update mechanism",
                    "affected_versions": ["<1.5"],
                    "cvss_score": 8.1,
                    "severity": "HIGH"
                }
            ]
        }
    
    def parse_version(self, version_str: str) -> tuple:
        """Parse version string into tuple for comparison"""
        try:
            parts = version_str.replace('v', '').replace('V', '').split('.')
            return tuple(int(p) for p in parts if p.isdigit())
        except:
            return (0,)
    
    def is_version_affected(self, device_version: str, affected_versions: str) -> bool:
        """Check if device version is affected by CVE"""
        try:
            device_ver = self.parse_version(device_version)
            
            # Simple comparison (in production, use proper version comparison library)
            if '<' in affected_versions:
                threshold = self.parse_version(affected_versions.replace('<', ''))
                return device_ver < threshold
            elif affected_versions == 'all':
                return True
            else:
                return device_version in affected_versions
        except:
            return False
    
    def match_cves(self, device_info: Dict) -> List[Dict]:
        """Match device to known CVEs"""
        matches = []
        
        firmware_version = device_info.get('firmware_version', '')
        device_type = device_info.get('device_type', 'unknown')
        
        # Get relevant CVEs for device type
        relevant_cves = self.cve_database.get(device_type, [])
        
        for cve in relevant_cves:
            if self.is_version_affected(firmware_version, cve['affected_versions']):
                match = {
                    "device_ip": device_info.get('ip'),
                    "device_type": device_type,
                    "firmware_version": firmware_version,
                    "cve_id": cve['cve_id'],
                    "description": cve['description'],
                    "cvss_score": cve['cvss_score'],
                    "severity": cve['severity'],
                    "exploitable": cve['cvss_score'] >= 7.0
                }
                matches.append(match)
        
        return matches
    
    def analyze_devices(self, devices: List[Dict]) -> Dict:
        """Analyze multiple devices for CVEs"""
        all_matches = []
        
        for device in devices:
            matches = self.match_cves(device)
            all_matches.extend(matches)
        
        # Calculate risk statistics
        critical_count = sum(1 for m in all_matches if m['severity'] == 'CRITICAL')
        high_count = sum(1 for m in all_matches if m['severity'] == 'HIGH')
        exploitable_count = sum(1 for m in all_matches if m['exploitable'])
        
        return {
            "total_cves_found": len(all_matches),
            "critical_cves": critical_count,
            "high_cves": high_count,
            "exploitable_cves": exploitable_count,
            "cve_matches": all_matches
        }

def main():
    if len(sys.argv) < 3:
        print("Usage: cve_matcher.py <firmware_info_file> <output_file>")
        sys.exit(1)
    
    firmware_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Load firmware information
    try:
        with open(firmware_file, 'r') as f:
            firmware_data = json.load(f)
            devices = firmware_data.get('devices', [])
    except Exception as e:
        print(f"[!] Error loading firmware data: {e}")
        sys.exit(1)
    
    print(f"[*] Matching {len(devices)} devices to CVE database...")
    
    matcher = CVEMatcher()
    results = matcher.analyze_devices(devices)
    
    # Add metadata
    results['scan_date'] = datetime.now().isoformat()
    results['note'] = "This is a sample CVE database. In production, integrate with NVD API or local CVE database."
    results['recommendations'] = [
        "Prioritize patching CRITICAL and HIGH severity CVEs",
        "Update firmware on devices with exploitable CVEs immediately",
        "Consider network segmentation for devices that cannot be patched",
        "Monitor vendor security advisories for new CVEs",
        "Implement a regular patch management schedule"
    ]
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] CVE matching complete.")
    print(f"[+] Found {results['total_cves_found']} CVE matches")
    print(f"[+] Critical: {results['critical_cves']}, High: {results['high_cves']}")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
