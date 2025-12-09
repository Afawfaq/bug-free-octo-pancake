#!/usr/bin/env python3
"""
Device Aging Scorer
Calculates an aging score for devices based on firmware age, outdated protocols, etc.
"""

import sys
import json
from datetime import datetime, timedelta
from typing import Dict, List

class DeviceAgingScorer:
    def __init__(self):
        self.deprecated_protocols = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'SMBv1']
        self.weak_ciphers = ['RC4', '3DES', 'DES', 'MD5']
    
    def calculate_firmware_age_score(self, days_old: int) -> int:
        """Score based on firmware age (0-40 points)"""
        if days_old > 1095:  # > 3 years
            return 40
        elif days_old > 730:  # > 2 years
            return 30
        elif days_old > 365:  # > 1 year
            return 20
        elif days_old > 180:  # > 6 months
            return 10
        else:
            return 0
    
    def calculate_protocol_score(self, protocols: List[str]) -> int:
        """Score based on deprecated protocols (0-30 points)"""
        score = 0
        for protocol in protocols:
            if protocol in self.deprecated_protocols:
                score += 10
        return min(score, 30)
    
    def calculate_cipher_score(self, ciphers: List[str]) -> int:
        """Score based on weak ciphers (0-20 points)"""
        score = 0
        for cipher in ciphers:
            if cipher in self.weak_ciphers:
                score += 5
        return min(score, 20)
    
    def calculate_vendor_support_score(self, support_status: str) -> int:
        """Score based on vendor support (0-10 points)"""
        if support_status == 'EOL':
            return 10
        elif support_status == 'EXTENDED':
            return 5
        else:
            return 0
    
    def calculate_overall_score(self, device: Dict) -> Dict:
        """Calculate overall aging score (0-100)"""
        
        # Extract device information
        firmware_age = device.get('firmware_age_days', 0)
        protocols = device.get('protocols', [])
        ciphers = device.get('ciphers', [])
        support_status = device.get('vendor_support_status', 'ACTIVE')
        patches_behind = device.get('patches_behind', 0)
        
        # Calculate component scores
        age_score = self.calculate_firmware_age_score(firmware_age)
        protocol_score = self.calculate_protocol_score(protocols)
        cipher_score = self.calculate_cipher_score(ciphers)
        support_score = self.calculate_vendor_support_score(support_status)
        
        # Patches behind (0-10 points)
        patch_score = min(patches_behind * 2, 10)
        
        # Calculate total
        total_score = age_score + protocol_score + cipher_score + support_score + patch_score
        
        # Determine risk level
        if total_score >= 75:
            risk_level = "CRITICAL"
        elif total_score >= 50:
            risk_level = "HIGH"
        elif total_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "total_score": total_score,
            "risk_level": risk_level,
            "score_breakdown": {
                "firmware_age_score": age_score,
                "protocol_score": protocol_score,
                "cipher_score": cipher_score,
                "vendor_support_score": support_score,
                "patch_score": patch_score
            },
            "factors": {
                "firmware_age_days": firmware_age,
                "deprecated_protocols": [p for p in protocols if p in self.deprecated_protocols],
                "weak_ciphers": [c for c in ciphers if c in self.weak_ciphers],
                "vendor_support_status": support_status,
                "patches_behind": patches_behind
            }
        }

def main():
    if len(sys.argv) < 3:
        print("Usage: aging_scorer.py <device_data_file> <output_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Load device data
    try:
        with open(input_file, 'r') as f:
            data = json.load(f)
            devices = data.get('devices', [])
    except Exception as e:
        print(f"[!] Error loading device data: {e}")
        # Create sample data for demonstration
        devices = [
            {
                "ip": "192.168.1.1",
                "device_type": "router",
                "firmware_age_days": 730,
                "protocols": ["TLSv1.0", "SSLv3"],
                "ciphers": ["RC4", "3DES"],
                "vendor_support_status": "ACTIVE",
                "patches_behind": 5
            }
        ]
    
    print(f"[*] Calculating aging scores for {len(devices)} devices...")
    
    scorer = DeviceAgingScorer()
    results = []
    
    for device in devices:
        device_ip = device.get('ip', 'unknown')
        print(f"[*] Scoring device {device_ip}...")
        
        score_result = scorer.calculate_overall_score(device)
        score_result['device_ip'] = device_ip
        score_result['device_type'] = device.get('device_type', 'unknown')
        
        results.append(score_result)
        print(f"[+] Score: {score_result['total_score']}/100 - Risk: {score_result['risk_level']}")
    
    # Calculate summary statistics
    avg_score = sum(r['total_score'] for r in results) / len(results) if results else 0
    critical_count = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
    high_count = sum(1 for r in results if r['risk_level'] == 'HIGH')
    
    output_data = {
        "total_devices_scored": len(results),
        "average_aging_score": round(avg_score, 2),
        "critical_risk_devices": critical_count,
        "high_risk_devices": high_count,
        "device_scores": results,
        "recommendations": [
            "Devices with CRITICAL scores should be prioritized for firmware updates",
            "Replace or isolate devices with EOL vendor support",
            "Disable deprecated protocols (SSLv3, TLSv1.0, TLSv1.1)",
            "Update cipher suites to remove weak algorithms",
            "Implement a regular firmware update schedule",
            "Consider replacing devices with scores consistently above 75"
        ]
    }
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Aging score calculation complete.")
    print(f"[+] Average score: {avg_score:.1f}/100")
    print(f"[+] Critical risk: {critical_count}, High risk: {high_count}")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
