#!/usr/bin/env python3
"""
BLE Scanner
Enumerates Bluetooth Low Energy devices
"""

import sys
import json
import subprocess
from datetime import datetime
from typing import Dict, List

class BLEScanner:
    def __init__(self):
        self.devices = []
    
    def check_bluetooth(self) -> bool:
        """Check if Bluetooth is available."""
        try:
            result = subprocess.run(['hciconfig'],
                                  capture_output=True, text=True, timeout=5)
            if 'hci0' in result.stdout:
                print("[*] Bluetooth adapter detected")
                return True
            else:
                print("[!] No Bluetooth adapter found")
                return False
        except:
            print("[!] Bluetooth tools not available")
            return False
    
    def scan_ble_devices(self, duration: int = 10) -> List[Dict]:
        """Scan for BLE devices."""
        devices = []
        
        if not self.check_bluetooth():
            return devices
        
        try:
            print(f"[*] Scanning for BLE devices ({duration}s)...")
            
            # Use hcitool for BLE scanning
            result = subprocess.run(['timeout', str(duration), 'hcitool', 'lescan'],
                                  capture_output=True, text=True)
            
            # Parse output
            seen_addresses = set()
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and ' ' in line:
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        address, name = parts
                        if address not in seen_addresses and ':' in address:
                            seen_addresses.add(address)
                            devices.append({
                                'address': address,
                                'name': name if name != '(unknown)' else 'Unknown',
                                'type': 'BLE'
                            })
        
        except Exception as e:
            print(f"[!] BLE scan error: {e}")
        
        return devices
    
    def analyze_ble_security(self, devices: List[Dict]) -> Dict:
        """Analyze BLE security implications."""
        analysis = {
            'total_devices': len(devices),
            'unnamed_devices': sum(1 for d in devices if d['name'] == 'Unknown'),
            'security_concerns': [
                'BLE devices may expose tracking identifiers',
                'Unnamed devices could be surveillance equipment',
                'BLE beacons can track physical location',
                'Some BLE devices have weak authentication'
            ],
            'recommendations': [
                'Disable Bluetooth when not in use',
                'Review paired BLE devices regularly',
                'Use address randomization where available',
                'Monitor for unauthorized BLE devices',
                'Keep firmware updated on BLE devices'
            ]
        }
        
        return analysis

def main():
    if len(sys.argv) < 2:
        print("Usage: ble_scanner.py <output_file> [duration]")
        sys.exit(1)
    
    output_file = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    scanner = BLEScanner()
    
    print("[*] Starting BLE device scan...")
    
    devices = scanner.scan_ble_devices(duration)
    analysis = scanner.analyze_ble_security(devices)
    
    output_data = {
        'timestamp': datetime.now().isoformat(),
        'scan_duration': duration,
        'devices': devices,
        'analysis': analysis
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] BLE scan complete.")
    print(f"[+] Found {len(devices)} BLE devices")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
