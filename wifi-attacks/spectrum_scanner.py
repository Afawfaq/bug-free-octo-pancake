#!/usr/bin/env python3
"""
Spectrum Scanner
Scans WiFi spectrum across 2.4 GHz, 5 GHz, and 6 GHz bands
"""

import sys
import json
import subprocess
from datetime import datetime
from typing import Dict, List

class SpectrumScanner:
    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.networks = []
    
    def check_interface(self) -> bool:
        """Check if WiFi interface exists and supports monitor mode."""
        try:
            result = subprocess.run(['iw', 'dev', self.interface, 'info'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"[*] Interface {self.interface} found")
                return True
            else:
                print(f"[!] Interface {self.interface} not found")
                return False
        except Exception as e:
            print(f"[!] Error checking interface: {e}")
            return False
    
    def scan_networks(self) -> List[Dict]:
        """Scan for WiFi networks using iwlist."""
        networks = []
        
        try:
            # Use iwlist for scanning
            result = subprocess.run(['iwlist', self.interface, 'scan'],
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                print(f"[!] Scan failed. May need root privileges.")
                return networks
            
            # Parse iwlist output
            current_network = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Cell' in line and 'Address:' in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {
                        'bssid': line.split('Address: ')[1].strip() if 'Address: ' in line else 'Unknown',
                        'channel': 'Unknown',
                        'frequency': 'Unknown',
                        'signal_strength': 'Unknown',
                        'essid': 'Hidden',
                        'encryption': 'Unknown',
                        'band': '2.4GHz'
                    }
                
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    current_network['essid'] = essid if essid else 'Hidden'
                
                elif 'Channel:' in line:
                    try:
                        channel = line.split('Channel:')[1].strip()
                        current_network['channel'] = int(channel)
                        
                        # Determine band by channel
                        if int(channel) <= 14:
                            current_network['band'] = '2.4GHz'
                        elif int(channel) <= 165:
                            current_network['band'] = '5GHz'
                        else:
                            current_network['band'] = '6GHz'
                    except:
                        pass
                
                elif 'Frequency:' in line:
                    freq = line.split('Frequency:')[1].split()[0].strip()
                    current_network['frequency'] = freq
                
                elif 'Quality=' in line or 'Signal level=' in line:
                    if 'Signal level=' in line:
                        signal = line.split('Signal level=')[1].split()[0].strip()
                        current_network['signal_strength'] = signal
                
                elif 'Encryption key:' in line:
                    if 'on' in line.lower():
                        current_network['encryption'] = 'Encrypted'
                    else:
                        current_network['encryption'] = 'Open'
                
                elif 'IE: IEEE 802.11i/WPA2' in line or 'WPA2' in line:
                    current_network['encryption'] = 'WPA2'
                
                elif 'IE: WPA Version' in line or 'WPA Version' in line:
                    current_network['encryption'] = 'WPA'
                
                elif 'WPA3' in line:
                    current_network['encryption'] = 'WPA3'
            
            # Add the last network
            if current_network:
                networks.append(current_network)
        
        except subprocess.TimeoutExpired:
            print("[!] Scan timeout")
        except Exception as e:
            print(f"[!] Error during scan: {e}")
        
        return networks
    
    def analyze_spectrum(self, networks: List[Dict]) -> Dict:
        """Analyze spectrum usage and congestion."""
        band_stats = {
            '2.4GHz': {'count': 0, 'channels': {}},
            '5GHz': {'count': 0, 'channels': {}},
            '6GHz': {'count': 0, 'channels': {}}
        }
        
        encryption_stats = {}
        hidden_networks = 0
        
        for network in networks:
            band = network.get('band', '2.4GHz')
            channel = network.get('channel', 'Unknown')
            encryption = network.get('encryption', 'Unknown')
            
            band_stats[band]['count'] += 1
            
            if channel != 'Unknown':
                if channel not in band_stats[band]['channels']:
                    band_stats[band]['channels'][channel] = 0
                band_stats[band]['channels'][channel] += 1
            
            encryption_stats[encryption] = encryption_stats.get(encryption, 0) + 1
            
            if network.get('essid') == 'Hidden':
                hidden_networks += 1
        
        return {
            'total_networks': len(networks),
            'band_distribution': band_stats,
            'encryption_distribution': encryption_stats,
            'hidden_networks': hidden_networks,
            'most_congested_24ghz': max(band_stats['2.4GHz']['channels'].items(), 
                                       key=lambda x: x[1])[0] if band_stats['2.4GHz']['channels'] else None,
            'most_congested_5ghz': max(band_stats['5GHz']['channels'].items(), 
                                      key=lambda x: x[1])[0] if band_stats['5GHz']['channels'] else None
        }

def main():
    if len(sys.argv) < 2:
        print("Usage: spectrum_scanner.py <output_file> [interface]")
        sys.exit(1)
    
    output_file = sys.argv[1]
    interface = sys.argv[2] if len(sys.argv) > 2 else "wlan0"
    
    scanner = SpectrumScanner(interface)
    
    print(f"[*] Starting WiFi spectrum scan on {interface}...")
    
    if not scanner.check_interface():
        # Create empty output
        output_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'interface': interface,
            'interface_available': False,
            'networks': [],
            'analysis': {}
        }
    else:
        networks = scanner.scan_networks()
        analysis = scanner.analyze_spectrum(networks)
        
        output_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'interface': interface,
            'interface_available': True,
            'networks': networks,
            'analysis': analysis
        }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Spectrum scan complete.")
    print(f"[+] Found {output_data.get('analysis', {}).get('total_networks', 0)} networks")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
