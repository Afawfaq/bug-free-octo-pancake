#!/usr/bin/env python3
"""
DHCP Personality Profiler
Analyzes DHCP requests to build device personality profiles
"""

import sys
import json
from scapy.all import *
from datetime import datetime
from collections import defaultdict

class DHCPProfiler:
    def __init__(self):
        self.devices = defaultdict(lambda: {
            "requests": [],
            "fingerprints": [],
            "hostnames": set(),
            "vendors": set(),
            "first_seen": None,
            "last_seen": None
        })
    
    def analyze_dhcp_packet(self, packet):
        """Extract personality from DHCP packet"""
        if DHCP in packet:
            # Get MAC address
            mac = packet[Ether].src if Ether in packet else None
            if not mac:
                return
            
            # Extract DHCP options
            options = {}
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and len(opt) == 2:
                    options[opt[0]] = opt[1]
            
            timestamp = datetime.now().isoformat()
            
            # Update device profile
            device = self.devices[mac]
            if not device["first_seen"]:
                device["first_seen"] = timestamp
            device["last_seen"] = timestamp
            
            # Extract fingerprint
            fingerprint = {
                "timestamp": timestamp,
                "message_type": options.get('message-type', 'unknown'),
                "requested_ip": packet[BOOTP].ciaddr if BOOTP in packet else None,
                "vendor_class": options.get('vendor_class_id', '').decode() if 'vendor_class_id' in options else None,
                "hostname": options.get('hostname', b'').decode() if 'hostname' in options else None,
                "param_request_list": options.get('param_req_list', [])
            }
            
            device["requests"].append(fingerprint)
            
            if fingerprint["hostname"]:
                device["hostnames"].add(fingerprint["hostname"])
            
            if fingerprint["vendor_class"]:
                device["vendors"].add(fingerprint["vendor_class"])
            
            # OS fingerprinting based on DHCP options
            device["fingerprints"].append(self.guess_os(options))
    
    def guess_os(self, options):
        """Guess OS from DHCP options"""
        param_list = options.get('param_req_list', [])
        vendor = options.get('vendor_class_id', b'').decode() if 'vendor_class_id' in options else ''
        
        os_guess = "Unknown"
        
        if 'MSFT' in vendor or 'Microsoft' in vendor:
            os_guess = "Windows"
        elif 'android' in vendor.lower():
            os_guess = "Android"
        elif 'iPhone' in vendor or 'iPad' in vendor:
            os_guess = "iOS"
        elif 'dhcpcd' in vendor:
            os_guess = "Linux/Unix"
        
        return {
            "os": os_guess,
            "confidence": "high" if vendor else "low",
            "vendor_string": vendor
        }
    
    def save_results(self, output_file):
        """Save profiling results"""
        results = {
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(self.devices),
            "devices": {}
        }
        
        for mac, data in self.devices.items():
            results["devices"][mac] = {
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"],
                "request_count": len(data["requests"]),
                "hostnames": list(data["hostnames"]),
                "vendors": list(data["vendors"]),
                "os_guesses": data["fingerprints"],
                "recent_requests": data["requests"][-5:]  # Last 5 requests
            }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

def capture_dhcp(duration, output_file):
    """Capture DHCP traffic and profile devices"""
    print(f"[*] Capturing DHCP traffic for {duration} seconds...")
    
    profiler = DHCPProfiler()
    
    def packet_handler(packet):
        profiler.analyze_dhcp_packet(packet)
    
    # Capture DHCP traffic
    sniff(filter="udp and (port 67 or port 68)", 
          prn=packet_handler, 
          timeout=duration,
          store=False)
    
    profiler.save_results(output_file)
    print(f"[+] DHCP profiling complete: {len(profiler.devices)} devices profiled")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <duration_seconds> <output_file>")
        sys.exit(1)
    
    duration = int(sys.argv[1])
    output_file = sys.argv[2]
    
    capture_dhcp(duration, output_file)
