#!/usr/bin/env python3
"""
Metadata Ghost Extractor
Collects all protocol metadata leakage into a unified profile
"""

import sys
import json
from scapy.all import *
from datetime import datetime
from collections import defaultdict

class MetadataExtractor:
    def __init__(self):
        self.metadata = defaultdict(lambda: {
            "dhcp_hostname": None,
            "smb_workstation": None,
            "mdns_services": [],
            "http_user_agents": [],
            "printer_banners": [],
            "ipv6_eui64": None,
            "first_seen": None,
            "last_seen": None
        })
    
    def extract_from_packet(self, packet):
        """Extract metadata from any protocol"""
        timestamp = datetime.now().isoformat()
        
        if IP in packet:
            ip = packet[IP].src
            self.update_timestamp(ip, timestamp)
            
            # DHCP hostname
            if DHCP in packet:
                self.extract_dhcp_metadata(packet, ip)
            
            # mDNS services
            if DNS in packet and packet.haslayer(DNSQR):
                self.extract_mdns_metadata(packet, ip)
            
            # HTTP User-Agent
            if Raw in packet and b'User-Agent:' in bytes(packet[Raw]):
                self.extract_http_metadata(packet, ip)
        
        if Ether in packet:
            mac = packet[Ether].src
            if IPv6 in packet:
                self.extract_ipv6_metadata(packet, mac)
    
    def extract_dhcp_metadata(self, packet, ip):
        """Extract DHCP hostname"""
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'hostname':
                hostname = opt[1].decode() if isinstance(opt[1], bytes) else str(opt[1])
                self.metadata[ip]["dhcp_hostname"] = hostname
    
    def extract_mdns_metadata(self, packet, ip):
        """Extract mDNS service announcements"""
        if packet[DNS].qr == 0:  # Query
            query = packet[DNSQR].qname.decode() if hasattr(packet[DNSQR].qname, 'decode') else str(packet[DNSQR].qname)
            if '_' in query:  # Likely a service
                self.metadata[ip]["mdns_services"].append(query)
    
    def extract_http_metadata(self, packet, ip):
        """Extract HTTP User-Agent"""
        try:
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
            for line in payload.split('\r\n'):
                if line.startswith('User-Agent:'):
                    ua = line.split(':', 1)[1].strip()
                    if ua not in self.metadata[ip]["http_user_agents"]:
                        self.metadata[ip]["http_user_agents"].append(ua)
        except:
            pass
    
    def extract_ipv6_metadata(self, packet, mac):
        """Extract IPv6 EUI-64 from MAC"""
        if IPv6 in packet:
            ipv6_addr = packet[IPv6].src
            # Check if it's EUI-64 based
            if 'fe80::' in ipv6_addr or 'ff:fe' in ipv6_addr:
                for ip in self.metadata:
                    if self.metadata[ip].get("mac") == mac:
                        self.metadata[ip]["ipv6_eui64"] = ipv6_addr
    
    def update_timestamp(self, ip, timestamp):
        """Update first/last seen timestamps"""
        if not self.metadata[ip]["first_seen"]:
            self.metadata[ip]["first_seen"] = timestamp
        self.metadata[ip]["last_seen"] = timestamp
    
    def save_results(self, output_file):
        """Save metadata extraction results"""
        results = {
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(self.metadata),
            "metadata": {}
        }
        
        for ip, data in self.metadata.items():
            # Calculate completeness score
            fields_filled = sum([
                1 if data["dhcp_hostname"] else 0,
                1 if data["smb_workstation"] else 0,
                len(data["mdns_services"]),
                len(data["http_user_agents"]),
                1 if data["ipv6_eui64"] else 0
            ])
            
            results["metadata"][ip] = {
                **data,
                "mdns_services": list(set(data["mdns_services"])),  # Deduplicate
                "completeness_score": fields_filled,
                "identity_leak_risk": "high" if fields_filled > 3 else "medium" if fields_filled > 1 else "low"
            }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

def capture_metadata(duration, output_file):
    """Capture traffic and extract all metadata"""
    print(f"[*] Extracting metadata for {duration} seconds...")
    
    extractor = MetadataExtractor()
    
    def packet_handler(packet):
        extractor.extract_from_packet(packet)
    
    # Capture all relevant traffic
    sniff(prn=packet_handler, timeout=duration, store=False)
    
    extractor.save_results(output_file)
    print(f"[+] Metadata extraction complete: {len(extractor.metadata)} devices profiled")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <duration_seconds> <output_file>")
        sys.exit(1)
    
    duration = int(sys.argv[1])
    output_file = sys.argv[2]
    
    capture_metadata(duration, output_file)
