#!/usr/bin/env python3
"""
Dependency Mapper
Identifies and maps device dependencies (DNS, DHCP, NTP, gateways)
Helps identify soft targets in dependency chains
"""

import sys
import json
from scapy.all import *
from datetime import datetime
from collections import defaultdict

class DependencyMapper:
    def __init__(self):
        self.dependencies = defaultdict(lambda: {
            "dns_servers": set(),
            "ntp_servers": set(),
            "gateways": set(),
            "dhcp_servers": set(),
            "dependency_count": 0,
            "dependency_chains": []
        })
        self.service_providers = defaultdict(set)
    
    def capture_dependencies(self, duration=60):
        """Capture network traffic to map dependencies"""
        print(f"[*] Mapping dependencies for {duration} seconds...")
        
        def packet_handler(packet):
            self.analyze_packet(packet)
        
        sniff(prn=packet_handler, timeout=duration, store=False)
    
    def analyze_packet(self, packet):
        """Extract dependency information from packets"""
        if IP not in packet:
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # DNS dependencies
        if DNS in packet and packet[DNS].qr == 0:  # Query
            self.dependencies[src_ip]["dns_servers"].add(dst_ip)
            self.service_providers["dns"].add(dst_ip)
        
        # DHCP dependencies
        if DHCP in packet:
            if packet[BOOTP].op == 1:  # Request
                # Client is source
                for opt in packet[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'server_id':
                        server = opt[1]
                        self.dependencies[src_ip]["dhcp_servers"].add(server)
                        self.service_providers["dhcp"].add(server)
        
        # NTP dependencies (port 123)
        if UDP in packet and (packet[UDP].dport == 123 or packet[UDP].sport == 123):
            if packet[UDP].dport == 123:
                self.dependencies[src_ip]["ntp_servers"].add(dst_ip)
                self.service_providers["ntp"].add(dst_ip)
        
        # Gateway detection (default route)
        # Devices talking to external IPs reveal gateway usage
        if self.is_external_ip(dst_ip):
            # The gateway is likely the first hop
            gateway = self.extract_gateway(packet)
            if gateway:
                self.dependencies[src_ip]["gateways"].add(gateway)
                self.service_providers["gateway"].add(gateway)
    
    def is_external_ip(self, ip):
        """Check if IP is external (not private)"""
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return False
        return True
    
    def extract_gateway(self, packet):
        """Try to extract gateway from packet"""
        # This is simplified - in reality would need ARP table
        if Ether in packet:
            # Gateway MAC would be in Ether layer for routed packets
            return None  # Placeholder
        return None
    
    def calculate_dependency_score(self, device_deps):
        """Calculate how dependent a device is"""
        score = 0
        score += len(device_deps["dns_servers"]) * 10
        score += len(device_deps["ntp_servers"]) * 5
        score += len(device_deps["dhcp_servers"]) * 15
        score += len(device_deps["gateways"]) * 20
        return score
    
    def find_soft_targets(self):
        """Identify soft targets in dependency chains"""
        soft_targets = []
        
        # Service providers are soft targets (if compromised, affect many)
        for service_type, providers in self.service_providers.items():
            for provider in providers:
                dependent_count = sum(
                    1 for deps in self.dependencies.values()
                    if provider in deps.get(f"{service_type}_servers", set())
                )
                
                if dependent_count > 2:  # Multiple devices depend on it
                    soft_targets.append({
                        "target": provider,
                        "type": service_type,
                        "dependent_devices": dependent_count,
                        "impact_score": dependent_count * 20,
                        "risk": "HIGH" if dependent_count > 5 else "MEDIUM"
                    })
        
        return sorted(soft_targets, key=lambda x: x['impact_score'], reverse=True)
    
    def map_attack_chains(self):
        """Map potential attack chains through dependencies"""
        chains = []
        
        # For each device, calculate path to critical services
        for device, deps in self.dependencies.items():
            if deps["dns_servers"] or deps["dhcp_servers"]:
                chain = {
                    "entry_point": device,
                    "can_compromise": [],
                    "chain_length": 0
                }
                
                # If we compromise this device, what can we impersonate?
                if deps["dns_servers"]:
                    chain["can_compromise"].append({
                        "type": "dns_poisoning",
                        "targets": list(deps["dns_servers"]),
                        "impact": "All DNS clients"
                    })
                
                if deps["dhcp_servers"]:
                    chain["can_compromise"].append({
                        "type": "dhcp_spoofing",
                        "targets": list(deps["dhcp_servers"]),
                        "impact": "Network configuration control"
                    })
                
                if chain["can_compromise"]:
                    chain["chain_length"] = len(chain["can_compromise"])
                    chains.append(chain)
        
        return chains
    
    def save_results(self, output_file):
        """Save dependency mapping results"""
        # Convert sets to lists for JSON serialization
        serializable_deps = {}
        for device, deps in self.dependencies.items():
            serializable_deps[device] = {
                "dns_servers": list(deps["dns_servers"]),
                "ntp_servers": list(deps["ntp_servers"]),
                "gateways": list(deps["gateways"]),
                "dhcp_servers": list(deps["dhcp_servers"]),
                "dependency_score": self.calculate_dependency_score(deps)
            }
        
        results = {
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(serializable_deps),
            "dependencies": serializable_deps,
            "soft_targets": self.find_soft_targets(),
            "attack_chains": self.map_attack_chains(),
            "service_providers": {
                k: list(v) for k, v in self.service_providers.items()
            },
            "summary": {
                "total_dns_servers": len(self.service_providers.get("dns", [])),
                "total_dhcp_servers": len(self.service_providers.get("dhcp", [])),
                "total_ntp_servers": len(self.service_providers.get("ntp", [])),
                "highest_impact_target": self.find_soft_targets()[0] if self.find_soft_targets() else None
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Dependency mapping complete:")
        print(f"    Devices mapped: {len(serializable_deps)}")
        print(f"    Soft targets found: {len(results['soft_targets'])}")
        print(f"    Attack chains identified: {len(results['attack_chains'])}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <duration_seconds> <output_file>")
        sys.exit(1)
    
    duration = int(sys.argv[1])
    output_file = sys.argv[2]
    
    mapper = DependencyMapper()
    mapper.capture_dependencies(duration)
    mapper.save_results(output_file)

if __name__ == "__main__":
    main()
