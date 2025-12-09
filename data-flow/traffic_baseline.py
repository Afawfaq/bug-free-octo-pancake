#!/usr/bin/env python3
"""
Traffic Baseline Builder
Establishes normal behavior patterns for each device on the network
"""

import sys
import json
import time
from collections import defaultdict, Counter
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from typing import Dict, List

class TrafficBaselineBuilder:
    def __init__(self):
        self.device_profiles = defaultdict(lambda: {
            'total_packets': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'destinations': Counter(),
            'protocols': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'inter_arrival_times': [],
            'first_seen': None,
            'last_seen': None
        })
        self.last_packet_time = {}
    
    def process_packet(self, packet):
        """Process a single packet and update baseline."""
        try:
            if not packet.haslayer(IP):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = time.time()
            packet_size = len(packet)
            
            # Update source device profile
            profile = self.device_profiles[src_ip]
            profile['total_packets'] += 1
            profile['bytes_sent'] += packet_size
            profile['destinations'][dst_ip] += 1
            profile['packet_sizes'].append(packet_size)
            
            # Update timestamps
            if profile['first_seen'] is None:
                profile['first_seen'] = timestamp
            profile['last_seen'] = timestamp
            
            # Calculate inter-arrival time
            if src_ip in self.last_packet_time:
                inter_arrival = timestamp - self.last_packet_time[src_ip]
                profile['inter_arrival_times'].append(inter_arrival)
            self.last_packet_time[src_ip] = timestamp
            
            # Protocol analysis
            if packet.haslayer(TCP):
                profile['protocols']['TCP'] += 1
                profile['ports'][packet[TCP].dport] += 1
            elif packet.haslayer(UDP):
                profile['protocols']['UDP'] += 1
                profile['ports'][packet[UDP].dport] += 1
            else:
                profile['protocols']['OTHER'] += 1
            
            # Update destination device profile (received traffic)
            dst_profile = self.device_profiles[dst_ip]
            dst_profile['bytes_received'] += packet_size
            
        except Exception as e:
            pass
    
    def calculate_statistics(self):
        """Calculate statistical features for each device."""
        baselines = {}
        
        for device_ip, profile in self.device_profiles.items():
            if profile['total_packets'] < 10:  # Skip devices with too few packets
                continue
            
            # Calculate basic statistics
            avg_packet_size = sum(profile['packet_sizes']) / len(profile['packet_sizes']) if profile['packet_sizes'] else 0
            
            # Calculate destination diversity (Shannon entropy)
            total_dests = sum(profile['destinations'].values())
            destination_entropy = 0
            if total_dests > 0:
                for count in profile['destinations'].values():
                    p = count / total_dests
                    if p > 0:
                        destination_entropy -= p * (p ** 0.5)  # Simplified entropy
            
            # Top destinations
            top_destinations = dict(profile['destinations'].most_common(5))
            
            # Protocol mix
            protocol_mix = {
                proto: count / profile['total_packets'] 
                for proto, count in profile['protocols'].items()
            }
            
            # Top ports
            top_ports = dict(profile['ports'].most_common(10))
            
            # Activity duration
            duration = 0
            if profile['first_seen'] and profile['last_seen']:
                duration = profile['last_seen'] - profile['first_seen']
            
            # Average inter-arrival time
            avg_inter_arrival = 0
            if profile['inter_arrival_times']:
                avg_inter_arrival = sum(profile['inter_arrival_times']) / len(profile['inter_arrival_times'])
            
            baselines[device_ip] = {
                'total_packets': profile['total_packets'],
                'bytes_sent': profile['bytes_sent'],
                'bytes_received': profile['bytes_received'],
                'avg_packet_size': round(avg_packet_size, 2),
                'destination_diversity': round(destination_entropy, 4),
                'top_destinations': top_destinations,
                'protocol_mix': protocol_mix,
                'top_ports': top_ports,
                'activity_duration_seconds': round(duration, 2),
                'avg_inter_arrival_time': round(avg_inter_arrival, 4),
                'packets_per_second': round(profile['total_packets'] / duration, 2) if duration > 0 else 0,
                'first_seen': datetime.fromtimestamp(profile['first_seen']).isoformat() if profile['first_seen'] else None,
                'last_seen': datetime.fromtimestamp(profile['last_seen']).isoformat() if profile['last_seen'] else None
            }
        
        return baselines
    
    def capture_and_baseline(self, duration: int = 300, interface: str = "eth0"):
        """Capture traffic and build baselines."""
        print(f"[*] Capturing traffic for {duration} seconds to build baseline...")
        print(f"[*] Interface: {interface}")
        
        try:
            sniff(
                prn=self.process_packet,
                timeout=duration,
                iface=interface,
                store=False
            )
        except Exception as e:
            print(f"[!] Error during packet capture: {e}")
        
        print(f"[*] Captured packets from {len(self.device_profiles)} devices")
        
        return self.calculate_statistics()

def main():
    if len(sys.argv) < 2:
        print("Usage: traffic_baseline.py <output_file> [duration] [interface]")
        sys.exit(1)
    
    output_file = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    interface = sys.argv[3] if len(sys.argv) > 3 else "eth0"
    
    builder = TrafficBaselineBuilder()
    baselines = builder.capture_and_baseline(duration=duration, interface=interface)
    
    # Save results
    output_data = {
        "capture_duration_seconds": duration,
        "devices_profiled": len(baselines),
        "capture_timestamp": datetime.now().isoformat(),
        "baselines": baselines,
        "summary": {
            "total_devices": len(baselines),
            "most_active_device": max(baselines.items(), key=lambda x: x[1]['total_packets'])[0] if baselines else None
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Traffic baseline complete.")
    print(f"[+] Profiled {len(baselines)} devices")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
