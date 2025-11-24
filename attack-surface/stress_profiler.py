#!/usr/bin/env python3
"""
Stress Profiler - Detect devices that leak info under stress
Tests how devices behave when protocols are stressed (non-destructively)
"""

import sys
import json
from scapy.all import *
from datetime import datetime
from collections import defaultdict
import time

class StressProfiler:
    def __init__(self):
        self.baseline_responses = defaultdict(list)
        self.stress_responses = defaultdict(list)
        self.leaked_info = defaultdict(list)
    
    def capture_baseline(self, target, duration=10):
        """Capture normal device behavior"""
        print(f"[*] Capturing baseline for {target}...")
        
        def packet_handler(packet):
            if IP in packet and packet[IP].src == target:
                self.baseline_responses[target].append({
                    "time": time.time(),
                    "protocol": packet.sprintf("%IP.proto%"),
                    "size": len(packet)
                })
        
        sniff(filter=f"host {target}", prn=packet_handler, timeout=duration, store=False)
    
    def stress_mdns(self, target):
        """Send multiple mDNS queries to trigger verbose responses"""
        print(f"[*] Stress testing mDNS on {target}...")
        
        queries = [
            "_services._dns-sd._udp.local",
            "_http._tcp.local",
            "_printer._tcp.local",
            "_airplay._tcp.local",
            "_googlecast._tcp.local",
            "_device-info._tcp.local"
        ]
        
        responses = []
        for query in queries:
            try:
                # Send mDNS query
                pkt = IP(dst="224.0.0.251")/UDP(dport=5353)/DNS(
                    qd=DNSQR(qname=query, qtype="PTR")
                )
                ans = sr1(pkt, timeout=2, verbose=0)
                if ans:
                    responses.append({
                        "query": query,
                        "response_size": len(ans),
                        "has_answer": ans.haslayer(DNS) and ans[DNS].ancount > 0
                    })
            except:
                pass
        
        return responses
    
    def stress_ssdp(self, target):
        """Send SSDP M-SEARCH to trigger device announcements"""
        print(f"[*] Stress testing SSDP on {target}...")
        
        search_types = [
            "ssdp:all",
            "upnp:rootdevice",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "urn:schemas-upnp-org:device:MediaServer:1",
            "urn:dial-multiscreen-org:service:dial:1"
        ]
        
        responses = []
        for st in search_types:
            try:
                message = f"M-SEARCH * HTTP/1.1\r\n" \
                         f"HOST: 239.255.255.250:1900\r\n" \
                         f"MAN: \"ssdp:discover\"\r\n" \
                         f"MX: 2\r\n" \
                         f"ST: {st}\r\n\r\n"
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(message.encode(), ("239.255.255.250", 1900))
                
                try:
                    data, addr = sock.recvfrom(8192)
                    if addr[0] == target:
                        responses.append({
                            "search_type": st,
                            "response_length": len(data),
                            "response_preview": data.decode('utf-8', errors='ignore')[:200]
                        })
                except socket.timeout:
                    pass
                finally:
                    sock.close()
            except:
                pass
        
        return responses
    
    def check_undocumented_ports(self, target):
        """Probe undocumented ports with crafted packets"""
        print(f"[*] Probing undocumented ports on {target}...")
        
        interesting_ports = [
            8008,   # Chromecast
            9100,   # Raw printer
            10001,  # IoT discovery
            8080,   # Alt HTTP
            8443,   # Alt HTTPS
            49152,  # UPnP dynamic
            5353,   # mDNS
            1900    # SSDP
        ]
        
        findings = []
        for port in interesting_ports:
            try:
                # TCP SYN probe
                pkt = IP(dst=target)/TCP(dport=port, flags="S")
                ans = sr1(pkt, timeout=1, verbose=0)
                
                if ans and ans.haslayer(TCP) and ans[TCP].flags == 0x12:  # SYN-ACK
                    findings.append({
                        "port": port,
                        "state": "open",
                        "flags": "SYN-ACK"
                    })
                    
                    # Send RST to close
                    rst = IP(dst=target)/TCP(dport=port, flags="R")
                    send(rst, verbose=0)
            except:
                pass
        
        return findings
    
    def analyze_stress_response(self, target, baseline_count, stress_data):
        """Analyze if device leaked more info under stress"""
        leaked = []
        
        # Check if stress produced more responses
        if len(stress_data.get('mdns_responses', [])) > baseline_count:
            leaked.append({
                "type": "mdns_verbose_mode",
                "severity": "medium",
                "detail": f"Device responded to {len(stress_data['mdns_responses'])} mDNS queries"
            })
        
        # Check SSDP verbosity
        ssdp_responses = stress_data.get('ssdp_responses', [])
        if ssdp_responses:
            leaked.append({
                "type": "ssdp_info_disclosure",
                "severity": "high",
                "detail": f"Device exposed {len(ssdp_responses)} SSDP service types",
                "sample": ssdp_responses[0].get('response_preview', '')[:100] if ssdp_responses else ''
            })
        
        # Check undocumented ports
        open_ports = [p['port'] for p in stress_data.get('undocumented_ports', []) if p['state'] == 'open']
        if open_ports:
            leaked.append({
                "type": "undocumented_ports_open",
                "severity": "high",
                "detail": f"Undocumented ports open: {open_ports}"
            })
        
        return leaked
    
    def profile_device(self, target):
        """Complete stress profile of a device"""
        print(f"\n[*] Stress profiling {target}...")
        
        # Baseline
        self.capture_baseline(target, 10)
        baseline_count = len(self.baseline_responses[target])
        
        # Stress tests
        stress_data = {
            "mdns_responses": self.stress_mdns(target),
            "ssdp_responses": self.stress_ssdp(target),
            "undocumented_ports": self.check_undocumented_ports(target)
        }
        
        # Analyze
        leaks = self.analyze_stress_response(target, baseline_count, stress_data)
        
        return {
            "target": target,
            "baseline_packet_count": baseline_count,
            "stress_data": stress_data,
            "leaked_information": leaks,
            "vulnerability_score": len(leaks) * 10
        }
    
    def save_results(self, results, output_file):
        """Save stress profiling results"""
        output = {
            "scan_time": datetime.now().isoformat(),
            "profiles": results,
            "summary": {
                "total_devices": len(results),
                "devices_with_leaks": sum(1 for r in results if r['leaked_information']),
                "average_vulnerability_score": sum(r['vulnerability_score'] for r in results) / len(results) if results else 0
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Stress profiling complete:")
        print(f"    Devices tested: {len(results)}")
        print(f"    Devices with leaks: {output['summary']['devices_with_leaks']}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <targets_file> <output_file>")
        sys.exit(1)
    
    # Read targets
    with open(sys.argv[1]) as f:
        targets = [line.strip() for line in f if line.strip()]
    
    profiler = StressProfiler()
    results = []
    
    for target in targets[:5]:  # Limit to prevent overwhelming network
        try:
            result = profiler.profile_device(target)
            results.append(result)
        except Exception as e:
            print(f"[-] Error profiling {target}: {e}")
    
    profiler.save_results(results, sys.argv[2])

if __name__ == "__main__":
    main()
