#!/usr/bin/env python3
"""
Passive DNS Mapper (Local LAN version)
Maps DNS queries to detect malware beaconing, IoT tattletales, and suspicious patterns
"""

import sys
import json
from scapy.all import *
from datetime import datetime
from collections import defaultdict
import socket

class DNSMapper:
    def __init__(self):
        self.queries = defaultdict(list)
        self.suspicious_domains = []
        self.stats = defaultdict(int)
    
    def analyze_dns_packet(self, packet):
        """Extract and analyze DNS queries"""
        if DNS in packet and packet[DNS].qr == 0:  # Query
            timestamp = datetime.now().isoformat()
            
            src_ip = packet[IP].src if IP in packet else "unknown"
            query = packet[DNSQR].qname.decode() if hasattr(packet[DNSQR].qname, 'decode') else str(packet[DNSQR].qname)
            qtype = packet[DNSQR].qtype
            
            query_info = {
                "timestamp": timestamp,
                "query": query,
                "type": qtype,
                "type_name": self.get_qtype_name(qtype)
            }
            
            self.queries[src_ip].append(query_info)
            self.stats["total_queries"] += 1
            
            # Detect suspicious patterns
            if self.is_suspicious(query, src_ip):
                self.suspicious_domains.append({
                    "source": src_ip,
                    "query": query,
                    "timestamp": timestamp,
                    "reason": self.get_suspicion_reason(query)
                })
    
    def get_qtype_name(self, qtype):
        """Convert query type number to name"""
        types = {
            1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 
            12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
            33: "SRV", 255: "ANY"
        }
        return types.get(qtype, f"TYPE{qtype}")
    
    def is_suspicious(self, query, src_ip):
        """Detect suspicious DNS queries"""
        query_lower = query.lower()
        
        # Check for DGA-like patterns
        if len(query) > 30 and query.count('.') > 3:
            return True
        
        # Check for known bad TLDs
        bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        if any(query_lower.endswith(tld) for tld in bad_tlds):
            return True
        
        # Check for high entropy (random-looking)
        if self.calculate_entropy(query) > 4.5:
            return True
        
        # Check for beaconing patterns (too many queries to same domain)
        domain_count = sum(1 for q in self.queries[src_ip] if q["query"] == query)
        if domain_count > 10:
            return True
        
        return False
    
    def calculate_entropy(self, string):
        """Calculate Shannon entropy"""
        import math
        if not string:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(string.count(chr(x))) / len(string)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy
    
    def get_suspicion_reason(self, query):
        """Explain why query is suspicious"""
        reasons = []
        
        if len(query) > 30:
            reasons.append("Long domain name")
        
        if self.calculate_entropy(query) > 4.5:
            reasons.append("High entropy (random-looking)")
        
        bad_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if any(query.lower().endswith(tld) for tld in bad_tlds):
            reasons.append("Suspicious TLD")
        
        return ", ".join(reasons) if reasons else "Multiple queries"
    
    def save_results(self, output_file):
        """Save DNS mapping results"""
        results = {
            "scan_time": datetime.now().isoformat(),
            "statistics": dict(self.stats),
            "total_sources": len(self.queries),
            "suspicious_count": len(self.suspicious_domains),
            "queries_by_host": {},
            "suspicious_domains": self.suspicious_domains,
            "top_queried": self.get_top_domains(10)
        }
        
        for src_ip, queries in self.queries.items():
            results["queries_by_host"][src_ip] = {
                "total_queries": len(queries),
                "unique_domains": len(set(q["query"] for q in queries)),
                "recent_queries": queries[-10:]  # Last 10
            }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def get_top_domains(self, n=10):
        """Get most queried domains"""
        all_queries = []
        for queries in self.queries.values():
            all_queries.extend([q["query"] for q in queries])
        
        from collections import Counter
        top = Counter(all_queries).most_common(n)
        return [{"domain": domain, "count": count} for domain, count in top]

def capture_dns(duration, output_file):
    """Capture DNS traffic and map queries"""
    print(f"[*] Capturing DNS traffic for {duration} seconds...")
    
    mapper = DNSMapper()
    
    def packet_handler(packet):
        mapper.analyze_dns_packet(packet)
    
    # Capture DNS traffic
    sniff(filter="udp port 53", 
          prn=packet_handler, 
          timeout=duration,
          store=False)
    
    mapper.save_results(output_file)
    print(f"[+] DNS mapping complete:")
    print(f"    Total queries: {mapper.stats['total_queries']}")
    print(f"    Unique sources: {len(mapper.queries)}")
    print(f"    Suspicious: {len(mapper.suspicious_domains)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <duration_seconds> <output_file>")
        sys.exit(1)
    
    duration = int(sys.argv[1])
    output_file = sys.argv[2]
    
    capture_dns(duration, output_file)
