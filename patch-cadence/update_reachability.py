#!/usr/bin/env python3
"""
Update Server Reachability Tester
Tests if devices can reach their update servers
"""

import sys
import json
import socket
import subprocess
from typing import Dict, List

class UpdateReachabilityTester:
    def __init__(self):
        self.common_update_servers = {
            "HP": ["h30318.www3.hp.com", "h20566.www2.hp.com"],
            "Epson": ["download.epson-europe.com", "download.epson.com"],
            "Canon": ["software.canon-europe.com", "cweb.canon.jp"],
            "Brother": ["support.brother.com", "download.brother.com"],
            "Google": ["clients2.google.com", "update.googleapis.com"],
            "Samsung": ["ospserver.net", "samsungcloudsolution.com"],
            "Microsoft": ["update.microsoft.com", "windowsupdate.com"],
            "Apple": ["swscan.apple.com", "updates.apple.com"]
        }
    
    def test_dns_resolution(self, hostname: str) -> bool:
        """Test if hostname can be resolved"""
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False
    
    def test_http_connectivity(self, hostname: str) -> bool:
        """Test if HTTP/HTTPS connection can be established"""
        try:
            import requests
            response = requests.head(f"https://{hostname}", timeout=5, verify=False)
            return True
        except:
            try:
                response = requests.head(f"http://{hostname}", timeout=5)
                return True
            except:
                return False
    
    def test_server_reachability(self, server: str) -> Dict:
        """Test reachability of an update server"""
        result = {
            "server": server,
            "dns_resolves": False,
            "http_reachable": False,
            "status": "UNREACHABLE"
        }
        
        # Test DNS
        if self.test_dns_resolution(server):
            result["dns_resolves"] = True
            
            # Test HTTP connectivity
            if self.test_http_connectivity(server):
                result["http_reachable"] = True
                result["status"] = "REACHABLE"
            else:
                result["status"] = "DNS_ONLY"
        
        return result
    
    def test_all_servers(self) -> Dict:
        """Test reachability of all common update servers"""
        results = {}
        
        for vendor, servers in self.common_update_servers.items():
            vendor_results = []
            
            for server in servers:
                print(f"[*] Testing {vendor} - {server}...")
                result = self.test_server_reachability(server)
                vendor_results.append(result)
            
            results[vendor] = vendor_results
        
        return results

def main():
    if len(sys.argv) < 2:
        print("Usage: update_reachability.py <output_file>")
        sys.exit(1)
    
    output_file = sys.argv[1]
    
    print("[*] Testing update server reachability...")
    
    tester = UpdateReachabilityTester()
    results = tester.test_all_servers()
    
    # Calculate summary statistics
    total_servers = sum(len(servers) for servers in results.values())
    reachable_servers = sum(
        1 for vendor_results in results.values()
        for server in vendor_results
        if server["status"] == "REACHABLE"
    )
    
    output_data = {
        "total_servers_tested": total_servers,
        "reachable_servers": reachable_servers,
        "reachability_rate": f"{(reachable_servers/total_servers)*100:.1f}%",
        "vendor_results": results,
        "security_implications": [
            "Devices unable to reach update servers may be running outdated firmware",
            "DNS resolution failures could indicate network configuration issues",
            "Blocked update servers could be due to firewall rules",
            "Consider implementing a local update server or proxy"
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Update server reachability test complete.")
    print(f"[+] {reachable_servers}/{total_servers} servers reachable")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
