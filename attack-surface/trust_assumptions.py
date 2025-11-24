#!/usr/bin/env python3
"""
Trust Assumptions Tester
Tests devices that assume "friendly LAN" and have weak/no authentication
"""

import sys
import json
import requests
import socket
from datetime import datetime

class TrustAssumptionsTester:
    def __init__(self):
        self.findings = []
    
    def test_printer_unauth_print(self, target):
        """Test if printer accepts unauthenticated print jobs"""
        findings = []
        
        # Test JetDirect (port 9100)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, 9100))
            
            if result == 0:
                # Try sending a test print job
                test_job = b"%!PS-Adobe-3.0\n%%Title: Test\n%%EndComments\n/Helvetica findfont 12 scalefont setfont\n100 100 moveto\n(Security Test) show\nshowpage\n"
                sock.send(test_job)
                
                findings.append({
                    "test": "printer_unauth_print",
                    "port": 9100,
                    "vulnerable": True,
                    "severity": "HIGH",
                    "description": "Printer accepts unauthenticated raw print jobs"
                })
            sock.close()
        except:
            pass
        
        return findings
    
    def test_chromecast_unauth_control(self, target):
        """Test if Chromecast accepts unauthenticated control"""
        findings = []
        
        endpoints = [
            "/setup/eureka_info",
            "/setup/offer"
        ]
        
        for endpoint in endpoints:
            try:
                resp = requests.get(f"http://{target}:8008{endpoint}", timeout=3)
                if resp.status_code == 200:
                    findings.append({
                        "test": "chromecast_unauth_api",
                        "endpoint": endpoint,
                        "vulnerable": True,
                        "severity": "MEDIUM",
                        "description": "Chromecast API accessible without authentication"
                    })
            except:
                pass
        
        return findings
    
    def test_tv_remote_control(self, target):
        """Test if TV accepts unauthenticated remote control"""
        findings = []
        
        # DLNA control endpoints
        try:
            resp = requests.post(
                f"http://{target}:8008/apps/Netflix",
                timeout=3,
                data=""
            )
            if resp.status_code != 404:  # Responds to control attempt
                findings.append({
                    "test": "tv_unauth_control",
                    "vulnerable": True,
                    "severity": "MEDIUM",
                    "description": "TV accepts remote control commands without authentication"
                })
        except:
            pass
        
        return findings
    
    def test_upnp_open_gateway(self, target):
        """Test if router UPnP is open"""
        findings = []
        
        try:
            # Try to get external IP via UPnP
            resp = requests.get(f"http://{target}:5000/rootDesc.xml", timeout=3)
            if resp.status_code == 200 and "InternetGatewayDevice" in resp.text:
                findings.append({
                    "test": "upnp_open_gateway",
                    "vulnerable": True,
                    "severity": "CRITICAL",
                    "description": "Router UPnP IGD exposed without authentication"
                })
        except:
            pass
        
        return findings
    
    def test_netbios_broadcast_response(self, target):
        """Test if device responds to NetBIOS broadcasts"""
        findings = []
        
        # This would require sending actual NetBIOS packets
        # Simplified version checks for port 137
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect((target, 137))
            
            findings.append({
                "test": "netbios_responsive",
                "vulnerable": True,
                "severity": "LOW",
                "description": "Device responds to NetBIOS queries (indicates Windows trust)"
            })
            sock.close()
        except:
            pass
        
        return findings
    
    def test_mdns_spoofing_response(self, target):
        """Test if device trusts mDNS responses"""
        findings = []
        
        # Check if device has open mDNS
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect((target, 5353))
            
            findings.append({
                "test": "mdns_trust",
                "vulnerable": True,
                "severity": "MEDIUM",
                "description": "Device likely trusts mDNS broadcasts (spoofing risk)"
            })
            sock.close()
        except:
            pass
        
        return findings
    
    def test_ssdp_trust(self, target):
        """Test if device trusts SSDP announcements"""
        findings = []
        
        # Check for SSDP listener
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect((target, 1900))
            
            findings.append({
                "test": "ssdp_trust",
                "vulnerable": True,
                "severity": "MEDIUM",
                "description": "Device listens to SSDP (trusts UPnP announcements)"
            })
            sock.close()
        except:
            pass
        
        return findings
    
    def test_device(self, target):
        """Run all trust assumption tests"""
        print(f"[*] Testing trust assumptions for {target}...")
        
        all_findings = []
        all_findings.extend(self.test_printer_unauth_print(target))
        all_findings.extend(self.test_chromecast_unauth_control(target))
        all_findings.extend(self.test_tv_remote_control(target))
        all_findings.extend(self.test_upnp_open_gateway(target))
        all_findings.extend(self.test_netbios_broadcast_response(target))
        all_findings.extend(self.test_mdns_spoofing_response(target))
        all_findings.extend(self.test_ssdp_trust(target))
        
        return {
            "target": target,
            "findings": all_findings,
            "total_vulnerabilities": len(all_findings),
            "critical_count": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "trust_score": len(all_findings) * 10  # Higher = more trust = worse
        }
    
    def save_results(self, results, output_file):
        """Save trust assumptions test results"""
        output = {
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(results),
            "results": results,
            "summary": {
                "total_vulnerabilities": sum(r["total_vulnerabilities"] for r in results),
                "critical_vulnerabilities": sum(r["critical_count"] for r in results),
                "high_vulnerabilities": sum(r["high_count"] for r in results),
                "most_trusting_device": max(results, key=lambda x: x["trust_score"])["target"] if results else None
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Trust assumptions test complete:")
        print(f"    Devices tested: {len(results)}")
        print(f"    Total vulnerabilities: {output['summary']['total_vulnerabilities']}")
        print(f"    Critical findings: {output['summary']['critical_vulnerabilities']}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <targets_file> <output_file>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        targets = [line.strip() for line in f if line.strip()]
    
    tester = TrustAssumptionsTester()
    results = []
    
    for target in targets:
        try:
            result = tester.test_device(target)
            results.append(result)
        except Exception as e:
            print(f"[-] Error testing {target}: {e}")
    
    tester.save_results(results, sys.argv[2])

if __name__ == "__main__":
    main()
