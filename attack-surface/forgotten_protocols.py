#!/usr/bin/env python3
"""
Forgotten Protocols Scanner
Finds half-implemented, forgotten protocols manufacturers never secured
"""

import sys
import json
import socket
import requests
from datetime import datetime
from xml.etree import ElementTree

class ForgottenProtocolScanner:
    def __init__(self):
        self.findings = []
    
    def scan_epson_soap(self, target):
        """Check for Epson printer SOAP endpoints"""
        endpoints = [
            "/PRESENTATION/HTML/TOP/INDEX.HTML",
            "/PRESENTATION/BONJOUR",
            "/cgi-bin/dynamic/printer/config/reports/devicestatus.html"
        ]
        
        findings = []
        for endpoint in endpoints:
            try:
                resp = requests.get(f"http://{target}{endpoint}", timeout=3)
                if resp.status_code == 200:
                    findings.append({
                        "protocol": "Epson SOAP/Web",
                        "endpoint": endpoint,
                        "status": resp.status_code,
                        "leaks_info": "Device status" in resp.text or "Epson" in resp.text
                    })
            except:
                pass
        
        return findings
    
    def scan_dlna_profiles(self, target):
        """Check for weak DLNA implementations"""
        try:
            # DLNA/UPnP device description
            resp = requests.get(f"http://{target}:8008/ssdp/device-desc.xml", timeout=3)
            if resp.status_code == 200:
                return [{
                    "protocol": "DLNA",
                    "endpoint": "/ssdp/device-desc.xml",
                    "info_leaked": resp.text[:500],
                    "has_auth": "authorization" in resp.text.lower()
                }]
        except:
            pass
        
        return []
    
    def scan_chromecast_json(self, target):
        """Check for unauthenticated Chromecast endpoints"""
        endpoints = [
            "/setup/eureka_info",
            "/setup/offer",
            "/setup/get_wifi_status"
        ]
        
        findings = []
        for endpoint in endpoints:
            try:
                resp = requests.get(f"http://{target}:8008{endpoint}", timeout=3)
                if resp.status_code == 200:
                    findings.append({
                        "protocol": "Chromecast/Cast",
                        "endpoint": endpoint,
                        "authenticated": False,
                        "data_leaked": len(resp.text) > 10
                    })
            except:
                pass
        
        return findings
    
    def scan_ws_discovery(self, target):
        """Check WS-Discovery protocol"""
        try:
            message = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
    <a:MessageID>uuid:test-123</a:MessageID>
    <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  </s:Header>
  <s:Body>
    <Probe xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery"/>
  </s:Body>
</s:Envelope>"""
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(message.encode(), (target, 3702))
            
            data, _ = sock.recvfrom(8192)
            sock.close()
            
            return [{
                "protocol": "WS-Discovery",
                "port": 3702,
                "responds": True,
                "response_size": len(data)
            }]
        except:
            pass
        
        return []
    
    def scan_raw_printer_ports(self, target):
        """Check raw printer protocols"""
        ports = {
            9100: "JetDirect",
            515: "LPD",
            631: "IPP"
        }
        
        findings = []
        for port, proto in ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    # Try to grab banner
                    try:
                        sock.send(b"\n")
                        banner = sock.recv(1024)
                        findings.append({
                            "protocol": proto,
                            "port": port,
                            "open": True,
                            "banner": banner.decode('utf-8', errors='ignore')[:100] if banner else None
                        })
                    except:
                        findings.append({
                            "protocol": proto,
                            "port": port,
                            "open": True
                        })
                
                sock.close()
            except:
                pass
        
        return findings
    
    def scan_iot_udp_protocols(self, target):
        """Scan for IoT protocols over UDP"""
        probes = [
            (10001, b"DISCOVER"),
            (7050, b"\x00\x00\x00\x00"),  # Camera control
            (8089, b"INFO")
        ]
        
        findings = []
        for port, probe in probes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                sock.sendto(probe, (target, port))
                
                data, _ = sock.recvfrom(1024)
                if data:
                    findings.append({
                        "protocol": f"UDP/{port}",
                        "port": port,
                        "responds_to_probe": True,
                        "response_size": len(data)
                    })
                sock.close()
            except:
                pass
        
        return findings
    
    def scan_target(self, target):
        """Scan all forgotten protocols on target"""
        print(f"[*] Scanning forgotten protocols on {target}...")
        
        results = {
            "target": target,
            "epson_soap": self.scan_epson_soap(target),
            "dlna": self.scan_dlna_profiles(target),
            "chromecast": self.scan_chromecast_json(target),
            "ws_discovery": self.scan_ws_discovery(target),
            "raw_printer": self.scan_raw_printer_ports(target),
            "iot_udp": self.scan_iot_udp_protocols(target)
        }
        
        # Calculate vulnerability score
        total_findings = sum(len(v) for v in results.values() if isinstance(v, list))
        results["vulnerability_score"] = total_findings * 5
        results["risk_level"] = "HIGH" if total_findings > 5 else "MEDIUM" if total_findings > 2 else "LOW"
        
        return results
    
    def save_results(self, results, output_file):
        """Save scan results"""
        output = {
            "scan_time": datetime.now().isoformat(),
            "scans": results,
            "summary": {
                "total_devices": len(results),
                "high_risk_devices": sum(1 for r in results if r.get('risk_level') == 'HIGH'),
                "total_forgotten_protocols": sum(
                    sum(len(v) for v in r.values() if isinstance(v, list))
                    for r in results
                )
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Forgotten protocol scan complete:")
        print(f"    Devices scanned: {len(results)}")
        print(f"    High-risk devices: {output['summary']['high_risk_devices']}")
        print(f"    Protocols found: {output['summary']['total_forgotten_protocols']}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <targets_file> <output_file>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        targets = [line.strip() for line in f if line.strip()]
    
    scanner = ForgottenProtocolScanner()
    results = []
    
    for target in targets:
        try:
            result = scanner.scan_target(target)
            results.append(result)
        except Exception as e:
            print(f"[-] Error scanning {target}: {e}")
    
    scanner.save_results(results, sys.argv[2])

if __name__ == "__main__":
    main()
