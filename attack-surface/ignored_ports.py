#!/usr/bin/env python3
"""
Ignored Ports Scanner
Scans ports nobody checks but attackers love
"""

import sys
import json
import socket
from datetime import datetime
import concurrent.futures

class IgnoredPortsScanner:
    def __init__(self):
        # Ports manufacturers forget about
        self.ignored_ports = {
            # Printer ports
            9100: "HP JetDirect (Raw print)",
            515: "LPD (Line Printer Daemon)",
            631: "IPP (Internet Printing Protocol)",
            9220: "Printer Admin",
            
            # Media/Cast ports
            8008: "Chromecast HTTP",
            8009: "Chromecast TLS",
            8080: "Alt HTTP (often unprotected)",
            8443: "Alt HTTPS",
            
            # IoT discovery
            10001: "IoT Discovery",
            10000: "Network Data Management",
            
            # UPnP dynamic range
            49152: "UPnP Dynamic 1",
            49153: "UPnP Dynamic 2",
            49154: "UPnP Dynamic 3",
            
            # Camera/surveillance
            554: "RTSP (Camera streaming)",
            7050: "Camera Control",
            7070: "Camera Web UI",
            8000: "Camera Admin",
            
            # IoT management
            5000: "UPnP/Device Control",
            5001: "Alt Device Control",
            1900: "SSDP",
            5353: "mDNS",
            
            # Debug/Admin ports
            23: "Telnet (often left open)",
            2323: "Alt Telnet",
            8888: "Debug/Admin UI",
            9999: "Debug Console"
        }
    
    def scan_port(self, target, port, protocol_name):
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # Port is open, try to grab banner
                banner = None
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(512).decode('utf-8', errors='ignore')
                except:
                    pass
                
                sock.close()
                
                return {
                    "port": port,
                    "protocol": protocol_name,
                    "state": "open",
                    "banner": banner[:200] if banner else None,
                    "severity": self.assess_severity(port, banner)
                }
            
            sock.close()
        except:
            pass
        
        return None
    
    def assess_severity(self, port, banner):
        """Assess how dangerous an open port is"""
        critical_ports = [23, 2323, 515, 9100]  # Direct attack vectors
        high_ports = [631, 8008, 5000, 554]     # Unauth access common
        
        if port in critical_ports:
            return "CRITICAL"
        elif port in high_ports:
            return "HIGH"
        elif banner and any(word in banner.lower() for word in ['admin', 'root', 'config']):
            return "HIGH"
        else:
            return "MEDIUM"
    
    def scan_target(self, target):
        """Scan all ignored ports on target"""
        print(f"[*] Scanning ignored ports on {target}...")
        
        open_ports = []
        
        # Parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.scan_port, target, port, proto): (port, proto)
                for port, proto in self.ignored_ports.items()
            }
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        # Sort by severity
        open_ports.sort(key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x['severity'], 3))
        
        return {
            "target": target,
            "open_ports": open_ports,
            "total_open": len(open_ports),
            "critical_count": sum(1 for p in open_ports if p['severity'] == 'CRITICAL'),
            "high_count": sum(1 for p in open_ports if p['severity'] == 'HIGH'),
            "attack_surface_score": len(open_ports) * 10 + sum(20 for p in open_ports if p['severity'] == 'CRITICAL')
        }
    
    def save_results(self, results, output_file):
        """Save scan results"""
        output = {
            "scan_time": datetime.now().isoformat(),
            "scans": results,
            "summary": {
                "total_devices": len(results),
                "total_open_ports": sum(r['total_open'] for r in results),
                "total_critical": sum(r['critical_count'] for r in results),
                "total_high": sum(r['high_count'] for r in results),
                "highest_risk_device": max(results, key=lambda x: x['attack_surface_score'])['target'] if results else None
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Ignored ports scan complete:")
        print(f"    Devices scanned: {len(results)}")
        print(f"    Open ignored ports: {output['summary']['total_open_ports']}")
        print(f"    Critical findings: {output['summary']['total_critical']}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <targets_file> <output_file>")
        sys.exit(1)
    
    with open(sys.argv[1]) as f:
        targets = [line.strip() for line in f if line.strip()]
    
    scanner = IgnoredPortsScanner()
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
