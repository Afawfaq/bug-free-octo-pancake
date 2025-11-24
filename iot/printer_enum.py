#!/usr/bin/env python3

import sys
import json
import requests

def enumerate_printer(ip, output_file):
    """Enumerate printer information and services"""
    results = {
        "ip": ip,
        "web_interfaces": {},
        "services": {}
    }
    
    # Common printer web interfaces
    endpoints = [
        ("http", 80, "/"),
        ("http", 80, "/hp/device/this.LCDispatcher"),
        ("http", 80, "/SSI/index.htm"),
        ("http", 80, "/web/guest/en/websys/webArch/mainFrame.cgi"),
        ("ipp", 631, "/"),
        ("https", 443, "/"),
    ]
    
    for proto, port, path in endpoints:
        try:
            url = f"{proto}://{ip}:{port}{path}"
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code == 200:
                results["web_interfaces"][f"{proto}_{port}{path}"] = {
                    "status": response.status_code,
                    "title": response.text[:500] if len(response.text) < 500 else "Content available",
                    "headers": dict(response.headers)
                }
        except Exception as e:
            results["web_interfaces"][f"{proto}_{port}{path}"] = {"error": str(e)}
    
    # SNMP info (if available)
    try:
        import subprocess
        result = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", ip],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout:
            results["services"]["snmp"] = result.stdout[:1000]
    except:
        pass
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Printer enumeration complete: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ip> <output_file>")
        sys.exit(1)
    
    enumerate_printer(sys.argv[1], sys.argv[2])
