#!/usr/bin/env python3

import sys
import json
import requests

def enumerate_chromecast(ip, output_file):
    """Enumerate Chromecast device information"""
    results = {
        "ip": ip,
        "endpoints": {},
        "info": {}
    }
    
    endpoints = [
        "/setup/eureka_info",
        "/setup/offer",
        "/setup/get_manifest",
        "/setup/get_wifi_status",
        "/ssdp/device-desc.xml"
    ]
    
    for endpoint in endpoints:
        try:
            url = f"http://{ip}:8008{endpoint}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                try:
                    results["endpoints"][endpoint] = response.json()
                except:
                    results["endpoints"][endpoint] = response.text
        except Exception as e:
            results["endpoints"][endpoint] = f"Error: {str(e)}"
    
    # Try pychromecast
    try:
        import pychromecast
        chromecasts, browser = pychromecast.get_chromecasts()
        for cc in chromecasts:
            if str(cc.host) == ip:
                results["info"] = {
                    "name": cc.name,
                    "model": cc.model_name,
                    "uuid": str(cc.uuid),
                    "cast_type": cc.cast_type
                }
                break
        pychromecast.discovery.stop_discovery(browser)
    except Exception as e:
        results["info"]["error"] = str(e)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Chromecast enumeration complete: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ip> <output_file>")
        sys.exit(1)
    
    enumerate_chromecast(sys.argv[1], sys.argv[2])
