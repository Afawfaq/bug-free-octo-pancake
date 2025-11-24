#!/usr/bin/env python3

import sys
import json
import requests
from xml.etree import ElementTree

def enumerate_dlna(ip, output_file):
    """Enumerate DLNA MediaServer information"""
    results = {
        "ip": ip,
        "services": [],
        "device_info": {}
    }
    
    # Try common DLNA ports
    ports = [8008, 8009, 8080, 49152, 49153, 1900]
    
    for port in ports:
        try:
            # Get device description
            url = f"http://{ip}:{port}/description.xml"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                results["services"].append({
                    "port": port,
                    "description_xml": response.text[:1000]
                })
                
                # Parse XML for device info
                try:
                    root = ElementTree.fromstring(response.text)
                    ns = {'d': 'urn:schemas-upnp-org:device-1-0'}
                    device = root.find('.//d:device', ns)
                    if device is not None:
                        results["device_info"]["friendlyName"] = device.findtext('.//d:friendlyName', '', ns)
                        results["device_info"]["manufacturer"] = device.findtext('.//d:manufacturer', '', ns)
                        results["device_info"]["modelName"] = device.findtext('.//d:modelName', '', ns)
                        results["device_info"]["modelNumber"] = device.findtext('.//d:modelNumber', '', ns)
                except:
                    pass
        except:
            pass
    
    # Try Netflix MDX
    try:
        url = f"http://{ip}:8080/nflx/status"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            results["netflix_mdx"] = response.text
    except:
        pass
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] DLNA enumeration complete: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ip> <output_file>")
        sys.exit(1)
    
    enumerate_dlna(sys.argv[1], sys.argv[2])
