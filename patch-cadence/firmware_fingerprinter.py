#!/usr/bin/env python3
"""
Firmware Version Fingerprinter
Identifies firmware versions from HTTP headers, UPnP, SNMP, and other sources
"""

import sys
import json
import re
import requests
from typing import Dict, List
import warnings
warnings.filterwarnings("ignore")

class FirmwareFingerprinter:
    def __init__(self):
        self.findings = []
    
    def fingerprint_http(self, ip: str, port: int = 80) -> Dict:
        """Extract firmware info from HTTP headers and web interface"""
        result = {
            "ip": ip,
            "source": "HTTP",
            "firmware_info": {}
        }
        
        try:
            response = requests.get(f"http://{ip}:{port}", timeout=5, verify=False)
            
            # Check Server header
            if 'Server' in response.headers:
                result["firmware_info"]["server"] = response.headers['Server']
            
            # Check for common firmware version patterns in response
            content = response.text
            
            # Pattern for version numbers
            version_patterns = [
                r'[Ff]irmware[:\s]+v?([\d\.]+)',
                r'[Vv]ersion[:\s]+v?([\d\.]+)',
                r'[Bb]uild[:\s]+v?([\d\.]+)',
                r'v([\d]+\.[\d]+\.[\d]+)',
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, content)
                if match:
                    result["firmware_info"]["version"] = match.group(1)
                    break
            
            # Look for model information
            model_patterns = [
                r'[Mm]odel[:\s]+([A-Za-z0-9\-]+)',
                r'[Dd]evice[:\s]+([A-Za-z0-9\-]+)',
            ]
            
            for pattern in model_patterns:
                match = re.search(pattern, content)
                if match:
                    result["firmware_info"]["model"] = match.group(1)
                    break
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def fingerprint_upnp(self, ip: str) -> Dict:
        """Extract firmware info from UPnP device description"""
        result = {
            "ip": ip,
            "source": "UPnP",
            "firmware_info": {}
        }
        
        upnp_paths = [
            "/rootDesc.xml",
            "/zetna/rootDesc.xml",
            "/desc.xml",
            "/device.xml"
        ]
        
        for path in upnp_paths:
            try:
                response = requests.get(f"http://{ip}:5000{path}", timeout=3, verify=False)
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract firmware version from XML
                    version_match = re.search(r'<firmwareVersion>([^<]+)</firmwareVersion>', content)
                    if version_match:
                        result["firmware_info"]["version"] = version_match.group(1)
                    
                    # Extract model
                    model_match = re.search(r'<modelName>([^<]+)</modelName>', content)
                    if model_match:
                        result["firmware_info"]["model"] = model_match.group(1)
                    
                    # Extract manufacturer
                    mfr_match = re.search(r'<manufacturer>([^<]+)</manufacturer>', content)
                    if mfr_match:
                        result["firmware_info"]["manufacturer"] = mfr_match.group(1)
                    
                    if result["firmware_info"]:
                        break
            
            except Exception:
                continue
        
        return result
    
    def fingerprint_snmp(self, ip: str) -> Dict:
        """Extract firmware info from SNMP (if available)"""
        result = {
            "ip": ip,
            "source": "SNMP",
            "firmware_info": {
                "note": "SNMP enumeration requires snmpwalk - placeholder for actual implementation"
            }
        }
        
        # In a real implementation, we would use:
        # snmpwalk -v2c -c public <ip> 1.3.6.1.2.1.1.1
        # to get sysDescr which often contains firmware version
        
        return result
    
    def analyze_device(self, ip: str) -> Dict:
        """Perform comprehensive firmware fingerprinting"""
        device_info = {
            "ip": ip,
            "firmware_sources": [],
            "consolidated_info": {}
        }
        
        # Try HTTP fingerprinting
        http_result = self.fingerprint_http(ip)
        if http_result.get("firmware_info"):
            device_info["firmware_sources"].append(http_result)
            device_info["consolidated_info"].update(http_result["firmware_info"])
        
        # Try UPnP fingerprinting
        upnp_result = self.fingerprint_upnp(ip)
        if upnp_result.get("firmware_info"):
            device_info["firmware_sources"].append(upnp_result)
            device_info["consolidated_info"].update(upnp_result["firmware_info"])
        
        return device_info

def main():
    if len(sys.argv) < 3:
        print("Usage: firmware_fingerprinter.py <target_ips_file> <output_file>")
        sys.exit(1)
    
    target_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Load targets
    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error loading targets: {e}")
        sys.exit(1)
    
    print(f"[*] Fingerprinting firmware on {len(targets)} targets...")
    
    fingerprinter = FirmwareFingerprinter()
    results = []
    
    for ip in targets:
        print(f"[*] Analyzing {ip}...")
        device_info = fingerprinter.analyze_device(ip)
        
        if device_info["consolidated_info"]:
            results.append(device_info)
            print(f"[+] Found firmware info: {device_info['consolidated_info']}")
    
    # Save results
    output_data = {
        "total_devices": len(targets),
        "devices_with_firmware_info": len(results),
        "devices": results
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Firmware fingerprinting complete.")
    print(f"[+] Found firmware info for {len(results)}/{len(targets)} devices")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
