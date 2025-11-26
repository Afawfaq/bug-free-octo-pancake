#!/usr/bin/env python3
"""
Protocol Guilt Index
Assigns guilt scores based on how leaky device protocols are
"""

import sys
import json
from datetime import datetime
from collections import defaultdict

class ProtocolGuiltAnalyzer:
    def __init__(self):
        self.device_scores = defaultdict(lambda: {
            "guilt_factors": [],
            "total_score": 0,
            "leak_count": 0,
            "protocols": set()
        })
        
        # Guilt weights for different leakages
        self.guilt_weights = {
            "mdns_hostname": 8,
            "ssdp_upnp_info": 9,
            "llmnr_windows_name": 7,
            "upnp_wan_config": 10,
            "smb_os_version": 9,
            "dhcp_vendor_class": 6,
            "http_server_header": 5,
            "snmp_public_access": 10,
            "printer_model_banner": 4,
            "chromecast_api_open": 7,
            "dlna_media_list": 5,
            "ipp_printer_open": 6
        }
    
    def analyze_device_data(self, ip, device_data):
        """Calculate guilt score for a device"""
        score = 0
        factors = []
        
        # Check mDNS leakage
        if device_data.get("mdns_services"):
            score += self.guilt_weights["mdns_hostname"]
            factors.append({
                "type": "mdns_hostname",
                "severity": "high",
                "score": self.guilt_weights["mdns_hostname"],
                "detail": f"{len(device_data['mdns_services'])} mDNS services exposed"
            })
            self.device_scores[ip]["protocols"].add("mDNS")
        
        # Check SSDP/UPnP
        if device_data.get("upnp_services"):
            score += self.guilt_weights["ssdp_upnp_info"]
            factors.append({
                "type": "ssdp_upnp_info",
                "severity": "critical",
                "score": self.guilt_weights["ssdp_upnp_info"],
                "detail": "UPnP services exposed"
            })
            self.device_scores[ip]["protocols"].add("UPnP")
        
        # Check SMB
        if device_data.get("smb_version"):
            score += self.guilt_weights["smb_os_version"]
            factors.append({
                "type": "smb_os_version",
                "severity": "high",
                "score": self.guilt_weights["smb_os_version"],
                "detail": f"SMB version leak: {device_data['smb_version']}"
            })
            self.device_scores[ip]["protocols"].add("SMB")
        
        # Check DHCP
        if device_data.get("dhcp_hostname") or device_data.get("vendor_class"):
            score += self.guilt_weights["dhcp_vendor_class"]
            factors.append({
                "type": "dhcp_vendor_class",
                "severity": "medium",
                "score": self.guilt_weights["dhcp_vendor_class"],
                "detail": "DHCP identity leakage"
            })
            self.device_scores[ip]["protocols"].add("DHCP")
        
        # Check HTTP server headers
        if device_data.get("http_server"):
            score += self.guilt_weights["http_server_header"]
            factors.append({
                "type": "http_server_header",
                "severity": "medium",
                "score": self.guilt_weights["http_server_header"],
                "detail": f"HTTP server: {device_data['http_server']}"
            })
            self.device_scores[ip]["protocols"].add("HTTP")
        
        # Check SNMP
        if device_data.get("snmp_public"):
            score += self.guilt_weights["snmp_public_access"]
            factors.append({
                "type": "snmp_public_access",
                "severity": "critical",
                "score": self.guilt_weights["snmp_public_access"],
                "detail": "SNMP with public community string"
            })
            self.device_scores[ip]["protocols"].add("SNMP")
        
        # Check Chromecast
        if device_data.get("chromecast_api"):
            score += self.guilt_weights["chromecast_api_open"]
            factors.append({
                "type": "chromecast_api_open",
                "severity": "high",
                "score": self.guilt_weights["chromecast_api_open"],
                "detail": "Chromecast API publicly accessible"
            })
            self.device_scores[ip]["protocols"].add("Cast")
        
        # Check DLNA
        if device_data.get("dlna_server"):
            score += self.guilt_weights["dlna_media_list"]
            factors.append({
                "type": "dlna_media_list",
                "severity": "medium",
                "score": self.guilt_weights["dlna_media_list"],
                "detail": "DLNA media server exposed"
            })
            self.device_scores[ip]["protocols"].add("DLNA")
        
        # Check Printer
        if device_data.get("printer_model"):
            score += self.guilt_weights["printer_model_banner"]
            factors.append({
                "type": "printer_model_banner",
                "severity": "low",
                "score": self.guilt_weights["printer_model_banner"],
                "detail": f"Printer: {device_data['printer_model']}"
            })
            self.device_scores[ip]["protocols"].add("Printer")
        
        # Update device scores
        self.device_scores[ip]["guilt_factors"] = factors
        self.device_scores[ip]["total_score"] = score
        self.device_scores[ip]["leak_count"] = len(factors)
        self.device_scores[ip]["protocols"] = list(self.device_scores[ip]["protocols"])
        
        return score
    
    def get_guilt_rating(self, score):
        """Convert score to guilt rating"""
        if score >= 40:
            return "CRITICAL"
        elif score >= 25:
            return "HIGH"
        elif score >= 15:
            return "MEDIUM"
        elif score >= 5:
            return "LOW"
        else:
            return "MINIMAL"
    
    def generate_report(self, devices_data, output_file):
        """Generate protocol guilt report"""
        # Analyze all devices
        for ip, data in devices_data.items():
            self.analyze_device_data(ip, data)
        
        # Build results
        results = {
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(self.device_scores),
            "guilt_distribution": defaultdict(int),
            "devices": {}
        }
        
        # Sort devices by guilt score
        sorted_devices = sorted(
            self.device_scores.items(),
            key=lambda x: x[1]["total_score"],
            reverse=True
        )
        
        for ip, score_data in sorted_devices:
            rating = self.get_guilt_rating(score_data["total_score"])
            results["guilt_distribution"][rating] += 1
            
            results["devices"][ip] = {
                **score_data,
                "guilt_rating": rating,
                "attack_surface_risk": "HIGH" if score_data["total_score"] > 20 else "MEDIUM" if score_data["total_score"] > 10 else "LOW"
            }
        
        # Summary
        results["summary"] = {
            "highest_guilt_device": sorted_devices[0][0] if sorted_devices else None,
            "highest_guilt_score": sorted_devices[0][1]["total_score"] if sorted_devices else 0,
            "average_guilt_score": sum(d["total_score"] for d in self.device_scores.values()) / len(self.device_scores) if self.device_scores else 0,
            "guilt_distribution": dict(results["guilt_distribution"])
        }
        
        # Save
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Protocol guilt analysis complete:")
        print(f"    Total devices: {len(self.device_scores)}")
        print(f"    Highest guilt: {results['summary']['highest_guilt_score']}")
        print(f"    Critical devices: {results['guilt_distribution']['CRITICAL']}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <devices_json> <output_file>")
        sys.exit(1)
    
    # Load device data from previous scans
    with open(sys.argv[1]) as f:
        devices_data = json.load(f)
    
    analyzer = ProtocolGuiltAnalyzer()
    analyzer.generate_report(devices_data, sys.argv[2])
