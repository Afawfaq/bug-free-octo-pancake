#!/usr/bin/env python3
"""
Entropy Analyzer
Analyzes randomness quality in device tokens, session IDs, and UUIDs
Weak entropy = predictable = exploitable
"""

import sys
import json
import re
import math
from datetime import datetime
from collections import Counter

class EntropyAnalyzer:
    def __init__(self):
        self.samples = {}
    
    def calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    def analyze_uuid(self, uuid_str):
        """Analyze UUID randomness"""
        # Remove dashes
        clean = uuid_str.replace('-', '').replace(':', '')
        
        analysis = {
            "uuid": uuid_str,
            "length": len(clean),
            "entropy": self.calculate_shannon_entropy(clean),
            "has_pattern": self.detect_pattern(clean),
            "sequential_chars": self.count_sequential(clean),
            "char_distribution": self.analyze_distribution(clean)
        }
        
        # Assess quality
        if analysis["entropy"] < 3.0:
            analysis["quality"] = "WEAK"
            analysis["exploitable"] = True
        elif analysis["entropy"] < 3.5:
            analysis["quality"] = "POOR"
            analysis["exploitable"] = True
        elif analysis["entropy"] < 4.0:
            analysis["quality"] = "FAIR"
            analysis["exploitable"] = False
        else:
            analysis["quality"] = "GOOD"
            analysis["exploitable"] = False
        
        return analysis
    
    def detect_pattern(self, data):
        """Detect obvious patterns"""
        patterns = [
            r'(.)\1{3,}',  # Repeated chars (aaaa)
            r'(012|123|234|345|456|567|678|789)',  # Sequential numbers
            r'(abc|bcd|cde|def)',  # Sequential letters
            r'^(00|ff|11|22|33|44|55|66|77|88|99)',  # Start with repeated
        ]
        
        for pattern in patterns:
            if re.search(pattern, data.lower()):
                return True
        
        return False
    
    def count_sequential(self, data):
        """Count sequential character runs"""
        sequential = 0
        for i in range(len(data) - 1):
            if abs(ord(data[i]) - ord(data[i+1])) == 1:
                sequential += 1
        
        return sequential
    
    def analyze_distribution(self, data):
        """Analyze character distribution"""
        counter = Counter(data.lower())
        most_common = counter.most_common(1)[0][1] if counter else 0
        unique_chars = len(counter)
        
        return {
            "unique_chars": unique_chars,
            "most_common_count": most_common,
            "uniformity": unique_chars / len(data) if data else 0
        }
    
    def analyze_session_id(self, session_id):
        """Analyze session ID randomness"""
        return self.analyze_uuid(session_id)
    
    def analyze_token(self, token):
        """Analyze authentication token randomness"""
        return self.analyze_uuid(token)
    
    def analyze_device_data(self, device_data):
        """Analyze all entropy sources for a device"""
        results = {
            "device": device_data.get("ip", "unknown"),
            "entropy_samples": [],
            "overall_score": 0,
            "weak_entropy_count": 0
        }
        
        # Check UUIDs
        if "upnp_udn" in device_data:
            analysis = self.analyze_uuid(device_data["upnp_udn"])
            analysis["source"] = "UPnP UDN"
            results["entropy_samples"].append(analysis)
            if analysis["exploitable"]:
                results["weak_entropy_count"] += 1
        
        # Check Chromecast tokens
        if "chromecast_id" in device_data:
            analysis = self.analyze_uuid(device_data["chromecast_id"])
            analysis["source"] = "Chromecast ID"
            results["entropy_samples"].append(analysis)
            if analysis["exploitable"]:
                results["weak_entropy_count"] += 1
        
        # Check session IDs from HTTP
        if "session_ids" in device_data:
            for sid in device_data["session_ids"]:
                analysis = self.analyze_session_id(sid)
                analysis["source"] = "HTTP Session ID"
                results["entropy_samples"].append(analysis)
                if analysis["exploitable"]:
                    results["weak_entropy_count"] += 1
        
        # Check printer job IDs
        if "printer_job_ids" in device_data:
            for jid in device_data["printer_job_ids"]:
                analysis = self.analyze_uuid(str(jid))
                analysis["source"] = "Printer Job ID"
                results["entropy_samples"].append(analysis)
                if analysis["exploitable"]:
                    results["weak_entropy_count"] += 1
        
        # Calculate overall score
        if results["entropy_samples"]:
            avg_entropy = sum(s["entropy"] for s in results["entropy_samples"]) / len(results["entropy_samples"])
            results["overall_score"] = avg_entropy
            results["risk_level"] = "HIGH" if results["weak_entropy_count"] > 2 else "MEDIUM" if results["weak_entropy_count"] > 0 else "LOW"
        
        return results
    
    def save_results(self, analysis_results, output_file):
        """Save entropy analysis results"""
        output = {
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(analysis_results),
            "results": analysis_results,
            "summary": {
                "devices_with_weak_entropy": sum(1 for r in analysis_results if r.get("weak_entropy_count", 0) > 0),
                "total_weak_samples": sum(r.get("weak_entropy_count", 0) for r in analysis_results),
                "average_entropy": sum(r.get("overall_score", 0) for r in analysis_results) / len(analysis_results) if analysis_results else 0
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n[+] Entropy analysis complete:")
        print(f"    Devices analyzed: {len(analysis_results)}")
        print(f"    Devices with weak entropy: {output['summary']['devices_with_weak_entropy']}")
        print(f"    Total weak samples: {output['summary']['total_weak_samples']}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <device_data_json> <output_file>")
        sys.exit(1)
    
    # Load device data
    with open(sys.argv[1]) as f:
        devices_data = json.load(f)
    
    analyzer = EntropyAnalyzer()
    results = []
    
    # Analyze each device
    for device_id, device_data in devices_data.items():
        if isinstance(device_data, dict):
            result = analyzer.analyze_device_data({**device_data, "ip": device_id})
            results.append(result)
    
    analyzer.save_results(results, sys.argv[2])

if __name__ == "__main__":
    main()
