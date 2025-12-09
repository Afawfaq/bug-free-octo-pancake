#!/usr/bin/env python3
"""
Threat Intelligence Feed Integration Module
Implements STIX/TAXII standards and IoC management
Based on modern CTI and SOAR research (2020-2024):
- STIX 2.1 (Structured Threat Information Expression)
- TAXII 2.1 (Trusted Automated eXchange of Intelligence Information)
- IoC (Indicators of Compromise) management
- Automated threat response integration

Features:
- STIX-formatted threat intelligence parsing
- IoC extraction and validation
- Threat actor and malware tracking
- Automated correlation with network findings
- Integration with SOAR workflows
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from collections import defaultdict
import os
import re


class ThreatIntelligenceFeed:
    """
    Manages threat intelligence using STIX/TAXII standards.
    Implements modern CTI concepts for automated security operations.
    """
    
    def __init__(self, output_dir: str = '/output/threat-intelligence'):
        self.output_dir = output_dir
        self.iocs = {
            'ipv4': set(),
            'ipv6': set(),
            'domain': set(),
            'url': set(),
            'file_hash': set(),
            'email': set()
        }
        self.threat_actors = {}
        self.malware_families = {}
        self.attack_patterns = {}
        self.correlations = []
        
        # STIX 2.1 Object Types
        self.stix_types = {
            'indicator', 'malware', 'threat-actor', 'attack-pattern',
            'campaign', 'intrusion-set', 'tool', 'vulnerability'
        }
    
    def parse_stix_bundle(self, stix_data: Dict) -> Dict:
        """
        Parse STIX 2.1 bundle and extract intelligence.
        Returns summary of extracted objects.
        """
        print("[TI Feed] Parsing STIX bundle...")
        
        summary = defaultdict(int)
        
        if 'objects' not in stix_data:
            print("[TI Feed] No objects found in STIX bundle")
            return dict(summary)
        
        for obj in stix_data['objects']:
            obj_type = obj.get('type', '')
            summary[obj_type] += 1
            
            if obj_type == 'indicator':
                self._process_indicator(obj)
            elif obj_type == 'malware':
                self._process_malware(obj)
            elif obj_type == 'threat-actor':
                self._process_threat_actor(obj)
            elif obj_type == 'attack-pattern':
                self._process_attack_pattern(obj)
        
        print(f"[TI Feed] Extracted: {dict(summary)}")
        return dict(summary)
    
    def _process_indicator(self, indicator: Dict):
        """Process STIX indicator object and extract IoCs."""
        pattern = indicator.get('pattern', '')
        ioc_type = indicator.get('indicator_types', ['unknown'])[0]
        
        # Extract IoCs from STIX pattern
        # Example: [ipv4-addr:value = '192.168.1.1']
        ipv4_match = re.findall(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        domain_match = re.findall(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        hash_match = re.findall(r"file:hashes\.'([^']+)'\s*=\s*'([^']+)'", pattern)
        url_match = re.findall(r"url:value\s*=\s*'([^']+)'", pattern)
        
        for ip in ipv4_match:
            self.iocs['ipv4'].add(ip)
            print(f"[TI Feed] Added IPv4 IoC: {ip}")
        
        for domain in domain_match:
            self.iocs['domain'].add(domain)
            print(f"[TI Feed] Added domain IoC: {domain}")
        
        for algo, hash_val in hash_match:
            self.iocs['file_hash'].add(f"{algo}:{hash_val}")
            print(f"[TI Feed] Added hash IoC: {algo}:{hash_val}")
        
        for url in url_match:
            self.iocs['url'].add(url)
            print(f"[TI Feed] Added URL IoC: {url}")
    
    def _process_malware(self, malware: Dict):
        """Process malware object."""
        malware_id = malware.get('id', '')
        name = malware.get('name', 'Unknown')
        
        self.malware_families[malware_id] = {
            'name': name,
            'is_family': malware.get('is_family', False),
            'malware_types': malware.get('malware_types', []),
            'description': malware.get('description', ''),
            'first_seen': malware.get('first_seen', ''),
            'capabilities': malware.get('capabilities', [])
        }
    
    def _process_threat_actor(self, actor: Dict):
        """Process threat actor object."""
        actor_id = actor.get('id', '')
        name = actor.get('name', 'Unknown')
        
        self.threat_actors[actor_id] = {
            'name': name,
            'description': actor.get('description', ''),
            'sophistication': actor.get('sophistication', 'unknown'),
            'resource_level': actor.get('resource_level', 'unknown'),
            'primary_motivation': actor.get('primary_motivation', 'unknown'),
            'aliases': actor.get('aliases', []),
            'goals': actor.get('goals', [])
        }
    
    def _process_attack_pattern(self, pattern: Dict):
        """Process MITRE ATT&CK pattern."""
        pattern_id = pattern.get('id', '')
        name = pattern.get('name', 'Unknown')
        
        # Extract MITRE ATT&CK ID from external references
        mitre_id = None
        for ref in pattern.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id', '')
                break
        
        self.attack_patterns[pattern_id] = {
            'name': name,
            'mitre_id': mitre_id,
            'description': pattern.get('description', ''),
            'kill_chain_phases': pattern.get('kill_chain_phases', [])
        }
    
    def add_ioc(self, ioc_type: str, value: str, context: Optional[Dict] = None):
        """
        Manually add an IoC to the feed.
        Context can include: source, confidence, threat_type, first_seen, last_seen
        """
        if ioc_type in self.iocs:
            self.iocs[ioc_type].add(value)
            print(f"[TI Feed] Added {ioc_type} IoC: {value}")
        else:
            print(f"[TI Feed] Unknown IoC type: {ioc_type}")
    
    def check_ioc(self, ioc_type: str, value: str) -> bool:
        """
        Check if a value matches a known IoC.
        Returns True if match found.
        """
        if ioc_type in self.iocs:
            return value in self.iocs[ioc_type]
        return False
    
    def correlate_finding(self, finding: Dict) -> Optional[Dict]:
        """
        Correlate a security finding with threat intelligence.
        Returns correlation info if IoC matches are found.
        """
        matches = []
        
        # Check IP addresses
        for ip_field in ['ip', 'src_ip', 'dst_ip', 'source_ip', 'dest_ip']:
            if ip_field in finding:
                ip = finding[ip_field]
                if self.check_ioc('ipv4', ip):
                    matches.append({
                        'ioc_type': 'ipv4',
                        'value': ip,
                        'field': ip_field
                    })
        
        # Check domains
        if 'domain' in finding and self.check_ioc('domain', finding['domain']):
            matches.append({
                'ioc_type': 'domain',
                'value': finding['domain'],
                'field': 'domain'
            })
        
        # Check URLs
        if 'url' in finding and self.check_ioc('url', finding['url']):
            matches.append({
                'ioc_type': 'url',
                'value': finding['url'],
                'field': 'url'
            })
        
        # Check file hashes
        for hash_field in ['md5', 'sha1', 'sha256']:
            if hash_field in finding:
                hash_str = f"{hash_field.upper()}:{finding[hash_field]}"
                if self.check_ioc('file_hash', hash_str):
                    matches.append({
                        'ioc_type': 'file_hash',
                        'value': hash_str,
                        'field': hash_field
                    })
        
        if matches:
            correlation = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'finding': finding,
                'ioc_matches': matches,
                'match_count': len(matches),
                'severity': 'HIGH' if len(matches) > 2 else 'MEDIUM',
                'recommended_actions': [
                    'Isolate affected system immediately',
                    'Review all activity from matched indicators',
                    'Check for lateral movement',
                    'Escalate to incident response team',
                    'Block IoCs at network perimeter'
                ]
            }
            self.correlations.append(correlation)
            return correlation
        
        return None
    
    def generate_stix_indicator(self, ioc_type: str, value: str, 
                                name: str = None, description: str = None) -> Dict:
        """
        Generate a STIX 2.1 indicator object from an IoC.
        Can be shared via TAXII.
        """
        indicator_id = f"indicator--{hashlib.sha256(value.encode()).hexdigest()[:36]}"
        
        # Build STIX pattern based on IoC type
        pattern_map = {
            'ipv4': f"[ipv4-addr:value = '{value}']",
            'domain': f"[domain-name:value = '{value}']",
            'url': f"[url:value = '{value}']",
        }
        
        pattern = pattern_map.get(ioc_type, f"[{ioc_type}:value = '{value}']")
        
        indicator = {
            'type': 'indicator',
            'spec_version': '2.1',
            'id': indicator_id,
            'created': datetime.utcnow().isoformat() + 'Z',
            'modified': datetime.utcnow().isoformat() + 'Z',
            'name': name or f"{ioc_type.upper()} Indicator",
            'description': description or f"Indicator for {ioc_type}: {value}",
            'indicator_types': ['malicious-activity'],
            'pattern': pattern,
            'pattern_type': 'stix',
            'valid_from': datetime.utcnow().isoformat() + 'Z'
        }
        
        return indicator
    
    def export_stix_bundle(self, include_correlations: bool = True) -> Dict:
        """
        Export collected intelligence as STIX 2.1 bundle.
        Can be shared via TAXII feed.
        """
        objects = []
        
        # Export indicators
        for ioc_type, values in self.iocs.items():
            for value in list(values)[:100]:  # Limit to 100 per type
                indicator = self.generate_stix_indicator(ioc_type, value)
                objects.append(indicator)
        
        bundle = {
            'type': 'bundle',
            'id': f"bundle--{hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()[:36]}",
            'spec_version': '2.1',
            'objects': objects
        }
        
        return bundle
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics."""
        return {
            'ioc_counts': {k: len(v) for k, v in self.iocs.items()},
            'total_iocs': sum(len(v) for v in self.iocs.values()),
            'threat_actors': len(self.threat_actors),
            'malware_families': len(self.malware_families),
            'attack_patterns': len(self.attack_patterns),
            'correlations': len(self.correlations)
        }
    
    def save_report(self):
        """Save threat intelligence report."""
        os.makedirs(self.output_dir, exist_ok=True)
        
        report = {
            'report_timestamp': datetime.utcnow().isoformat() + 'Z',
            'standards': ['STIX 2.1', 'TAXII 2.1'],
            'statistics': self.get_statistics(),
            'threat_actors': list(self.threat_actors.values())[:10],
            'malware_families': list(self.malware_families.values())[:10],
            'attack_patterns': list(self.attack_patterns.values())[:10],
            'recent_correlations': self.correlations[-20:],
            'ioc_samples': {
                ioc_type: list(values)[:10]
                for ioc_type, values in self.iocs.items()
            }
        }
        
        output_file = f"{self.output_dir}/threat_intelligence_report.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[TI Feed] Report saved to {output_file}")
        print(f"[TI Feed] Total IoCs: {report['statistics']['total_iocs']}")
        print(f"[TI Feed] Correlations found: {len(self.correlations)}")


def main():
    """Example usage."""
    feed = ThreatIntelligenceFeed()
    
    # Example: Parse STIX bundle
    example_stix = {
        'type': 'bundle',
        'id': 'bundle--example',
        'objects': [
            {
                'type': 'indicator',
                'id': 'indicator--test-1',
                'pattern': "[ipv4-addr:value = '192.0.2.1']",
                'indicator_types': ['malicious-activity']
            },
            {
                'type': 'indicator',
                'id': 'indicator--test-2',
                'pattern': "[domain-name:value = 'evil.example.com']",
                'indicator_types': ['malicious-activity']
            }
        ]
    }
    
    feed.parse_stix_bundle(example_stix)
    
    # Example: Add custom IoCs
    feed.add_ioc('ipv4', '198.51.100.1')
    feed.add_ioc('domain', 'malware.example.org')
    
    # Example: Correlate finding
    test_finding = {
        'src_ip': '192.0.2.1',
        'dst_ip': '10.0.0.1',
        'action': 'connection_attempt'
    }
    
    correlation = feed.correlate_finding(test_finding)
    if correlation:
        print(f"\n[CORRELATION] Found {correlation['match_count']} IoC matches")
        print(f"Severity: {correlation['severity']}")
    
    # Example: Export as STIX bundle
    bundle = feed.export_stix_bundle()
    print(f"\n[STIX Export] Generated bundle with {len(bundle['objects'])} indicators")
    
    feed.save_report()


if __name__ == '__main__':
    main()
