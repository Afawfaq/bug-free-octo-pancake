#!/usr/bin/env python3
"""
Unified Reporting System
Generates comprehensive reports in multiple formats from all reconnaissance modules.
Supports executive, technical, and compliance reporting.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any


class UnifiedReporter:
    """
    Unified reporting system that aggregates data from all modules
    and generates formatted reports for different audiences.
    """
    
    def __init__(self, output_dir: str = '/output'):
        self.output_dir = output_dir
        self.report_data = {}
        self.timestamp = datetime.now()
    
    def load_all_module_data(self) -> Dict[str, Any]:
        """Load data from all reconnaissance and offensive modules."""
        data = {
            # Credential attacks
            'credential_attacks': {
                'default_creds': self._load_json('credential-attacks/default_creds_results.json'),
                'cleartext': self._load_json('credential-attacks/cleartext_creds.json'),
                'ssh_analysis': self._load_json('credential-attacks/ssh_analysis.json')
            },
            # Patch cadence
            'patch_cadence': {
                'firmware': self._load_json('patch-cadence/firmware_versions.json'),
                'cves': self._load_json('patch-cadence/cve_matches.json'),
                'aging': self._load_json('patch-cadence/aging_scores.json')
            },
            # Data flow
            'data_flow': {
                'baseline': self._load_json('data-flow/baseline.json'),
                'fingerprints': self._load_json('data-flow/fingerprints.json'),
                'anomalies': self._load_json('data-flow/anomalies.json')
            },
            # WiFi attacks
            'wifi_attacks': {
                'spectrum': self._load_json('wifi-attacks/spectrum_analysis.json'),
                'wps': self._load_json('wifi-attacks/wps_analysis.json'),
                'ble': self._load_json('wifi-attacks/ble_devices.json')
            },
            # Trust mapping
            'trust_mapping': {
                'windows_trust': self._load_json('trust-mapping/windows_trust_graph.json'),
                'smb': self._load_json('trust-mapping/smb_relationships.json'),
                'attack_paths': self._load_json('trust-mapping/attack_paths.json')
            },
            # Deception
            'deception': {
                'alerts': self._load_json('deception/alerts.json'),
                'smb_honeypot': self._load_json('deception/smb_honeypot.json'),
                'ipp_honeypot': self._load_json('deception/ipp_honeypot.json')
            }
        }
        self.report_data = data
        return data
    
    def _load_json(self, rel_path: str) -> Dict[str, Any]:
        """Load JSON file from output directory."""
        path = os.path.join(self.output_dir, rel_path)
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Info: Could not load {path}")
        return {}
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary report (non-technical)."""
        report = []
        report.append("="*70)
        report.append("EXECUTIVE SECURITY ASSESSMENT SUMMARY")
        report.append("="*70)
        report.append(f"Assessment Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Overall risk assessment
        report.append("OVERALL RISK ASSESSMENT")
        report.append("-"*70)
        risk_summary = self._calculate_overall_risk()
        report.append(f"Risk Level: {risk_summary['level']}")
        report.append(f"Critical Findings: {risk_summary['critical']}")
        report.append(f"High Findings: {risk_summary['high']}")
        report.append(f"Medium Findings: {risk_summary['medium']}")
        report.append("")
        
        # Key findings
        report.append("KEY FINDINGS")
        report.append("-"*70)
        findings = self._extract_key_findings()
        for i, finding in enumerate(findings[:5], 1):
            report.append(f"{i}. [{finding['severity']}] {finding['title']}")
            report.append(f"   Impact: {finding['impact']}")
        report.append("")
        
        # Attack path summary
        attack_paths = self.report_data.get('trust_mapping', {}).get('attack_paths', {})
        if attack_paths:
            chains = attack_paths.get('attack_chains', [])
            critical_chains = [c for c in chains if c.get('risk_level') == 'CRITICAL']
            report.append("ATTACK PATH ANALYSIS")
            report.append("-"*70)
            report.append(f"Potential Attack Chains: {len(chains)}")
            report.append(f"Critical Risk Paths: {len(critical_chains)}")
            if critical_chains:
                report.append(f"\nMost Critical Attack Path:")
                top_chain = critical_chains[0]
                report.append(f"  Entry Point: {top_chain['entry_point']['description']}")
                report.append(f"  Impact: {top_chain['impact']}")
        report.append("")
        
        # Recommendations
        report.append("TOP RECOMMENDATIONS")
        report.append("-"*70)
        recommendations = self._get_top_recommendations()
        for i, rec in enumerate(recommendations[:5], 1):
            report.append(f"{i}. [{rec['severity']}] {rec['title']}")
            report.append(f"   Action: {rec['mitigation']}")
        report.append("")
        
        report.append("="*70)
        report.append("END OF EXECUTIVE SUMMARY")
        report.append("="*70)
        
        return "\n".join(report)
    
    def generate_technical_report(self) -> str:
        """Generate detailed technical report."""
        report = []
        report.append("="*70)
        report.append("TECHNICAL SECURITY ASSESSMENT REPORT")
        report.append("="*70)
        report.append(f"Assessment Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Credential vulnerabilities
        report.append("1. CREDENTIAL SECURITY ANALYSIS")
        report.append("-"*70)
        cred_data = self.report_data.get('credential_attacks', {})
        default_creds = cred_data.get('default_creds', {})
        if default_creds:
            successful = default_creds.get('successful_logins', [])
            report.append(f"Default Credentials Found: {len(successful)}")
            for cred in successful[:10]:
                report.append(f"  - {cred.get('target')}: {cred.get('service')} "
                            f"({cred.get('username')})")
        
        cleartext = cred_data.get('cleartext', {})
        if cleartext:
            captures = cleartext.get('captures', [])
            report.append(f"Cleartext Credentials Captured: {len(captures)}")
            for cap in captures[:10]:
                report.append(f"  - {cap.get('protocol')}: {cap.get('username')} "
                            f"on {cap.get('target')}")
        report.append("")
        
        # Patch management
        report.append("2. PATCH MANAGEMENT & VULNERABILITIES")
        report.append("-"*70)
        patch_data = self.report_data.get('patch_cadence', {})
        cves = patch_data.get('cves', {})
        if cves:
            matches = cves.get('matches', [])
            critical_cves = [c for c in matches if c.get('cvss_score', 0) >= 9.0]
            high_cves = [c for c in matches if 7.0 <= c.get('cvss_score', 0) < 9.0]
            report.append(f"Total CVEs Identified: {len(matches)}")
            report.append(f"Critical (CVSS >= 9.0): {len(critical_cves)}")
            report.append(f"High (CVSS 7.0-8.9): {len(high_cves)}")
            
            if critical_cves:
                report.append("\nCritical CVEs:")
                for cve in critical_cves[:5]:
                    report.append(f"  - {cve.get('cve_id')}: {cve.get('device')} "
                                f"(CVSS: {cve.get('cvss_score')})")
        
        aging = patch_data.get('aging', {})
        if aging:
            scores = aging.get('scores', [])
            critical_aging = [s for s in scores if s.get('score', 0) > 80]
            report.append(f"\nCritical Aging Scores: {len(critical_aging)}")
            for score in critical_aging[:5]:
                report.append(f"  - {score.get('device')}: Score {score.get('score')}/100 "
                            f"(Risk: {score.get('risk_level')})")
        report.append("")
        
        # Network anomalies
        report.append("3. NETWORK BEHAVIOR ANALYSIS")
        report.append("-"*70)
        flow_data = self.report_data.get('data_flow', {})
        anomalies = flow_data.get('anomalies', {})
        if anomalies:
            all_anomalies = anomalies.get('anomalies', [])
            by_severity = {}
            for a in all_anomalies:
                sev = a.get('severity', 'MEDIUM')
                by_severity[sev] = by_severity.get(sev, 0) + 1
            
            report.append(f"Total Anomalies Detected: {len(all_anomalies)}")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if sev in by_severity:
                    report.append(f"  {sev}: {by_severity[sev]}")
            
            # Beaconing detection
            beaconing = [a for a in all_anomalies if a.get('type') == 'POSSIBLE_BEACONING']
            if beaconing:
                report.append(f"\n⚠ CRITICAL: Beaconing patterns detected ({len(beaconing)})")
                report.append("  Possible C2 communication channels identified")
        report.append("")
        
        # Wireless security
        report.append("4. WIRELESS SECURITY ASSESSMENT")
        report.append("-"*70)
        wifi_data = self.report_data.get('wifi_attacks', {})
        spectrum = wifi_data.get('spectrum', {})
        if spectrum:
            networks = spectrum.get('networks', [])
            open_nets = [n for n in networks if n.get('encryption', '').upper() == 'OPEN']
            wep_nets = [n for n in networks if n.get('encryption', '').upper() == 'WEP']
            
            report.append(f"Total Networks Scanned: {len(networks)}")
            report.append(f"Open Networks (CRITICAL): {len(open_nets)}")
            report.append(f"WEP Networks (HIGH): {len(wep_nets)}")
            
            if open_nets:
                report.append("\nOpen Networks:")
                for net in open_nets[:5]:
                    report.append(f"  - {net.get('ssid')} ({net.get('bssid')})")
        
        wps = wifi_data.get('wps', {})
        if wps:
            wps_enabled = wps.get('wps_enabled_networks', [])
            report.append(f"WPS-Enabled Networks: {len(wps_enabled)}")
        report.append("")
        
        # Lateral movement
        report.append("5. LATERAL MOVEMENT & ATTACK PATHS")
        report.append("-"*70)
        trust_data = self.report_data.get('trust_mapping', {})
        attack_paths = trust_data.get('attack_paths', {})
        if attack_paths:
            chains = attack_paths.get('attack_chains', [])
            report.append(f"Attack Chains Identified: {len(chains)}")
            
            # Group by risk
            by_risk = {}
            for chain in chains:
                risk = chain.get('risk_level', 'MEDIUM')
                by_risk[risk] = by_risk.get(risk, 0) + 1
            
            for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if risk in by_risk:
                    report.append(f"  {risk}: {by_risk[risk]}")
            
            # MITRE ATT&CK coverage
            all_techniques = set()
            for chain in chains:
                all_techniques.update(chain.get('mitre_techniques', []))
            report.append(f"\nMITRE ATT&CK Techniques Identified: {len(all_techniques)}")
            report.append(f"  Techniques: {', '.join(sorted(all_techniques))}")
        report.append("")
        
        # Honeypot activity
        report.append("6. DECEPTION & THREAT DETECTION")
        report.append("-"*70)
        deception_data = self.report_data.get('deception', {})
        alerts = deception_data.get('alerts', {})
        if alerts:
            all_alerts = alerts.get('all_alerts', [])
            patterns = alerts.get('patterns', [])
            
            report.append(f"Honeypot Alerts Generated: {len(all_alerts)}")
            report.append(f"Attack Patterns Detected: {len(patterns)}")
            
            if patterns:
                report.append("\nDetected Patterns:")
                for pattern in patterns:
                    report.append(f"  - [{pattern.get('severity')}] {pattern.get('type')}")
                    report.append(f"    Source: {pattern.get('source')}")
        report.append("")
        
        report.append("="*70)
        report.append("END OF TECHNICAL REPORT")
        report.append("="*70)
        
        return "\n".join(report)
    
    def generate_compliance_report(self) -> str:
        """Generate compliance-focused report (NIST, ISO, PCI-DSS aligned)."""
        report = []
        report.append("="*70)
        report.append("SECURITY COMPLIANCE ASSESSMENT REPORT")
        report.append("="*70)
        report.append(f"Assessment Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Framework Alignment: NIST CSF, ISO 27001, PCI-DSS")
        report.append("")
        
        # NIST CSF Categories
        report.append("NIST CYBERSECURITY FRAMEWORK FINDINGS")
        report.append("-"*70)
        
        # Identify (ID)
        report.append("\n1. IDENTIFY (ID)")
        report.append("   Asset Management & Risk Assessment")
        device_count = self._count_discovered_devices()
        report.append(f"   - Devices Identified: {device_count}")
        report.append(f"   - Vulnerability Assessment: COMPLETED")
        report.append(f"   - Risk Rating: {self._calculate_overall_risk()['level']}")
        
        # Protect (PR)
        report.append("\n2. PROTECT (PR)")
        report.append("   Access Control & Data Security")
        cred_issues = self._count_credential_issues()
        report.append(f"   - Default Credentials Found: {cred_issues['default']} (NON-COMPLIANT)")
        report.append(f"   - Cleartext Protocols: {cred_issues['cleartext']} (NON-COMPLIANT)")
        patch_issues = self._count_patch_issues()
        report.append(f"   - Unpatched Critical CVEs: {patch_issues['critical']} (NON-COMPLIANT)")
        report.append(f"   - Devices Requiring Updates: {patch_issues['aging']}")
        
        # Detect (DE)
        report.append("\n3. DETECT (DE)")
        report.append("   Anomaly Detection & Monitoring")
        anomaly_count = self._count_anomalies()
        report.append(f"   - Behavioral Anomalies: {anomaly_count['total']}")
        report.append(f"   - Beaconing Patterns: {anomaly_count['beaconing']} (CRITICAL)")
        deception_count = self._count_deception_alerts()
        report.append(f"   - Honeypot Alerts: {deception_count}")
        
        # Respond (RS)
        report.append("\n4. RESPOND (RS)")
        report.append("   Incident Response Readiness")
        report.append(f"   - Attack Paths Identified: {self._count_attack_paths()}")
        report.append(f"   - Response Plan Required: YES")
        
        # Recover (RC)
        report.append("\n5. RECOVER (RC)")
        report.append("   Recovery Planning")
        report.append(f"   - Backup Validation: REQUIRED")
        report.append(f"   - Disaster Recovery: REVIEW NEEDED")
        
        # Compliance status
        report.append("")
        report.append("COMPLIANCE STATUS SUMMARY")
        report.append("-"*70)
        compliance_score = self._calculate_compliance_score()
        report.append(f"Overall Compliance: {compliance_score}%")
        report.append(f"Status: {'COMPLIANT' if compliance_score >= 80 else 'NON-COMPLIANT'}")
        report.append("")
        
        # Required actions
        report.append("REQUIRED REMEDIATION ACTIONS")
        report.append("-"*70)
        actions = self._get_compliance_actions()
        for i, action in enumerate(actions, 1):
            report.append(f"{i}. {action}")
        report.append("")
        
        report.append("="*70)
        report.append("END OF COMPLIANCE REPORT")
        report.append("="*70)
        
        return "\n".join(report)
    
    def _calculate_overall_risk(self) -> Dict[str, Any]:
        """Calculate overall risk assessment."""
        critical = 0
        high = 0
        medium = 0
        
        # Count from attack paths
        attack_paths = self.report_data.get('trust_mapping', {}).get('attack_paths', {})
        if attack_paths:
            chains = attack_paths.get('attack_chains', [])
            for chain in chains:
                risk = chain.get('risk_level', 'MEDIUM')
                if risk == 'CRITICAL':
                    critical += 1
                elif risk == 'HIGH':
                    high += 1
                elif risk == 'MEDIUM':
                    medium += 1
        
        # Determine overall level
        if critical > 0:
            level = 'CRITICAL'
        elif high > 5:
            level = 'HIGH'
        elif high > 0 or medium > 10:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {'level': level, 'critical': critical, 'high': high, 'medium': medium}
    
    def _extract_key_findings(self) -> List[Dict[str, Any]]:
        """Extract key findings across all modules."""
        findings = []
        
        # Default credentials
        cred_data = self.report_data.get('credential_attacks', {})
        default_creds = cred_data.get('default_creds', {})
        if default_creds:
            successful = default_creds.get('successful_logins', [])
            if successful:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': f'{len(successful)} devices using default credentials',
                    'impact': 'Immediate unauthorized access possible'
                })
        
        # Critical CVEs
        patch_data = self.report_data.get('patch_cadence', {})
        cves = patch_data.get('cves', {})
        if cves:
            critical_cves = [c for c in cves.get('matches', []) if c.get('cvss_score', 0) >= 9.0]
            if critical_cves:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': f'{len(critical_cves)} critical vulnerabilities identified',
                    'impact': 'Remote code execution and system compromise possible'
                })
        
        # Beaconing
        flow_data = self.report_data.get('data_flow', {})
        anomalies = flow_data.get('anomalies', {})
        if anomalies:
            beaconing = [a for a in anomalies.get('anomalies', []) 
                        if a.get('type') == 'POSSIBLE_BEACONING']
            if beaconing:
                findings.append({
                    'severity': 'CRITICAL',
                    'title': f'Beaconing patterns detected on {len(beaconing)} devices',
                    'impact': 'Potential command and control communication'
                })
        
        # Open WiFi
        wifi_data = self.report_data.get('wifi_attacks', {})
        spectrum = wifi_data.get('spectrum', {})
        if spectrum:
            open_nets = [n for n in spectrum.get('networks', []) 
                        if n.get('encryption', '').upper() == 'OPEN']
            if open_nets:
                findings.append({
                    'severity': 'HIGH',
                    'title': f'{len(open_nets)} open wireless networks',
                    'impact': 'Unauthorized network access and eavesdropping'
                })
        
        # Attack paths
        trust_data = self.report_data.get('trust_mapping', {})
        attack_paths = trust_data.get('attack_paths', {})
        if attack_paths:
            critical_chains = [c for c in attack_paths.get('attack_chains', []) 
                             if c.get('risk_level') == 'CRITICAL']
            if critical_chains:
                findings.append({
                    'severity': 'HIGH',
                    'title': f'{len(critical_chains)} critical attack paths to domain compromise',
                    'impact': 'Complete network compromise feasible'
                })
        
        return findings
    
    def _get_top_recommendations(self) -> List[Dict[str, Any]]:
        """Get top security recommendations."""
        attack_paths = self.report_data.get('trust_mapping', {}).get('attack_paths', {})
        if attack_paths:
            return attack_paths.get('recommendations', [])
        return []
    
    def _count_discovered_devices(self) -> int:
        """Count total discovered devices."""
        count = 0
        flow_data = self.report_data.get('data_flow', {}).get('baseline', {})
        if flow_data:
            baselines = flow_data.get('baselines', {})
            count = len(baselines)
        return count
    
    def _count_credential_issues(self) -> Dict[str, int]:
        """Count credential-related issues."""
        cred_data = self.report_data.get('credential_attacks', {})
        default = len(cred_data.get('default_creds', {}).get('successful_logins', []))
        cleartext = len(cred_data.get('cleartext', {}).get('captures', []))
        return {'default': default, 'cleartext': cleartext}
    
    def _count_patch_issues(self) -> Dict[str, int]:
        """Count patch-related issues."""
        patch_data = self.report_data.get('patch_cadence', {})
        cves = patch_data.get('cves', {}).get('matches', [])
        critical = len([c for c in cves if c.get('cvss_score', 0) >= 9.0])
        
        aging = patch_data.get('aging', {}).get('scores', [])
        aging_critical = len([s for s in aging if s.get('score', 0) > 70])
        
        return {'critical': critical, 'aging': aging_critical}
    
    def _count_anomalies(self) -> Dict[str, int]:
        """Count anomalies by type."""
        flow_data = self.report_data.get('data_flow', {}).get('anomalies', {})
        all_anomalies = flow_data.get('anomalies', [])
        beaconing = len([a for a in all_anomalies if a.get('type') == 'POSSIBLE_BEACONING'])
        return {'total': len(all_anomalies), 'beaconing': beaconing}
    
    def _count_deception_alerts(self) -> int:
        """Count deception alerts."""
        deception_data = self.report_data.get('deception', {}).get('alerts', {})
        return len(deception_data.get('all_alerts', []))
    
    def _count_attack_paths(self) -> int:
        """Count identified attack paths."""
        attack_paths = self.report_data.get('trust_mapping', {}).get('attack_paths', {})
        return len(attack_paths.get('attack_chains', []))
    
    def _calculate_compliance_score(self) -> int:
        """Calculate compliance score (0-100)."""
        score = 100
        
        # Deduct for credential issues
        cred_issues = self._count_credential_issues()
        score -= min(30, cred_issues['default'] * 5)
        score -= min(20, cred_issues['cleartext'] * 3)
        
        # Deduct for patch issues
        patch_issues = self._count_patch_issues()
        score -= min(30, patch_issues['critical'] * 5)
        
        # Deduct for anomalies
        anomalies = self._count_anomalies()
        score -= min(20, anomalies['beaconing'] * 10)
        
        return max(0, score)
    
    def _get_compliance_actions(self) -> List[str]:
        """Get required compliance actions."""
        actions = []
        
        cred_issues = self._count_credential_issues()
        if cred_issues['default'] > 0:
            actions.append("Immediately change all default credentials and implement password policy")
        if cred_issues['cleartext'] > 0:
            actions.append("Eliminate cleartext protocols and enforce encrypted communications")
        
        patch_issues = self._count_patch_issues()
        if patch_issues['critical'] > 0:
            actions.append("Apply critical security patches within 30 days")
        
        if self._count_anomalies()['beaconing'] > 0:
            actions.append("Investigate and remediate beaconing patterns immediately")
        
        if len(actions) == 0:
            actions.append("Maintain current security posture with regular assessments")
        
        return actions
    
    def generate_all_reports(self):
        """Generate all report types and save to files."""
        print("[*] Loading all module data...")
        self.load_all_module_data()
        
        print("[*] Generating executive summary...")
        executive = self.generate_executive_summary()
        exec_path = os.path.join(self.output_dir, 'report', 'executive_summary.txt')
        os.makedirs(os.path.dirname(exec_path), exist_ok=True)
        with open(exec_path, 'w') as f:
            f.write(executive)
        print(f"[+] Executive summary saved to {exec_path}")
        
        print("[*] Generating technical report...")
        technical = self.generate_technical_report()
        tech_path = os.path.join(self.output_dir, 'report', 'technical_report.txt')
        with open(tech_path, 'w') as f:
            f.write(technical)
        print(f"[+] Technical report saved to {tech_path}")
        
        print("[*] Generating compliance report...")
        compliance = self.generate_compliance_report()
        comp_path = os.path.join(self.output_dir, 'report', 'compliance_report.txt')
        with open(comp_path, 'w') as f:
            f.write(compliance)
        print(f"[+] Compliance report saved to {comp_path}")
        
        print("[*] All reports generated successfully!")


def main():
    """Main execution function."""
    import sys
    
    output_dir = sys.argv[1] if len(sys.argv) > 1 else '/output'
    
    reporter = UnifiedReporter(output_dir)
    reporter.generate_all_reports()


if __name__ == '__main__':
    main()
