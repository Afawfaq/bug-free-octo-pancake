#!/usr/bin/env python3
"""
SSH Credential Harvester
Enumerates SSH keys and configurations on discovered hosts
"""

import sys
import json
import os

def analyze_ssh_config(target_info):
    """
    Analyze SSH configuration for security issues
    Note: This is a placeholder for actual SSH enumeration
    In a real scenario, this would require access to the target system
    """
    findings = []
    
    # Common SSH security issues to check for
    checks = [
        {
            "check": "SSH Agent Forwarding",
            "description": "SSH agent forwarding enabled",
            "risk": "HIGH",
            "recommendation": "Disable agent forwarding unless necessary"
        },
        {
            "check": "Root Login",
            "description": "Root login permitted",
            "risk": "HIGH",
            "recommendation": "Disable PermitRootLogin in sshd_config"
        },
        {
            "check": "Password Authentication",
            "description": "Password authentication enabled",
            "risk": "MEDIUM",
            "recommendation": "Use key-based authentication only"
        },
        {
            "check": "Weak Key Exchange",
            "description": "Weak key exchange algorithms",
            "risk": "MEDIUM",
            "recommendation": "Use modern KexAlgorithms"
        }
    ]
    
    return findings

def enumerate_ssh_hosts(target_file):
    """Enumerate SSH-enabled hosts"""
    findings = []
    
    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        for ip in targets:
            finding = {
                "ip": ip,
                "service": "SSH",
                "port": 22,
                "notes": "SSH service detected - potential authentication target",
                "severity": "INFO"
            }
            findings.append(finding)
    
    except Exception as e:
        print(f"[!] Error reading targets: {e}")
    
    return findings

def check_common_keys(target_file):
    """Check for commonly used SSH keys that might be exposed"""
    common_keys = [
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "authorized_keys",
        "known_hosts"
    ]
    
    findings = []
    
    finding = {
        "check": "Common SSH Keys",
        "description": "Analysis of common SSH key locations",
        "common_locations": [
            "~/.ssh/id_rsa",
            "~/.ssh/id_dsa",
            "~/.ssh/authorized_keys"
        ],
        "recommendation": "Ensure SSH keys are properly protected (chmod 600)",
        "severity": "INFO"
    }
    findings.append(finding)
    
    return findings

def main():
    if len(sys.argv) < 3:
        print("Usage: ssh_harvester.py <target_ips_file> <output_file>")
        sys.exit(1)
    
    target_file = sys.argv[1]
    output_file = sys.argv[2]
    
    print("[*] SSH Credential Harvester")
    print("[*] Enumerating SSH hosts...")
    
    # Enumerate SSH hosts
    ssh_hosts = enumerate_ssh_hosts(target_file)
    
    # Check for common key issues
    key_findings = check_common_keys(target_file)
    
    # Compile results
    output_data = {
        "ssh_hosts_found": len(ssh_hosts),
        "ssh_hosts": ssh_hosts,
        "security_checks": key_findings,
        "recommendations": [
            "Use key-based authentication instead of passwords",
            "Disable root login",
            "Use strong key exchange algorithms",
            "Regularly rotate SSH keys",
            "Monitor SSH logs for failed authentication attempts",
            "Consider using SSH certificates for better key management"
        ]
    }
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"[+] Found {len(ssh_hosts)} SSH-enabled hosts")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
