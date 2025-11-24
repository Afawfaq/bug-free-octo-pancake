#!/usr/bin/env python3
"""
Local PKI Tamper Monitor
Tracks certificate changes, weak ciphers, and suspicious PKI activity on LAN
"""

import sys
import json
import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import subprocess

def get_certificate(host, port=443):
    """Retrieve SSL certificate from host"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                return {
                    "host": host,
                    "port": port,
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "not_before": cert.not_valid_before.isoformat(),
                    "not_after": cert.not_valid_after.isoformat(),
                    "serial": str(cert.serial_number),
                    "version": cert.version.name,
                    "is_self_signed": cert.issuer == cert.subject,
                    "signature_algorithm": cert.signature_algorithm_oid._name,
                    "key_size": cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 'N/A'
                }
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}

def analyze_cipher_strength(host, port=443):
    """Check for weak ciphers"""
    weak_ciphers = []
    
    # Test for weak SSL/TLS versions
    weak_protocols = [
        ('SSLv2', ssl.PROTOCOL_SSLv23),
        ('SSLv3', ssl.PROTOCOL_SSLv23),
        ('TLSv1.0', ssl.PROTOCOL_TLSv1),
    ]
    
    for proto_name, proto in weak_protocols:
        try:
            context = ssl.SSLContext(proto)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock) as ssock:
                    weak_ciphers.append({
                        "protocol": proto_name,
                        "cipher": ssock.cipher()
                    })
        except:
            pass
    
    return weak_ciphers

def scan_pki_infrastructure(targets_file, output_file):
    """Scan all hosts for PKI issues"""
    results = {
        "scan_time": datetime.now().isoformat(),
        "certificates": [],
        "weak_ciphers": [],
        "self_signed": [],
        "expiring_soon": []
    }
    
    # Read targets
    with open(targets_file) as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Scanning {len(targets)} hosts for PKI issues...")
    
    for target in targets:
        # Try HTTPS
        cert_info = get_certificate(target, 443)
        if 'error' not in cert_info:
            results["certificates"].append(cert_info)
            
            if cert_info.get("is_self_signed"):
                results["self_signed"].append(cert_info)
            
            # Check cipher strength
            weak = analyze_cipher_strength(target, 443)
            if weak:
                results["weak_ciphers"].append({
                    "host": target,
                    "weak_protocols": weak
                })
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] PKI scan complete: {len(results['certificates'])} certificates found")
    print(f"    Self-signed: {len(results['self_signed'])}")
    print(f"    Weak ciphers: {len(results['weak_ciphers'])}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <targets_file> <output_file>")
        sys.exit(1)
    
    scan_pki_infrastructure(sys.argv[1], sys.argv[2])
