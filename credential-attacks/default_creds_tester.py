#!/usr/bin/env python3
"""
Default Credentials Tester
Tests common default credentials on discovered devices
"""

import json
import sys
import socket
import requests
import ftplib
import telnetlib
import base64
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings("ignore")

def load_credentials_db(db_file: str = "/usr/local/bin/default_creds_db.json") -> Dict:
    """Load default credentials database"""
    try:
        with open(db_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading credentials database: {e}")
        return {}

def test_http_auth(ip: str, port: int, username: str, password: str) -> bool:
    """Test HTTP Basic Authentication"""
    try:
        urls = [
            f"http://{ip}:{port}/",
            f"http://{ip}:{port}/admin",
            f"http://{ip}:{port}/login",
            f"http://{ip}:{port}/cgi-bin/"
        ]
        
        for url in urls:
            try:
                response = requests.get(
                    url,
                    auth=(username, password),
                    timeout=5,
                    verify=False
                )
                if response.status_code == 200:
                    return True
            except:
                pass
        return False
    except Exception:
        return False

def test_ftp_auth(ip: str, port: int, username: str, password: str) -> bool:
    """Test FTP authentication"""
    try:
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(ip, port)
        ftp.login(username, password)
        ftp.quit()
        return True
    except Exception:
        return False

def test_telnet_auth(ip: str, port: int, username: str, password: str) -> bool:
    """Test Telnet authentication (basic check)"""
    try:
        tn = telnetlib.Telnet(ip, port, timeout=5)
        tn.read_until(b"login: ", timeout=3)
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", timeout=3)
        tn.write(password.encode('ascii') + b"\n")
        
        # Check for successful login (very basic)
        response = tn.read_some()
        tn.close()
        
        if b"incorrect" not in response.lower() and b"failed" not in response.lower():
            return True
        return False
    except Exception:
        return False

def test_ssh_auth(ip: str, port: int, username: str, password: str) -> bool:
    """Test SSH authentication"""
    try:
        import paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, port=port, username=username, password=password, timeout=5, allow_agent=False, look_for_keys=False)
        ssh.close()
        return True
    except Exception:
        return False

def identify_device_type(ip: str) -> str:
    """Identify device type based on open ports and banners"""
    device_type = "unknown"
    
    # Check for printer ports
    printer_ports = [631, 9100, 515]
    for port in printer_ports:
        if is_port_open(ip, port):
            device_type = "printer"
            break
    
    # Check for router/gateway
    if is_port_open(ip, 80) or is_port_open(ip, 443):
        try:
            response = requests.get(f"http://{ip}", timeout=3, verify=False)
            content = response.text.lower()
            if any(keyword in content for keyword in ["router", "gateway", "wan", "dhcp"]):
                device_type = "router"
        except:
            pass
    
    # Check for NAS
    nas_ports = [139, 445, 548, 2049]
    if any(is_port_open(ip, port) for port in nas_ports):
        device_type = "nas"
    
    # Check for camera (RTSP, ONVIF)
    if is_port_open(ip, 554) or is_port_open(ip, 8000):
        device_type = "camera"
    
    # Check for IoT device
    if is_port_open(ip, 8008) or is_port_open(ip, 8080):
        device_type = "iot_device"
    
    return device_type

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def test_device_credentials(ip: str, device_type: str, creds_db: Dict) -> List[Tuple[str, str, str, str]]:
    """Test default credentials on a device"""
    results = []
    
    # Get credentials for device type
    credentials = creds_db.get(device_type, [])
    if not credentials:
        credentials = creds_db.get("iot_devices", [])
    
    print(f"[*] Testing {len(credentials)} credential pairs on {ip} (type: {device_type})...")
    
    # Test HTTP/HTTPS (common web interfaces)
    if is_port_open(ip, 80):
        for cred in credentials[:5]:  # Limit to avoid lockouts
            username = cred.get("username", "")
            password = cred.get("password", "")
            
            if test_http_auth(ip, 80, username, password):
                results.append((ip, "http", username, password))
                print(f"[+] SUCCESS: {ip}:80 - {username}:{password}")
                break
    
    # Test FTP
    if is_port_open(ip, 21):
        for cred in credentials[:3]:
            username = cred.get("username", "")
            password = cred.get("password", "")
            
            if test_ftp_auth(ip, 21, username, password):
                results.append((ip, "ftp", username, password))
                print(f"[+] SUCCESS: {ip}:21 - {username}:{password}")
                break
    
    # Test SSH
    if is_port_open(ip, 22):
        for cred in credentials[:3]:
            username = cred.get("username", "")
            password = cred.get("password", "")
            
            if test_ssh_auth(ip, 22, username, password):
                results.append((ip, "ssh", username, password))
                print(f"[+] SUCCESS: {ip}:22 - {username}:{password}")
                break
    
    # Test Telnet
    if is_port_open(ip, 23):
        for cred in credentials[:3]:
            username = cred.get("username", "")
            password = cred.get("password", "")
            
            if test_telnet_auth(ip, 23, username, password):
                results.append((ip, "telnet", username, password))
                print(f"[+] SUCCESS: {ip}:23 - {username}:{password}")
                break
    
    return results

def main():
    if len(sys.argv) < 3:
        print("Usage: default_creds_tester.py <target_ips_file> <output_file>")
        sys.exit(1)
    
    target_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Load credentials database
    creds_db = load_credentials_db()
    if not creds_db:
        print("[!] No credentials database loaded. Exiting.")
        sys.exit(1)
    
    # Load target IPs
    try:
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error loading targets: {e}")
        sys.exit(1)
    
    print(f"[*] Loaded {len(targets)} targets")
    print(f"[*] Testing default credentials...")
    
    all_results = []
    
    for ip in targets:
        print(f"\n[*] Testing {ip}...")
        device_type = identify_device_type(ip)
        results = test_device_credentials(ip, device_type, creds_db)
        all_results.extend(results)
    
    # Save results
    output_data = {
        "tested_targets": len(targets),
        "successful_auths": len(all_results),
        "findings": [
            {
                "ip": r[0],
                "service": r[1],
                "username": r[2],
                "password": r[3],
                "severity": "CRITICAL"
            }
            for r in all_results
        ]
    }
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"\n[+] Testing complete. Found {len(all_results)} default credentials.")
    print(f"[+] Results saved to {output_file}")

if __name__ == "__main__":
    main()
