#!/usr/bin/env python3
"""
SSDP Media Device Honeypot
Simulates UPnP media renderer for DLNA/UPnP exploitation detection.
"""

import json
import socket
import threading
import time
from datetime import datetime
import sys
import os

class SSDPHoneypot:
    """Fake UPnP media device"""
    
    def __init__(self, output_dir="/output/deception", port=1900):
        self.output_dir = output_dir
        self.port = port
        self.discoveries = []
        self.service_requests = []
        self.control_attempts = []
        self.alerts = []
        self.running = False
        
        self.devices = [
            {'type': 'MediaRenderer', 'name': 'Living Room TV'},
            {'type': 'MediaServer', 'name': 'Home Media Server'},
            {'type': 'AVTransport', 'name': 'Smart Speaker'}
        ]
        
    def log_discovery(self, source_ip, search_target):
        """Log SSDP M-SEARCH discoveries"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'discovery',
            'source_ip': source_ip,
            'search_target': search_target
        }
        self.discoveries.append(event)
        
        # Alert on discovery
        self.generate_alert('LOW', 'ssdp_discovery', source_ip,
                          f"UPnP discovery: {search_target}")
    
    def log_service_request(self, source_ip, service_type):
        """Log UPnP service requests"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'service_request',
            'source_ip': source_ip,
            'service_type': service_type
        }
        self.service_requests.append(event)
        
        # Alert on service enumeration
        self.generate_alert('MEDIUM', 'ssdp_service_enum', source_ip,
                          f"Service enumeration: {service_type}")
    
    def log_control_attempt(self, source_ip, action):
        """Log UPnP control attempts"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'control_attempt',
            'source_ip': source_ip,
            'action': action
        }
        self.control_attempts.append(event)
        
        # Alert on control attempts
        self.generate_alert('MEDIUM', 'ssdp_control_attempt', source_ip,
                          f"Control attempt: {action}")
    
    def generate_alert(self, severity, alert_type, source_ip, description):
        """Generate security alert"""
        alert = {
            'alert_id': f"ssdp_{len(self.alerts):03d}",
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'honeypot': 'ssdp',
            'severity': severity,
            'alert_type': alert_type,
            'source_ip': source_ip,
            'description': description
        }
        self.alerts.append(alert)
        print(f"[ALERT] {severity}: {description} from {source_ip}")
    
    def handle_ssdp(self):
        """Handle SSDP multicast messages"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', self.port))
            sock.settimeout(1.0)
            
            # Join SSDP multicast group
            mreq = socket.inet_aton('239.255.255.250') + socket.inet_aton('0.0.0.0')
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            while self.running:
                try:
                    data, address = sock.recvfrom(2048)
                    source_ip = address[0]
                    
                    if b'M-SEARCH' in data:
                        # Extract search target
                        st_line = [line for line in data.decode('utf-8', errors='ignore').split('\r\n') 
                                  if 'ST:' in line]
                        search_target = st_line[0].split('ST:')[1].strip() if st_line else 'unknown'
                        
                        print(f"[SSDP] M-SEARCH from {source_ip} for {search_target}")
                        self.log_discovery(source_ip, search_target)
                        
                        # Respond with device advertisement
                        for device in self.devices:
                            response = (
                                f"HTTP/1.1 200 OK\r\n"
                                f"CACHE-CONTROL: max-age=1800\r\n"
                                f"LOCATION: http://192.168.1.100:8200/device.xml\r\n"
                                f"SERVER: Linux/5.4, UPnP/1.1, MiniUPnPd/2.1\r\n"
                                f"ST: urn:schemas-upnp-org:device:{device['type']}:1\r\n"
                                f"USN: uuid:12345678-1234-1234-1234-{len(self.discoveries):012d}\r\n\r\n"
                            ).encode()
                            sock.sendto(response, address)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[SSDP] Error: {e}")
                        
        except Exception as e:
            print(f"[SSDP] Error setting up listener: {e}")
        finally:
            sock.close()
    
    def start(self, duration=3600):
        """Start the SSDP honeypot"""
        print(f"[SSDP] Starting honeypot on port {self.port}")
        self.running = True
        
        # Start SSDP handler in background
        ssdp_thread = threading.Thread(target=self.handle_ssdp)
        ssdp_thread.daemon = True
        ssdp_thread.start()
        
        # Run for specified duration
        time.sleep(duration)
        self.running = False
        
        print("[SSDP] Honeypot stopped")
    
    def stop(self):
        """Stop the honeypot"""
        self.running = False
    
    def save_results(self):
        """Save honeypot results"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        results = {
            'honeypot': 'ssdp',
            'devices': self.devices,
            'discoveries': self.discoveries,
            'service_requests': self.service_requests,
            'control_attempts': self.control_attempts,
            'alerts': self.alerts,
            'statistics': {
                'total_discoveries': len(self.discoveries),
                'total_service_requests': len(self.service_requests),
                'total_control_attempts': len(self.control_attempts),
                'total_alerts': len(self.alerts)
            }
        }
        
        output_file = os.path.join(self.output_dir, 'ssdp_honeypot.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[SSDP] Results saved to {output_file}")
        print(f"[SSDP] Total discoveries: {len(self.discoveries)}")
        print(f"[SSDP] Total control attempts: {len(self.control_attempts)}")

def main():
    """Main function"""
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/output/deception"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
    
    honeypot = SSDPHoneypot(output_dir)
    
    try:
        honeypot.start(duration)
    except KeyboardInterrupt:
        print("\n[SSDP] Interrupted by user")
    finally:
        honeypot.stop()
        honeypot.save_results()

if __name__ == "__main__":
    main()
