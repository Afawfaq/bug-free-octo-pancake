#!/usr/bin/env python3
"""
Chromecast Honeypot
Simulates Google Cast protocol to detect IoT targeting and media hijacking attempts.
"""

import json
import socket
import threading
import time
from datetime import datetime
import sys
import os

class ChromecastHoneypot:
    """Fake Chromecast device using DIAL/SSDP"""
    
    def __init__(self, output_dir="/output/deception", port=8008):
        self.output_dir = output_dir
        self.port = port
        self.ssdp_port = 1900
        self.discoveries = []
        self.cast_attempts = []
        self.app_launches = []
        self.alerts = []
        self.running = False
        
        self.device_info = {
            'name': 'Living Room TV',
            'model': 'Chromecast Ultra',
            'manufacturer': 'Google Inc.',
            'uuid': '12345678-1234-1234-1234-123456789abc'
        }
        
    def log_discovery(self, source_ip):
        """Log SSDP discovery"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'discovery',
            'source_ip': source_ip,
            'protocol': 'SSDP'
        }
        self.discoveries.append(event)
        
        # Alert on discovery
        self.generate_alert('MEDIUM', 'chromecast_discovery', source_ip,
                          "Chromecast device discovered")
    
    def log_cast_attempt(self, source_ip, app_name, media_url=None):
        """Log cast attempts"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'cast_attempt',
            'source_ip': source_ip,
            'app_name': app_name,
            'media_url': media_url
        }
        self.cast_attempts.append(event)
        
        # Alert on cast attempt
        self.generate_alert('MEDIUM', 'chromecast_cast_attempt', source_ip,
                          f"Cast attempt for app: {app_name}")
    
    def log_app_launch(self, source_ip, app_id):
        """Log app launch attempts"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'app_launch',
            'source_ip': source_ip,
            'app_id': app_id
        }
        self.app_launches.append(event)
        
        # Alert on app launch
        self.generate_alert('MEDIUM', 'chromecast_app_launch', source_ip,
                          f"App launch attempt: {app_id}")
    
    def generate_alert(self, severity, alert_type, source_ip, description):
        """Generate security alert"""
        alert = {
            'alert_id': f"chromecast_{len(self.alerts):03d}",
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'honeypot': 'chromecast',
            'severity': severity,
            'alert_type': alert_type,
            'source_ip': source_ip,
            'description': description
        }
        self.alerts.append(alert)
        print(f"[ALERT] {severity}: {description} from {source_ip}")
    
    def handle_ssdp(self):
        """Handle SSDP discovery responses"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', self.ssdp_port))
            sock.settimeout(1.0)
            
            # Join multicast group
            mreq = socket.inet_aton('239.255.255.250') + socket.inet_aton('0.0.0.0')
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            while self.running:
                try:
                    data, address = sock.recvfrom(1024)
                    if b'M-SEARCH' in data:
                        source_ip = address[0]
                        print(f"[Chromecast] SSDP discovery from {source_ip}")
                        self.log_discovery(source_ip)
                        
                        # Send SSDP response
                        response = (
                            b'HTTP/1.1 200 OK\r\n'
                            b'CACHE-CONTROL: max-age=1800\r\n'
                            b'LOCATION: http://192.168.1.100:8008/ssdp/device-desc.xml\r\n'
                            b'SERVER: Linux/3.8.13, UPnP/1.0, Portable SDK for UPnP devices/1.6.18\r\n'
                            b'ST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n'
                        )
                        sock.sendto(response, address)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[Chromecast] SSDP error: {e}")
                        
        except Exception as e:
            print(f"[Chromecast] Error setting up SSDP: {e}")
        finally:
            sock.close()
    
    def start(self, duration=3600):
        """Start the Chromecast honeypot"""
        print(f"[Chromecast] Starting honeypot on port {self.port}")
        self.running = True
        
        # Start SSDP handler in background
        ssdp_thread = threading.Thread(target=self.handle_ssdp)
        ssdp_thread.daemon = True
        ssdp_thread.start()
        
        # Run for specified duration
        time.sleep(duration)
        self.running = False
        
        print("[Chromecast] Honeypot stopped")
    
    def stop(self):
        """Stop the honeypot"""
        self.running = False
    
    def save_results(self):
        """Save honeypot results"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        results = {
            'honeypot': 'chromecast',
            'device_info': self.device_info,
            'discoveries': self.discoveries,
            'cast_attempts': self.cast_attempts,
            'app_launches': self.app_launches,
            'alerts': self.alerts,
            'statistics': {
                'total_discoveries': len(self.discoveries),
                'total_cast_attempts': len(self.cast_attempts),
                'total_app_launches': len(self.app_launches),
                'total_alerts': len(self.alerts)
            }
        }
        
        output_file = os.path.join(self.output_dir, 'chromecast_honeypot.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[Chromecast] Results saved to {output_file}")
        print(f"[Chromecast] Total discoveries: {len(self.discoveries)}")
        print(f"[Chromecast] Total cast attempts: {len(self.cast_attempts)}")

def main():
    """Main function"""
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/output/deception"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
    
    honeypot = ChromecastHoneypot(output_dir)
    
    try:
        honeypot.start(duration)
    except KeyboardInterrupt:
        print("\n[Chromecast] Interrupted by user")
    finally:
        honeypot.stop()
        honeypot.save_results()

if __name__ == "__main__":
    main()
