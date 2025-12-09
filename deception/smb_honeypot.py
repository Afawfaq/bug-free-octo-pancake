#!/usr/bin/env python3
"""
SMB Share Honeypot
Simulates Windows file sharing to detect SMB enumeration and access attempts.
"""

import json
import socket
import threading
import time
from datetime import datetime
import sys
import os

class SMBHoneypot:
    """Fake SMB server to detect file sharing attacks"""
    
    def __init__(self, output_dir="/output/deception", port=445):
        self.output_dir = output_dir
        self.port = port
        self.connections = []
        self.authentications = []
        self.file_access = []
        self.alerts = []
        self.running = False
        
        # Tempting share names that attract attackers
        self.shares = [
            'backup$',
            'passwords',
            'confidential',
            'finance',
            'hr-docs'
        ]
        
    def log_connection(self, source_ip, username=None, share=None):
        """Log a connection attempt"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'connection',
            'source_ip': source_ip,
            'username': username,
            'target_share': share,
            'port': self.port
        }
        self.connections.append(event)
        
        # Generate alert for connection to high-value shares
        if share in ['backup$', 'passwords', 'confidential']:
            self.generate_alert('HIGH', 'smb_high_value_share_access', source_ip, 
                              f"Access attempt to sensitive share: {share}")
        
    def log_authentication(self, source_ip, username, password_hash):
        """Log authentication attempts"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'authentication',
            'source_ip': source_ip,
            'username': username,
            'password_hash': password_hash
        }
        self.authentications.append(event)
        
        # Alert on authentication attempts
        self.generate_alert('HIGH', 'smb_authentication_attempt', source_ip,
                          f"Authentication attempt with username: {username}")
        
    def log_file_access(self, source_ip, share, filename, operation):
        """Log file access operations"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'file_access',
            'source_ip': source_ip,
            'share': share,
            'filename': filename,
            'operation': operation
        }
        self.file_access.append(event)
        
        # Alert on file access
        self.generate_alert('HIGH', 'smb_file_access', source_ip,
                          f"File access: {operation} on {share}/{filename}")
        
    def generate_alert(self, severity, alert_type, source_ip, description):
        """Generate security alert"""
        alert = {
            'alert_id': f"smb_{len(self.alerts):03d}",
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'honeypot': 'smb',
            'severity': severity,
            'alert_type': alert_type,
            'source_ip': source_ip,
            'description': description
        }
        self.alerts.append(alert)
        print(f"[ALERT] {severity}: {description} from {source_ip}")
        
    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        source_ip = address[0]
        print(f"[SMB] Connection from {source_ip}")
        
        self.log_connection(source_ip)
        
        try:
            # Simple SMB banner simulation
            # In a real implementation, would use impacket's SMB server
            data = client_socket.recv(1024)
            if data:
                # Log the connection attempt
                self.log_authentication(source_ip, "unknown", "N/A")
                
                # Send a simple response
                response = b"SMB honeypot - access logged"
                client_socket.send(response)
        except Exception as e:
            print(f"[SMB] Error handling client {source_ip}: {e}")
        finally:
            client_socket.close()
            
    def start(self, duration=3600):
        """Start the SMB honeypot"""
        print(f"[SMB] Starting honeypot on port {self.port}")
        self.running = True
        
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)
            
            start_time = time.time()
            
            while self.running and (time.time() - start_time) < duration:
                try:
                    client_socket, address = server_socket.accept()
                    thread = threading.Thread(target=self.handle_client, 
                                            args=(client_socket, address))
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[SMB] Error accepting connection: {e}")
                    
        except Exception as e:
            print(f"[SMB] Error starting server: {e}")
        finally:
            self.running = False
            print("[SMB] Honeypot stopped")
            
    def stop(self):
        """Stop the honeypot"""
        self.running = False
        
    def save_results(self):
        """Save honeypot results to JSON"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        results = {
            'honeypot': 'smb',
            'port': self.port,
            'shares': self.shares,
            'connections': self.connections,
            'authentications': self.authentications,
            'file_access': self.file_access,
            'alerts': self.alerts,
            'statistics': {
                'total_connections': len(self.connections),
                'total_authentications': len(self.authentications),
                'total_file_access': len(self.file_access),
                'total_alerts': len(self.alerts)
            }
        }
        
        output_file = os.path.join(self.output_dir, 'smb_honeypot.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[SMB] Results saved to {output_file}")
        print(f"[SMB] Total connections: {len(self.connections)}")
        print(f"[SMB] Total alerts: {len(self.alerts)}")

def main():
    """Main function"""
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/output/deception"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 445
    
    honeypot = SMBHoneypot(output_dir, port)
    
    try:
        honeypot.start(duration)
    except KeyboardInterrupt:
        print("\n[SMB] Interrupted by user")
    finally:
        honeypot.stop()
        honeypot.save_results()

if __name__ == "__main__":
    main()
