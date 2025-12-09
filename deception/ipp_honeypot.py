#!/usr/bin/env python3
"""
IPP (Internet Printing Protocol) Honeypot
Simulates a network printer to detect printer enumeration and exploitation.
"""

import json
import socket
import threading
import time
from datetime import datetime
import sys
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

class IPPHandler(BaseHTTPRequestHandler):
    """HTTP handler for IPP requests"""
    
    def __init__(self, *args, honeypot=None, **kwargs):
        self.honeypot = honeypot
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to suppress default logging"""
        pass
    
    def do_GET(self):
        """Handle GET requests"""
        source_ip = self.client_address[0]
        print(f"[IPP] GET request from {source_ip}: {self.path}")
        
        if self.honeypot:
            self.honeypot.log_discovery(source_ip, 'GET', self.path)
        
        # Respond with printer attributes
        response = {
            'printer-name': 'Brother HL-L2350DW',
            'printer-location': 'Office Floor 2',
            'printer-make-and-model': 'Brother HL-L2350DW series',
            'printer-state': 'idle',
            'printer-state-reasons': 'none',
            'operations-supported': ['Print-Job', 'Get-Printer-Attributes']
        }
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
        """Handle POST requests (print jobs)"""
        source_ip = self.client_address[0]
        content_length = int(self.headers.get('Content-Length', 0))
        
        print(f"[IPP] POST request from {source_ip}: {self.path}")
        
        if self.honeypot:
            self.honeypot.log_print_job(source_ip, self.path, content_length)
        
        # Read the body (print job data)
        if content_length > 0:
            body = self.rfile.read(content_length)
            if self.honeypot:
                self.honeypot.log_print_data(source_ip, len(body))
        
        # Respond with success
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Job accepted')

class IPPHoneypot:
    """IPP honeypot printer server"""
    
    def __init__(self, output_dir="/output/deception", port=631):
        self.output_dir = output_dir
        self.port = port
        self.discoveries = []
        self.print_jobs = []
        self.alerts = []
        self.running = False
        self.server = None
        
    def log_discovery(self, source_ip, method, path):
        """Log printer discovery attempts"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'discovery',
            'source_ip': source_ip,
            'method': method,
            'path': path
        }
        self.discoveries.append(event)
        
        # Alert on discovery
        self.generate_alert('MEDIUM', 'ipp_discovery', source_ip,
                          f"Printer discovery from {source_ip}")
    
    def log_print_job(self, source_ip, path, size):
        """Log print job submissions"""
        event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': 'print_job',
            'source_ip': source_ip,
            'path': path,
            'size': size
        }
        self.print_jobs.append(event)
        
        # Alert on print job (potential exfiltration)
        severity = 'HIGH' if size > 10000 else 'MEDIUM'
        self.generate_alert(severity, 'ipp_print_job', source_ip,
                          f"Print job submitted: {size} bytes")
    
    def log_print_data(self, source_ip, data_size):
        """Log print data details"""
        print(f"[IPP] Print data received: {data_size} bytes from {source_ip}")
    
    def generate_alert(self, severity, alert_type, source_ip, description):
        """Generate security alert"""
        alert = {
            'alert_id': f"ipp_{len(self.alerts):03d}",
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'honeypot': 'ipp',
            'severity': severity,
            'alert_type': alert_type,
            'source_ip': source_ip,
            'description': description
        }
        self.alerts.append(alert)
        print(f"[ALERT] {severity}: {description}")
    
    def start(self, duration=3600):
        """Start the IPP honeypot"""
        print(f"[IPP] Starting honeypot on port {self.port}")
        self.running = True
        
        def handler(*args, **kwargs):
            return IPPHandler(*args, honeypot=self, **kwargs)
        
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), handler)
            self.server.timeout = 1.0
            
            start_time = time.time()
            
            while self.running and (time.time() - start_time) < duration:
                self.server.handle_request()
                
        except Exception as e:
            print(f"[IPP] Error starting server: {e}")
        finally:
            self.running = False
            if self.server:
                self.server.server_close()
            print("[IPP] Honeypot stopped")
    
    def stop(self):
        """Stop the honeypot"""
        self.running = False
        if self.server:
            self.server.shutdown()
    
    def save_results(self):
        """Save honeypot results"""
        os.makedirs(self.output_dir, exist_ok=True)
        
        results = {
            'honeypot': 'ipp',
            'port': self.port,
            'printer_model': 'Brother HL-L2350DW',
            'discoveries': self.discoveries,
            'print_jobs': self.print_jobs,
            'alerts': self.alerts,
            'statistics': {
                'total_discoveries': len(self.discoveries),
                'total_print_jobs': len(self.print_jobs),
                'total_alerts': len(self.alerts)
            }
        }
        
        output_file = os.path.join(self.output_dir, 'ipp_honeypot.json')
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[IPP] Results saved to {output_file}")
        print(f"[IPP] Total discoveries: {len(self.discoveries)}")
        print(f"[IPP] Total print jobs: {len(self.print_jobs)}")

def main():
    """Main function"""
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "/output/deception"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 631
    
    honeypot = IPPHoneypot(output_dir, port)
    
    try:
        honeypot.start(duration)
    except KeyboardInterrupt:
        print("\n[IPP] Interrupted by user")
    finally:
        honeypot.stop()
        honeypot.save_results()

if __name__ == "__main__":
    main()
