#!/usr/bin/env python3
"""
Fake NTP Server - Environment Manipulation Module
Tests NTP security by responding with manipulated time.

DEFENSIVE SECURITY TOOL - Requires Authorization
"""

import socket
import struct
import time
import json
import signal
import sys
from datetime import datetime, timedelta

# NTP epoch offset (1900 to 1970)
NTP_EPOCH_OFFSET = 2208988800

class FakeNTPServer:
    """Fake NTP server for security testing."""
    
    def __init__(self, port=123, time_offset=0, output_dir="/output"):
        self.port = port
        self.time_offset = time_offset
        self.output_dir = output_dir
        self.sock = None
        self.running = False
        self.queries_received = 0
        self.clients = {}
        
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        print(f"\n[*] Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', self.port))
            self.sock.settimeout(1.0)
            self.running = True
            
            print(f"[+] Fake NTP server started on port {self.port}")
            print(f"[*] Time offset: {self.time_offset} seconds")
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    self._handle_request(data, addr)
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[-] Failed to start: {e}")
        finally:
            self.stop()
    
    def _handle_request(self, data, addr):
        if len(data) < 48:
            return
        
        client_ip = addr[0]
        self.queries_received += 1
        
        if client_ip not in self.clients:
            self.clients[client_ip] = {'ip': client_ip, 'query_count': 0}
        self.clients[client_ip]['query_count'] += 1
        
        # Get manipulated time
        current_time = time.time() + self.time_offset
        ntp_time = current_time + NTP_EPOCH_OFFSET
        ntp_seconds = int(ntp_time)
        ntp_fraction = int((ntp_time - ntp_seconds) * 2**32)
        
        # Build NTP response
        response = struct.pack('!B B B b', 0x24, 1, 6, 0xEC)
        response += struct.pack('!I I', 0, 0)
        response += b'FAKE'
        response += struct.pack('!I I', ntp_seconds, ntp_fraction)
        response += data[40:48]
        response += struct.pack('!I I', ntp_seconds, ntp_fraction)
        response += struct.pack('!I I', ntp_seconds, ntp_fraction)
        
        self.sock.sendto(response, addr)
        print(f"[+] NTP query from {client_ip} - Response sent")
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        
        print(f"\n[*] Total queries: {self.queries_received}")
        self._save_results()
    
    def _save_results(self):
        import os
        log_file = f"{self.output_dir}/environment-manipulation/ntp_manipulation_log.json"
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        results = {
            'service': 'fake_ntp',
            'timestamp': datetime.now().isoformat(),
            'queries_received': self.queries_received,
            'unique_clients': len(self.clients),
            'time_offset_seconds': self.time_offset,
            'clients': list(self.clients.values())
        }
        
        with open(log_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Results saved to {log_file}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--offset', type=int, default=-31536000)
    parser.add_argument('--output', default='/output')
    args = parser.parse_args()
    
    server = FakeNTPServer(time_offset=args.offset, output_dir=args.output)
    server.start()
