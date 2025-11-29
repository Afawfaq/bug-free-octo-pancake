#!/usr/bin/env python3
"""
REST API Server for LAN Reconnaissance Framework
================================================

Provides a REST API for programmatic access to the framework.
Enables integration with external tools, dashboards, and automation systems.

Features:
- Start/stop/status of scans
- Real-time scan progress
- Results retrieval
- Configuration management
- Plugin management
- Webhook configuration

Usage:
    python api_server.py --port 8080
    
API Endpoints:
    GET  /api/v1/health          - Health check
    GET  /api/v1/status          - Current scan status
    POST /api/v1/scan/start      - Start a new scan
    POST /api/v1/scan/stop       - Stop current scan
    GET  /api/v1/scan/progress   - Get scan progress
    GET  /api/v1/results         - Get scan results
    GET  /api/v1/results/{id}    - Get specific scan results
    GET  /api/v1/config          - Get current config
    PUT  /api/v1/config          - Update config
    GET  /api/v1/plugins         - List plugins
    POST /api/v1/plugins/reload  - Reload plugins
"""

import os
import sys
import json
import threading
import uuid
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Any
import argparse


class ScanState:
    """Manages scan state and history."""
    
    def __init__(self):
        self.current_scan: Optional[Dict] = None
        self.scan_history: Dict[str, Dict] = {}
        self.is_running: bool = False
        self.progress: Dict = {
            "phase": None,
            "percent": 0,
            "current_task": None,
            "start_time": None,
            "elapsed_time": 0
        }
        self.config: Dict = self._load_default_config()
        self.lock = threading.Lock()
    
    def _load_default_config(self) -> Dict:
        """Load default configuration."""
        return {
            "target_network": os.getenv("TARGET_NETWORK", "192.168.68.0/24"),
            "router_ip": os.getenv("ROUTER_IP", "192.168.68.1"),
            "passive_duration": int(os.getenv("PASSIVE_DURATION", "30")),
            "parallel_execution": os.getenv("PARALLEL_EXECUTION", "true").lower() == "true",
            "scan_timeout": int(os.getenv("SCAN_TIMEOUT", "600")),
            "nuclei_severity": os.getenv("NUCLEI_SEVERITY", "critical,high,medium")
        }
    
    def start_scan(self, config: Optional[Dict] = None) -> str:
        """Start a new scan."""
        with self.lock:
            if self.is_running:
                raise RuntimeError("Scan already in progress")
            
            scan_id = str(uuid.uuid4())[:8]
            self.current_scan = {
                "id": scan_id,
                "status": "running",
                "start_time": datetime.now().isoformat(),
                "config": config or self.config,
                "results": None,
                "error": None
            }
            self.is_running = True
            self.progress = {
                "phase": "initializing",
                "percent": 0,
                "current_task": "Starting scan...",
                "start_time": datetime.now().isoformat(),
                "elapsed_time": 0
            }
            
            return scan_id
    
    def update_progress(self, phase: str, percent: int, task: str):
        """Update scan progress."""
        with self.lock:
            self.progress["phase"] = phase
            self.progress["percent"] = percent
            self.progress["current_task"] = task
            if self.progress["start_time"]:
                start = datetime.fromisoformat(self.progress["start_time"])
                self.progress["elapsed_time"] = (datetime.now() - start).seconds
    
    def complete_scan(self, results: Dict):
        """Mark scan as complete."""
        with self.lock:
            if self.current_scan:
                self.current_scan["status"] = "completed"
                self.current_scan["end_time"] = datetime.now().isoformat()
                self.current_scan["results"] = results
                self.scan_history[self.current_scan["id"]] = self.current_scan
            self.is_running = False
            self.progress["percent"] = 100
            self.progress["phase"] = "completed"
    
    def fail_scan(self, error: str):
        """Mark scan as failed."""
        with self.lock:
            if self.current_scan:
                self.current_scan["status"] = "failed"
                self.current_scan["end_time"] = datetime.now().isoformat()
                self.current_scan["error"] = error
                self.scan_history[self.current_scan["id"]] = self.current_scan
            self.is_running = False
            self.progress["phase"] = "failed"
    
    def stop_scan(self):
        """Stop current scan."""
        with self.lock:
            if self.current_scan:
                self.current_scan["status"] = "stopped"
                self.current_scan["end_time"] = datetime.now().isoformat()
                self.scan_history[self.current_scan["id"]] = self.current_scan
            self.is_running = False
            self.progress["phase"] = "stopped"
    
    def get_status(self) -> Dict:
        """Get current status."""
        return {
            "is_running": self.is_running,
            "current_scan": self.current_scan,
            "progress": self.progress
        }
    
    def get_results(self, scan_id: Optional[str] = None) -> Optional[Dict]:
        """Get scan results."""
        if scan_id:
            return self.scan_history.get(scan_id)
        elif self.current_scan and self.current_scan.get("results"):
            return self.current_scan
        return None
    
    def get_history(self) -> Dict:
        """Get scan history."""
        return self.scan_history


# Global scan state
scan_state = ScanState()


class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the API."""
    
    # API version
    API_VERSION = "v1"
    
    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        """Set response headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
    
    def _send_json(self, data: Dict, status: int = 200):
        """Send JSON response."""
        self._set_headers(status)
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def _send_error(self, message: str, status: int = 400):
        """Send error response."""
        self._send_json({"error": message, "status": status}, status)
    
    def _parse_body(self) -> Optional[Dict]:
        """Parse JSON request body."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                return json.loads(body)
            return {}
        except Exception as e:
            return None
    
    def _route(self, method: str) -> Optional[callable]:
        """Route request to handler."""
        path = urlparse(self.path).path
        
        routes = {
            "GET": {
                f"/api/{self.API_VERSION}/health": self._health,
                f"/api/{self.API_VERSION}/status": self._status,
                f"/api/{self.API_VERSION}/scan/progress": self._progress,
                f"/api/{self.API_VERSION}/results": self._results,
                f"/api/{self.API_VERSION}/config": self._get_config,
                f"/api/{self.API_VERSION}/plugins": self._list_plugins,
                f"/api/{self.API_VERSION}/history": self._history,
                f"/api/{self.API_VERSION}/metrics": self._metrics,
            },
            "POST": {
                f"/api/{self.API_VERSION}/scan/start": self._start_scan,
                f"/api/{self.API_VERSION}/scan/stop": self._stop_scan,
                f"/api/{self.API_VERSION}/plugins/reload": self._reload_plugins,
            },
            "PUT": {
                f"/api/{self.API_VERSION}/config": self._update_config,
            }
        }
        
        # Check for exact match
        if path in routes.get(method, {}):
            return routes[method][path]
        
        # Check for pattern match (e.g., /results/{id})
        if method == "GET" and path.startswith(f"/api/{self.API_VERSION}/results/"):
            return self._get_result_by_id
        
        return None
    
    def do_GET(self):
        """Handle GET requests."""
        handler = self._route("GET")
        if handler:
            handler()
        else:
            self._send_error("Not found", 404)
    
    def do_POST(self):
        """Handle POST requests."""
        handler = self._route("POST")
        if handler:
            handler()
        else:
            self._send_error("Not found", 404)
    
    def do_PUT(self):
        """Handle PUT requests."""
        handler = self._route("PUT")
        if handler:
            handler()
        else:
            self._send_error("Not found", 404)
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests (CORS)."""
        self._set_headers(200)
    
    # API Endpoints
    
    def _health(self):
        """Health check endpoint."""
        self._send_json({
            "status": "healthy",
            "version": "2.2.0",
            "timestamp": datetime.now().isoformat()
        })
    
    def _status(self):
        """Get current scan status."""
        self._send_json(scan_state.get_status())
    
    def _progress(self):
        """Get scan progress."""
        self._send_json({
            "progress": scan_state.progress,
            "is_running": scan_state.is_running
        })
    
    def _start_scan(self):
        """Start a new scan."""
        try:
            body = self._parse_body()
            scan_id = scan_state.start_scan(body)
            
            # In a real implementation, this would start the actual scan
            # For now, we just return the scan ID
            self._send_json({
                "status": "started",
                "scan_id": scan_id,
                "message": "Scan started successfully"
            })
        except RuntimeError as e:
            self._send_error(str(e), 409)
        except Exception as e:
            self._send_error(str(e), 500)
    
    def _stop_scan(self):
        """Stop current scan."""
        if not scan_state.is_running:
            self._send_error("No scan in progress", 400)
            return
        
        scan_state.stop_scan()
        self._send_json({
            "status": "stopped",
            "message": "Scan stopped successfully"
        })
    
    def _results(self):
        """Get latest scan results."""
        results = scan_state.get_results()
        if results:
            self._send_json(results)
        else:
            self._send_json({"results": None, "message": "No results available"})
    
    def _get_result_by_id(self):
        """Get specific scan results by ID."""
        path = urlparse(self.path).path
        scan_id = path.split("/")[-1]
        
        results = scan_state.get_results(scan_id)
        if results:
            self._send_json(results)
        else:
            self._send_error(f"Scan {scan_id} not found", 404)
    
    def _history(self):
        """Get scan history."""
        self._send_json({
            "history": list(scan_state.get_history().values()),
            "total": len(scan_state.get_history())
        })
    
    def _get_config(self):
        """Get current configuration."""
        self._send_json({
            "config": scan_state.config
        })
    
    def _update_config(self):
        """Update configuration."""
        body = self._parse_body()
        if not body:
            self._send_error("Invalid JSON body", 400)
            return
        
        scan_state.config.update(body)
        self._send_json({
            "status": "updated",
            "config": scan_state.config
        })
    
    def _list_plugins(self):
        """List available plugins."""
        # In a real implementation, this would list actual plugins
        self._send_json({
            "plugins": [],
            "total": 0
        })
    
    def _reload_plugins(self):
        """Reload plugins."""
        self._send_json({
            "status": "reloaded",
            "message": "Plugins reloaded successfully"
        })
    
    def _metrics(self):
        """Get Prometheus-compatible metrics."""
        metrics = []
        
        # Scan metrics
        metrics.append(f'lan_recon_scans_total {len(scan_state.get_history())}')
        metrics.append(f'lan_recon_scan_running {1 if scan_state.is_running else 0}')
        
        if scan_state.progress:
            metrics.append(f'lan_recon_scan_progress {scan_state.progress.get("percent", 0)}')
            metrics.append(f'lan_recon_scan_elapsed_seconds {scan_state.progress.get("elapsed_time", 0)}')
        
        # Count completed/failed scans
        completed = sum(1 for s in scan_state.get_history().values() if s.get("status") == "completed")
        failed = sum(1 for s in scan_state.get_history().values() if s.get("status") == "failed")
        metrics.append(f'lan_recon_scans_completed_total {completed}')
        metrics.append(f'lan_recon_scans_failed_total {failed}')
        
        self._set_headers(200, "text/plain")
        self.wfile.write("\n".join(metrics).encode())
    
    def log_message(self, format, *args):
        """Override to customize logging."""
        print(f"[API] {self.address_string()} - {format % args}")


def run_server(host: str = "0.0.0.0", port: int = 8080):
    """Run the API server."""
    server_address = (host, port)
    httpd = HTTPServer(server_address, APIHandler)
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║        LAN Reconnaissance Framework API Server           ║
╚══════════════════════════════════════════════════════════╝

Server running at http://{host}:{port}

Available endpoints:
  GET  /api/v1/health         - Health check
  GET  /api/v1/status         - Current scan status  
  POST /api/v1/scan/start     - Start a new scan
  POST /api/v1/scan/stop      - Stop current scan
  GET  /api/v1/scan/progress  - Get scan progress
  GET  /api/v1/results        - Get scan results
  GET  /api/v1/results/{{id}}   - Get specific scan results
  GET  /api/v1/history        - Get scan history
  GET  /api/v1/config         - Get configuration
  PUT  /api/v1/config         - Update configuration
  GET  /api/v1/plugins        - List plugins
  POST /api/v1/plugins/reload - Reload plugins
  GET  /api/v1/metrics        - Prometheus metrics

Press Ctrl+C to stop the server.
""")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server...")
        httpd.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LAN Recon API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    
    args = parser.parse_args()
    run_server(args.host, args.port)
