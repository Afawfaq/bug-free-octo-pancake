#!/usr/bin/env python3
"""
Web Dashboard for LAN Reconnaissance Framework
==============================================

Provides a web-based dashboard for monitoring and managing scans.
Includes real-time status updates, result visualization, and configuration.

Features:
- Real-time scan status
- Interactive network topology
- Finding severity breakdown
- Historical scan comparison
- Configuration management
- REST API integration

Usage:
    python web_dashboard.py --port 8080
    
Then open http://localhost:8080 in your browser.
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


# HTML Template for the dashboard
DASHBOARD_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAN Recon Dashboard</title>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #e6e6e6;
            --text-secondary: #94a3b8;
            --accent: #00d9ff;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --critical: #dc2626;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: var(--bg-secondary);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--bg-card);
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--accent);
        }
        
        .status-badge {
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .status-idle { background: var(--bg-card); }
        .status-running { background: var(--success); color: #000; }
        .status-error { background: var(--danger); }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        
        .card-title {
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        
        .card-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent);
        }
        
        .card-subtitle {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }
        
        .section-title {
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--bg-card);
        }
        
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--bg-secondary);
        }
        
        th {
            background: var(--bg-secondary);
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        tr:hover {
            background: var(--bg-secondary);
        }
        
        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .severity-critical { background: var(--critical); }
        .severity-high { background: var(--danger); }
        .severity-medium { background: var(--warning); color: #000; }
        .severity-low { background: var(--success); color: #000; }
        .severity-info { background: var(--bg-secondary); }
        
        .controls {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-primary {
            background: var(--accent);
            color: #000;
        }
        
        .btn-primary:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn-secondary {
            background: var(--bg-card);
            color: var(--text-primary);
            border: 1px solid var(--text-secondary);
        }
        
        .input-group {
            display: flex;
            gap: 0.5rem;
        }
        
        input[type="text"] {
            padding: 0.75rem 1rem;
            border: 1px solid var(--bg-card);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 1rem;
            min-width: 200px;
        }
        
        select {
            padding: 0.75rem 1rem;
            border: 1px solid var(--bg-card);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 1rem;
        }
        
        .chart-container {
            height: 200px;
            display: flex;
            align-items: flex-end;
            gap: 0.5rem;
            padding: 1rem 0;
        }
        
        .chart-bar {
            flex: 1;
            background: var(--accent);
            border-radius: 4px 4px 0 0;
            min-height: 20px;
            position: relative;
        }
        
        .chart-bar::after {
            content: attr(data-label);
            position: absolute;
            bottom: -25px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.75rem;
            color: var(--text-secondary);
        }
        
        .progress-bar {
            height: 8px;
            background: var(--bg-secondary);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 1rem;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--accent);
            transition: width 0.3s;
        }
        
        .log-container {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1rem;
            max-height: 300px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 0.875rem;
        }
        
        .log-entry {
            padding: 0.25rem 0;
            border-bottom: 1px solid var(--bg-card);
        }
        
        .log-time {
            color: var(--text-secondary);
            margin-right: 1rem;
        }
        
        .log-info { color: var(--accent); }
        .log-success { color: var(--success); }
        .log-warning { color: var(--warning); }
        .log-error { color: var(--danger); }
        
        .topology {
            min-height: 400px;
            background: var(--bg-secondary);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--text-secondary);
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--bg-card);
            margin-bottom: 1rem;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        
        .tab:hover {
            color: var(--accent);
        }
        
        .tab.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @media (max-width: 768px) {
            .header {
                flex-direction: column;
                gap: 1rem;
            }
            
            .controls {
                flex-direction: column;
            }
            
            .input-group {
                flex-direction: column;
            }
            
            input[type="text"], select {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">🔍 LAN Recon Dashboard</div>
        <div id="status" class="status-badge status-idle">Idle</div>
    </header>
    
    <div class="container">
        <!-- Controls -->
        <div class="controls">
            <div class="input-group">
                <input type="text" id="target" placeholder="Target Network (e.g., 192.168.1.0/24)" value="192.168.1.0/24">
                <select id="profile">
                    <option value="quick">Quick Scan</option>
                    <option value="standard" selected>Standard Scan</option>
                    <option value="thorough">Thorough Scan</option>
                    <option value="stealth">Stealth Scan</option>
                    <option value="iot_focused">IoT Focused</option>
                    <option value="vulnerability">Vulnerability Scan</option>
                </select>
            </div>
            <button class="btn btn-primary" onclick="startScan()">▶ Start Scan</button>
            <button class="btn btn-danger" onclick="stopScan()">⬛ Stop</button>
            <button class="btn btn-secondary" onclick="refreshData()">🔄 Refresh</button>
        </div>
        
        <!-- Summary Cards -->
        <div class="grid">
            <div class="card">
                <div class="card-title">Hosts Discovered</div>
                <div class="card-value" id="hosts-count">0</div>
                <div class="card-subtitle">Active on network</div>
            </div>
            <div class="card">
                <div class="card-title">Open Ports</div>
                <div class="card-value" id="ports-count">0</div>
                <div class="card-subtitle">Across all hosts</div>
            </div>
            <div class="card">
                <div class="card-title">Security Findings</div>
                <div class="card-value" id="findings-count">0</div>
                <div class="card-subtitle" id="findings-breakdown">-</div>
            </div>
            <div class="card">
                <div class="card-title">Risk Score</div>
                <div class="card-value" id="risk-score">-</div>
                <div class="card-subtitle">Network security rating</div>
            </div>
        </div>
        
        <!-- Progress -->
        <div class="card" id="progress-card" style="display: none;">
            <div class="card-title">Scan Progress</div>
            <div id="current-phase">Initializing...</div>
            <div class="progress-bar">
                <div class="progress-fill" id="progress-bar" style="width: 0%"></div>
            </div>
            <div class="card-subtitle" id="elapsed-time">Elapsed: 0s</div>
        </div>
        
        <!-- Tabs -->
        <div class="tabs">
            <div class="tab active" onclick="showTab('findings')">Findings</div>
            <div class="tab" onclick="showTab('hosts')">Hosts</div>
            <div class="tab" onclick="showTab('topology')">Topology</div>
            <div class="tab" onclick="showTab('logs')">Logs</div>
            <div class="tab" onclick="showTab('history')">History</div>
        </div>
        
        <!-- Findings Tab -->
        <div id="findings-tab" class="tab-content active">
            <div class="card">
                <h3 class="section-title">Security Findings</h3>
                <div class="table-container">
                    <table id="findings-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Host</th>
                                <th>Port</th>
                                <th>Title</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody id="findings-body">
                            <tr><td colspan="5" style="text-align: center;">No findings yet</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Hosts Tab -->
        <div id="hosts-tab" class="tab-content">
            <div class="card">
                <h3 class="section-title">Discovered Hosts</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>MAC Address</th>
                                <th>Hostname</th>
                                <th>OS</th>
                                <th>Device Type</th>
                                <th>Open Ports</th>
                            </tr>
                        </thead>
                        <tbody id="hosts-body">
                            <tr><td colspan="6" style="text-align: center;">No hosts discovered</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Topology Tab -->
        <div id="topology-tab" class="tab-content">
            <div class="card">
                <h3 class="section-title">Network Topology</h3>
                <div class="topology" id="topology-view">
                    Network topology visualization will appear here after scan
                </div>
            </div>
        </div>
        
        <!-- Logs Tab -->
        <div id="logs-tab" class="tab-content">
            <div class="card">
                <h3 class="section-title">Scan Logs</h3>
                <div class="log-container" id="log-container">
                    <div class="log-entry">
                        <span class="log-time">--:--:--</span>
                        <span class="log-info">Waiting for scan to start...</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- History Tab -->
        <div id="history-tab" class="tab-content">
            <div class="card">
                <h3 class="section-title">Scan History</h3>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Date</th>
                                <th>Target</th>
                                <th>Profile</th>
                                <th>Duration</th>
                                <th>Hosts</th>
                                <th>Findings</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="history-body">
                            <tr><td colspan="7" style="text-align: center;">No scan history</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // State
        let isScanning = false;
        let scanId = null;
        let pollInterval = null;
        
        // API calls
        async function apiCall(endpoint, method = 'GET', data = null) {
            const options = {
                method,
                headers: { 'Content-Type': 'application/json' }
            };
            if (data) options.body = JSON.stringify(data);
            
            try {
                const response = await fetch(endpoint, options);
                return await response.json();
            } catch (error) {
                console.error('API error:', error);
                return { error: error.message };
            }
        }
        
        // Start scan
        async function startScan() {
            const target = document.getElementById('target').value;
            const profile = document.getElementById('profile').value;
            
            if (!target) {
                alert('Please enter a target network');
                return;
            }
            
            const result = await apiCall('/api/scan/start', 'POST', { target, profile });
            
            if (result.scan_id) {
                scanId = result.scan_id;
                isScanning = true;
                updateStatus('running');
                document.getElementById('progress-card').style.display = 'block';
                addLog('info', `Scan started: ${target} (${profile})`);
                startPolling();
            } else {
                addLog('error', `Failed to start scan: ${result.error || 'Unknown error'}`);
            }
        }
        
        // Stop scan
        async function stopScan() {
            if (!isScanning) return;
            
            const result = await apiCall('/api/scan/stop', 'POST');
            isScanning = false;
            stopPolling();
            updateStatus('idle');
            addLog('warning', 'Scan stopped');
        }
        
        // Refresh data
        async function refreshData() {
            const status = await apiCall('/api/status');
            
            if (status.is_running) {
                isScanning = true;
                updateStatus('running');
                startPolling();
            }
            
            updateDashboard(status);
        }
        
        // Update dashboard
        function updateDashboard(data) {
            document.getElementById('hosts-count').textContent = data.hosts_count || 0;
            document.getElementById('ports-count').textContent = data.ports_count || 0;
            document.getElementById('findings-count').textContent = data.findings_count || 0;
            document.getElementById('risk-score').textContent = data.risk_score || '-';
            
            if (data.findings_breakdown) {
                document.getElementById('findings-breakdown').textContent = 
                    `Critical: ${data.findings_breakdown.critical || 0} | High: ${data.findings_breakdown.high || 0}`;
            }
            
            if (data.progress) {
                document.getElementById('current-phase').textContent = data.progress.phase || 'Processing...';
                document.getElementById('progress-bar').style.width = `${data.progress.percent || 0}%`;
                document.getElementById('elapsed-time').textContent = `Elapsed: ${data.progress.elapsed || 0}s`;
            }
            
            if (data.hosts) updateHostsTable(data.hosts);
            if (data.findings) updateFindingsTable(data.findings);
        }
        
        // Update hosts table
        function updateHostsTable(hosts) {
            const tbody = document.getElementById('hosts-body');
            if (!hosts || hosts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center;">No hosts discovered</td></tr>';
                return;
            }
            
            tbody.innerHTML = hosts.map(host => `
                <tr>
                    <td>${host.ip || '-'}</td>
                    <td>${host.mac || '-'}</td>
                    <td>${host.hostname || '-'}</td>
                    <td>${host.os || '-'}</td>
                    <td>${host.device_type || '-'}</td>
                    <td>${(host.ports || []).join(', ') || '-'}</td>
                </tr>
            `).join('');
        }
        
        // Update findings table
        function updateFindingsTable(findings) {
            const tbody = document.getElementById('findings-body');
            if (!findings || findings.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No findings yet</td></tr>';
                return;
            }
            
            tbody.innerHTML = findings.map(finding => `
                <tr>
                    <td><span class="severity-badge severity-${finding.severity}">${finding.severity}</span></td>
                    <td>${finding.host || '-'}</td>
                    <td>${finding.port || '-'}</td>
                    <td>${finding.title || '-'}</td>
                    <td>${finding.description || '-'}</td>
                </tr>
            `).join('');
        }
        
        // Status update
        function updateStatus(status) {
            const badge = document.getElementById('status');
            badge.className = `status-badge status-${status}`;
            badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);
        }
        
        // Log entry
        function addLog(level, message) {
            const container = document.getElementById('log-container');
            const time = new Date().toLocaleTimeString();
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = `<span class="log-time">${time}</span><span class="log-${level}">${message}</span>`;
            container.appendChild(entry);
            container.scrollTop = container.scrollHeight;
        }
        
        // Polling
        function startPolling() {
            if (pollInterval) return;
            pollInterval = setInterval(async () => {
                if (!isScanning) {
                    stopPolling();
                    return;
                }
                
                const status = await apiCall('/api/status');
                updateDashboard(status);
                
                if (!status.is_running && isScanning) {
                    isScanning = false;
                    stopPolling();
                    updateStatus('idle');
                    document.getElementById('progress-card').style.display = 'none';
                    addLog('success', 'Scan completed');
                }
            }, 2000);
        }
        
        function stopPolling() {
            if (pollInterval) {
                clearInterval(pollInterval);
                pollInterval = null;
            }
        }
        
        // Tab switching
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            
            event.target.classList.add('active');
            document.getElementById(`${tabName}-tab`).classList.add('active');
        }
        
        // Initial load
        refreshData();
    </script>
</body>
</html>
'''


class DashboardState:
    """Manages dashboard state."""
    
    def __init__(self):
        self.is_running = False
        self.current_scan = None
        self.progress = {
            "phase": None,
            "percent": 0,
            "elapsed": 0
        }
        self.results = {
            "hosts": [],
            "findings": [],
            "hosts_count": 0,
            "ports_count": 0,
            "findings_count": 0,
            "risk_score": 0,
            "findings_breakdown": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        self.history = []
        self.lock = threading.Lock()
    
    def start_scan(self, target: str, profile: str) -> str:
        """Start a new scan."""
        with self.lock:
            if self.is_running:
                raise RuntimeError("Scan already running")
            
            scan_id = str(uuid.uuid4())[:8]
            self.current_scan = {
                "id": scan_id,
                "target": target,
                "profile": profile,
                "start_time": datetime.now().isoformat()
            }
            self.is_running = True
            self.progress = {"phase": "Initializing", "percent": 0, "elapsed": 0}
            
            # Reset results
            self.results = {
                "hosts": [],
                "findings": [],
                "hosts_count": 0,
                "ports_count": 0,
                "findings_count": 0,
                "risk_score": 0,
                "findings_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            }
            
            return scan_id
    
    def stop_scan(self):
        """Stop current scan."""
        with self.lock:
            if self.current_scan:
                self.current_scan["end_time"] = datetime.now().isoformat()
                self.history.append(self.current_scan)
            self.is_running = False
            self.current_scan = None
    
    def get_status(self) -> Dict:
        """Get current status."""
        with self.lock:
            return {
                "is_running": self.is_running,
                "scan": self.current_scan,
                "progress": self.progress,
                **self.results
            }
    
    def update_progress(self, phase: str, percent: int, elapsed: int = 0):
        """Update scan progress."""
        with self.lock:
            self.progress = {
                "phase": phase,
                "percent": percent,
                "elapsed": elapsed
            }
    
    def add_host(self, host: Dict):
        """Add discovered host."""
        with self.lock:
            self.results["hosts"].append(host)
            self.results["hosts_count"] = len(self.results["hosts"])
            self.results["ports_count"] += len(host.get("ports", []))
    
    def add_finding(self, finding: Dict):
        """Add security finding."""
        with self.lock:
            self.results["findings"].append(finding)
            self.results["findings_count"] = len(self.results["findings"])
            
            severity = finding.get("severity", "info").lower()
            if severity in self.results["findings_breakdown"]:
                self.results["findings_breakdown"][severity] += 1


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for dashboard."""
    
    state = DashboardState()
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass
    
    def send_json(self, data: Any, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())
    
    def send_html(self, html: str):
        """Send HTML response."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())
    
    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/" or path == "/index.html":
            self.send_html(DASHBOARD_HTML)
        
        elif path == "/api/status":
            self.send_json(self.state.get_status())
        
        elif path == "/api/history":
            self.send_json({"history": self.state.history})
        
        elif path == "/api/health":
            self.send_json({"status": "healthy", "timestamp": datetime.now().isoformat()})
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path
        
        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else "{}"
        
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            data = {}
        
        if path == "/api/scan/start":
            try:
                target = data.get("target", "192.168.1.0/24")
                profile = data.get("profile", "standard")
                scan_id = self.state.start_scan(target, profile)
                
                # Start simulated scan in background
                threading.Thread(
                    target=self._simulate_scan,
                    args=(scan_id,),
                    daemon=True
                ).start()
                
                self.send_json({"scan_id": scan_id, "status": "started"})
            except RuntimeError as e:
                self.send_json({"error": str(e)}, 409)
        
        elif path == "/api/scan/stop":
            self.state.stop_scan()
            self.send_json({"status": "stopped"})
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def _simulate_scan(self, scan_id: str):
        """Simulate a scan for demo purposes."""
        import time
        import random
        
        phases = [
            ("Passive Reconnaissance", 10),
            ("Active Discovery", 25),
            ("Service Fingerprinting", 40),
            ("IoT Enumeration", 55),
            ("Vulnerability Scanning", 70),
            ("Web Screenshots", 85),
            ("Report Generation", 95),
            ("Finalizing", 100)
        ]
        
        # Simulate hosts
        sample_hosts = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "hostname": "router.local", "os": "Linux", "device_type": "Router", "ports": [80, 443, 22]},
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "desktop-pc", "os": "Windows 10", "device_type": "Workstation", "ports": [135, 445, 3389]},
            {"ip": "192.168.1.20", "mac": "11:22:33:44:55:66", "hostname": "printer.local", "os": "Embedded", "device_type": "Printer", "ports": [80, 9100, 515]},
            {"ip": "192.168.1.30", "mac": "77:88:99:AA:BB:CC", "hostname": "smart-tv", "os": "Embedded Linux", "device_type": "Smart TV", "ports": [8008, 8443]},
            {"ip": "192.168.1.40", "mac": "DD:EE:FF:00:11:22", "hostname": "nas-server", "os": "Linux", "device_type": "NAS", "ports": [80, 443, 445, 22]}
        ]
        
        sample_findings = [
            {"severity": "critical", "host": "192.168.1.1", "port": 80, "title": "Default Credentials", "description": "Router using default admin password"},
            {"severity": "high", "host": "192.168.1.10", "port": 3389, "title": "RDP Exposed", "description": "Remote Desktop Protocol accessible"},
            {"severity": "medium", "host": "192.168.1.20", "port": 9100, "title": "Raw Printing", "description": "Unauthenticated raw printing enabled"},
            {"severity": "low", "host": "192.168.1.30", "port": 8008, "title": "Debug Endpoint", "description": "Debug API accessible without auth"},
            {"severity": "info", "host": "192.168.1.40", "port": 80, "title": "HTTP Info", "description": "Server version disclosed"}
        ]
        
        elapsed = 0
        
        for phase_name, percent in phases:
            if not self.state.is_running:
                return
            
            self.state.update_progress(phase_name, percent, elapsed)
            
            # Add hosts during discovery phase
            if "Discovery" in phase_name:
                for host in sample_hosts[:random.randint(2, len(sample_hosts))]:
                    if not self.state.is_running:
                        return
                    self.state.add_host(host)
                    time.sleep(0.5)
            
            # Add findings during vulnerability phase
            if "Vulnerability" in phase_name:
                for finding in sample_findings[:random.randint(2, len(sample_findings))]:
                    if not self.state.is_running:
                        return
                    self.state.add_finding(finding)
                    time.sleep(0.3)
            
            # Calculate risk score
            findings = self.state.results["findings_breakdown"]
            risk = (
                findings["critical"] * 25 +
                findings["high"] * 15 +
                findings["medium"] * 5 +
                findings["low"] * 1
            )
            self.state.results["risk_score"] = min(100, risk)
            
            time.sleep(2)
            elapsed += 2
        
        self.state.stop_scan()


def run_dashboard(port: int = 8080, host: str = "0.0.0.0"):
    """Run the dashboard server."""
    server = HTTPServer((host, port), DashboardHandler)
    print(f"Dashboard running at http://{host}:{port}")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LAN Recon Web Dashboard")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Port to run on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    
    args = parser.parse_args()
    run_dashboard(args.port, args.host)
