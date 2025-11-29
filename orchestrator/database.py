#!/usr/bin/env python3
"""
Database Integration for LAN Reconnaissance Framework
=====================================================

Provides persistent storage for scan results, configurations, and history.
Supports SQLite for local storage and can be extended for other databases.

Features:
- Scan result persistence
- Configuration storage
- Finding tracking
- Host inventory
- Scan history and comparison

Usage:
    from database import Database
    
    db = Database()
    db.save_scan(scan_data)
    results = db.get_scans(limit=10)
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Any
from contextlib import contextmanager


class Database:
    """
    SQLite database wrapper for persistent storage.
    
    Provides methods for storing and retrieving:
    - Scan results and metadata
    - Individual findings
    - Host inventory
    - Configuration snapshots
    - Scan comparisons
    """
    
    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__), 
            "..", 
            "data", 
            "lan_recon.db"
        )
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize schema
        self._init_schema()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_schema(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target_network TEXT,
                    status TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    config TEXT,
                    summary TEXT,
                    risk_score INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Hosts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    ip_address TEXT,
                    hostname TEXT,
                    mac_address TEXT,
                    device_type TEXT,
                    os_fingerprint TEXT,
                    open_ports TEXT,
                    services TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    host_id INTEGER,
                    finding_type TEXT,
                    severity TEXT,
                    name TEXT,
                    description TEXT,
                    template TEXT,
                    matched_at TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id),
                    FOREIGN KEY (host_id) REFERENCES hosts(id)
                )
            ''')
            
            # Configuration snapshots
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    config TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
    
    # Scan operations
    
    def save_scan(self, scan_data: Dict) -> str:
        """
        Save a scan result.
        
        Args:
            scan_data: Scan data dictionary
            
        Returns:
            Scan ID
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            scan_id = scan_data.get("id", datetime.now().strftime("%Y%m%d_%H%M%S"))
            
            cursor.execute('''
                INSERT OR REPLACE INTO scans 
                (id, target_network, status, start_time, end_time, config, summary, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                scan_data.get("target_network"),
                scan_data.get("status"),
                scan_data.get("start_time"),
                scan_data.get("end_time"),
                json.dumps(scan_data.get("config", {})),
                json.dumps(scan_data.get("summary", {})),
                scan_data.get("risk_score", 0)
            ))
            
            # Save hosts
            for host in scan_data.get("hosts", []):
                self._save_host(cursor, scan_id, host)
            
            # Save findings
            for finding in scan_data.get("findings", []):
                self._save_finding(cursor, scan_id, finding)
            
            return scan_id
    
    def _save_host(self, cursor, scan_id: str, host: Dict):
        """Save a host record."""
        cursor.execute('''
            INSERT INTO hosts 
            (scan_id, ip_address, hostname, mac_address, device_type, 
             os_fingerprint, open_ports, services, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            host.get("ip"),
            host.get("hostname"),
            host.get("mac"),
            host.get("device_type"),
            host.get("os"),
            json.dumps(host.get("ports", [])),
            json.dumps(host.get("services", [])),
            host.get("first_seen", datetime.now().isoformat()),
            datetime.now().isoformat()
        ))
    
    def _save_finding(self, cursor, scan_id: str, finding: Dict, host_id: Optional[int] = None):
        """Save a finding record."""
        cursor.execute('''
            INSERT INTO findings 
            (scan_id, host_id, finding_type, severity, name, description, 
             template, matched_at, evidence, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            host_id,
            finding.get("type", "vulnerability"),
            self._extract_finding_field(finding, "severity", "info"),
            self._extract_finding_field(finding, "name", ""),
            self._extract_finding_field(finding, "description", ""),
            finding.get("template", ""),
            finding.get("matched-at", finding.get("host", "")),
            json.dumps(finding.get("evidence", {})),
            finding.get("remediation", "")
        ))
    
    def _extract_finding_field(self, finding: Dict, field: str, default: str = "") -> str:
        """Extract a field from finding, checking both nested 'info' and root level."""
        info = finding.get("info", {})
        return info.get(field, finding.get(field, default))
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get a scan by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
            row = cursor.fetchone()
            
            if row:
                scan = dict(row)
                scan["config"] = json.loads(scan["config"] or "{}")
                scan["summary"] = json.loads(scan["summary"] or "{}")
                scan["hosts"] = self.get_hosts(scan_id)
                scan["findings"] = self.get_findings(scan_id)
                return scan
            
            return None
    
    def get_scans(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get recent scans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM scans 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            scans = []
            for row in cursor.fetchall():
                scan = dict(row)
                scan["config"] = json.loads(scan["config"] or "{}")
                scan["summary"] = json.loads(scan["summary"] or "{}")
                scans.append(scan)
            
            return scans
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and related data."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM findings WHERE scan_id = ?', (scan_id,))
            cursor.execute('DELETE FROM hosts WHERE scan_id = ?', (scan_id,))
            cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            
            return cursor.rowcount > 0
    
    # Host operations
    
    def get_hosts(self, scan_id: str) -> List[Dict]:
        """Get hosts for a scan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM hosts WHERE scan_id = ?', (scan_id,))
            
            hosts = []
            for row in cursor.fetchall():
                host = dict(row)
                host["open_ports"] = json.loads(host["open_ports"] or "[]")
                host["services"] = json.loads(host["services"] or "[]")
                hosts.append(host)
            
            return hosts
    
    def get_host_history(self, ip_address: str) -> List[Dict]:
        """Get historical data for an IP address."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT h.*, s.id as scan_id, s.start_time as scan_time
                FROM hosts h
                JOIN scans s ON h.scan_id = s.id
                WHERE h.ip_address = ?
                ORDER BY s.start_time DESC
            ''', (ip_address,))
            
            history = []
            for row in cursor.fetchall():
                entry = dict(row)
                entry["open_ports"] = json.loads(entry["open_ports"] or "[]")
                entry["services"] = json.loads(entry["services"] or "[]")
                history.append(entry)
            
            return history
    
    def get_all_hosts(self) -> List[Dict]:
        """Get all unique hosts across all scans."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT ip_address, hostname, mac_address, device_type,
                       MIN(first_seen) as first_seen,
                       MAX(last_seen) as last_seen,
                       COUNT(DISTINCT scan_id) as scan_count
                FROM hosts
                GROUP BY ip_address
                ORDER BY last_seen DESC
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
    
    # Finding operations
    
    def get_findings(self, scan_id: str) -> List[Dict]:
        """Get findings for a scan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM findings WHERE scan_id = ?', (scan_id,))
            
            findings = []
            for row in cursor.fetchall():
                finding = dict(row)
                finding["evidence"] = json.loads(finding["evidence"] or "{}")
                findings.append(finding)
            
            return findings
    
    def get_findings_by_severity(self, severity: str) -> List[Dict]:
        """Get all findings by severity."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT f.*, s.target_network, s.start_time as scan_time
                FROM findings f
                JOIN scans s ON f.scan_id = s.id
                WHERE f.severity = ?
                ORDER BY f.created_at DESC
            ''', (severity,))
            
            findings = []
            for row in cursor.fetchall():
                finding = dict(row)
                finding["evidence"] = json.loads(finding["evidence"] or "{}")
                findings.append(finding)
            
            return findings
    
    def get_finding_stats(self) -> Dict:
        """Get finding statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Count by severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM findings
                GROUP BY severity
            ''')
            
            severity_counts = {row["severity"]: row["count"] for row in cursor.fetchall()}
            
            # Count by type
            cursor.execute('''
                SELECT finding_type, COUNT(*) as count
                FROM findings
                GROUP BY finding_type
            ''')
            
            type_counts = {row["finding_type"]: row["count"] for row in cursor.fetchall()}
            
            # Total
            cursor.execute('SELECT COUNT(*) as total FROM findings')
            total = cursor.fetchone()["total"]
            
            return {
                "total": total,
                "by_severity": severity_counts,
                "by_type": type_counts
            }
    
    # Configuration operations
    
    def save_config(self, name: str, config: Dict):
        """Save a configuration snapshot."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO configs (name, config)
                VALUES (?, ?)
            ''', (name, json.dumps(config)))
    
    def get_config(self, name: str) -> Optional[Dict]:
        """Get a configuration by name."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT config FROM configs 
                WHERE name = ?
                ORDER BY created_at DESC
                LIMIT 1
            ''', (name,))
            
            row = cursor.fetchone()
            if row:
                return json.loads(row["config"])
            return None
    
    def list_configs(self) -> List[Dict]:
        """List all saved configurations."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT name, created_at FROM configs
                ORDER BY created_at DESC
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
    
    # Comparison operations
    
    def compare_scans(self, scan_id_1: str, scan_id_2: str) -> Dict:
        """Compare two scans."""
        scan1 = self.get_scan(scan_id_1)
        scan2 = self.get_scan(scan_id_2)
        
        if not scan1 or not scan2:
            return {"error": "One or both scans not found"}
        
        # Compare hosts
        hosts1 = {h["ip_address"] for h in scan1.get("hosts", [])}
        hosts2 = {h["ip_address"] for h in scan2.get("hosts", [])}
        
        new_hosts = hosts2 - hosts1
        removed_hosts = hosts1 - hosts2
        
        # Compare findings
        findings1 = {f["name"] for f in scan1.get("findings", [])}
        findings2 = {f["name"] for f in scan2.get("findings", [])}
        
        new_findings = findings2 - findings1
        resolved_findings = findings1 - findings2
        
        return {
            "scan1": {"id": scan_id_1, "time": scan1.get("start_time")},
            "scan2": {"id": scan_id_2, "time": scan2.get("start_time")},
            "hosts": {
                "new": list(new_hosts),
                "removed": list(removed_hosts),
                "unchanged": list(hosts1 & hosts2)
            },
            "findings": {
                "new": list(new_findings),
                "resolved": list(resolved_findings),
                "unchanged": list(findings1 & findings2)
            },
            "risk_score_change": (scan2.get("risk_score", 0) - scan1.get("risk_score", 0))
        }
    
    # Utility methods
    
    def get_stats(self) -> Dict:
        """Get database statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) as count FROM scans')
            scan_count = cursor.fetchone()["count"]
            
            cursor.execute('SELECT COUNT(DISTINCT ip_address) as count FROM hosts')
            host_count = cursor.fetchone()["count"]
            
            cursor.execute('SELECT COUNT(*) as count FROM findings')
            finding_count = cursor.fetchone()["count"]
            
            return {
                "total_scans": scan_count,
                "unique_hosts": host_count,
                "total_findings": finding_count,
                "database_path": self.db_path
            }
    
    def cleanup_old_scans(self, days: int = 30) -> int:
        """Delete scans older than specified days."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id FROM scans 
                WHERE datetime(created_at) < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            old_scans = [row["id"] for row in cursor.fetchall()]
            
            for scan_id in old_scans:
                self.delete_scan(scan_id)
            
            return len(old_scans)


if __name__ == "__main__":
    # Demo usage
    db = Database()
    
    print("Database Demo")
    print("=" * 40)
    print(f"Database path: {db.db_path}")
    print(f"Stats: {db.get_stats()}")
    
    # Save a test scan
    test_scan = {
        "id": "test_001",
        "target_network": "192.168.1.0/24",
        "status": "completed",
        "start_time": datetime.now().isoformat(),
        "end_time": datetime.now().isoformat(),
        "risk_score": 45,
        "config": {"passive_duration": 30},
        "hosts": [
            {"ip": "192.168.1.1", "hostname": "router", "device_type": "router"},
            {"ip": "192.168.1.100", "hostname": "workstation", "device_type": "workstation"}
        ],
        "findings": [
            {"name": "Test Finding", "severity": "high", "description": "Test"}
        ]
    }
    
    scan_id = db.save_scan(test_scan)
    print(f"Saved scan: {scan_id}")
    
    # Retrieve scan
    retrieved = db.get_scan(scan_id)
    print(f"Retrieved scan: {retrieved['id'] if retrieved else 'Not found'}")
