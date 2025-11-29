#!/usr/bin/env python3
"""
Anomaly Detection Module for LAN Reconnaissance Framework
=========================================================

Provides ML-based anomaly detection for network behavior analysis.
Detects unusual patterns in network traffic, device behavior, and scan results.

Features:
- Statistical anomaly detection
- Device behavior baselines
- Traffic pattern analysis
- New device detection
- Port usage anomalies
- Time-based pattern recognition

Usage:
    from anomaly_detection import AnomalyDetector
    
    detector = AnomalyDetector()
    detector.train(historical_data)
    anomalies = detector.detect(current_scan)
"""

import os
import json
import math
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class AnomalyType(Enum):
    """Types of anomalies detected."""
    NEW_HOST = "new_host"
    MISSING_HOST = "missing_host"
    NEW_PORT = "new_port"
    CLOSED_PORT = "closed_port"
    SERVICE_CHANGE = "service_change"
    OS_CHANGE = "os_change"
    UNUSUAL_PORT = "unusual_port"
    HIGH_PORT_COUNT = "high_port_count"
    SUSPICIOUS_SERVICE = "suspicious_service"
    TIMING_ANOMALY = "timing_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    DEVICE_TYPE_CHANGE = "device_type_change"


class AnomalySeverity(Enum):
    """Severity levels for anomalies."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    host: Optional[str]
    description: str
    details: Dict = field(default_factory=dict)
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "type": self.anomaly_type.value,
            "severity": self.severity.value,
            "host": self.host,
            "description": self.description,
            "details": self.details,
            "confidence": self.confidence,
            "timestamp": self.timestamp
        }


class StatisticalAnalyzer:
    """
    Statistical analysis for anomaly detection.
    Uses mean/std deviation for threshold-based detection.
    """
    
    def __init__(self):
        self.stats: Dict[str, Dict[str, float]] = {}
    
    def update(self, metric: str, value: float):
        """Update statistics for a metric."""
        if metric not in self.stats:
            self.stats[metric] = {
                "n": 0,
                "mean": 0.0,
                "m2": 0.0,
                "min": float('inf'),
                "max": float('-inf')
            }
        
        s = self.stats[metric]
        s["n"] += 1
        delta = value - s["mean"]
        s["mean"] += delta / s["n"]
        delta2 = value - s["mean"]
        s["m2"] += delta * delta2
        s["min"] = min(s["min"], value)
        s["max"] = max(s["max"], value)
    
    def get_stats(self, metric: str) -> Optional[Dict]:
        """Get statistics for a metric."""
        if metric not in self.stats:
            return None
        
        s = self.stats[metric]
        if s["n"] < 2:
            return {"mean": s["mean"], "std": 0, "n": s["n"], "min": s["min"], "max": s["max"]}
        
        variance = s["m2"] / (s["n"] - 1)
        return {
            "mean": s["mean"],
            "std": math.sqrt(variance),
            "n": s["n"],
            "min": s["min"],
            "max": s["max"]
        }
    
    def is_anomaly(self, metric: str, value: float, threshold: float = 2.0) -> Tuple[bool, float]:
        """
        Check if value is anomalous (beyond threshold std deviations).
        
        Returns:
            Tuple of (is_anomaly, z_score)
        """
        stats = self.get_stats(metric)
        if not stats or stats["std"] == 0:
            return False, 0.0
        
        z_score = abs(value - stats["mean"]) / stats["std"]
        return z_score > threshold, z_score


class DeviceBaseline:
    """
    Maintains baseline behavior for a device.
    """
    
    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.seen_count: int = 0
        
        # Port history
        self.known_ports: set = set()
        self.port_history: List[Tuple[datetime, set]] = []
        
        # Service history
        self.known_services: Dict[int, str] = {}
        
        # OS history
        self.os_history: List[str] = []
        
        # Device type
        self.device_type: Optional[str] = None
        
        # Timing patterns
        self.active_hours: Dict[int, int] = defaultdict(int)  # hour -> count
        self.active_days: Dict[int, int] = defaultdict(int)   # weekday -> count
    
    def update(self, scan_data: Dict, scan_time: datetime):
        """Update baseline with new scan data."""
        if self.first_seen is None:
            self.first_seen = scan_time
        self.last_seen = scan_time
        self.seen_count += 1
        
        # Update ports
        current_ports = set(scan_data.get("ports", []))
        self.port_history.append((scan_time, current_ports))
        self.known_ports.update(current_ports)
        
        # Update services
        for port, service in scan_data.get("services", {}).items():
            self.known_services[int(port)] = service
        
        # Update OS
        os_info = scan_data.get("os")
        if os_info and (not self.os_history or self.os_history[-1] != os_info):
            self.os_history.append(os_info)
        
        # Update device type
        if scan_data.get("device_type"):
            self.device_type = scan_data["device_type"]
        
        # Update timing
        self.active_hours[scan_time.hour] += 1
        self.active_days[scan_time.weekday()] += 1
    
    def get_typical_ports(self, min_occurrence: float = 0.5) -> set:
        """Get ports that appear in at least min_occurrence fraction of scans."""
        if not self.port_history:
            return set()
        
        port_counts = defaultdict(int)
        for _, ports in self.port_history:
            for port in ports:
                port_counts[port] += 1
        
        threshold = len(self.port_history) * min_occurrence
        return {port for port, count in port_counts.items() if count >= threshold}
    
    def to_dict(self) -> Dict:
        return {
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "seen_count": self.seen_count,
            "known_ports": list(self.known_ports),
            "known_services": self.known_services,
            "os_history": self.os_history,
            "device_type": self.device_type
        }


class AnomalyDetector:
    """
    Main anomaly detection engine.
    """
    
    # Suspicious ports commonly used by malware or backdoors
    SUSPICIOUS_PORTS = {
        4444,   # Metasploit default
        5555,   # Android debug
        6666,   # IRC backdoors
        6667,   # IRC
        31337,  # Elite/Back Orifice
        12345,  # NetBus
        27374,  # SubSeven
        1337,   # Elite
        8888,   # Common backdoor
        9999,   # Common backdoor
        65535,  # Max port - often used
    }
    
    # Uncommon ports that might indicate issues
    HIGH_RISK_SERVICES = {
        "telnet": AnomalySeverity.HIGH,
        "ftp": AnomalySeverity.MEDIUM,
        "rsh": AnomalySeverity.CRITICAL,
        "rlogin": AnomalySeverity.CRITICAL,
        "vnc": AnomalySeverity.MEDIUM,
        "rdp": AnomalySeverity.MEDIUM,
        "netbios": AnomalySeverity.LOW,
    }
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize anomaly detector."""
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "anomaly.db"
        )
        
        self.baselines: Dict[str, DeviceBaseline] = {}
        self.stats = StatisticalAnalyzer()
        self.known_hosts: set = set()
        
        # Detection thresholds
        self.new_port_threshold = 0.3  # Port seen in < 30% of scans is "new"
        self.missing_threshold_days = 7  # Host missing > 7 days is anomaly
        self.high_port_count_threshold = 50  # More than 50 ports is unusual
        self.z_score_threshold = 2.5  # Standard deviations for statistical anomaly
        
        # Initialize database
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        self._load_baselines()
    
    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS device_baselines (
                    ip TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomaly_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    anomaly_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host TEXT,
                    description TEXT,
                    details TEXT,
                    confidence REAL,
                    detected_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    metric TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    def _load_baselines(self):
        """Load baselines from database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT ip, data FROM device_baselines")
            for row in cursor.fetchall():
                data = json.loads(row["data"])
                baseline = DeviceBaseline(row["ip"])
                baseline.known_ports = set(data.get("known_ports", []))
                baseline.known_services = data.get("known_services", {})
                baseline.os_history = data.get("os_history", [])
                baseline.device_type = data.get("device_type")
                baseline.seen_count = data.get("seen_count", 0)
                
                if data.get("first_seen"):
                    baseline.first_seen = datetime.fromisoformat(data["first_seen"])
                if data.get("last_seen"):
                    baseline.last_seen = datetime.fromisoformat(data["last_seen"])
                
                self.baselines[row["ip"]] = baseline
                self.known_hosts.add(row["ip"])
            
            # Load statistics
            cursor.execute("SELECT metric, data FROM statistics")
            for row in cursor.fetchall():
                data = json.loads(row["data"])
                self.stats.stats[row["metric"]] = data
    
    def _save_baseline(self, baseline: DeviceBaseline):
        """Save baseline to database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO device_baselines (ip, data, updated_at)
                VALUES (?, ?, ?)
            ''', (
                baseline.ip,
                json.dumps(baseline.to_dict()),
                datetime.now().isoformat()
            ))
            conn.commit()
    
    def _save_statistics(self):
        """Save statistics to database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for metric, data in self.stats.stats.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO statistics (metric, data, updated_at)
                    VALUES (?, ?, ?)
                ''', (metric, json.dumps(data), datetime.now().isoformat()))
            conn.commit()
    
    def _save_anomaly(self, anomaly: Anomaly, scan_id: Optional[str] = None):
        """Save anomaly to history."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO anomaly_history 
                (scan_id, anomaly_type, severity, host, description, details, confidence, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                anomaly.anomaly_type.value,
                anomaly.severity.value,
                anomaly.host,
                anomaly.description,
                json.dumps(anomaly.details),
                anomaly.confidence,
                anomaly.timestamp
            ))
            conn.commit()
    
    def train(self, historical_scans: List[Dict]):
        """
        Train on historical scan data.
        
        Args:
            historical_scans: List of past scan results
        """
        for scan in historical_scans:
            scan_time = datetime.fromisoformat(scan.get("timestamp", datetime.now().isoformat()))
            
            hosts = scan.get("hosts", [])
            
            # Update statistics
            self.stats.update("hosts_per_scan", len(hosts))
            
            total_ports = 0
            for host in hosts:
                ip = host.get("ip")
                if not ip:
                    continue
                
                # Update baseline
                if ip not in self.baselines:
                    self.baselines[ip] = DeviceBaseline(ip)
                
                self.baselines[ip].update(host, scan_time)
                self.known_hosts.add(ip)
                
                # Update port statistics
                ports = host.get("ports", [])
                total_ports += len(ports)
                self.stats.update(f"ports_{ip}", len(ports))
            
            self.stats.update("total_ports_per_scan", total_ports)
        
        # Save baselines and statistics
        for baseline in self.baselines.values():
            self._save_baseline(baseline)
        self._save_statistics()
    
    def detect(self, current_scan: Dict, scan_id: Optional[str] = None) -> List[Anomaly]:
        """
        Detect anomalies in current scan.
        
        Args:
            current_scan: Current scan results
            scan_id: Optional scan identifier
        
        Returns:
            List of detected anomalies
        """
        anomalies = []
        scan_time = datetime.fromisoformat(
            current_scan.get("timestamp", datetime.now().isoformat())
        )
        
        current_hosts = set()
        hosts = current_scan.get("hosts", [])
        
        # Check host count anomaly
        is_anomaly, z_score = self.stats.is_anomaly(
            "hosts_per_scan", 
            len(hosts), 
            self.z_score_threshold
        )
        if is_anomaly:
            expected = self.stats.get_stats("hosts_per_scan")
            anomalies.append(Anomaly(
                anomaly_type=AnomalyType.BEHAVIORAL_ANOMALY,
                severity=AnomalySeverity.MEDIUM,
                host=None,
                description=f"Unusual number of hosts: {len(hosts)} (expected ~{expected['mean']:.0f})",
                details={"count": len(hosts), "expected": expected, "z_score": z_score},
                confidence=min(z_score / 3.0, 1.0)
            ))
        
        for host in hosts:
            ip = host.get("ip")
            if not ip:
                continue
            
            current_hosts.add(ip)
            current_ports = set(host.get("ports", []))
            
            # New host detection
            if ip not in self.known_hosts:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.NEW_HOST,
                    severity=AnomalySeverity.MEDIUM,
                    host=ip,
                    description=f"New host detected: {ip}",
                    details=host,
                    confidence=1.0
                ))
                
                # Create baseline for new host
                self.baselines[ip] = DeviceBaseline(ip)
                self.baselines[ip].update(host, scan_time)
                self.known_hosts.add(ip)
                continue
            
            baseline = self.baselines.get(ip)
            if not baseline:
                continue
            
            # Check for new ports
            typical_ports = baseline.get_typical_ports(self.new_port_threshold)
            new_ports = current_ports - typical_ports
            for port in new_ports:
                severity = AnomalySeverity.LOW
                if port in self.SUSPICIOUS_PORTS:
                    severity = AnomalySeverity.HIGH
                
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.NEW_PORT,
                    severity=severity,
                    host=ip,
                    description=f"New port detected on {ip}: {port}",
                    details={"port": port, "typical_ports": list(typical_ports)},
                    confidence=0.8
                ))
            
            # Check for closed ports
            closed_ports = typical_ports - current_ports
            for port in closed_ports:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.CLOSED_PORT,
                    severity=AnomalySeverity.LOW,
                    host=ip,
                    description=f"Previously open port now closed on {ip}: {port}",
                    details={"port": port},
                    confidence=0.7
                ))
            
            # Check port count anomaly
            is_anomaly, z_score = self.stats.is_anomaly(
                f"ports_{ip}",
                len(current_ports),
                self.z_score_threshold
            )
            if is_anomaly:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.BEHAVIORAL_ANOMALY,
                    severity=AnomalySeverity.MEDIUM,
                    host=ip,
                    description=f"Unusual port count on {ip}: {len(current_ports)}",
                    details={"count": len(current_ports), "z_score": z_score},
                    confidence=min(z_score / 3.0, 1.0)
                ))
            
            # Check for high port count
            if len(current_ports) > self.high_port_count_threshold:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.HIGH_PORT_COUNT,
                    severity=AnomalySeverity.MEDIUM,
                    host=ip,
                    description=f"High number of open ports on {ip}: {len(current_ports)}",
                    details={"count": len(current_ports), "ports": list(current_ports)[:20]},
                    confidence=0.9
                ))
            
            # Check for suspicious ports
            suspicious_found = current_ports & self.SUSPICIOUS_PORTS
            for port in suspicious_found:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.SUSPICIOUS_SERVICE,
                    severity=AnomalySeverity.HIGH,
                    host=ip,
                    description=f"Suspicious port detected on {ip}: {port}",
                    details={"port": port},
                    confidence=0.95
                ))
            
            # Check for service changes
            current_services = host.get("services", {})
            for port, service in current_services.items():
                port_int = int(port)
                if port_int in baseline.known_services:
                    old_service = baseline.known_services[port_int]
                    if old_service != service:
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.SERVICE_CHANGE,
                            severity=AnomalySeverity.MEDIUM,
                            host=ip,
                            description=f"Service changed on {ip}:{port} from {old_service} to {service}",
                            details={"port": port, "old": old_service, "new": service},
                            confidence=0.85
                        ))
                
                # Check for high-risk services
                service_lower = service.lower()
                for risk_service, severity in self.HIGH_RISK_SERVICES.items():
                    if risk_service in service_lower:
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.SUSPICIOUS_SERVICE,
                            severity=severity,
                            host=ip,
                            description=f"High-risk service detected on {ip}:{port}: {service}",
                            details={"port": port, "service": service},
                            confidence=0.9
                        ))
            
            # Check for OS changes
            current_os = host.get("os")
            if current_os and baseline.os_history:
                if current_os != baseline.os_history[-1]:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.OS_CHANGE,
                        severity=AnomalySeverity.MEDIUM,
                        host=ip,
                        description=f"OS change detected on {ip}: {baseline.os_history[-1]} -> {current_os}",
                        details={"old": baseline.os_history[-1], "new": current_os},
                        confidence=0.75
                    ))
            
            # Check for device type changes
            current_device_type = host.get("device_type")
            if current_device_type and baseline.device_type:
                if current_device_type != baseline.device_type:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.DEVICE_TYPE_CHANGE,
                        severity=AnomalySeverity.HIGH,
                        host=ip,
                        description=f"Device type change on {ip}: {baseline.device_type} -> {current_device_type}",
                        details={"old": baseline.device_type, "new": current_device_type},
                        confidence=0.8
                    ))
            
            # Update baseline
            baseline.update(host, scan_time)
            self._save_baseline(baseline)
        
        # Check for missing hosts
        for ip in self.known_hosts:
            if ip not in current_hosts:
                baseline = self.baselines.get(ip)
                if baseline and baseline.last_seen:
                    days_missing = (scan_time - baseline.last_seen).days
                    if days_missing > self.missing_threshold_days:
                        continue  # Already reported as missing
                    
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.MISSING_HOST,
                        severity=AnomalySeverity.LOW,
                        host=ip,
                        description=f"Previously seen host not detected: {ip}",
                        details={
                            "last_seen": baseline.last_seen.isoformat(),
                            "seen_count": baseline.seen_count
                        },
                        confidence=0.6
                    ))
        
        # Update statistics
        self.stats.update("hosts_per_scan", len(hosts))
        total_ports = sum(len(h.get("ports", [])) for h in hosts)
        self.stats.update("total_ports_per_scan", total_ports)
        self._save_statistics()
        
        # Save anomalies
        for anomaly in anomalies:
            self._save_anomaly(anomaly, scan_id)
        
        return anomalies
    
    def get_anomaly_history(
        self,
        host: Optional[str] = None,
        anomaly_type: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get anomaly history with optional filters."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM anomaly_history WHERE 1=1"
            params = []
            
            if host:
                query += " AND host = ?"
                params.append(host)
            
            if anomaly_type:
                query += " AND anomaly_type = ?"
                params.append(anomaly_type)
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            if since:
                query += " AND detected_at >= ?"
                params.append(since.isoformat())
            
            query += " ORDER BY detected_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                if result.get("details"):
                    result["details"] = json.loads(result["details"])
                results.append(result)
            
            return results
    
    def get_baseline_summary(self, ip: Optional[str] = None) -> Dict:
        """Get summary of device baselines."""
        if ip:
            baseline = self.baselines.get(ip)
            if baseline:
                return baseline.to_dict()
            return {}
        
        return {
            "total_devices": len(self.baselines),
            "devices": [b.to_dict() for b in self.baselines.values()]
        }
    
    def get_statistics_summary(self) -> Dict:
        """Get summary of collected statistics."""
        return {
            metric: self.stats.get_stats(metric)
            for metric in self.stats.stats.keys()
        }


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Anomaly Detection for LAN Recon")
    subparsers = parser.add_subparsers(dest="command")
    
    # Train command
    train_parser = subparsers.add_parser("train", help="Train on historical data")
    train_parser.add_argument("data_file", help="JSON file with historical scans")
    
    # Detect command
    detect_parser = subparsers.add_parser("detect", help="Detect anomalies in scan")
    detect_parser.add_argument("scan_file", help="JSON file with scan results")
    
    # History command
    history_parser = subparsers.add_parser("history", help="View anomaly history")
    history_parser.add_argument("--host", help="Filter by host")
    history_parser.add_argument("--type", help="Filter by anomaly type")
    history_parser.add_argument("--severity", help="Filter by severity")
    history_parser.add_argument("--limit", type=int, default=20, help="Max results")
    
    # Baseline command
    baseline_parser = subparsers.add_parser("baseline", help="View device baselines")
    baseline_parser.add_argument("--ip", help="Specific IP to view")
    
    args = parser.parse_args()
    
    detector = AnomalyDetector()
    
    if args.command == "train":
        with open(args.data_file) as f:
            data = json.load(f)
        if isinstance(data, list):
            detector.train(data)
        else:
            detector.train([data])
        print("Training complete")
    
    elif args.command == "detect":
        with open(args.scan_file) as f:
            scan = json.load(f)
        anomalies = detector.detect(scan)
        print(f"Detected {len(anomalies)} anomalies:")
        for a in anomalies:
            print(f"  [{a.severity.value.upper()}] {a.description}")
    
    elif args.command == "history":
        history = detector.get_anomaly_history(
            host=args.host,
            anomaly_type=args.type,
            severity=args.severity,
            limit=args.limit
        )
        for item in history:
            print(f"[{item['severity']}] {item['detected_at']}: {item['description']}")
    
    elif args.command == "baseline":
        summary = detector.get_baseline_summary(args.ip)
        print(json.dumps(summary, indent=2))
    
    else:
        parser.print_help()
