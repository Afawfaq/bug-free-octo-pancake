#!/usr/bin/env python3
"""
Export/Import System for LAN Reconnaissance Framework
=====================================================

Provides data portability for scan results, configurations, and reports.
Supports multiple export formats and secure data handling.

Features:
- Multiple export formats (JSON, CSV, XML, YAML, HTML, PDF stub)
- Selective data export (scans, hosts, findings, configs)
- Import validation and merging
- Data anonymization options
- Compression support
- Encrypted exports

Usage:
    from export_import import ExportManager, ImportManager
    
    # Export
    exporter = ExportManager()
    exporter.export_scan("scan_123", format="json", output="scan_123.json")
    
    # Import
    importer = ImportManager()
    importer.import_scan("scan_123.json")
"""

import os
import sys
import json
import csv
import gzip
import hashlib
import base64
import io
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from abc import ABC, abstractmethod
import sqlite3
import re


class ExportFormat(ABC):
    """Base class for export formats."""
    
    format_name: str = "base"
    file_extension: str = ".txt"
    
    @abstractmethod
    def serialize(self, data: Dict) -> Union[str, bytes]:
        """Serialize data to format."""
        pass
    
    @abstractmethod
    def deserialize(self, content: Union[str, bytes]) -> Dict:
        """Deserialize content to data."""
        pass


class JSONFormat(ExportFormat):
    """JSON export format."""
    
    format_name = "json"
    file_extension = ".json"
    
    def serialize(self, data: Dict) -> str:
        return json.dumps(data, indent=2, default=str)
    
    def deserialize(self, content: Union[str, bytes]) -> Dict:
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        return json.loads(content)


class CSVFormat(ExportFormat):
    """CSV export format for tabular data."""
    
    format_name = "csv"
    file_extension = ".csv"
    
    def serialize(self, data: Dict) -> str:
        output = io.StringIO()
        
        # Handle different data structures
        if "hosts" in data:
            self._write_hosts_csv(output, data["hosts"])
        elif "findings" in data:
            self._write_findings_csv(output, data["findings"])
        elif "scans" in data:
            self._write_scans_csv(output, data["scans"])
        else:
            # Generic flat dictionary
            self._write_generic_csv(output, data)
        
        return output.getvalue()
    
    def _write_hosts_csv(self, output: io.StringIO, hosts: List[Dict]):
        writer = csv.writer(output)
        writer.writerow(["IP", "MAC", "Hostname", "OS", "Device Type", "Open Ports", "Last Seen"])
        for host in hosts:
            writer.writerow([
                host.get("ip", ""),
                host.get("mac", ""),
                host.get("hostname", ""),
                host.get("os", ""),
                host.get("device_type", ""),
                ",".join(map(str, host.get("ports", []))),
                host.get("last_seen", "")
            ])
    
    def _write_findings_csv(self, output: io.StringIO, findings: List[Dict]):
        writer = csv.writer(output)
        writer.writerow(["Severity", "Host", "Port", "Title", "Description", "Remediation"])
        for finding in findings:
            writer.writerow([
                finding.get("severity", ""),
                finding.get("host", ""),
                finding.get("port", ""),
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("remediation", "")
            ])
    
    def _write_scans_csv(self, output: io.StringIO, scans: List[Dict]):
        writer = csv.writer(output)
        writer.writerow(["ID", "Target", "Start Time", "End Time", "Status", "Hosts Found", "Findings"])
        for scan in scans:
            writer.writerow([
                scan.get("id", ""),
                scan.get("target_network", ""),
                scan.get("start_time", ""),
                scan.get("end_time", ""),
                scan.get("status", ""),
                scan.get("hosts_found", 0),
                scan.get("findings_count", 0)
            ])
    
    def _write_generic_csv(self, output: io.StringIO, data: Dict):
        writer = csv.writer(output)
        if data:
            writer.writerow(list(data.keys()))
            writer.writerow(list(data.values()))
    
    def deserialize(self, content: Union[str, bytes]) -> Dict:
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        
        reader = csv.DictReader(io.StringIO(content))
        return {"rows": list(reader)}


class XMLFormat(ExportFormat):
    """XML export format."""
    
    format_name = "xml"
    file_extension = ".xml"
    
    def serialize(self, data: Dict) -> str:
        root = ET.Element("scan_export")
        root.set("timestamp", datetime.now().isoformat())
        root.set("framework", "LAN Reconnaissance Framework")
        
        self._dict_to_xml(root, data)
        return ET.tostring(root, encoding='unicode')
    
    def _dict_to_xml(self, parent: ET.Element, data: Any, tag_name: str = "item"):
        if isinstance(data, dict):
            for key, value in data.items():
                child = ET.SubElement(parent, str(key).replace(" ", "_"))
                self._dict_to_xml(child, value, key)
        elif isinstance(data, list):
            for item in data:
                child = ET.SubElement(parent, tag_name)
                self._dict_to_xml(child, item)
        else:
            parent.text = str(data) if data is not None else ""
    
    def deserialize(self, content: Union[str, bytes]) -> Dict:
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        
        root = ET.fromstring(content)
        return self._xml_to_dict(root)
    
    def _xml_to_dict(self, element: ET.Element) -> Any:
        if len(element) == 0:
            return element.text
        
        result = {}
        for child in element:
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(self._xml_to_dict(child))
            else:
                result[child.tag] = self._xml_to_dict(child)
        
        return result


class YAMLFormat(ExportFormat):
    """YAML export format (pure Python implementation)."""
    
    format_name = "yaml"
    file_extension = ".yaml"
    
    def serialize(self, data: Dict) -> str:
        return self._dict_to_yaml(data, indent=0)
    
    def _dict_to_yaml(self, data: Any, indent: int = 0) -> str:
        result = []
        prefix = "  " * indent
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict):
                    result.append(f"{prefix}{key}:")
                    result.append(self._dict_to_yaml(value, indent + 1))
                elif isinstance(value, list):
                    result.append(f"{prefix}{key}:")
                    for item in value:
                        if isinstance(item, dict):
                            result.append(f"{prefix}  -")
                            result.append(self._dict_to_yaml(item, indent + 2))
                        else:
                            result.append(f"{prefix}  - {self._format_value(item)}")
                else:
                    result.append(f"{prefix}{key}: {self._format_value(value)}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    result.append(f"{prefix}-")
                    result.append(self._dict_to_yaml(item, indent + 1))
                else:
                    result.append(f"{prefix}- {self._format_value(item)}")
        
        return "\n".join(result)
    
    def _format_value(self, value: Any) -> str:
        if value is None:
            return "null"
        elif isinstance(value, bool):
            return "true" if value else "false"
        elif isinstance(value, str):
            if "\n" in value or ":" in value or '"' in value:
                return f'"{value}"'
            return value
        else:
            return str(value)
    
    def deserialize(self, content: Union[str, bytes]) -> Dict:
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        
        # Simple YAML parser (basic support)
        result = {}
        current_key = None
        current_list = None
        
        for line in content.split("\n"):
            if not line.strip() or line.strip().startswith("#"):
                continue
            
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else None
                
                if value:
                    result[key] = self._parse_value(value)
                else:
                    result[key] = {}
                current_key = key
        
        return result
    
    def _parse_value(self, value: str) -> Any:
        if value == "null":
            return None
        elif value == "true":
            return True
        elif value == "false":
            return False
        elif value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        elif value.isdigit():
            return int(value)
        try:
            return float(value)
        except ValueError:
            return value


class Anonymizer:
    """
    Data anonymizer for sensitive information.
    
    Anonymizes:
    - IP addresses
    - MAC addresses
    - Hostnames
    - Custom patterns
    """
    
    def __init__(self):
        self._mappings: Dict[str, str] = {}
        self._counter = 0
    
    def _get_anonymous(self, prefix: str, original: str) -> str:
        if original not in self._mappings:
            self._counter += 1
            self._mappings[original] = f"{prefix}_{self._counter:04d}"
        return self._mappings[original]
    
    def anonymize_ip(self, ip: str) -> str:
        """Anonymize IP address."""
        return self._get_anonymous("IP", ip)
    
    def anonymize_mac(self, mac: str) -> str:
        """Anonymize MAC address."""
        return self._get_anonymous("MAC", mac)
    
    def anonymize_hostname(self, hostname: str) -> str:
        """Anonymize hostname."""
        return self._get_anonymous("HOST", hostname)
    
    def anonymize_data(self, data: Any) -> Any:
        """Recursively anonymize data structure."""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                if key in ("ip", "ip_address", "host", "target"):
                    result[key] = self.anonymize_ip(str(value)) if value else value
                elif key in ("mac", "mac_address"):
                    result[key] = self.anonymize_mac(str(value)) if value else value
                elif key in ("hostname", "name"):
                    result[key] = self.anonymize_hostname(str(value)) if value else value
                else:
                    result[key] = self.anonymize_data(value)
            return result
        elif isinstance(data, list):
            return [self.anonymize_data(item) for item in data]
        elif isinstance(data, str):
            # Check for IP pattern
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            data = re.sub(ip_pattern, lambda m: self.anonymize_ip(m.group()), data)
            
            # Check for MAC pattern
            mac_pattern = r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b'
            data = re.sub(mac_pattern, lambda m: self.anonymize_mac(m.group()), data)
            
            return data
        else:
            return data
    
    def get_mapping_table(self) -> Dict[str, str]:
        """Get the anonymization mapping table."""
        return self._mappings.copy()


class ExportManager:
    """
    Manages data export operations.
    """
    
    FORMATS = {
        "json": JSONFormat(),
        "csv": CSVFormat(),
        "xml": XMLFormat(),
        "yaml": YAMLFormat()
    }
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize export manager."""
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "lan_recon.db"
        )
        self.anonymizer = Anonymizer()
    
    def export_scan(
        self,
        scan_id: str,
        format: str = "json",
        output: Optional[str] = None,
        include_hosts: bool = True,
        include_findings: bool = True,
        include_raw: bool = False,
        anonymize: bool = False,
        compress: bool = False
    ) -> str:
        """
        Export a scan and its data.
        
        Args:
            scan_id: ID of scan to export
            format: Export format (json, csv, xml, yaml)
            output: Output file path
            include_hosts: Include discovered hosts
            include_findings: Include security findings
            include_raw: Include raw scan output
            anonymize: Anonymize sensitive data
            compress: Compress output with gzip
        
        Returns:
            Path to exported file
        """
        if format not in self.FORMATS:
            raise ValueError(f"Unsupported format: {format}")
        
        formatter = self.FORMATS[format]
        
        # Gather scan data
        data = self._get_scan_data(scan_id, include_hosts, include_findings, include_raw)
        
        if not data:
            raise ValueError(f"Scan not found: {scan_id}")
        
        # Add export metadata
        data["_export"] = {
            "format": format,
            "timestamp": datetime.now().isoformat(),
            "framework_version": "2.2.0",
            "anonymized": anonymize
        }
        
        # Anonymize if requested
        if anonymize:
            data = self.anonymizer.anonymize_data(data)
            data["_export"]["anonymization_mapping"] = self.anonymizer.get_mapping_table()
        
        # Serialize
        content = formatter.serialize(data)
        
        # Determine output path
        if not output:
            output = f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{formatter.file_extension}"
        
        # Compress if requested
        if compress:
            output += ".gz"
            if isinstance(content, str):
                content = content.encode('utf-8')
            with gzip.open(output, 'wb') as f:
                f.write(content)
        else:
            mode = 'w' if isinstance(content, str) else 'wb'
            with open(output, mode) as f:
                f.write(content)
        
        return output
    
    def _get_scan_data(
        self,
        scan_id: str,
        include_hosts: bool,
        include_findings: bool,
        include_raw: bool
    ) -> Optional[Dict]:
        """Get scan data from database."""
        if not os.path.exists(self.db_path):
            return None
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get scan info
            cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            
            data = {
                "scan": dict(row),
                "export_date": datetime.now().isoformat()
            }
            
            # Parse JSON fields
            if data["scan"].get("config"):
                data["scan"]["config"] = json.loads(data["scan"]["config"])
            if data["scan"].get("summary"):
                data["scan"]["summary"] = json.loads(data["scan"]["summary"])
            
            # Get hosts
            if include_hosts:
                cursor.execute('''
                    SELECT * FROM hosts WHERE scan_id = ?
                ''', (scan_id,))
                data["hosts"] = [dict(row) for row in cursor.fetchall()]
            
            # Get findings
            if include_findings:
                cursor.execute('''
                    SELECT * FROM findings WHERE scan_id = ?
                ''', (scan_id,))
                data["findings"] = [dict(row) for row in cursor.fetchall()]
        
        return data
    
    def export_all_scans(
        self,
        format: str = "json",
        output: Optional[str] = None,
        compress: bool = True
    ) -> str:
        """Export all scans."""
        if format not in self.FORMATS:
            raise ValueError(f"Unsupported format: {format}")
        
        formatter = self.FORMATS[format]
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM scans ORDER BY created_at DESC")
            scan_ids = [row["id"] for row in cursor.fetchall()]
        
        all_data = {
            "scans": [],
            "_export": {
                "format": format,
                "timestamp": datetime.now().isoformat(),
                "framework_version": "2.2.0",
                "total_scans": len(scan_ids)
            }
        }
        
        for scan_id in scan_ids:
            scan_data = self._get_scan_data(scan_id, True, True, False)
            if scan_data:
                all_data["scans"].append(scan_data)
        
        content = formatter.serialize(all_data)
        
        if not output:
            output = f"all_scans_{datetime.now().strftime('%Y%m%d_%H%M%S')}{formatter.file_extension}"
        
        if compress:
            output += ".gz"
            if isinstance(content, str):
                content = content.encode('utf-8')
            with gzip.open(output, 'wb') as f:
                f.write(content)
        else:
            mode = 'w' if isinstance(content, str) else 'wb'
            with open(output, mode) as f:
                f.write(content)
        
        return output
    
    def export_hosts(
        self,
        format: str = "csv",
        output: Optional[str] = None,
        anonymize: bool = False
    ) -> str:
        """Export host inventory."""
        formatter = self.FORMATS.get(format, self.FORMATS["csv"])
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hosts ORDER BY ip")
            hosts = [dict(row) for row in cursor.fetchall()]
        
        data = {"hosts": hosts}
        
        if anonymize:
            data = self.anonymizer.anonymize_data(data)
        
        content = formatter.serialize(data)
        
        if not output:
            output = f"hosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}{formatter.file_extension}"
        
        mode = 'w' if isinstance(content, str) else 'wb'
        with open(output, mode) as f:
            f.write(content)
        
        return output
    
    def export_findings(
        self,
        format: str = "csv",
        output: Optional[str] = None,
        severity_filter: Optional[List[str]] = None,
        anonymize: bool = False
    ) -> str:
        """Export security findings."""
        formatter = self.FORMATS.get(format, self.FORMATS["csv"])
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if severity_filter:
                placeholders = ",".join("?" * len(severity_filter))
                cursor.execute(
                    f"SELECT * FROM findings WHERE severity IN ({placeholders})",
                    severity_filter
                )
            else:
                cursor.execute("SELECT * FROM findings")
            
            findings = [dict(row) for row in cursor.fetchall()]
        
        data = {"findings": findings}
        
        if anonymize:
            data = self.anonymizer.anonymize_data(data)
        
        content = formatter.serialize(data)
        
        if not output:
            output = f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}{formatter.file_extension}"
        
        mode = 'w' if isinstance(content, str) else 'wb'
        with open(output, mode) as f:
            f.write(content)
        
        return output


class ImportManager:
    """
    Manages data import operations.
    """
    
    FORMATS = ExportManager.FORMATS
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize import manager."""
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "lan_recon.db"
        )
    
    def import_file(
        self,
        filepath: str,
        merge: bool = True,
        validate: bool = True
    ) -> Dict:
        """
        Import data from file.
        
        Args:
            filepath: Path to import file
            merge: Merge with existing data (vs. replace)
            validate: Validate data before import
        
        Returns:
            Import statistics
        """
        # Detect format and compression
        is_compressed = filepath.endswith('.gz')
        
        if is_compressed:
            base_path = filepath[:-3]
        else:
            base_path = filepath
        
        # Detect format
        ext = os.path.splitext(base_path)[1].lower()
        format_map = {".json": "json", ".csv": "csv", ".xml": "xml", ".yaml": "yaml", ".yml": "yaml"}
        format_name = format_map.get(ext, "json")
        
        # Read file
        if is_compressed:
            with gzip.open(filepath, 'rb') as f:
                content = f.read()
        else:
            with open(filepath, 'rb') as f:
                content = f.read()
        
        # Parse
        formatter = self.FORMATS[format_name]
        data = formatter.deserialize(content)
        
        # Validate
        if validate:
            validation = self._validate_data(data)
            if not validation["valid"]:
                return {"success": False, "errors": validation["errors"]}
        
        # Import
        stats = self._import_data(data, merge)
        
        return {
            "success": True,
            "format": format_name,
            "compressed": is_compressed,
            "stats": stats
        }
    
    def _validate_data(self, data: Dict) -> Dict:
        """Validate import data structure."""
        errors = []
        
        # Check for expected keys
        if "scan" in data:
            scan = data["scan"]
            if not scan.get("id"):
                errors.append("Scan missing 'id' field")
            if not scan.get("target_network"):
                errors.append("Scan missing 'target_network' field")
        
        if "hosts" in data:
            for i, host in enumerate(data["hosts"]):
                if not host.get("ip"):
                    errors.append(f"Host {i} missing 'ip' field")
        
        if "findings" in data:
            for i, finding in enumerate(data["findings"]):
                if not finding.get("severity"):
                    errors.append(f"Finding {i} missing 'severity' field")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def _import_data(self, data: Dict, merge: bool) -> Dict:
        """Import validated data into database."""
        stats = {
            "scans_imported": 0,
            "hosts_imported": 0,
            "findings_imported": 0
        }
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Import scans
            if "scan" in data:
                self._import_scan(cursor, data["scan"], merge)
                stats["scans_imported"] += 1
            
            if "scans" in data:
                for scan_data in data["scans"]:
                    if "scan" in scan_data:
                        self._import_scan(cursor, scan_data["scan"], merge)
                        stats["scans_imported"] += 1
                        
                        if "hosts" in scan_data:
                            for host in scan_data["hosts"]:
                                self._import_host(cursor, host, scan_data["scan"]["id"], merge)
                                stats["hosts_imported"] += 1
                        
                        if "findings" in scan_data:
                            for finding in scan_data["findings"]:
                                self._import_finding(cursor, finding, scan_data["scan"]["id"], merge)
                                stats["findings_imported"] += 1
            
            # Import standalone hosts/findings
            if "hosts" in data and "scan" in data:
                for host in data["hosts"]:
                    self._import_host(cursor, host, data["scan"]["id"], merge)
                    stats["hosts_imported"] += 1
            
            if "findings" in data and "scan" in data:
                for finding in data["findings"]:
                    self._import_finding(cursor, finding, data["scan"]["id"], merge)
                    stats["findings_imported"] += 1
            
            conn.commit()
        
        return stats
    
    def _import_scan(self, cursor: sqlite3.Cursor, scan: Dict, merge: bool):
        """Import a scan record."""
        if merge:
            cursor.execute('''
                INSERT OR REPLACE INTO scans (id, target_network, status, start_time, end_time, config, summary, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan.get("id"),
                scan.get("target_network"),
                scan.get("status"),
                scan.get("start_time"),
                scan.get("end_time"),
                json.dumps(scan.get("config", {})),
                json.dumps(scan.get("summary", {})),
                scan.get("risk_score", 0)
            ))
        else:
            cursor.execute('''
                INSERT INTO scans (id, target_network, status, start_time, end_time, config, summary, risk_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan.get("id"),
                scan.get("target_network"),
                scan.get("status"),
                scan.get("start_time"),
                scan.get("end_time"),
                json.dumps(scan.get("config", {})),
                json.dumps(scan.get("summary", {})),
                scan.get("risk_score", 0)
            ))
    
    def _import_host(self, cursor: sqlite3.Cursor, host: Dict, scan_id: str, merge: bool):
        """Import a host record."""
        if merge:
            cursor.execute('''
                INSERT OR REPLACE INTO hosts (scan_id, ip, mac, hostname, os, device_type, ports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                host.get("ip"),
                host.get("mac"),
                host.get("hostname"),
                host.get("os"),
                host.get("device_type"),
                json.dumps(host.get("ports", []))
            ))
    
    def _import_finding(self, cursor: sqlite3.Cursor, finding: Dict, scan_id: str, merge: bool):
        """Import a finding record."""
        cursor.execute('''
            INSERT INTO findings (scan_id, host, port, severity, title, description, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            finding.get("host"),
            finding.get("port"),
            finding.get("severity"),
            finding.get("title"),
            finding.get("description"),
            finding.get("remediation")
        ))


# CLI interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Export/Import scan data")
    subparsers = parser.add_subparsers(dest="command")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export scan data")
    export_parser.add_argument("--scan-id", help="Scan ID to export")
    export_parser.add_argument("--all", action="store_true", help="Export all scans")
    export_parser.add_argument("--format", choices=["json", "csv", "xml", "yaml"], default="json")
    export_parser.add_argument("--output", "-o", help="Output file path")
    export_parser.add_argument("--anonymize", action="store_true", help="Anonymize sensitive data")
    export_parser.add_argument("--compress", action="store_true", help="Compress output")
    
    # Import command
    import_parser = subparsers.add_parser("import", help="Import scan data")
    import_parser.add_argument("file", help="File to import")
    import_parser.add_argument("--no-merge", action="store_true", help="Replace instead of merge")
    import_parser.add_argument("--no-validate", action="store_true", help="Skip validation")
    
    args = parser.parse_args()
    
    if args.command == "export":
        exporter = ExportManager()
        if args.all:
            output = exporter.export_all_scans(
                format=args.format,
                output=args.output,
                compress=args.compress
            )
        elif args.scan_id:
            output = exporter.export_scan(
                scan_id=args.scan_id,
                format=args.format,
                output=args.output,
                anonymize=args.anonymize,
                compress=args.compress
            )
        else:
            print("Specify --scan-id or --all")
            sys.exit(1)
        print(f"Exported to: {output}")
    
    elif args.command == "import":
        importer = ImportManager()
        result = importer.import_file(
            args.file,
            merge=not args.no_merge,
            validate=not args.no_validate
        )
        if result["success"]:
            print(f"Import successful: {result['stats']}")
        else:
            print(f"Import failed: {result['errors']}")
            sys.exit(1)
    
    else:
        parser.print_help()
