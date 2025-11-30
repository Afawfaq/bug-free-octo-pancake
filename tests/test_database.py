"""
Unit tests for the Database module.
"""

import os
import json
import pytest
import tempfile
from datetime import datetime


class TestDatabaseInitialization:
    """Test Database initialization."""
    
    def test_default_initialization(self, tmp_path):
        """Test database initialization with default path."""
        from database import Database
        
        db_path = str(tmp_path / "test.db")
        db = Database(db_path=db_path)
        
        assert db.db_path == db_path
        assert os.path.exists(db_path)
    
    def test_schema_initialization(self, tmp_path):
        """Test that schema is properly initialized."""
        from database import Database
        import sqlite3
        
        db_path = str(tmp_path / "test.db")
        db = Database(db_path=db_path)
        
        # Check tables exist
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        
        assert "scans" in tables
        assert "hosts" in tables
        assert "findings" in tables
        assert "configs" in tables
        
        conn.close()


class TestScanOperations:
    """Test scan CRUD operations."""
    
    @pytest.fixture
    def db(self, tmp_path):
        """Create a temporary database for testing."""
        from database import Database
        
        db_path = str(tmp_path / "test.db")
        return Database(db_path=db_path)
    
    def test_save_scan(self, db):
        """Test saving a scan."""
        scan_data = {
            "id": "test_scan_001",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "risk_score": 50,
            "config": {"passive_duration": 30},
            "hosts": [
                {"ip": "192.168.1.1", "hostname": "router", "device_type": "router"}
            ],
            "findings": [
                {"name": "Test Finding", "severity": "high", "description": "Test"}
            ]
        }
        
        scan_id = db.save_scan(scan_data)
        
        assert scan_id == "test_scan_001"
    
    def test_get_scan(self, db):
        """Test retrieving a scan by ID."""
        scan_data = {
            "id": "test_scan_002",
            "target_network": "10.0.0.0/24",
            "status": "completed",
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "risk_score": 30,
            "config": {"verbose": True}
        }
        
        db.save_scan(scan_data)
        retrieved = db.get_scan("test_scan_002")
        
        assert retrieved is not None
        assert retrieved["target_network"] == "10.0.0.0/24"
        assert retrieved["status"] == "completed"
        assert retrieved["risk_score"] == 30
    
    def test_get_scan_not_found(self, db):
        """Test retrieving a non-existent scan."""
        result = db.get_scan("nonexistent_id")
        
        assert result is None
    
    def test_get_scans(self, db):
        """Test retrieving multiple scans."""
        for i in range(5):
            scan_data = {
                "id": f"test_scan_{i}",
                "target_network": "192.168.1.0/24",
                "status": "completed"
            }
            db.save_scan(scan_data)
        
        scans = db.get_scans(limit=3)
        
        assert len(scans) == 3
    
    def test_delete_scan(self, db):
        """Test deleting a scan."""
        scan_data = {
            "id": "to_delete",
            "target_network": "192.168.1.0/24",
            "status": "completed"
        }
        
        db.save_scan(scan_data)
        
        # Verify it exists
        assert db.get_scan("to_delete") is not None
        
        # Delete it
        result = db.delete_scan("to_delete")
        
        assert result == True
        assert db.get_scan("to_delete") is None


class TestHostOperations:
    """Test host CRUD operations."""
    
    @pytest.fixture
    def db_with_scan(self, tmp_path):
        """Create a database with a scan and hosts."""
        from database import Database
        
        db_path = str(tmp_path / "test.db")
        db = Database(db_path=db_path)
        
        scan_data = {
            "id": "host_test_scan",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "hosts": [
                {"ip": "192.168.1.1", "hostname": "router", "device_type": "router", "ports": [80, 443]},
                {"ip": "192.168.1.100", "hostname": "workstation", "device_type": "workstation"},
                {"ip": "192.168.1.50", "hostname": "printer", "device_type": "printer"}
            ]
        }
        
        db.save_scan(scan_data)
        return db
    
    def test_get_hosts(self, db_with_scan):
        """Test getting hosts for a scan."""
        hosts = db_with_scan.get_hosts("host_test_scan")
        
        assert len(hosts) == 3
        
        ips = {h["ip_address"] for h in hosts}
        assert "192.168.1.1" in ips
        assert "192.168.1.100" in ips
        assert "192.168.1.50" in ips
    
    def test_get_all_hosts(self, db_with_scan):
        """Test getting all unique hosts."""
        # Add another scan with some overlapping hosts
        scan_data = {
            "id": "host_test_scan_2",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "hosts": [
                {"ip": "192.168.1.1", "hostname": "router", "device_type": "router"},
                {"ip": "192.168.1.200", "hostname": "server", "device_type": "server"}
            ]
        }
        
        db_with_scan.save_scan(scan_data)
        
        all_hosts = db_with_scan.get_all_hosts()
        
        # Should have 4 unique IPs
        assert len(all_hosts) == 4
    
    def test_get_host_history(self, db_with_scan):
        """Test getting host history."""
        # Add another scan with the same host
        scan_data = {
            "id": "host_test_scan_3",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "hosts": [
                {"ip": "192.168.1.1", "hostname": "router-updated", "device_type": "router"}
            ]
        }
        
        db_with_scan.save_scan(scan_data)
        
        history = db_with_scan.get_host_history("192.168.1.1")
        
        assert len(history) == 2


class TestFindingOperations:
    """Test finding CRUD operations."""
    
    @pytest.fixture
    def db_with_findings(self, tmp_path):
        """Create a database with findings."""
        from database import Database
        
        db_path = str(tmp_path / "test.db")
        db = Database(db_path=db_path)
        
        scan_data = {
            "id": "findings_test_scan",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "findings": [
                {"name": "Critical Bug", "severity": "critical", "description": "Critical issue"},
                {"name": "High Issue", "severity": "high", "description": "High severity"},
                {"name": "Medium Issue", "severity": "medium", "description": "Medium severity"},
                {"name": "Low Issue", "severity": "low", "description": "Low severity"}
            ]
        }
        
        db.save_scan(scan_data)
        return db
    
    def test_get_findings(self, db_with_findings):
        """Test getting findings for a scan."""
        findings = db_with_findings.get_findings("findings_test_scan")
        
        assert len(findings) == 4
    
    def test_get_findings_by_severity(self, db_with_findings):
        """Test getting findings by severity."""
        critical_findings = db_with_findings.get_findings_by_severity("critical")
        
        assert len(critical_findings) == 1
        assert critical_findings[0]["name"] == "Critical Bug"
    
    def test_get_finding_stats(self, db_with_findings):
        """Test getting finding statistics."""
        stats = db_with_findings.get_finding_stats()
        
        assert stats["total"] == 4
        assert "critical" in stats["by_severity"]
        assert stats["by_severity"]["critical"] == 1


class TestConfigOperations:
    """Test configuration operations."""
    
    @pytest.fixture
    def db(self, tmp_path):
        """Create a temporary database for testing."""
        from database import Database
        
        db_path = str(tmp_path / "test.db")
        return Database(db_path=db_path)
    
    def test_save_config(self, db):
        """Test saving a configuration."""
        config = {
            "target_network": "192.168.1.0/24",
            "passive_duration": 60,
            "parallel_execution": True
        }
        
        db.save_config("test_config", config)
        
        # Should not raise an exception
        assert True
    
    def test_get_config(self, db):
        """Test retrieving a configuration."""
        config = {"test_key": "test_value", "number": 42}
        
        db.save_config("retrieve_test", config)
        retrieved = db.get_config("retrieve_test")
        
        assert retrieved is not None
        assert retrieved["test_key"] == "test_value"
        assert retrieved["number"] == 42
    
    def test_get_config_not_found(self, db):
        """Test retrieving a non-existent configuration."""
        result = db.get_config("nonexistent")
        
        assert result is None
    
    def test_list_configs(self, db):
        """Test listing all configurations."""
        db.save_config("config1", {"key": "value1"})
        db.save_config("config2", {"key": "value2"})
        
        configs = db.list_configs()
        
        assert len(configs) >= 2
        names = {c["name"] for c in configs}
        assert "config1" in names
        assert "config2" in names


class TestScanComparison:
    """Test scan comparison functionality."""
    
    @pytest.fixture
    def db_with_two_scans(self, tmp_path):
        """Create a database with two scans for comparison."""
        from database import Database
        
        db_path = str(tmp_path / "test.db")
        db = Database(db_path=db_path)
        
        scan1 = {
            "id": "scan_old",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "risk_score": 50,
            "hosts": [
                {"ip": "192.168.1.1"},
                {"ip": "192.168.1.100"}
            ],
            "findings": [
                {"name": "Finding A", "severity": "high"},
                {"name": "Finding B", "severity": "medium"}
            ]
        }
        
        scan2 = {
            "id": "scan_new",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "risk_score": 30,
            "hosts": [
                {"ip": "192.168.1.1"},
                {"ip": "192.168.1.200"}  # New host, 192.168.1.100 removed
            ],
            "findings": [
                {"name": "Finding A", "severity": "high"},
                {"name": "Finding C", "severity": "low"}  # Finding B resolved, C is new
            ]
        }
        
        db.save_scan(scan1)
        db.save_scan(scan2)
        
        return db
    
    def test_compare_scans(self, db_with_two_scans):
        """Test comparing two scans."""
        comparison = db_with_two_scans.compare_scans("scan_old", "scan_new")
        
        assert "error" not in comparison
        assert "192.168.1.200" in comparison["hosts"]["new"]
        assert "192.168.1.100" in comparison["hosts"]["removed"]
        assert "Finding C" in comparison["findings"]["new"]
        assert "Finding B" in comparison["findings"]["resolved"]
        assert comparison["risk_score_change"] == -20  # 30 - 50 = -20
    
    def test_compare_nonexistent_scan(self, db_with_two_scans):
        """Test comparing with a non-existent scan."""
        comparison = db_with_two_scans.compare_scans("scan_old", "nonexistent")
        
        assert "error" in comparison


class TestUtilityMethods:
    """Test utility methods."""
    
    @pytest.fixture
    def db(self, tmp_path):
        """Create a temporary database for testing."""
        from database import Database
        
        db_path = str(tmp_path / "test.db")
        return Database(db_path=db_path)
    
    def test_get_stats(self, db):
        """Test getting database statistics."""
        # Add some data
        scan_data = {
            "id": "stats_test",
            "target_network": "192.168.1.0/24",
            "status": "completed",
            "hosts": [{"ip": "192.168.1.1"}],
            "findings": [{"name": "Test", "severity": "high"}]
        }
        
        db.save_scan(scan_data)
        
        stats = db.get_stats()
        
        assert stats["total_scans"] >= 1
        assert stats["unique_hosts"] >= 1
        assert stats["total_findings"] >= 1
        assert "database_path" in stats
