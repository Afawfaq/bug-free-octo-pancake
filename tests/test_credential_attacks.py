"""
Unit tests for the Credential Attacks module.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock, mock_open

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'credential-attacks'))


class TestDefaultCredsTester:
    """Test default credentials tester functionality."""
    
    def test_load_credentials_db(self):
        """Test loading credentials database."""
        import default_creds_tester
        
        # Create mock credentials data
        mock_creds = {
            "printers": [
                {"username": "admin", "password": "admin"}
            ],
            "routers": [
                {"username": "admin", "password": "password"}
            ]
        }
        
        with patch('builtins.open', mock_open(read_data=json.dumps(mock_creds))):
            creds_db = default_creds_tester.load_credentials_db()
            
            assert "printers" in creds_db
            assert "routers" in creds_db
            assert len(creds_db["printers"]) == 1
            assert creds_db["printers"][0]["username"] == "admin"
    
    def test_identify_device_type(self):
        """Test device type identification."""
        import default_creds_tester
        
        with patch.object(default_creds_tester, 'is_port_open') as mock_port_open:
            # Mock printer ports open
            mock_port_open.side_effect = lambda ip, port: port in [631, 9100]
            
            device_type = default_creds_tester.identify_device_type("192.168.1.100")
            assert device_type == "printer"
    
    def test_is_port_open(self):
        """Test port open checking."""
        import default_creds_tester
        
        # Test closed port
        result = default_creds_tester.is_port_open("127.0.0.1", 65535, timeout=0.1)
        assert result == False


class TestCleartextSniffer:
    """Test cleartext protocol sniffer."""
    
    def test_sniffer_initialization(self):
        """Test sniffer initialization."""
        import cleartext_sniffer
        
        sniffer = cleartext_sniffer.CleartextSniffer("/tmp/test_output.json")
        assert sniffer.output_file == "/tmp/test_output.json"
        assert sniffer.findings == []
    
    def test_save_results(self):
        """Test saving results to JSON."""
        import cleartext_sniffer
        
        sniffer = cleartext_sniffer.CleartextSniffer("/tmp/test_output.json")
        sniffer.findings = [
            {"protocol": "FTP", "type": "username", "value": "test"}
        ]
        
        with patch('builtins.open', mock_open()) as mock_file:
            sniffer.save_results()
            mock_file.assert_called_once_with("/tmp/test_output.json", 'w')


class TestSSHHarvester:
    """Test SSH harvester functionality."""
    
    def test_enumerate_ssh_hosts(self):
        """Test SSH host enumeration."""
        import ssh_harvester
        
        mock_ips = "192.168.1.1\n192.168.1.2\n192.168.1.3\n"
        
        with patch('builtins.open', mock_open(read_data=mock_ips)):
            findings = ssh_harvester.enumerate_ssh_hosts("/tmp/test_ips.txt")
            
            assert len(findings) == 3
            assert findings[0]["ip"] == "192.168.1.1"
            assert findings[0]["service"] == "SSH"
            assert findings[0]["port"] == 22


class TestCredentialsDatabase:
    """Test credentials database structure."""
    
    def test_database_structure(self):
        """Test that credentials database has expected structure."""
        db_path = os.path.join(os.path.dirname(__file__), '..', 'credential-attacks', 'default_creds_db.json')
        
        with open(db_path, 'r') as f:
            creds_db = json.load(f)
        
        # Verify expected categories exist
        assert "printers" in creds_db
        assert "routers" in creds_db
        assert "iot_devices" in creds_db
        assert "cameras" in creds_db
        assert "nas" in creds_db
        assert "smart_tv" in creds_db
        
        # Verify structure of entries
        for category, creds in creds_db.items():
            assert isinstance(creds, list)
            for cred in creds:
                assert "username" in cred
                assert "password" in cred


class TestCredentialAttacksIntegration:
    """Integration tests for credential attacks module."""
    
    def test_credential_scan_script_exists(self):
        """Test that main scan script exists and is executable."""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'credential-attacks', 'credential_scan.sh')
        
        assert os.path.exists(script_path)
        assert os.access(script_path, os.X_OK)
    
    def test_all_python_scripts_executable(self):
        """Test that all Python scripts are executable."""
        scripts = [
            'default_creds_tester.py',
            'cleartext_sniffer.py',
            'ssh_harvester.py'
        ]
        
        for script in scripts:
            script_path = os.path.join(os.path.dirname(__file__), '..', 'credential-attacks', script)
            assert os.path.exists(script_path), f"{script} does not exist"
            assert os.access(script_path, os.X_OK), f"{script} is not executable"
