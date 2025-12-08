"""
Unit tests for the Patch Cadence module.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock, mock_open

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'patch-cadence'))


class TestFirmwareFingerprinter:
    """Test firmware fingerprinting functionality."""
    
    def test_fingerprinter_initialization(self):
        """Test fingerprinter initialization."""
        import firmware_fingerprinter
        
        fp = firmware_fingerprinter.FirmwareFingerprinter()
        assert fp.findings == []
    
    def test_fingerprint_http_success(self):
        """Test HTTP fingerprinting with successful response."""
        import firmware_fingerprinter
        
        fp = firmware_fingerprinter.FirmwareFingerprinter()
        
        # Mock successful HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'CUPS/2.3.3'}
        mock_response.text = 'Firmware version: 1.2.3\nModel: TestPrinter'
        
        with patch('requests.get', return_value=mock_response):
            result = fp.fingerprint_http("192.168.1.100")
            
            assert result["ip"] == "192.168.1.100"
            assert result["source"] == "HTTP"
            assert "firmware_info" in result
            assert result["firmware_info"]["server"] == "CUPS/2.3.3"
            assert result["firmware_info"]["version"] == "1.2.3"
    
    def test_fingerprint_upnp(self):
        """Test UPnP fingerprinting."""
        import firmware_fingerprinter
        
        fp = firmware_fingerprinter.FirmwareFingerprinter()
        
        # Mock UPnP XML response
        upnp_xml = """<?xml version="1.0"?>
        <root>
            <device>
                <firmwareVersion>2.4.5</firmwareVersion>
                <modelName>TestRouter</modelName>
                <manufacturer>TestCorp</manufacturer>
            </device>
        </root>"""
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = upnp_xml
        
        with patch('requests.get', return_value=mock_response):
            result = fp.fingerprint_upnp("192.168.1.1")
            
            assert result["ip"] == "192.168.1.1"
            assert result["source"] == "UPnP"
            assert result["firmware_info"]["version"] == "2.4.5"
            assert result["firmware_info"]["model"] == "TestRouter"
            assert result["firmware_info"]["manufacturer"] == "TestCorp"


class TestUpdateReachability:
    """Test update server reachability tester."""
    
    def test_tester_initialization(self):
        """Test tester initialization."""
        import update_reachability
        
        tester = update_reachability.UpdateReachabilityTester()
        assert len(tester.common_update_servers) > 0
        assert "HP" in tester.common_update_servers
        assert "Google" in tester.common_update_servers
    
    def test_dns_resolution_success(self):
        """Test DNS resolution with success."""
        import update_reachability
        
        tester = update_reachability.UpdateReachabilityTester()
        
        with patch('socket.gethostbyname', return_value='8.8.8.8'):
            result = tester.test_dns_resolution("google.com")
            assert result == True
    
    def test_dns_resolution_failure(self):
        """Test DNS resolution with failure."""
        import update_reachability
        
        tester = update_reachability.UpdateReachabilityTester()
        
        with patch('socket.gethostbyname', side_effect=Exception("DNS failure")):
            result = tester.test_dns_resolution("nonexistent.example.com")
            assert result == False


class TestCVEMatcher:
    """Test CVE matching functionality."""
    
    def test_matcher_initialization(self):
        """Test matcher initialization."""
        import cve_matcher
        
        matcher = cve_matcher.CVEMatcher()
        assert len(matcher.cve_database) > 0
        assert "printers" in matcher.cve_database
        assert "routers" in matcher.cve_database
    
    def test_parse_version(self):
        """Test version parsing."""
        import cve_matcher
        
        matcher = cve_matcher.CVEMatcher()
        
        # Test various version formats
        assert matcher.parse_version("1.2.3") == (1, 2, 3)
        assert matcher.parse_version("v2.0.1") == (2, 0, 1)
        assert matcher.parse_version("V3.1") == (3, 1)
    
    def test_is_version_affected(self):
        """Test version affected checking."""
        import cve_matcher
        
        matcher = cve_matcher.CVEMatcher()
        
        # Test less than comparison
        assert matcher.is_version_affected("2.0", "<3.0") == True
        assert matcher.is_version_affected("4.0", "<3.0") == False
        
        # Test 'all' versions
        assert matcher.is_version_affected("1.0", "all") == True
    
    def test_match_cves(self):
        """Test CVE matching for devices."""
        import cve_matcher
        
        matcher = cve_matcher.CVEMatcher()
        
        # Test device with vulnerable firmware
        device_info = {
            "ip": "192.168.1.100",
            "device_type": "printers",
            "firmware_version": "2.0"
        }
        
        matches = matcher.match_cves(device_info)
        assert isinstance(matches, list)


class TestAgingScorer:
    """Test device aging scorer."""
    
    def test_scorer_initialization(self):
        """Test scorer initialization."""
        import aging_scorer
        
        scorer = aging_scorer.DeviceAgingScorer()
        assert len(scorer.deprecated_protocols) > 0
        assert len(scorer.weak_ciphers) > 0
        assert "SSLv3" in scorer.deprecated_protocols
        assert "RC4" in scorer.weak_ciphers
    
    def test_firmware_age_score(self):
        """Test firmware age scoring."""
        import aging_scorer
        
        scorer = aging_scorer.DeviceAgingScorer()
        
        # Test different age ranges
        assert scorer.calculate_firmware_age_score(30) == 0    # 1 month
        assert scorer.calculate_firmware_age_score(200) == 10  # 6+ months
        assert scorer.calculate_firmware_age_score(400) == 20  # 1+ year
        assert scorer.calculate_firmware_age_score(800) == 30  # 2+ years
        assert scorer.calculate_firmware_age_score(1200) == 40 # 3+ years
    
    def test_protocol_score(self):
        """Test protocol scoring."""
        import aging_scorer
        
        scorer = aging_scorer.DeviceAgingScorer()
        
        # Test with deprecated protocols
        protocols = ["TLSv1.0", "SSLv3"]
        score = scorer.calculate_protocol_score(protocols)
        assert score > 0
        assert score <= 30
        
        # Test with modern protocols
        protocols = ["TLSv1.3"]
        score = scorer.calculate_protocol_score(protocols)
        assert score == 0
    
    def test_cipher_score(self):
        """Test cipher scoring."""
        import aging_scorer
        
        scorer = aging_scorer.DeviceAgingScorer()
        
        # Test with weak ciphers
        ciphers = ["RC4", "3DES"]
        score = scorer.calculate_cipher_score(ciphers)
        assert score > 0
        assert score <= 20
    
    def test_overall_score(self):
        """Test overall aging score calculation."""
        import aging_scorer
        
        scorer = aging_scorer.DeviceAgingScorer()
        
        # Test high-risk device
        device = {
            "firmware_age_days": 1200,
            "protocols": ["SSLv3", "TLSv1.0"],
            "ciphers": ["RC4", "3DES"],
            "vendor_support_status": "EOL",
            "patches_behind": 10
        }
        
        result = scorer.calculate_overall_score(device)
        
        assert "total_score" in result
        assert "risk_level" in result
        assert result["total_score"] > 50  # Should be high risk
        assert result["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class TestPatchCadenceIntegration:
    """Integration tests for patch cadence module."""
    
    def test_patch_scan_script_exists(self):
        """Test that main scan script exists and is executable."""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'patch-cadence', 'patch_scan.sh')
        
        assert os.path.exists(script_path)
        assert os.access(script_path, os.X_OK)
    
    def test_all_python_scripts_executable(self):
        """Test that all Python scripts are executable."""
        scripts = [
            'firmware_fingerprinter.py',
            'update_reachability.py',
            'cve_matcher.py',
            'aging_scorer.py'
        ]
        
        for script in scripts:
            script_path = os.path.join(os.path.dirname(__file__), '..', 'patch-cadence', script)
            assert os.path.exists(script_path), f"{script} does not exist"
            assert os.access(script_path, os.X_OK), f"{script} is not executable"
