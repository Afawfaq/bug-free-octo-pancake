"""
Unit tests for the WiFi Attacks module.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock, mock_open

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'wifi-attacks'))


class TestSpectrumScanner:
    """Test spectrum scanner functionality."""
    
    def test_scanner_initialization(self):
        """Test scanner initialization."""
        import spectrum_scanner
        
        scanner = spectrum_scanner.SpectrumScanner("wlan0")
        assert scanner.interface == "wlan0"
        assert scanner.networks == []
    
    def test_analyze_spectrum(self):
        """Test spectrum analysis."""
        import spectrum_scanner
        
        scanner = spectrum_scanner.SpectrumScanner()
        
        networks = [
            {'band': '2.4GHz', 'channel': 6, 'encryption': 'WPA2', 'essid': 'TestNet1'},
            {'band': '2.4GHz', 'channel': 6, 'encryption': 'WPA2', 'essid': 'TestNet2'},
            {'band': '5GHz', 'channel': 36, 'encryption': 'WPA3', 'essid': 'TestNet3'},
            {'band': '2.4GHz', 'channel': 11, 'encryption': 'Open', 'essid': 'Hidden'}
        ]
        
        analysis = scanner.analyze_spectrum(networks)
        
        assert analysis['total_networks'] == 4
        assert analysis['band_distribution']['2.4GHz']['count'] == 3
        assert analysis['band_distribution']['5GHz']['count'] == 1
        assert analysis['encryption_distribution']['WPA2'] == 2
        assert analysis['most_congested_24ghz'] == 6


class TestPMKIDHarvester:
    """Test PMKID harvester functionality."""
    
    def test_harvester_initialization(self):
        """Test harvester initialization."""
        import pmkid_harvester
        
        harvester = pmkid_harvester.PMKIDHarvester("wlan0")
        assert harvester.interface == "wlan0"
        assert harvester.pmkids == []
    
    def test_check_tools(self):
        """Test tool availability checking."""
        import pmkid_harvester
        
        harvester = pmkid_harvester.PMKIDHarvester()
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            tools = harvester.check_tools()
            
            assert 'hcxdumptool' in tools
            assert 'hcxpcapngtool' in tools
    
    def test_harvest_pmkids_no_tools(self):
        """Test PMKID harvesting without tools."""
        import pmkid_harvester
        
        harvester = pmkid_harvester.PMKIDHarvester()
        
        with patch.object(harvester, 'check_tools', return_value={'hcxdumptool': False}):
            result = harvester.harvest_pmkids(60)
            
            assert result['success'] == False
            assert 'note' in result


class TestWPSAttacker:
    """Test WPS attacker functionality."""
    
    def test_attacker_initialization(self):
        """Test attacker initialization."""
        import wps_attacker
        
        attacker = wps_attacker.WPSAttacker("wlan0")
        assert attacker.interface == "wlan0"
    
    def test_check_wps_tools(self):
        """Test WPS tool checking."""
        import wps_attacker
        
        attacker = wps_attacker.WPSAttacker()
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Tool not found")
            tools = attacker.check_wps_tools()
            
            assert 'wash' in tools
            assert 'reaver' in tools
            assert 'bully' in tools
    
    def test_analyze_wps_security(self):
        """Test WPS security analysis."""
        import wps_attacker
        
        attacker = wps_attacker.WPSAttacker()
        
        networks = [
            {'bssid': '00:11:22:33:44:55', 'wps_locked': False},
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'wps_locked': True}
        ]
        
        analysis = attacker.analyze_wps_security(networks)
        
        assert analysis['total_wps_networks'] == 2
        assert 'security_recommendations' in analysis


class TestEvilTwinAnalyzer:
    """Test evil twin analyzer functionality."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        import evil_twin_analyzer
        
        analyzer = evil_twin_analyzer.EvilTwinAnalyzer()
        assert analyzer.analysis == {}
    
    def test_analyze_channel_utilization(self):
        """Test channel utilization analysis."""
        import evil_twin_analyzer
        
        analyzer = evil_twin_analyzer.EvilTwinAnalyzer()
        
        networks = [
            {'channel': 6},
            {'channel': 6},
            {'channel': 11},
            {'channel': 36},
            {'channel': 36},
            {'channel': 36}
        ]
        
        analysis = analyzer.analyze_channel_utilization(networks)
        
        assert 'channel_utilization' in analysis
        assert analysis['channel_utilization'][6] == 2
        assert analysis['channel_utilization'][36] == 3
        assert 'optimal_24ghz_channels' in analysis
        assert 'optimal_5ghz_channels' in analysis
    
    def test_analyze_encryption(self):
        """Test encryption analysis."""
        import evil_twin_analyzer
        
        analyzer = evil_twin_analyzer.EvilTwinAnalyzer()
        
        networks = [
            {'encryption': 'WPA2'},
            {'encryption': 'WPA2'},
            {'encryption': 'Open'},
            {'encryption': 'WPA3'}
        ]
        
        analysis = analyzer.analyze_encryption(networks)
        
        assert analysis['encryption_distribution']['WPA2'] == 2
        assert analysis['encryption_distribution']['Open'] == 1
        assert len(analysis['potential_vulnerabilities']) > 0
    
    def test_generate_recommendations(self):
        """Test recommendation generation."""
        import evil_twin_analyzer
        
        analyzer = evil_twin_analyzer.EvilTwinAnalyzer()
        recommendations = analyzer.generate_recommendations()
        
        assert len(recommendations) > 0
        assert any('verify network names' in r.lower() for r in recommendations)


class TestBLEScanner:
    """Test BLE scanner functionality."""
    
    def test_scanner_initialization(self):
        """Test scanner initialization."""
        import ble_scanner
        
        scanner = ble_scanner.BLEScanner()
        assert scanner.devices == []
    
    def test_check_bluetooth(self):
        """Test Bluetooth checking."""
        import ble_scanner
        
        scanner = ble_scanner.BLEScanner()
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = 'hci0: Type: Primary'
            result = scanner.check_bluetooth()
            assert result == True
    
    def test_analyze_ble_security(self):
        """Test BLE security analysis."""
        import ble_scanner
        
        scanner = ble_scanner.BLEScanner()
        
        devices = [
            {'address': '00:11:22:33:44:55', 'name': 'Device1', 'type': 'BLE'},
            {'address': 'AA:BB:CC:DD:EE:FF', 'name': 'Unknown', 'type': 'BLE'},
            {'address': '11:22:33:44:55:66', 'name': 'Unknown', 'type': 'BLE'}
        ]
        
        analysis = scanner.analyze_ble_security(devices)
        
        assert analysis['total_devices'] == 3
        assert analysis['unnamed_devices'] == 2
        assert 'security_concerns' in analysis
        assert 'recommendations' in analysis


class TestWiFiIntegration:
    """Integration tests for WiFi attacks module."""
    
    def test_wifi_scan_script_exists(self):
        """Test that main scan script exists and is executable."""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'wifi-attacks', 'wifi_scan.sh')
        
        assert os.path.exists(script_path)
        assert os.access(script_path, os.X_OK)
    
    def test_all_python_scripts_executable(self):
        """Test that all Python scripts are executable."""
        scripts = [
            'spectrum_scanner.py',
            'pmkid_harvester.py',
            'wps_attacker.py',
            'evil_twin_analyzer.py',
            'ble_scanner.py'
        ]
        
        for script in scripts:
            script_path = os.path.join(os.path.dirname(__file__), '..', 'wifi-attacks', script)
            assert os.path.exists(script_path), f"{script} does not exist"
            assert os.access(script_path, os.X_OK), f"{script} is not executable"
