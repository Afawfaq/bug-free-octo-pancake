"""
Unit tests for the Data Flow module.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock, mock_open
from collections import Counter

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'data-flow'))


class TestTrafficBaselineBuilder:
    """Test traffic baseline builder functionality."""
    
    def test_baseline_builder_initialization(self):
        """Test baseline builder initialization."""
        import traffic_baseline
        
        builder = traffic_baseline.TrafficBaselineBuilder()
        assert len(builder.device_profiles) == 0
        assert len(builder.last_packet_time) == 0
    
    def test_calculate_statistics(self):
        """Test statistics calculation."""
        import traffic_baseline
        
        builder = traffic_baseline.TrafficBaselineBuilder()
        
        # Simulate device profile
        builder.device_profiles['192.168.1.100'] = {
            'total_packets': 100,
            'bytes_sent': 50000,
            'bytes_received': 30000,
            'destinations': Counter({'192.168.1.1': 50, '192.168.1.2': 30}),
            'protocols': Counter({'TCP': 80, 'UDP': 20}),
            'ports': Counter({80: 40, 443: 40}),
            'packet_sizes': [100, 200, 150] * 10,
            'inter_arrival_times': [0.1, 0.2, 0.15] * 10,
            'first_seen': 1000.0,
            'last_seen': 1100.0
        }
        
        baselines = builder.calculate_statistics()
        
        assert '192.168.1.100' in baselines
        assert baselines['192.168.1.100']['total_packets'] == 100
        assert baselines['192.168.1.100']['bytes_sent'] == 50000
        assert baselines['192.168.1.100']['avg_packet_size'] > 0
        assert baselines['192.168.1.100']['packets_per_second'] > 0


class TestChatterFingerprinter:
    """Test chatter fingerprinter functionality."""
    
    def test_fingerprinter_initialization(self):
        """Test fingerprinter initialization."""
        import chatter_fingerprinter
        
        fp = chatter_fingerprinter.ChatterFingerprinter()
        assert fp.patterns == {}
    
    def test_analyze_destination_patterns(self):
        """Test destination pattern analysis."""
        import chatter_fingerprinter
        
        fp = chatter_fingerprinter.ChatterFingerprinter()
        
        baseline = {
            'top_destinations': {'192.168.1.1': 50, '192.168.1.2': 30},
            'destination_diversity': 0.5
        }
        
        patterns = fp.analyze_destination_patterns(baseline)
        
        assert 'communication_style' in patterns
        assert 'primary_destinations' in patterns
        assert patterns['communication_style'] == 'moderate'
    
    def test_analyze_protocol_behavior(self):
        """Test protocol behavior analysis."""
        import chatter_fingerprinter
        
        fp = chatter_fingerprinter.ChatterFingerprinter()
        
        baseline = {
            'protocol_mix': {'TCP': 0.8, 'UDP': 0.2},
            'top_ports': {80: 40, 443: 40, 631: 20}
        }
        
        behavior = fp.analyze_protocol_behavior(baseline)
        
        assert 'primary_protocol' in behavior
        assert behavior['primary_protocol'] == 'TCP'
        assert 'IPP' in behavior['common_services']


class TestAnomalyDetector:
    """Test anomaly detector functionality."""
    
    def test_detector_initialization(self):
        """Test detector initialization."""
        import anomaly_detector
        
        baseline_data = {'baselines': {}}
        detector = anomaly_detector.AnomalyDetector(baseline_data)
        
        assert detector.baselines == {}
        assert detector.anomalies == []
    
    def test_detect_traffic_volume_anomaly(self):
        """Test traffic volume anomaly detection."""
        import anomaly_detector
        
        baseline_data = {
            'baselines': {
                '192.168.1.100': {
                    'packets_per_second': 10.0
                }
            }
        }
        
        detector = anomaly_detector.AnomalyDetector(baseline_data)
        
        # Test traffic spike
        current_fingerprint = {
            'traffic_characteristics': {
                'packets_per_second': 35.0
            }
        }
        
        anomalies = detector.detect_traffic_volume_anomaly(current_fingerprint, '192.168.1.100')
        
        assert len(anomalies) > 0
        assert anomalies[0]['type'] == 'TRAFFIC_SPIKE'
        assert anomalies[0]['severity'] == 'HIGH'
    
    def test_detect_beaconing_pattern(self):
        """Test beaconing pattern detection."""
        import anomaly_detector
        
        baseline_data = {'baselines': {}}
        detector = anomaly_detector.AnomalyDetector(baseline_data)
        
        # Simulate beaconing pattern
        current_fingerprint = {
            'destination_patterns': {
                'communication_style': 'focused'
            },
            'traffic_characteristics': {
                'packets_per_second': 0.5,
                'avg_packet_size': 150
            }
        }
        
        anomalies = detector.detect_beaconing_pattern(current_fingerprint, '192.168.1.100')
        
        assert len(anomalies) > 0
        assert anomalies[0]['type'] == 'POSSIBLE_BEACONING'
        assert anomalies[0]['severity'] == 'CRITICAL'


class TestFlowGraphBuilder:
    """Test flow graph builder functionality."""
    
    def test_graph_builder_initialization(self):
        """Test graph builder initialization."""
        import flow_graph_builder
        
        builder = flow_graph_builder.FlowGraphBuilder()
        
        assert len(builder.graph.nodes) == 0
        assert len(builder.graph.edges) == 0
        assert len(builder.anomalous_connections) == 0
    
    def test_build_graph(self):
        """Test graph building."""
        import flow_graph_builder
        
        builder = flow_graph_builder.FlowGraphBuilder()
        
        baselines = {
            '192.168.1.100': {
                'total_packets': 100,
                'bytes_sent': 50000,
                'top_destinations': {'192.168.1.1': 50}
            },
            '192.168.1.1': {
                'total_packets': 50,
                'bytes_sent': 25000,
                'top_destinations': {}
            }
        }
        
        anomalies = []
        
        builder.build_graph(baselines, anomalies)
        
        assert len(builder.graph.nodes) == 2
        assert builder.graph.has_node('192.168.1.100')
        assert builder.graph.has_node('192.168.1.1')
    
    def test_generate_graph_data(self):
        """Test graph data generation."""
        import flow_graph_builder
        
        builder = flow_graph_builder.FlowGraphBuilder()
        
        baselines = {
            '192.168.1.100': {
                'total_packets': 100,
                'bytes_sent': 50000,
                'top_destinations': {'192.168.1.1': 50}
            }
        }
        
        builder.build_graph(baselines, [])
        graph_data = builder.generate_graph_data()
        
        assert 'nodes' in graph_data
        assert 'edges' in graph_data
        assert 'statistics' in graph_data
        assert graph_data['statistics']['total_nodes'] > 0


class TestTimeSeriesAnalyzer:
    """Test time series analyzer functionality."""
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        import time_series_analyzer
        
        analyzer = time_series_analyzer.TimeSeriesAnalyzer()
        assert analyzer.time_series_data == []
    
    def test_analyze_temporal_patterns(self):
        """Test temporal pattern analysis."""
        import time_series_analyzer
        
        analyzer = time_series_analyzer.TimeSeriesAnalyzer()
        
        baseline = {
            'first_seen': '2025-12-08T03:00:00',
            'last_seen': '2025-12-08T04:00:00',
            'packets_per_second': 5.0,
            'total_packets': 18000
        }
        
        analysis = analyzer.analyze_temporal_patterns(baseline, '192.168.1.100')
        
        assert 'device_ip' in analysis
        assert 'activity_window' in analysis
        assert 'patterns' in analysis


class TestDataFlowIntegration:
    """Integration tests for data flow module."""
    
    def test_data_flow_scan_script_exists(self):
        """Test that main scan script exists and is executable."""
        script_path = os.path.join(os.path.dirname(__file__), '..', 'data-flow', 'data_flow_scan.sh')
        
        assert os.path.exists(script_path)
        assert os.access(script_path, os.X_OK)
    
    def test_all_python_scripts_executable(self):
        """Test that all Python scripts are executable."""
        scripts = [
            'traffic_baseline.py',
            'chatter_fingerprinter.py',
            'anomaly_detector.py',
            'flow_graph_builder.py',
            'time_series_analyzer.py'
        ]
        
        for script in scripts:
            script_path = os.path.join(os.path.dirname(__file__), '..', 'data-flow', script)
            assert os.path.exists(script_path), f"{script} does not exist"
            assert os.access(script_path, os.X_OK), f"{script} is not executable"
