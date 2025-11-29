"""
Unit tests for the Orchestrator module.
"""

import os
import sys
import json
import pytest
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'orchestrator'))


class TestOrchestratorInitialization:
    """Test orchestrator initialization and configuration."""
    
    def test_default_configuration(self):
        """Test that default configuration values are set correctly."""
        # Set up mock environment
        with patch.dict(os.environ, {}, clear=True):
            # Import after environment is set
            from run import ReconOrchestrator
            
            orchestrator = ReconOrchestrator()
            
            assert orchestrator.target_network == "192.168.68.0/24"
            assert orchestrator.router_ip == "192.168.68.1"
            assert orchestrator.passive_duration == 30
            assert orchestrator.parallel_execution == True
    
    def test_custom_configuration(self):
        """Test that custom environment variables override defaults."""
        custom_env = {
            "TARGET_NETWORK": "10.0.0.0/24",
            "ROUTER_IP": "10.0.0.1",
            "PASSIVE_DURATION": "60",
            "PARALLEL_EXECUTION": "false",
            "VERBOSE": "true"
        }
        
        with patch.dict(os.environ, custom_env, clear=True):
            from run import ReconOrchestrator
            
            # Need to reimport to pick up new env vars
            import importlib
            import run
            importlib.reload(run)
            
            orchestrator = run.ReconOrchestrator()
            
            assert orchestrator.target_network == "10.0.0.0/24"
            assert orchestrator.router_ip == "10.0.0.1"
            assert orchestrator.passive_duration == 60
            assert orchestrator.parallel_execution == False
            assert orchestrator.verbose == True


class TestOrchestratorLogging:
    """Test the logging functionality."""
    
    def test_log_output_format(self, capsys):
        """Test that log output has correct format."""
        with patch.dict(os.environ, {}, clear=True):
            from run import ReconOrchestrator
            
            orchestrator = ReconOrchestrator()
            orchestrator.log("Test message", "INFO")
            
            captured = capsys.readouterr()
            assert "Test message" in captured.out
            assert "INFO" in captured.out


class TestContainerHealthCheck:
    """Test container health checking functionality."""
    
    def test_check_container_health_success(self):
        """Test successful container health check."""
        with patch.dict(os.environ, {}, clear=True):
            from run import ReconOrchestrator
            
            orchestrator = ReconOrchestrator()
            
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="true\n"
                )
                
                result = orchestrator.check_container_health("test-container")
                assert result == True
    
    def test_check_container_health_failure(self):
        """Test failed container health check."""
        with patch.dict(os.environ, {}, clear=True):
            from run import ReconOrchestrator
            
            orchestrator = ReconOrchestrator()
            
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1,
                    stdout=""
                )
                
                result = orchestrator.check_container_health("test-container")
                assert result == False


class TestPhaseStatistics:
    """Test phase execution statistics."""
    
    def test_phase_stats_initialization(self):
        """Test that phase stats are properly initialized."""
        with patch.dict(os.environ, {}, clear=True):
            from run import ReconOrchestrator
            
            orchestrator = ReconOrchestrator()
            
            assert orchestrator.phase_stats == {}
            assert orchestrator.errors == []


class TestExecutionStatsExport:
    """Test execution statistics export functionality."""
    
    def test_save_execution_stats(self, tmp_path):
        """Test saving execution statistics to JSON."""
        with patch.dict(os.environ, {}, clear=True):
            from run import ReconOrchestrator
            
            orchestrator = ReconOrchestrator()
            orchestrator.output_dir = str(tmp_path)
            orchestrator.phase_stats = {
                "phase_1": {"name": "Test Phase", "success": True, "duration": 10.5}
            }
            
            orchestrator.save_execution_stats(100.0)
            
            stats_file = tmp_path / "execution_stats.json"
            assert stats_file.exists()
            
            with open(stats_file) as f:
                stats = json.load(f)
            
            assert stats["version"] == ReconOrchestrator.VERSION
            assert stats["total_duration_seconds"] == 100.0
            assert "phase_1" in stats["phases"]


class TestColors:
    """Test the Colors utility class."""
    
    def test_color_codes_exist(self):
        """Test that color codes are defined."""
        from run import Colors
        
        assert hasattr(Colors, 'HEADER')
        assert hasattr(Colors, 'BLUE')
        assert hasattr(Colors, 'GREEN')
        assert hasattr(Colors, 'WARNING')
        assert hasattr(Colors, 'FAIL')
        assert hasattr(Colors, 'ENDC')


# Integration tests (require Docker)
class TestDockerIntegration:
    """Integration tests that require Docker."""
    
    @pytest.mark.skipif(
        os.system("docker --version > /dev/null 2>&1") != 0,
        reason="Docker not available"
    )
    def test_docker_compose_validation(self):
        """Test that docker-compose.yml is valid."""
        import subprocess
        
        result = subprocess.run(
            ["docker", "compose", "config", "--quiet"],
            capture_output=True,
            text=True,
            cwd=os.path.join(os.path.dirname(__file__), '..')
        )
        
        assert result.returncode == 0, f"docker-compose validation failed: {result.stderr}"
