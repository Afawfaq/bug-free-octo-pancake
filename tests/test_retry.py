"""
Unit tests for the Retry and Recovery module.
"""

import os
import json
import time
import pytest
import tempfile
from unittest.mock import patch, MagicMock


class TestRetryStrategy:
    """Test RetryStrategy enum."""
    
    def test_retry_strategies_exist(self):
        """Test that all retry strategies are defined."""
        from retry import RetryStrategy
        
        assert RetryStrategy.FIXED.value == "fixed"
        assert RetryStrategy.LINEAR.value == "linear"
        assert RetryStrategy.EXPONENTIAL.value == "exponential"
        assert RetryStrategy.EXPONENTIAL_JITTER.value == "exponential_jitter"


class TestCircuitState:
    """Test CircuitState enum."""
    
    def test_circuit_states_exist(self):
        """Test that all circuit states are defined."""
        from retry import CircuitState
        
        assert CircuitState.CLOSED.value == "closed"
        assert CircuitState.OPEN.value == "open"
        assert CircuitState.HALF_OPEN.value == "half_open"


class TestRetryError:
    """Test RetryError exception."""
    
    def test_retry_error_creation(self):
        """Test creating a RetryError."""
        from retry import RetryError
        
        original = ValueError("Original error")
        error = RetryError("All retries failed", last_exception=original)
        
        assert str(error) == "All retries failed"
        assert error.last_exception == original


class TestCircuitBreakerOpen:
    """Test CircuitBreakerOpen exception."""
    
    def test_circuit_breaker_open_creation(self):
        """Test creating a CircuitBreakerOpen exception."""
        from retry import CircuitBreakerOpen
        
        error = CircuitBreakerOpen("Circuit is open")
        
        assert str(error) == "Circuit is open"


class TestRetryHandlerInitialization:
    """Test RetryHandler initialization."""
    
    def test_default_initialization(self):
        """Test default RetryHandler initialization."""
        from retry import RetryHandler, RetryStrategy
        
        handler = RetryHandler()
        
        assert handler.max_retries == 3
        assert handler.strategy == RetryStrategy.EXPONENTIAL
        assert handler.base_delay == 1.0
        assert handler.max_delay == 60.0
    
    def test_custom_initialization(self):
        """Test custom RetryHandler initialization."""
        from retry import RetryHandler, RetryStrategy
        
        handler = RetryHandler(
            max_retries=5,
            strategy=RetryStrategy.LINEAR,
            base_delay=2.0,
            max_delay=30.0
        )
        
        assert handler.max_retries == 5
        assert handler.strategy == RetryStrategy.LINEAR
        assert handler.base_delay == 2.0
        assert handler.max_delay == 30.0


class TestDelayCalculation:
    """Test delay calculation methods."""
    
    def test_fixed_delay(self):
        """Test fixed delay calculation."""
        from retry import RetryHandler, RetryStrategy
        
        handler = RetryHandler(strategy=RetryStrategy.FIXED, base_delay=5.0)
        
        assert handler._calculate_delay(1) == 5.0
        assert handler._calculate_delay(2) == 5.0
        assert handler._calculate_delay(3) == 5.0
    
    def test_linear_delay(self):
        """Test linear delay calculation."""
        from retry import RetryHandler, RetryStrategy
        
        handler = RetryHandler(strategy=RetryStrategy.LINEAR, base_delay=2.0)
        
        assert handler._calculate_delay(1) == 2.0
        assert handler._calculate_delay(2) == 4.0
        assert handler._calculate_delay(3) == 6.0
    
    def test_exponential_delay(self):
        """Test exponential delay calculation."""
        from retry import RetryHandler, RetryStrategy
        
        handler = RetryHandler(strategy=RetryStrategy.EXPONENTIAL, base_delay=1.0)
        
        assert handler._calculate_delay(1) == 1.0
        assert handler._calculate_delay(2) == 2.0
        assert handler._calculate_delay(3) == 4.0
        assert handler._calculate_delay(4) == 8.0
    
    def test_delay_capped_at_max(self):
        """Test that delay is capped at max_delay."""
        from retry import RetryHandler, RetryStrategy
        
        handler = RetryHandler(
            strategy=RetryStrategy.EXPONENTIAL,
            base_delay=10.0,
            max_delay=25.0
        )
        
        assert handler._calculate_delay(5) == 25.0  # Would be 160 without cap
    
    def test_exponential_jitter_delay(self):
        """Test exponential with jitter delay calculation."""
        from retry import RetryHandler, RetryStrategy
        
        handler = RetryHandler(strategy=RetryStrategy.EXPONENTIAL_JITTER, base_delay=1.0)
        
        # Jitter adds randomness, so check range
        delay = handler._calculate_delay(3)
        # Base exponential would be 4.0, jitter multiplies by 0.5-1.5
        assert 2.0 <= delay <= 6.0


class TestRetryExecution:
    """Test retry execution."""
    
    def test_successful_execution(self):
        """Test successful execution without retries."""
        from retry import RetryHandler
        
        handler = RetryHandler(max_retries=3, base_delay=0.01)
        
        def success_func():
            return "success"
        
        result = handler.execute(success_func)
        
        assert result == "success"
    
    def test_retry_on_failure(self):
        """Test retrying on failure."""
        from retry import RetryHandler, RetryError
        
        handler = RetryHandler(max_retries=2, base_delay=0.01)
        
        call_count = 0
        
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        result = handler.execute(flaky_func)
        
        assert result == "success"
        assert call_count == 3  # Initial + 2 retries
    
    def test_all_retries_exhausted(self):
        """Test when all retries are exhausted."""
        from retry import RetryHandler, RetryError
        
        handler = RetryHandler(max_retries=2, base_delay=0.01)
        
        def always_fails():
            raise ValueError("Always fails")
        
        with pytest.raises(RetryError) as exc_info:
            handler.execute(always_fails)
        
        assert "Failed after" in str(exc_info.value)
        assert isinstance(exc_info.value.last_exception, ValueError)
    
    def test_non_retryable_exception(self):
        """Test that non-retryable exceptions are not retried."""
        from retry import RetryHandler, RetryError
        
        handler = RetryHandler(
            max_retries=3,
            base_delay=0.01,
            retryable_exceptions=[ConnectionError]
        )
        
        call_count = 0
        
        def raises_value_error():
            nonlocal call_count
            call_count += 1
            raise ValueError("Non-retryable")
        
        with pytest.raises(RetryError):
            handler.execute(raises_value_error)
        
        # Should only be called once since ValueError is not retryable
        assert call_count == 1
    
    def test_on_retry_callback(self):
        """Test that on_retry callback is called."""
        from retry import RetryHandler
        
        callback_calls = []
        
        def on_retry(attempt, delay, exception):
            callback_calls.append((attempt, delay, str(exception)))
        
        handler = RetryHandler(max_retries=2, base_delay=0.01, on_retry=on_retry)
        
        call_count = 0
        
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        handler.execute(flaky_func)
        
        assert len(callback_calls) == 2  # Two retries


class TestRetryDecorator:
    """Test the retry_with_backoff decorator."""
    
    def test_decorator_success(self):
        """Test decorator with successful function."""
        from retry import retry_with_backoff
        
        @retry_with_backoff(max_retries=3, base_delay=0.01)
        def success_func():
            return "decorated_success"
        
        result = success_func()
        
        assert result == "decorated_success"
    
    def test_decorator_retry(self):
        """Test decorator with retrying function."""
        from retry import retry_with_backoff
        
        call_count = 0
        
        @retry_with_backoff(max_retries=2, base_delay=0.01)
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary")
            return "success"
        
        result = flaky_func()
        
        assert result == "success"
        assert call_count == 3


class TestCircuitBreakerInitialization:
    """Test CircuitBreaker initialization."""
    
    def test_default_initialization(self):
        """Test default CircuitBreaker initialization."""
        from retry import CircuitBreaker, CircuitState
        
        cb = CircuitBreaker()
        
        assert cb.failure_threshold == 5
        assert cb.recovery_timeout == 30.0
        assert cb.state == CircuitState.CLOSED
    
    def test_custom_initialization(self):
        """Test custom CircuitBreaker initialization."""
        from retry import CircuitBreaker
        
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)
        
        assert cb.failure_threshold == 3
        assert cb.recovery_timeout == 10.0


class TestCircuitBreakerBehavior:
    """Test CircuitBreaker behavior."""
    
    def test_circuit_opens_after_failures(self):
        """Test that circuit opens after reaching failure threshold."""
        from retry import CircuitBreaker, CircuitState, CircuitBreakerOpen
        
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=60.0)
        
        def failing_func():
            raise ValueError("Failure")
        
        # Cause failures
        for _ in range(3):
            try:
                cb.call(failing_func)
            except ValueError:
                pass
        
        assert cb.state == CircuitState.OPEN
        
        # Next call should raise CircuitBreakerOpen
        with pytest.raises(CircuitBreakerOpen):
            cb.call(failing_func)
    
    def test_circuit_resets_on_success(self):
        """Test that circuit resets on success."""
        from retry import CircuitBreaker, CircuitState
        
        cb = CircuitBreaker(failure_threshold=3)
        
        def success_func():
            return "success"
        
        # Cause some failures but not enough to open
        def failing_func():
            raise ValueError("Failure")
        
        for _ in range(2):
            try:
                cb.call(failing_func)
            except ValueError:
                pass
        
        # Success should reset failure count
        cb.call(success_func)
        
        assert cb.state == CircuitState.CLOSED
        assert cb._failures == 0
    
    def test_circuit_half_open_after_timeout(self):
        """Test circuit transitions to half-open after timeout."""
        from retry import CircuitBreaker, CircuitState
        
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        def failing_func():
            raise ValueError("Failure")
        
        # Open the circuit
        for _ in range(2):
            try:
                cb.call(failing_func)
            except ValueError:
                pass
        
        assert cb.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        assert cb.state == CircuitState.HALF_OPEN
    
    def test_circuit_manual_reset(self):
        """Test manual circuit reset."""
        from retry import CircuitBreaker, CircuitState
        
        cb = CircuitBreaker(failure_threshold=2)
        
        def failing_func():
            raise ValueError("Failure")
        
        # Open the circuit
        for _ in range(2):
            try:
                cb.call(failing_func)
            except ValueError:
                pass
        
        assert cb.state == CircuitState.OPEN
        
        # Manual reset
        cb.reset()
        
        assert cb.state == CircuitState.CLOSED
        assert cb._failures == 0


class TestCheckpointManager:
    """Test CheckpointManager functionality."""
    
    @pytest.fixture
    def checkpoint_manager(self, tmp_path):
        """Create a CheckpointManager with temporary directory."""
        from retry import CheckpointManager
        return CheckpointManager(checkpoint_dir=str(tmp_path))
    
    def test_save_checkpoint(self, checkpoint_manager):
        """Test saving a checkpoint."""
        checkpoint_manager.save_checkpoint(
            scan_id="test_scan",
            phase="discovery",
            completed_targets=["192.168.1.1", "192.168.1.2"],
            partial_results={"hosts_found": 2},
            metadata={"start_time": "2025-01-01T00:00:00"}
        )
        
        # Check file exists
        checkpoint_path = checkpoint_manager._get_checkpoint_path("test_scan")
        assert os.path.exists(checkpoint_path)
    
    def test_load_checkpoint(self, checkpoint_manager):
        """Test loading a checkpoint."""
        # Save first
        checkpoint_manager.save_checkpoint(
            scan_id="test_scan",
            phase="fingerprint",
            completed_targets=["192.168.1.1"],
            partial_results={"services": ["http", "ssh"]}
        )
        
        # Load
        checkpoint = checkpoint_manager.load_checkpoint("test_scan")
        
        assert checkpoint is not None
        assert checkpoint["scan_id"] == "test_scan"
        assert checkpoint["phase"] == "fingerprint"
        assert "192.168.1.1" in checkpoint["completed_targets"]
    
    def test_load_nonexistent_checkpoint(self, checkpoint_manager):
        """Test loading a non-existent checkpoint."""
        result = checkpoint_manager.load_checkpoint("nonexistent")
        
        assert result is None
    
    def test_delete_checkpoint(self, checkpoint_manager):
        """Test deleting a checkpoint."""
        # Save first
        checkpoint_manager.save_checkpoint(
            scan_id="to_delete",
            phase="test",
            completed_targets=[],
            partial_results={}
        )
        
        # Verify it exists
        assert checkpoint_manager.load_checkpoint("to_delete") is not None
        
        # Delete
        checkpoint_manager.delete_checkpoint("to_delete")
        
        # Verify it's gone
        assert checkpoint_manager.load_checkpoint("to_delete") is None
    
    def test_list_checkpoints(self, checkpoint_manager):
        """Test listing all checkpoints."""
        # Create multiple checkpoints
        for i in range(3):
            checkpoint_manager.save_checkpoint(
                scan_id=f"scan_{i}",
                phase="test",
                completed_targets=[],
                partial_results={}
            )
        
        checkpoints = checkpoint_manager.list_checkpoints()
        
        assert len(checkpoints) == 3
        scan_ids = {cp["scan_id"] for cp in checkpoints}
        assert "scan_0" in scan_ids
        assert "scan_1" in scan_ids
        assert "scan_2" in scan_ids


class TestGracefulDegradation:
    """Test GracefulDegradation functionality."""
    
    def test_register_fallback(self):
        """Test registering a fallback handler."""
        from retry import GracefulDegradation
        
        gd = GracefulDegradation()
        
        def fallback():
            return "fallback_result"
        
        gd.register_fallback("test_service", fallback)
        
        assert "test_service" in gd.fallback_handlers
    
    def test_mark_degraded(self):
        """Test marking a service as degraded."""
        from retry import GracefulDegradation
        
        gd = GracefulDegradation()
        
        assert not gd.is_degraded("test_service")
        
        gd.mark_degraded("test_service")
        
        assert gd.is_degraded("test_service")
    
    def test_mark_recovered(self):
        """Test marking a service as recovered."""
        from retry import GracefulDegradation
        
        gd = GracefulDegradation()
        
        gd.mark_degraded("test_service")
        assert gd.is_degraded("test_service")
        
        gd.mark_recovered("test_service")
        assert not gd.is_degraded("test_service")
    
    def test_execute_with_fallback_primary_success(self):
        """Test execute_with_fallback when primary succeeds."""
        from retry import GracefulDegradation
        
        gd = GracefulDegradation()
        
        def primary():
            return "primary_result"
        
        def fallback():
            return "fallback_result"
        
        gd.register_fallback("test_service", fallback)
        
        result = gd.execute_with_fallback("test_service", primary)
        
        assert result == "primary_result"
    
    def test_execute_with_fallback_primary_fails(self):
        """Test execute_with_fallback when primary fails."""
        from retry import GracefulDegradation
        
        gd = GracefulDegradation()
        
        def primary():
            raise RuntimeError("Primary failed")
        
        def fallback():
            return "fallback_result"
        
        gd.register_fallback("test_service", fallback)
        
        result = gd.execute_with_fallback("test_service", primary)
        
        assert result == "fallback_result"
        assert gd.is_degraded("test_service")
    
    def test_execute_with_fallback_degraded_service(self):
        """Test execute_with_fallback when service is degraded."""
        from retry import GracefulDegradation
        
        gd = GracefulDegradation()
        
        primary_called = False
        
        def primary():
            nonlocal primary_called
            primary_called = True
            return "primary_result"
        
        def fallback():
            return "fallback_result"
        
        gd.register_fallback("test_service", fallback)
        gd.mark_degraded("test_service")
        
        result = gd.execute_with_fallback("test_service", primary)
        
        assert result == "fallback_result"
        assert not primary_called  # Primary should not be called
    
    def test_execute_with_fallback_no_fallback_raises(self):
        """Test execute_with_fallback raises when no fallback and service degraded."""
        from retry import GracefulDegradation
        
        gd = GracefulDegradation()
        gd.mark_degraded("test_service")
        
        def primary():
            return "primary_result"
        
        with pytest.raises(RuntimeError):
            gd.execute_with_fallback("test_service", primary)
