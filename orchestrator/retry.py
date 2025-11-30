#!/usr/bin/env python3
"""
Retry and Recovery System for LAN Reconnaissance Framework
==========================================================

Provides robust error handling, retry logic, and recovery mechanisms
for handling transient failures and ensuring scan reliability.

Features:
- Configurable retry strategies (exponential backoff, linear, fixed)
- Circuit breaker pattern for failing services
- Checkpoint/resume for long-running scans
- Graceful degradation

Usage:
    from retry import RetryHandler, retry_with_backoff
    
    @retry_with_backoff(max_retries=3)
    def scan_host(ip):
        ...
"""

import os
import json
import time
import functools
import threading
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List, Type
from enum import Enum
import random


class RetryStrategy(Enum):
    """Retry strategy types."""
    FIXED = "fixed"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    EXPONENTIAL_JITTER = "exponential_jitter"


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting calls
    HALF_OPEN = "half_open"  # Testing if recovered


class RetryError(Exception):
    """Exception raised when all retries are exhausted."""
    
    def __init__(self, message: str, last_exception: Optional[Exception] = None):
        super().__init__(message)
        self.last_exception = last_exception


class CircuitBreakerOpen(Exception):
    """Exception raised when circuit breaker is open."""
    pass


class RetryHandler:
    """
    Handles retry logic with configurable strategies.
    
    Supports:
    - Multiple retry strategies
    - Custom exception handling
    - Callbacks for retry events
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        strategy: RetryStrategy = RetryStrategy.EXPONENTIAL,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        retryable_exceptions: Optional[List[Type[Exception]]] = None,
        on_retry: Optional[Callable] = None
    ):
        """
        Initialize retry handler.
        
        Args:
            max_retries: Maximum number of retry attempts
            strategy: Retry delay strategy
            base_delay: Base delay in seconds
            max_delay: Maximum delay cap in seconds
            retryable_exceptions: Exceptions to retry on (default: all)
            on_retry: Callback function called on each retry
        """
        self.max_retries = max_retries
        self.strategy = strategy
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.retryable_exceptions = retryable_exceptions or [Exception]
        self.on_retry = on_retry
    
    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay based on strategy."""
        if self.strategy == RetryStrategy.FIXED:
            delay = self.base_delay
        elif self.strategy == RetryStrategy.LINEAR:
            delay = self.base_delay * attempt
        elif self.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.base_delay * (2 ** (attempt - 1))
        elif self.strategy == RetryStrategy.EXPONENTIAL_JITTER:
            delay = self.base_delay * (2 ** (attempt - 1))
            delay = delay * (0.5 + random.random())  # Add jitter
        else:
            delay = self.base_delay
        
        return min(delay, self.max_delay)
    
    def _is_retryable(self, exception: Exception) -> bool:
        """Check if exception is retryable."""
        return any(isinstance(exception, exc_type) for exc_type in self.retryable_exceptions)
    
    def execute(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with retry logic.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            RetryError: If all retries are exhausted
        """
        last_exception = None
        
        # Initial attempt + max_retries = total attempts
        total_attempts = self.max_retries + 1
        
        for attempt in range(1, total_attempts + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                # Check if we should retry
                is_last_attempt = (attempt >= total_attempts)
                if is_last_attempt or not self._is_retryable(e):
                    raise RetryError(
                        f"Failed after {attempt} attempts: {str(e)}",
                        last_exception=e
                    )
                
                delay = self._calculate_delay(attempt)
                
                if self.on_retry:
                    self.on_retry(attempt, delay, e)
                
                time.sleep(delay)
        
        raise RetryError(
            f"Failed after {self.max_retries} retries",
            last_exception=last_exception
        )


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_JITTER,
    retryable_exceptions: Optional[List[Type[Exception]]] = None
):
    """
    Decorator for adding retry logic to functions.
    
    Usage:
        @retry_with_backoff(max_retries=3)
        def my_function():
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            handler = RetryHandler(
                max_retries=max_retries,
                strategy=strategy,
                base_delay=base_delay,
                max_delay=max_delay,
                retryable_exceptions=retryable_exceptions
            )
            return handler.execute(func, *args, **kwargs)
        return wrapper
    return decorator


class CircuitBreaker:
    """
    Circuit breaker pattern implementation.
    
    Prevents repeated calls to failing services and allows
    them time to recover.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        expected_exceptions: Optional[List[Type[Exception]]] = None
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Time in seconds before attempting recovery
            expected_exceptions: Exceptions that count as failures
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exceptions = expected_exceptions or [Exception]
        
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._last_failure_time = None
        self._lock = threading.Lock()
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                # Check if recovery timeout has passed
                if self._last_failure_time:
                    elapsed = time.time() - self._last_failure_time
                    if elapsed >= self.recovery_timeout:
                        self._state = CircuitState.HALF_OPEN
            return self._state
    
    def _record_failure(self):
        """Record a failure."""
        with self._lock:
            self._failures += 1
            self._last_failure_time = time.time()
            
            if self._failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
    
    def _record_success(self):
        """Record a success."""
        with self._lock:
            self._failures = 0
            self._state = CircuitState.CLOSED
    
    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function through circuit breaker.
        
        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerOpen: If circuit is open
        """
        state = self.state
        
        if state == CircuitState.OPEN:
            raise CircuitBreakerOpen(
                f"Circuit breaker is open. Retry after {self.recovery_timeout}s"
            )
        
        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            if any(isinstance(e, exc) for exc in self.expected_exceptions):
                self._record_failure()
            raise
    
    def reset(self):
        """Manually reset the circuit breaker."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failures = 0
            self._last_failure_time = None


class CheckpointManager:
    """
    Manages checkpoints for resumable operations.
    
    Allows long-running scans to save progress and resume
    from the last checkpoint on failure.
    """
    
    def __init__(self, checkpoint_dir: Optional[str] = None):
        """
        Initialize checkpoint manager.
        
        Args:
            checkpoint_dir: Directory to store checkpoints
        """
        self.checkpoint_dir = checkpoint_dir or os.path.join(
            os.path.dirname(__file__),
            "..",
            "data",
            "checkpoints"
        )
        os.makedirs(self.checkpoint_dir, exist_ok=True)
    
    def _get_checkpoint_path(self, scan_id: str) -> str:
        """Get checkpoint file path."""
        return os.path.join(self.checkpoint_dir, f"{scan_id}.checkpoint.json")
    
    def save_checkpoint(
        self,
        scan_id: str,
        phase: str,
        completed_targets: List[str],
        partial_results: Dict,
        metadata: Optional[Dict] = None
    ):
        """
        Save a checkpoint.
        
        Args:
            scan_id: Scan identifier
            phase: Current phase name
            completed_targets: List of completed target IPs
            partial_results: Results collected so far
            metadata: Additional metadata
        """
        checkpoint = {
            "scan_id": scan_id,
            "phase": phase,
            "completed_targets": completed_targets,
            "partial_results": partial_results,
            "metadata": metadata or {},
            "timestamp": datetime.now().isoformat()
        }
        
        path = self._get_checkpoint_path(scan_id)
        with open(path, 'w') as f:
            json.dump(checkpoint, f, indent=2)
    
    def load_checkpoint(self, scan_id: str) -> Optional[Dict]:
        """
        Load a checkpoint.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Checkpoint data or None if not found
        """
        path = self._get_checkpoint_path(scan_id)
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return None
    
    def delete_checkpoint(self, scan_id: str):
        """Delete a checkpoint."""
        path = self._get_checkpoint_path(scan_id)
        if os.path.exists(path):
            os.remove(path)
    
    def list_checkpoints(self) -> List[Dict]:
        """List all available checkpoints."""
        checkpoints = []
        for filename in os.listdir(self.checkpoint_dir):
            if filename.endswith('.checkpoint.json'):
                path = os.path.join(self.checkpoint_dir, filename)
                with open(path) as f:
                    checkpoint = json.load(f)
                    checkpoints.append({
                        "scan_id": checkpoint["scan_id"],
                        "phase": checkpoint["phase"],
                        "timestamp": checkpoint["timestamp"]
                    })
        return checkpoints
    
    def cleanup_old_checkpoints(self, max_age_days: int = 7):
        """Remove checkpoints older than specified days."""
        cutoff = datetime.now().timestamp() - (max_age_days * 24 * 60 * 60)
        
        for filename in os.listdir(self.checkpoint_dir):
            if filename.endswith('.checkpoint.json'):
                path = os.path.join(self.checkpoint_dir, filename)
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)


class GracefulDegradation:
    """
    Handles graceful degradation when services fail.
    
    Provides fallback mechanisms and partial functionality
    when certain components are unavailable.
    """
    
    def __init__(self):
        """Initialize graceful degradation handler."""
        self.degraded_services: Dict[str, bool] = {}
        self.fallback_handlers: Dict[str, Callable] = {}
    
    def register_fallback(self, service_name: str, fallback: Callable):
        """
        Register a fallback handler for a service.
        
        Args:
            service_name: Name of the service
            fallback: Fallback function to call on failure
        """
        self.fallback_handlers[service_name] = fallback
    
    def mark_degraded(self, service_name: str):
        """Mark a service as degraded."""
        self.degraded_services[service_name] = True
    
    def mark_recovered(self, service_name: str):
        """Mark a service as recovered."""
        self.degraded_services[service_name] = False
    
    def is_degraded(self, service_name: str) -> bool:
        """Check if a service is degraded."""
        return self.degraded_services.get(service_name, False)
    
    def execute_with_fallback(
        self,
        service_name: str,
        primary: Callable,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute with fallback on failure.
        
        Args:
            service_name: Name of the service
            primary: Primary function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Result from primary or fallback function
        """
        if self.is_degraded(service_name):
            fallback = self.fallback_handlers.get(service_name)
            if fallback:
                return fallback(*args, **kwargs)
            raise RuntimeError(f"Service {service_name} is degraded and no fallback available")
        
        try:
            return primary(*args, **kwargs)
        except Exception as e:
            self.mark_degraded(service_name)
            fallback = self.fallback_handlers.get(service_name)
            if fallback:
                return fallback(*args, **kwargs)
            raise


if __name__ == "__main__":
    # Demo usage
    print("Retry System Demo")
    print("=" * 40)
    
    # Test retry decorator
    @retry_with_backoff(max_retries=3, base_delay=0.1)
    def flaky_function():
        if random.random() < 0.7:
            raise ConnectionError("Simulated failure")
        return "Success!"
    
    try:
        result = flaky_function()
        print(f"Result: {result}")
    except RetryError as e:
        print(f"Failed: {e}")
    
    # Test circuit breaker
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=5.0)
    
    def always_fails():
        raise Exception("Always fails")
    
    for i in range(5):
        try:
            cb.call(always_fails)
        except CircuitBreakerOpen:
            print(f"Attempt {i+1}: Circuit breaker is open")
        except Exception:
            print(f"Attempt {i+1}: Function failed")
    
    print(f"Circuit state: {cb.state}")
