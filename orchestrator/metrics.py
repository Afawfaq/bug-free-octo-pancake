#!/usr/bin/env python3
"""
Metrics and Monitoring for LAN Reconnaissance Framework
=======================================================

Provides comprehensive metrics collection and monitoring capabilities
for observability, performance tracking, and integration with monitoring systems.

Features:
- Prometheus-compatible metrics
- Real-time progress tracking
- Performance statistics
- Health monitoring
- Custom metric registration

Usage:
    from metrics import MetricsCollector
    
    metrics = MetricsCollector()
    metrics.increment('scans_total')
    metrics.observe('scan_duration_seconds', 45.2)
"""

import os
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any
from collections import defaultdict


class Counter:
    """A monotonically increasing counter."""
    
    def __init__(self, name: str, description: str = "", labels: Optional[List[str]] = None):
        self.name = name
        self.description = description
        self.labels = labels or []
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def inc(self, amount: float = 1.0, **label_values):
        """Increment the counter."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            self._values[key] += amount
    
    def get(self, **label_values) -> float:
        """Get the counter value."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            return self._values.get(key, 0)
    
    def reset(self):
        """Reset the counter."""
        with self._lock:
            self._values.clear()


class Gauge:
    """A gauge that can go up and down."""
    
    def __init__(self, name: str, description: str = "", labels: Optional[List[str]] = None):
        self.name = name
        self.description = description
        self.labels = labels or []
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()
    
    def set(self, value: float, **label_values):
        """Set the gauge value."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            self._values[key] = value
    
    def inc(self, amount: float = 1.0, **label_values):
        """Increment the gauge."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            self._values[key] += amount
    
    def dec(self, amount: float = 1.0, **label_values):
        """Decrement the gauge."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            self._values[key] -= amount
    
    def get(self, **label_values) -> float:
        """Get the gauge value."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            return self._values.get(key, 0)


class Histogram:
    """A histogram for tracking distributions."""
    
    DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0, float('inf')]
    
    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        buckets: Optional[List[float]] = None
    ):
        self.name = name
        self.description = description
        self.labels = labels or []
        self.buckets = sorted(buckets or self.DEFAULT_BUCKETS)
        self._counts: Dict[tuple, Dict[float, int]] = defaultdict(lambda: defaultdict(int))
        self._sums: Dict[tuple, float] = defaultdict(float)
        self._totals: Dict[tuple, int] = defaultdict(int)
        self._lock = threading.Lock()
    
    def observe(self, value: float, **label_values):
        """Record an observation."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            self._sums[key] += value
            self._totals[key] += 1
            
            for bucket in self.buckets:
                if value <= bucket:
                    self._counts[key][bucket] += 1
    
    def get_bucket_count(self, bucket: float, **label_values) -> int:
        """Get count for a specific bucket."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            return self._counts.get(key, {}).get(bucket, 0)
    
    def get_sum(self, **label_values) -> float:
        """Get sum of all observations."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            return self._sums.get(key, 0)
    
    def get_count(self, **label_values) -> int:
        """Get total count of observations."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            return self._totals.get(key, 0)


class Summary:
    """A summary for tracking quantiles."""
    
    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        max_age: int = 600  # 10 minutes
    ):
        self.name = name
        self.description = description
        self.labels = labels or []
        self.max_age = max_age
        self._observations: Dict[tuple, List[tuple]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def observe(self, value: float, **label_values):
        """Record an observation."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            now = time.time()
            self._observations[key].append((now, value))
            
            # Clean old observations
            cutoff = now - self.max_age
            self._observations[key] = [
                (t, v) for t, v in self._observations[key] if t > cutoff
            ]
    
    def get_quantile(self, q: float, **label_values) -> Optional[float]:
        """Get a specific quantile."""
        with self._lock:
            key = tuple(label_values.get(l, "") for l in self.labels)
            values = [v for _, v in self._observations.get(key, [])]
            
            if not values:
                return None
            
            sorted_values = sorted(values)
            idx = int(len(sorted_values) * q)
            return sorted_values[min(idx, len(sorted_values) - 1)]


class MetricsCollector:
    """
    Central metrics collection and management.
    
    Provides a registry for metrics and methods for
    exposing them in Prometheus format.
    """
    
    def __init__(self, prefix: str = "lan_recon"):
        """
        Initialize metrics collector.
        
        Args:
            prefix: Prefix for all metric names
        """
        self.prefix = prefix
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._histograms: Dict[str, Histogram] = {}
        self._summaries: Dict[str, Summary] = {}
        self._lock = threading.Lock()
        
        # Initialize default metrics
        self._init_default_metrics()
    
    def _init_default_metrics(self):
        """Initialize default framework metrics."""
        # Scan metrics
        self.register_counter(
            "scans_total",
            "Total number of scans executed",
            labels=["status"]
        )
        self.register_gauge(
            "scan_running",
            "Whether a scan is currently running"
        )
        self.register_gauge(
            "scan_progress_percent",
            "Current scan progress percentage"
        )
        self.register_histogram(
            "scan_duration_seconds",
            "Scan duration in seconds",
            buckets=[60, 120, 300, 600, 900, 1200, 1800, 3600]
        )
        
        # Phase metrics
        self.register_counter(
            "phase_executions_total",
            "Total phase executions",
            labels=["phase", "status"]
        )
        self.register_histogram(
            "phase_duration_seconds",
            "Phase duration in seconds",
            labels=["phase"],
            buckets=[5, 10, 30, 60, 120, 300, 600]
        )
        
        # Finding metrics
        self.register_counter(
            "findings_total",
            "Total findings discovered",
            labels=["severity"]
        )
        
        # Host metrics
        self.register_gauge(
            "hosts_discovered",
            "Number of hosts discovered in current scan"
        )
        self.register_gauge(
            "ports_discovered",
            "Number of open ports discovered"
        )
        
        # Container metrics
        self.register_gauge(
            "containers_healthy",
            "Number of healthy containers"
        )
        self.register_counter(
            "container_failures_total",
            "Total container failures",
            labels=["container"]
        )
        
        # API metrics (if API server is used)
        self.register_counter(
            "api_requests_total",
            "Total API requests",
            labels=["method", "endpoint", "status"]
        )
        self.register_histogram(
            "api_request_duration_seconds",
            "API request duration",
            labels=["method", "endpoint"]
        )
    
    # Registration methods
    
    def register_counter(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None
    ) -> Counter:
        """Register a counter metric."""
        full_name = f"{self.prefix}_{name}"
        with self._lock:
            if full_name not in self._counters:
                self._counters[full_name] = Counter(full_name, description, labels)
            return self._counters[full_name]
    
    def register_gauge(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None
    ) -> Gauge:
        """Register a gauge metric."""
        full_name = f"{self.prefix}_{name}"
        with self._lock:
            if full_name not in self._gauges:
                self._gauges[full_name] = Gauge(full_name, description, labels)
            return self._gauges[full_name]
    
    def register_histogram(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None,
        buckets: Optional[List[float]] = None
    ) -> Histogram:
        """Register a histogram metric."""
        full_name = f"{self.prefix}_{name}"
        with self._lock:
            if full_name not in self._histograms:
                self._histograms[full_name] = Histogram(full_name, description, labels, buckets)
            return self._histograms[full_name]
    
    def register_summary(
        self,
        name: str,
        description: str = "",
        labels: Optional[List[str]] = None
    ) -> Summary:
        """Register a summary metric."""
        full_name = f"{self.prefix}_{name}"
        with self._lock:
            if full_name not in self._summaries:
                self._summaries[full_name] = Summary(full_name, description, labels)
            return self._summaries[full_name]
    
    # Convenience methods
    
    def increment(self, name: str, amount: float = 1.0, **labels):
        """Increment a counter."""
        full_name = f"{self.prefix}_{name}"
        if full_name in self._counters:
            self._counters[full_name].inc(amount, **labels)
    
    def set_gauge(self, name: str, value: float, **labels):
        """Set a gauge value."""
        full_name = f"{self.prefix}_{name}"
        if full_name in self._gauges:
            self._gauges[full_name].set(value, **labels)
    
    def observe(self, name: str, value: float, **labels):
        """Record an observation in a histogram."""
        full_name = f"{self.prefix}_{name}"
        if full_name in self._histograms:
            self._histograms[full_name].observe(value, **labels)
    
    # Export methods
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []
        
        # Export counters
        for name, counter in self._counters.items():
            if counter.description:
                lines.append(f"# HELP {name} {counter.description}")
            lines.append(f"# TYPE {name} counter")
            
            with counter._lock:
                for labels, value in counter._values.items():
                    label_str = self._format_labels(counter.labels, labels)
                    lines.append(f"{name}{label_str} {value}")
        
        # Export gauges
        for name, gauge in self._gauges.items():
            if gauge.description:
                lines.append(f"# HELP {name} {gauge.description}")
            lines.append(f"# TYPE {name} gauge")
            
            with gauge._lock:
                for labels, value in gauge._values.items():
                    label_str = self._format_labels(gauge.labels, labels)
                    lines.append(f"{name}{label_str} {value}")
        
        # Export histograms
        for name, histogram in self._histograms.items():
            if histogram.description:
                lines.append(f"# HELP {name} {histogram.description}")
            lines.append(f"# TYPE {name} histogram")
            
            with histogram._lock:
                for labels, counts in histogram._counts.items():
                    base_labels = self._build_label_dict(histogram.labels, labels)
                    
                    cumulative = 0
                    for bucket in histogram.buckets:
                        cumulative += counts.get(bucket, 0)
                        bucket_labels = dict(base_labels)
                        bucket_labels["le"] = str(bucket) if bucket != float('inf') else "+Inf"
                        label_str = self._format_label_dict(bucket_labels)
                        lines.append(f"{name}_bucket{label_str} {cumulative}")
                    
                    base_label_str = self._format_label_dict(base_labels)
                    lines.append(f"{name}_sum{base_label_str} {histogram._sums.get(labels, 0)}")
                    lines.append(f"{name}_count{base_label_str} {histogram._totals.get(labels, 0)}")
        
        return "\n".join(lines)
    
    def _build_label_dict(self, label_names: List[str], label_values: tuple) -> Dict[str, str]:
        """Build a dictionary of labels from names and values."""
        return {name: value for name, value in zip(label_names, label_values) if value}
    
    def _format_label_dict(self, labels: Dict[str, str]) -> str:
        """Format a label dictionary for Prometheus output."""
        if not labels:
            return ""
        pairs = [f'{name}="{value}"' for name, value in labels.items()]
        return "{" + ",".join(pairs) + "}"
    
    def _format_labels(self, label_names: List[str], label_values: tuple) -> str:
        """Format labels for Prometheus output."""
        label_dict = self._build_label_dict(label_names, label_values)
        return self._format_label_dict(label_dict)
    
    def export_json(self) -> Dict:
        """Export metrics as JSON."""
        result = {
            "timestamp": datetime.now().isoformat(),
            "counters": {},
            "gauges": {},
            "histograms": {}
        }
        
        for name, counter in self._counters.items():
            result["counters"][name] = dict(counter._values)
        
        for name, gauge in self._gauges.items():
            result["gauges"][name] = dict(gauge._values)
        
        for name, histogram in self._histograms.items():
            result["histograms"][name] = {
                "buckets": dict(histogram._counts),
                "sum": dict(histogram._sums),
                "count": dict(histogram._totals)
            }
        
        return result


# Global metrics instance
_metrics: Optional[MetricsCollector] = None


def get_metrics() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsCollector()
    return _metrics


# Context manager for timing
class Timer:
    """Context manager for timing operations."""
    
    def __init__(self, histogram_name: str, metrics: Optional[MetricsCollector] = None, **labels):
        self.histogram_name = histogram_name
        self.metrics = metrics or get_metrics()
        self.labels = labels
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.metrics.observe(self.histogram_name, duration, **self.labels)


if __name__ == "__main__":
    # Demo usage
    print("Metrics System Demo")
    print("=" * 40)
    
    metrics = MetricsCollector()
    
    # Increment counters
    metrics.increment("scans_total", status="completed")
    metrics.increment("scans_total", status="completed")
    metrics.increment("scans_total", status="failed")
    
    # Set gauges
    metrics.set_gauge("scan_running", 1)
    metrics.set_gauge("hosts_discovered", 15)
    
    # Record histogram observations
    metrics.observe("scan_duration_seconds", 125.5)
    metrics.observe("scan_duration_seconds", 245.3)
    metrics.observe("phase_duration_seconds", 30.2, phase="passive")
    
    # Export
    print("\nPrometheus format:")
    print(metrics.export_prometheus())
    
    print("\nJSON format:")
    import json
    print(json.dumps(metrics.export_json(), indent=2, default=str))
