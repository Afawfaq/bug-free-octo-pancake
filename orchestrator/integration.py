#!/usr/bin/env python3
"""
Integration Module for LAN Reconnaissance Framework v2.5.0

Provides a unified interface that ties all framework modules together.
This is the main entry point for programmatic access to all features.

Usage:
    from integration import LANReconFramework
    
    framework = LANReconFramework()
    framework.start_scan(target='192.168.1.0/24')
    report = framework.get_report()
"""

import os
import sys
import json
import time
import signal
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

# Import all framework modules
try:
    from .run import NetworkReconOrchestrator
    from .database import ScanDatabase
    from .scheduler import ScanScheduler
    from .notifications import NotificationManager
    from .config_validator import ConfigValidator
    from .metrics import MetricsCollector, framework_metrics
    from .export_import import DataExporter, DataImporter
    from .anomaly_detection import AnomalyDetector
    from .health_checker import HealthChecker
    from .retry import RetryManager
except ImportError:
    # Allow running standalone
    pass


class FrameworkState(Enum):
    """Framework operational states"""
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    READY = "ready"
    SCANNING = "scanning"
    PAUSED = "paused"
    ERROR = "error"
    SHUTDOWN = "shutdown"


@dataclass
class FrameworkConfig:
    """Configuration for the framework"""
    # Target network
    target_network: str = "192.168.1.0/24"
    router_ip: str = "192.168.1.1"
    
    # Scan settings
    passive_duration: int = 30
    scan_timeout: int = 600
    parallel_execution: bool = True
    
    # Feature flags
    enable_notifications: bool = True
    enable_database: bool = True
    enable_scheduler: bool = True
    enable_metrics: bool = True
    enable_anomaly_detection: bool = True
    
    # Notification settings
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None
    email_settings: Optional[Dict] = None
    
    # Paths
    output_dir: str = "./output"
    data_dir: str = "./data"
    
    # Advanced
    log_level: str = "INFO"
    verbose: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'target_network': self.target_network,
            'router_ip': self.router_ip,
            'passive_duration': self.passive_duration,
            'scan_timeout': self.scan_timeout,
            'parallel_execution': self.parallel_execution,
            'enable_notifications': self.enable_notifications,
            'enable_database': self.enable_database,
            'enable_scheduler': self.enable_scheduler,
            'enable_metrics': self.enable_metrics,
            'enable_anomaly_detection': self.enable_anomaly_detection,
            'output_dir': self.output_dir,
            'data_dir': self.data_dir,
            'log_level': self.log_level,
            'verbose': self.verbose
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FrameworkConfig':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
    
    @classmethod
    def from_env(cls) -> 'FrameworkConfig':
        """Create from environment variables"""
        return cls(
            target_network=os.getenv('TARGET_NETWORK', '192.168.1.0/24'),
            router_ip=os.getenv('ROUTER_IP', '192.168.1.1'),
            passive_duration=int(os.getenv('PASSIVE_DURATION', '30')),
            scan_timeout=int(os.getenv('SCAN_TIMEOUT', '600')),
            parallel_execution=os.getenv('PARALLEL_EXECUTION', 'true').lower() == 'true',
            enable_notifications=os.getenv('ENABLE_NOTIFICATIONS', 'true').lower() == 'true',
            enable_database=os.getenv('ENABLE_DATABASE', 'true').lower() == 'true',
            slack_webhook=os.getenv('SLACK_WEBHOOK'),
            discord_webhook=os.getenv('DISCORD_WEBHOOK'),
            output_dir=os.getenv('OUTPUT_DIR', './output'),
            verbose=os.getenv('VERBOSE', 'false').lower() == 'true'
        )


class LANReconFramework:
    """
    Main entry point for the LAN Reconnaissance Framework.
    
    Provides unified access to all framework capabilities:
    - Network scanning and discovery
    - Vulnerability assessment
    - Report generation
    - Scheduling and automation
    - Notifications
    - Data persistence
    - Anomaly detection
    
    Example:
        framework = LANReconFramework()
        framework.configure(target_network='192.168.1.0/24')
        
        # Run a scan
        scan_id = framework.start_scan()
        framework.wait_for_completion(scan_id)
        
        # Get results
        report = framework.get_report(scan_id)
        
        # Export
        framework.export_results(scan_id, format='html')
    """
    
    VERSION = "2.5.0"
    
    def __init__(self, config: Optional[FrameworkConfig] = None):
        """Initialize the framework"""
        self.config = config or FrameworkConfig.from_env()
        self.state = FrameworkState.UNINITIALIZED
        
        # Core components (lazy loaded)
        self._orchestrator: Optional[NetworkReconOrchestrator] = None
        self._database: Optional[ScanDatabase] = None
        self._scheduler: Optional[ScanScheduler] = None
        self._notifications: Optional[NotificationManager] = None
        self._metrics: Optional[MetricsCollector] = None
        self._anomaly_detector: Optional[AnomalyDetector] = None
        self._health_checker: Optional[HealthChecker] = None
        self._exporter: Optional[DataExporter] = None
        self._importer: Optional[DataImporter] = None
        
        # Runtime state
        self._current_scan_id: Optional[str] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._shutdown_event = threading.Event()
        self._callbacks: Dict[str, List[Callable]] = {}
        
        # Setup signal handlers
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers"""
        def signal_handler(signum, frame):
            self.shutdown()
        
        try:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        except ValueError:
            # Can't set signal handlers in non-main thread
            pass
    
    def _log(self, message: str, level: str = "INFO"):
        """Log a message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if self.config.verbose or level in ("ERROR", "WARNING"):
            print(f"[{timestamp}] [{level}] {message}")
    
    # ===========================================
    # Initialization
    # ===========================================
    
    def initialize(self) -> bool:
        """
        Initialize all framework components.
        
        Returns:
            bool: True if initialization successful
        """
        if self.state != FrameworkState.UNINITIALIZED:
            self._log("Framework already initialized", "WARNING")
            return False
        
        self.state = FrameworkState.INITIALIZING
        self._log("Initializing LAN Reconnaissance Framework v" + self.VERSION)
        
        try:
            # Create output directories
            Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
            Path(self.config.data_dir).mkdir(parents=True, exist_ok=True)
            
            # Initialize database
            if self.config.enable_database:
                self._log("Initializing database...")
                db_path = Path(self.config.data_dir) / "scans.db"
                self._database = ScanDatabase(str(db_path))
            
            # Initialize metrics
            if self.config.enable_metrics:
                self._log("Initializing metrics collector...")
                self._metrics = MetricsCollector()
            
            # Initialize notifications
            if self.config.enable_notifications:
                self._log("Initializing notification manager...")
                notif_config = {}
                if self.config.slack_webhook:
                    notif_config['slack'] = {'webhook_url': self.config.slack_webhook}
                if self.config.discord_webhook:
                    notif_config['discord'] = {'webhook_url': self.config.discord_webhook}
                self._notifications = NotificationManager(notif_config)
            
            # Initialize scheduler
            if self.config.enable_scheduler:
                self._log("Initializing scheduler...")
                self._scheduler = ScanScheduler(
                    scan_callback=self._scheduled_scan_callback,
                    persistence_file=str(Path(self.config.data_dir) / "schedules.json")
                )
            
            # Initialize anomaly detector
            if self.config.enable_anomaly_detection:
                self._log("Initializing anomaly detector...")
                self._anomaly_detector = AnomalyDetector()
            
            # Initialize health checker
            self._health_checker = HealthChecker(verbose=self.config.verbose)
            
            # Initialize exporters
            self._exporter = DataExporter()
            self._importer = DataImporter()
            
            self.state = FrameworkState.READY
            self._log("Framework initialized successfully")
            self._trigger_callback('on_initialized')
            
            return True
            
        except Exception as e:
            self.state = FrameworkState.ERROR
            self._log(f"Initialization failed: {e}", "ERROR")
            return False
    
    def _scheduled_scan_callback(self, job_config: Dict[str, Any]):
        """Callback for scheduled scans"""
        self._log(f"Running scheduled scan: {job_config.get('name', 'unnamed')}")
        self.start_scan(
            target=job_config.get('target', self.config.target_network),
            profile=job_config.get('profile'),
            async_mode=True
        )
    
    # ===========================================
    # Configuration
    # ===========================================
    
    def configure(self, **kwargs) -> 'LANReconFramework':
        """
        Update configuration.
        
        Args:
            **kwargs: Configuration options to update
            
        Returns:
            self for chaining
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
            else:
                self._log(f"Unknown config option: {key}", "WARNING")
        
        return self
    
    def get_config(self) -> Dict[str, Any]:
        """Get current configuration"""
        return self.config.to_dict()
    
    # ===========================================
    # Health & Status
    # ===========================================
    
    def health_check(self, quick: bool = False) -> Dict[str, Any]:
        """
        Run health check.
        
        Args:
            quick: Run quick check only
            
        Returns:
            Health check report
        """
        if not self._health_checker:
            self._health_checker = HealthChecker()
        
        if quick:
            report = self._health_checker.quick_check()
        else:
            report = self._health_checker.full_health_check()
        
        return report.to_dict()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current framework status"""
        return {
            'version': self.VERSION,
            'state': self.state.value,
            'current_scan': self._current_scan_id,
            'config': self.config.to_dict(),
            'components': {
                'database': self._database is not None,
                'scheduler': self._scheduler is not None,
                'notifications': self._notifications is not None,
                'metrics': self._metrics is not None,
                'anomaly_detection': self._anomaly_detector is not None
            }
        }
    
    # ===========================================
    # Scanning
    # ===========================================
    
    def start_scan(
        self,
        target: Optional[str] = None,
        profile: Optional[str] = None,
        async_mode: bool = False
    ) -> str:
        """
        Start a network scan.
        
        Args:
            target: Target network (e.g., "192.168.1.0/24")
            profile: Scan profile name (e.g., "quick", "thorough")
            async_mode: Run scan in background thread
            
        Returns:
            Scan ID
        """
        if self.state == FrameworkState.UNINITIALIZED:
            self.initialize()
        
        if self.state == FrameworkState.SCANNING:
            raise RuntimeError("A scan is already in progress")
        
        # Generate scan ID
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._current_scan_id = scan_id
        
        # Update target if provided
        if target:
            self.config.target_network = target
        
        self._log(f"Starting scan {scan_id} on {self.config.target_network}")
        
        # Notify
        if self._notifications:
            self._notifications.send_notification(
                title="Scan Started",
                message=f"Network scan started on {self.config.target_network}",
                severity="info"
            )
        
        if async_mode:
            self._scan_thread = threading.Thread(
                target=self._run_scan,
                args=(scan_id, profile),
                daemon=True
            )
            self._scan_thread.start()
        else:
            self._run_scan(scan_id, profile)
        
        return scan_id
    
    def _run_scan(self, scan_id: str, profile: Optional[str] = None):
        """Internal scan execution"""
        self.state = FrameworkState.SCANNING
        start_time = time.time()
        
        try:
            self._trigger_callback('on_scan_start', scan_id)
            
            # Set environment variables for orchestrator
            os.environ['TARGET_NETWORK'] = self.config.target_network
            os.environ['ROUTER_IP'] = self.config.router_ip
            os.environ['PASSIVE_DURATION'] = str(self.config.passive_duration)
            os.environ['PARALLEL_EXECUTION'] = str(self.config.parallel_execution).lower()
            
            # Create and run orchestrator
            self._orchestrator = NetworkReconOrchestrator()
            self._orchestrator.run()
            
            duration = time.time() - start_time
            
            # Store in database
            if self._database:
                self._database.save_scan({
                    'scan_id': scan_id,
                    'target': self.config.target_network,
                    'profile': profile,
                    'duration': duration,
                    'status': 'completed',
                    'timestamp': datetime.now().isoformat()
                })
            
            # Run anomaly detection
            if self._anomaly_detector:
                results_path = Path(self.config.output_dir) / "discovery" / "hosts.json"
                if results_path.exists():
                    with open(results_path) as f:
                        hosts = json.load(f)
                    anomalies = self._anomaly_detector.analyze(hosts)
                    if anomalies:
                        self._log(f"Detected {len(anomalies)} anomalies")
            
            # Notify completion
            if self._notifications:
                self._notifications.send_notification(
                    title="Scan Completed",
                    message=f"Scan {scan_id} completed in {duration:.1f}s",
                    severity="success"
                )
            
            self._trigger_callback('on_scan_complete', scan_id)
            
        except Exception as e:
            self._log(f"Scan failed: {e}", "ERROR")
            self.state = FrameworkState.ERROR
            
            if self._notifications:
                self._notifications.send_notification(
                    title="Scan Failed",
                    message=f"Scan {scan_id} failed: {str(e)}",
                    severity="critical"
                )
            
            self._trigger_callback('on_scan_error', scan_id, str(e))
        
        finally:
            if self.state == FrameworkState.SCANNING:
                self.state = FrameworkState.READY
            self._current_scan_id = None
    
    def stop_scan(self) -> bool:
        """Stop the current scan"""
        if self.state != FrameworkState.SCANNING:
            return False
        
        self._log("Stopping scan...")
        self._shutdown_event.set()
        
        # Wait for scan thread to complete
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=30)
        
        self.state = FrameworkState.READY
        return True
    
    def wait_for_completion(self, timeout: Optional[float] = None) -> bool:
        """Wait for current scan to complete"""
        if not self._scan_thread:
            return True
        
        self._scan_thread.join(timeout=timeout)
        return not self._scan_thread.is_alive()
    
    # ===========================================
    # Results & Reports
    # ===========================================
    
    def get_results(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Get scan results"""
        results = {}
        output_path = Path(self.config.output_dir)
        
        # Load discovery results
        hosts_file = output_path / "discovery" / "hosts.json"
        if hosts_file.exists():
            with open(hosts_file) as f:
                results['hosts'] = json.load(f)
        
        # Load fingerprint results
        fingerprint_file = output_path / "fingerprint" / "fingerprints.json"
        if fingerprint_file.exists():
            with open(fingerprint_file) as f:
                results['fingerprints'] = json.load(f)
        
        # Load vulnerability results
        vuln_file = output_path / "nuclei" / "vulnerabilities.json"
        if vuln_file.exists():
            with open(vuln_file) as f:
                results['vulnerabilities'] = json.load(f)
        
        return results
    
    def get_report(self, scan_id: Optional[str] = None, format: str = 'html') -> str:
        """Get scan report in specified format"""
        report_path = Path(self.config.output_dir) / "final_report"
        
        if format == 'html':
            report_file = report_path / "report.html"
        elif format == 'json':
            report_file = report_path / "report.json"
        else:
            raise ValueError(f"Unknown format: {format}")
        
        if report_file.exists():
            return report_file.read_text()
        
        return ""
    
    def export_results(
        self,
        scan_id: Optional[str] = None,
        format: str = 'json',
        output_path: Optional[str] = None,
        anonymize: bool = False
    ) -> str:
        """
        Export scan results.
        
        Args:
            scan_id: Scan ID to export
            format: Export format (json, csv, xml, yaml)
            output_path: Output file path
            anonymize: Anonymize sensitive data
            
        Returns:
            Path to exported file
        """
        results = self.get_results(scan_id)
        
        if not output_path:
            output_path = f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
        
        if self._exporter:
            return self._exporter.export(
                data=results,
                format=format,
                output_path=output_path,
                anonymize=anonymize
            )
        
        return output_path
    
    # ===========================================
    # Scheduling
    # ===========================================
    
    def schedule_scan(
        self,
        name: str,
        schedule: str,
        target: Optional[str] = None,
        profile: Optional[str] = None
    ) -> str:
        """
        Schedule a recurring scan.
        
        Args:
            name: Job name
            schedule: Cron expression (e.g., "0 2 * * *" for 2 AM daily)
            target: Target network
            profile: Scan profile
            
        Returns:
            Job ID
        """
        if not self._scheduler:
            raise RuntimeError("Scheduler not enabled")
        
        job_config = {
            'name': name,
            'schedule': schedule,
            'target': target or self.config.target_network,
            'profile': profile
        }
        
        return self._scheduler.add_job(job_config)
    
    def list_scheduled_scans(self) -> List[Dict[str, Any]]:
        """List all scheduled scans"""
        if not self._scheduler:
            return []
        return self._scheduler.list_jobs()
    
    def cancel_scheduled_scan(self, job_id: str) -> bool:
        """Cancel a scheduled scan"""
        if not self._scheduler:
            return False
        return self._scheduler.remove_job(job_id)
    
    # ===========================================
    # Callbacks & Events
    # ===========================================
    
    def on(self, event: str, callback: Callable) -> 'LANReconFramework':
        """
        Register an event callback.
        
        Events:
        - on_initialized
        - on_scan_start
        - on_scan_complete
        - on_scan_error
        - on_shutdown
        
        Args:
            event: Event name
            callback: Callback function
            
        Returns:
            self for chaining
        """
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)
        return self
    
    def _trigger_callback(self, event: str, *args, **kwargs):
        """Trigger callbacks for an event"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                self._log(f"Callback error for {event}: {e}", "ERROR")
    
    # ===========================================
    # Shutdown
    # ===========================================
    
    def shutdown(self):
        """Gracefully shutdown the framework"""
        if self.state == FrameworkState.SHUTDOWN:
            return
        
        self._log("Shutting down framework...")
        self._trigger_callback('on_shutdown')
        
        # Stop any running scan
        if self.state == FrameworkState.SCANNING:
            self.stop_scan()
        
        # Stop scheduler
        if self._scheduler:
            self._scheduler.stop()
        
        # Close database
        if self._database:
            self._database.close()
        
        self.state = FrameworkState.SHUTDOWN
        self._log("Framework shutdown complete")
    
    def __enter__(self):
        """Context manager entry"""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.shutdown()
        return False


# ===========================================
# Convenience Functions
# ===========================================

def quick_scan(target: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Perform a quick scan of a network.
    
    Args:
        target: Target network
        verbose: Enable verbose output
        
    Returns:
        Scan results
    """
    config = FrameworkConfig(
        target_network=target,
        verbose=verbose,
        enable_database=False,
        enable_scheduler=False
    )
    
    with LANReconFramework(config) as framework:
        scan_id = framework.start_scan()
        framework.wait_for_completion()
        return framework.get_results(scan_id)


def get_framework_version() -> str:
    """Get framework version"""
    return LANReconFramework.VERSION


# ===========================================
# CLI Interface
# ===========================================

def main():
    """Main CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='LAN Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python integration.py scan 192.168.1.0/24
  python integration.py status
  python integration.py health
  python integration.py export --format json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run a network scan')
    scan_parser.add_argument('target', help='Target network')
    scan_parser.add_argument('--profile', help='Scan profile')
    scan_parser.add_argument('--verbose', '-v', action='store_true')
    
    # Status command
    subparsers.add_parser('status', help='Show framework status')
    
    # Health command
    health_parser = subparsers.add_parser('health', help='Run health check')
    health_parser.add_argument('--quick', '-q', action='store_true')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export results')
    export_parser.add_argument('--format', '-f', default='json',
                               choices=['json', 'csv', 'xml', 'yaml'])
    export_parser.add_argument('--output', '-o', help='Output file')
    export_parser.add_argument('--anonymize', action='store_true')
    
    # Version command
    subparsers.add_parser('version', help='Show version')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        config = FrameworkConfig(
            target_network=args.target,
            verbose=args.verbose
        )
        with LANReconFramework(config) as framework:
            framework.start_scan(profile=args.profile)
            framework.wait_for_completion()
            print(f"Scan complete. Results in {framework.config.output_dir}")
    
    elif args.command == 'status':
        framework = LANReconFramework()
        print(json.dumps(framework.get_status(), indent=2))
    
    elif args.command == 'health':
        framework = LANReconFramework()
        report = framework.health_check(quick=args.quick)
        framework._health_checker.print_report(
            framework._health_checker.full_health_check()
        )
    
    elif args.command == 'export':
        framework = LANReconFramework()
        output = framework.export_results(
            format=args.format,
            output_path=args.output,
            anonymize=args.anonymize
        )
        print(f"Results exported to {output}")
    
    elif args.command == 'version':
        print(f"LAN Reconnaissance Framework v{get_framework_version()}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
