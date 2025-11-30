#!/usr/bin/env python3
"""
Health Checker Module for LAN Reconnaissance Framework v2.5.0

Comprehensive system health monitoring including:
- Docker environment checks
- Container health status
- Network connectivity tests
- Disk space monitoring
- Memory usage checks
- Dependency verification
- Service availability tests

Usage:
    from health_checker import HealthChecker
    
    checker = HealthChecker()
    report = checker.full_health_check()
    print(report)
"""

import os
import sys
import json
import socket
import shutil
import subprocess
import platform
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path


class HealthStatus(Enum):
    """Health status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a single health check"""
    name: str
    status: HealthStatus
    message: str
    details: Optional[Dict[str, Any]] = None
    duration_ms: float = 0.0
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        return result


@dataclass
class HealthReport:
    """Complete health report"""
    overall_status: HealthStatus
    checks: List[HealthCheckResult]
    summary: Dict[str, int]
    recommendations: List[str]
    system_info: Dict[str, Any]
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall_status': self.overall_status.value,
            'checks': [c.to_dict() for c in self.checks],
            'summary': self.summary,
            'recommendations': self.recommendations,
            'system_info': self.system_info,
            'timestamp': self.timestamp
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class HealthChecker:
    """
    Comprehensive health checker for the LAN Reconnaissance Framework.
    
    Features:
    - Docker environment verification
    - Container health monitoring
    - Network connectivity tests
    - System resource checks
    - Dependency verification
    - Service availability tests
    """
    
    # Required containers
    REQUIRED_CONTAINERS = [
        'recon-orchestrator',
        'recon-passive',
        'recon-discovery',
        'recon-fingerprint',
        'recon-iot',
        'recon-nuclei',
        'recon-webshot',
        'recon-report',
        'recon-advanced-monitor',
        'recon-attack-surface'
    ]
    
    # Required Python modules
    REQUIRED_PYTHON_MODULES = [
        'docker',
        'requests',
        'jinja2',
        'flask',
        'yaml',
        'networkx'
    ]
    
    # Required system commands
    REQUIRED_COMMANDS = [
        'docker',
        'docker-compose'
    ]
    
    # Minimum resource requirements
    MIN_DISK_GB = 10
    MIN_MEMORY_GB = 4
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.checks: List[HealthCheckResult] = []
        self.recommendations: List[str] = []
    
    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            print(f"[HealthChecker] {message}")
    
    def _run_check(self, name: str, check_func) -> HealthCheckResult:
        """Run a health check and record timing"""
        start = time.time()
        try:
            status, message, details = check_func()
        except Exception as e:
            status = HealthStatus.CRITICAL
            message = f"Check failed with exception: {str(e)}"
            details = {'exception': str(e)}
        duration_ms = (time.time() - start) * 1000
        
        result = HealthCheckResult(
            name=name,
            status=status,
            message=message,
            details=details,
            duration_ms=round(duration_ms, 2)
        )
        self.checks.append(result)
        self._log(f"{name}: {status.value} - {message}")
        return result
    
    # ===========================================
    # Docker Checks
    # ===========================================
    
    def check_docker_installed(self) -> Tuple[HealthStatus, str, Dict]:
        """Check if Docker is installed and accessible"""
        details = {}
        
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                details['version'] = result.stdout.strip()
                return HealthStatus.HEALTHY, "Docker is installed", details
            else:
                return HealthStatus.CRITICAL, "Docker command failed", details
        except FileNotFoundError:
            self.recommendations.append("Install Docker: https://docs.docker.com/get-docker/")
            return HealthStatus.CRITICAL, "Docker is not installed", details
        except subprocess.TimeoutExpired:
            return HealthStatus.WARNING, "Docker command timed out", details
    
    def check_docker_running(self) -> Tuple[HealthStatus, str, Dict]:
        """Check if Docker daemon is running"""
        details = {}
        
        try:
            result = subprocess.run(
                ['docker', 'info', '--format', '{{json .}}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                try:
                    info = json.loads(result.stdout)
                    details['server_version'] = info.get('ServerVersion', 'unknown')
                    details['containers'] = info.get('Containers', 0)
                    details['images'] = info.get('Images', 0)
                    details['os_type'] = info.get('OSType', 'unknown')
                except json.JSONDecodeError:
                    pass
                return HealthStatus.HEALTHY, "Docker daemon is running", details
            else:
                self.recommendations.append("Start Docker daemon: sudo systemctl start docker")
                return HealthStatus.CRITICAL, "Docker daemon is not running", details
        except Exception as e:
            return HealthStatus.CRITICAL, f"Cannot connect to Docker: {e}", details
    
    def check_docker_compose(self) -> Tuple[HealthStatus, str, Dict]:
        """Check if Docker Compose is available"""
        details = {}
        
        # Try docker compose (v2)
        try:
            result = subprocess.run(
                ['docker', 'compose', 'version', '--short'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                details['version'] = result.stdout.strip()
                details['type'] = 'docker compose v2'
                return HealthStatus.HEALTHY, "Docker Compose v2 is available", details
        except Exception:
            pass
        
        # Try docker-compose (v1)
        try:
            result = subprocess.run(
                ['docker-compose', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                details['version'] = result.stdout.strip()
                details['type'] = 'docker-compose v1'
                return HealthStatus.HEALTHY, "Docker Compose v1 is available", details
        except FileNotFoundError:
            pass
        
        self.recommendations.append("Install Docker Compose: https://docs.docker.com/compose/install/")
        return HealthStatus.CRITICAL, "Docker Compose is not installed", details
    
    def check_containers_status(self) -> Tuple[HealthStatus, str, Dict]:
        """Check status of all framework containers"""
        details = {'containers': {}, 'running': 0, 'stopped': 0, 'missing': 0}
        
        try:
            result = subprocess.run(
                ['docker', 'ps', '-a', '--format', '{{.Names}}|{{.Status}}|{{.State}}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            running_containers = {}
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 3:
                            name, status, state = parts[0], parts[1], parts[2]
                            running_containers[name] = {'status': status, 'state': state}
            
            for container in self.REQUIRED_CONTAINERS:
                if container in running_containers:
                    state = running_containers[container]['state']
                    details['containers'][container] = state
                    if state == 'running':
                        details['running'] += 1
                    else:
                        details['stopped'] += 1
                else:
                    details['containers'][container] = 'missing'
                    details['missing'] += 1
            
            if details['missing'] > 0:
                self.recommendations.append(
                    f"Build missing containers: docker compose build"
                )
                return HealthStatus.WARNING, f"{details['missing']} containers missing", details
            elif details['stopped'] > 0:
                return HealthStatus.WARNING, f"{details['stopped']} containers stopped", details
            else:
                return HealthStatus.HEALTHY, f"All {details['running']} containers running", details
                
        except Exception as e:
            return HealthStatus.CRITICAL, f"Failed to check containers: {e}", details
    
    # ===========================================
    # System Resource Checks
    # ===========================================
    
    def check_disk_space(self) -> Tuple[HealthStatus, str, Dict]:
        """Check available disk space"""
        details = {}
        
        try:
            # Get disk usage for current directory
            total, used, free = shutil.disk_usage('.')
            details['total_gb'] = round(total / (1024**3), 2)
            details['used_gb'] = round(used / (1024**3), 2)
            details['free_gb'] = round(free / (1024**3), 2)
            details['used_percent'] = round((used / total) * 100, 1)
            
            if details['free_gb'] < self.MIN_DISK_GB:
                self.recommendations.append(
                    f"Free up disk space. Minimum {self.MIN_DISK_GB}GB recommended."
                )
                return HealthStatus.CRITICAL, f"Low disk space: {details['free_gb']}GB free", details
            elif details['used_percent'] > 90:
                return HealthStatus.WARNING, f"Disk usage high: {details['used_percent']}%", details
            else:
                return HealthStatus.HEALTHY, f"{details['free_gb']}GB available", details
                
        except Exception as e:
            return HealthStatus.UNKNOWN, f"Could not check disk space: {e}", details
    
    def check_memory(self) -> Tuple[HealthStatus, str, Dict]:
        """Check available system memory"""
        details = {}
        
        try:
            # Try to read from /proc/meminfo (Linux)
            if os.path.exists('/proc/meminfo'):
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split(':')
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = parts[1].strip().split()[0]
                            meminfo[key] = int(value) * 1024  # Convert KB to bytes
                    
                    total = meminfo.get('MemTotal', 0)
                    available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
                    
                    details['total_gb'] = round(total / (1024**3), 2)
                    details['available_gb'] = round(available / (1024**3), 2)
                    details['used_percent'] = round(((total - available) / total) * 100, 1) if total > 0 else 0
            else:
                # Fallback for other systems
                import psutil
                mem = psutil.virtual_memory()
                details['total_gb'] = round(mem.total / (1024**3), 2)
                details['available_gb'] = round(mem.available / (1024**3), 2)
                details['used_percent'] = mem.percent
            
            if details['available_gb'] < self.MIN_MEMORY_GB:
                self.recommendations.append(
                    f"Low memory. Minimum {self.MIN_MEMORY_GB}GB recommended for smooth operation."
                )
                return HealthStatus.WARNING, f"Low memory: {details['available_gb']}GB available", details
            else:
                return HealthStatus.HEALTHY, f"{details['available_gb']}GB memory available", details
                
        except ImportError:
            details['note'] = "psutil not installed, limited memory info"
            return HealthStatus.UNKNOWN, "Could not check memory (install psutil)", details
        except Exception as e:
            return HealthStatus.UNKNOWN, f"Could not check memory: {e}", details
    
    # ===========================================
    # Network Checks
    # ===========================================
    
    def check_network_connectivity(self) -> Tuple[HealthStatus, str, Dict]:
        """Check basic network connectivity"""
        details = {'tests': []}
        
        test_hosts = [
            ('8.8.8.8', 53, 'Google DNS'),
            ('1.1.1.1', 53, 'Cloudflare DNS'),
        ]
        
        successful = 0
        for host, port, name in test_hosts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    details['tests'].append({'host': name, 'status': 'reachable'})
                    successful += 1
                else:
                    details['tests'].append({'host': name, 'status': 'unreachable'})
            except Exception as e:
                details['tests'].append({'host': name, 'status': f'error: {e}'})
        
        if successful == len(test_hosts):
            return HealthStatus.HEALTHY, "Network connectivity OK", details
        elif successful > 0:
            return HealthStatus.WARNING, "Partial network connectivity", details
        else:
            self.recommendations.append("Check network connection and firewall settings")
            return HealthStatus.CRITICAL, "No network connectivity", details
    
    def check_local_network(self) -> Tuple[HealthStatus, str, Dict]:
        """Check local network interface"""
        details = {'interfaces': []}
        
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            details['hostname'] = hostname
            details['local_ip'] = local_ip
            
            # Try to get all interfaces
            try:
                import netifaces
                interfaces = netifaces.interfaces()
                for iface in interfaces:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            details['interfaces'].append({
                                'name': iface,
                                'ip': addr.get('addr'),
                                'netmask': addr.get('netmask')
                            })
            except ImportError:
                pass
            
            if local_ip and not local_ip.startswith('127.'):
                return HealthStatus.HEALTHY, f"Local network OK ({local_ip})", details
            else:
                return HealthStatus.WARNING, "Only localhost available", details
                
        except Exception as e:
            return HealthStatus.WARNING, f"Could not determine local network: {e}", details
    
    # ===========================================
    # Dependency Checks
    # ===========================================
    
    def check_python_version(self) -> Tuple[HealthStatus, str, Dict]:
        """Check Python version"""
        details = {
            'version': platform.python_version(),
            'implementation': platform.python_implementation(),
            'executable': sys.executable
        }
        
        major, minor = sys.version_info[:2]
        if major >= 3 and minor >= 8:
            return HealthStatus.HEALTHY, f"Python {details['version']}", details
        elif major >= 3 and minor >= 6:
            self.recommendations.append("Consider upgrading to Python 3.8+ for best compatibility")
            return HealthStatus.WARNING, f"Python {details['version']} (3.8+ recommended)", details
        else:
            self.recommendations.append("Upgrade to Python 3.8 or higher")
            return HealthStatus.CRITICAL, f"Python {details['version']} not supported", details
    
    def check_python_modules(self) -> Tuple[HealthStatus, str, Dict]:
        """Check required Python modules"""
        details = {'installed': [], 'missing': []}
        
        for module in self.REQUIRED_PYTHON_MODULES:
            try:
                __import__(module)
                details['installed'].append(module)
            except ImportError:
                details['missing'].append(module)
        
        if details['missing']:
            self.recommendations.append(
                f"Install missing modules: pip install {' '.join(details['missing'])}"
            )
            return HealthStatus.WARNING, f"{len(details['missing'])} modules missing", details
        else:
            return HealthStatus.HEALTHY, f"All {len(details['installed'])} modules installed", details
    
    def check_system_commands(self) -> Tuple[HealthStatus, str, Dict]:
        """Check required system commands"""
        details = {'available': [], 'missing': []}
        
        for cmd in self.REQUIRED_COMMANDS:
            if shutil.which(cmd):
                details['available'].append(cmd)
            else:
                details['missing'].append(cmd)
        
        if details['missing']:
            return HealthStatus.WARNING, f"{len(details['missing'])} commands missing", details
        else:
            return HealthStatus.HEALTHY, "All required commands available", details
    
    # ===========================================
    # File System Checks
    # ===========================================
    
    def check_output_directory(self) -> Tuple[HealthStatus, str, Dict]:
        """Check output directory exists and is writable"""
        details = {}
        output_dir = Path('./output')
        
        try:
            if not output_dir.exists():
                output_dir.mkdir(parents=True, exist_ok=True)
                details['created'] = True
            
            # Test write permission
            test_file = output_dir / '.health_check_test'
            test_file.write_text('test')
            test_file.unlink()
            
            details['path'] = str(output_dir.absolute())
            details['writable'] = True
            return HealthStatus.HEALTHY, "Output directory ready", details
            
        except PermissionError:
            self.recommendations.append(f"Fix permissions: chmod -R 755 {output_dir}")
            return HealthStatus.CRITICAL, "Output directory not writable", details
        except Exception as e:
            return HealthStatus.CRITICAL, f"Output directory error: {e}", details
    
    def check_config_files(self) -> Tuple[HealthStatus, str, Dict]:
        """Check configuration files exist"""
        details = {'found': [], 'missing': []}
        
        config_files = [
            'docker-compose.yml',
            '.env.example',
            'Makefile',
            'README.md'
        ]
        
        for config in config_files:
            if Path(config).exists():
                details['found'].append(config)
            else:
                details['missing'].append(config)
        
        # Check for .env file
        if Path('.env').exists():
            details['env_configured'] = True
        else:
            details['env_configured'] = False
            if Path('.env.example').exists():
                self.recommendations.append("Copy .env.example to .env and configure")
        
        if details['missing']:
            return HealthStatus.WARNING, f"{len(details['missing'])} config files missing", details
        else:
            return HealthStatus.HEALTHY, "All config files present", details
    
    # ===========================================
    # Main Health Check Methods
    # ===========================================
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        return {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': socket.gethostname(),
            'python_version': platform.python_version(),
            'processor': platform.processor(),
            'timestamp': datetime.now().isoformat()
        }
    
    def full_health_check(self) -> HealthReport:
        """Run all health checks and generate report"""
        self.checks = []
        self.recommendations = []
        
        self._log("Starting full health check...")
        
        # Run all checks
        check_methods = [
            ('Docker Installation', self.check_docker_installed),
            ('Docker Daemon', self.check_docker_running),
            ('Docker Compose', self.check_docker_compose),
            ('Container Status', self.check_containers_status),
            ('Disk Space', self.check_disk_space),
            ('Memory', self.check_memory),
            ('Network Connectivity', self.check_network_connectivity),
            ('Local Network', self.check_local_network),
            ('Python Version', self.check_python_version),
            ('Python Modules', self.check_python_modules),
            ('System Commands', self.check_system_commands),
            ('Output Directory', self.check_output_directory),
            ('Config Files', self.check_config_files),
        ]
        
        for name, method in check_methods:
            self._run_check(name, method)
        
        # Calculate summary
        summary = {
            'healthy': sum(1 for c in self.checks if c.status == HealthStatus.HEALTHY),
            'warning': sum(1 for c in self.checks if c.status == HealthStatus.WARNING),
            'critical': sum(1 for c in self.checks if c.status == HealthStatus.CRITICAL),
            'unknown': sum(1 for c in self.checks if c.status == HealthStatus.UNKNOWN),
            'total': len(self.checks)
        }
        
        # Determine overall status
        if summary['critical'] > 0:
            overall_status = HealthStatus.CRITICAL
        elif summary['warning'] > 0:
            overall_status = HealthStatus.WARNING
        elif summary['unknown'] > 0:
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY
        
        # Create report
        report = HealthReport(
            overall_status=overall_status,
            checks=self.checks,
            summary=summary,
            recommendations=self.recommendations,
            system_info=self.get_system_info()
        )
        
        self._log(f"Health check complete: {overall_status.value}")
        return report
    
    def quick_check(self) -> HealthReport:
        """Run quick essential health checks"""
        self.checks = []
        self.recommendations = []
        
        quick_checks = [
            ('Docker Daemon', self.check_docker_running),
            ('Container Status', self.check_containers_status),
            ('Disk Space', self.check_disk_space),
            ('Output Directory', self.check_output_directory),
        ]
        
        for name, method in quick_checks:
            self._run_check(name, method)
        
        summary = {
            'healthy': sum(1 for c in self.checks if c.status == HealthStatus.HEALTHY),
            'warning': sum(1 for c in self.checks if c.status == HealthStatus.WARNING),
            'critical': sum(1 for c in self.checks if c.status == HealthStatus.CRITICAL),
            'unknown': sum(1 for c in self.checks if c.status == HealthStatus.UNKNOWN),
            'total': len(self.checks)
        }
        
        if summary['critical'] > 0:
            overall_status = HealthStatus.CRITICAL
        elif summary['warning'] > 0:
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY
        
        return HealthReport(
            overall_status=overall_status,
            checks=self.checks,
            summary=summary,
            recommendations=self.recommendations,
            system_info=self.get_system_info()
        )
    
    def print_report(self, report: HealthReport, color: bool = True):
        """Print health report to console"""
        # Color codes
        if color and sys.stdout.isatty():
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            RED = '\033[91m'
            BLUE = '\033[94m'
            RESET = '\033[0m'
            BOLD = '\033[1m'
        else:
            GREEN = YELLOW = RED = BLUE = RESET = BOLD = ''
        
        status_colors = {
            HealthStatus.HEALTHY: GREEN,
            HealthStatus.WARNING: YELLOW,
            HealthStatus.CRITICAL: RED,
            HealthStatus.UNKNOWN: BLUE
        }
        
        status_icons = {
            HealthStatus.HEALTHY: '✓',
            HealthStatus.WARNING: '⚠',
            HealthStatus.CRITICAL: '✗',
            HealthStatus.UNKNOWN: '?'
        }
        
        print(f"\n{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}║          LAN Reconnaissance Framework Health Check            ║{RESET}")
        print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
        
        # Overall status
        color = status_colors[report.overall_status]
        icon = status_icons[report.overall_status]
        print(f"Overall Status: {color}{icon} {report.overall_status.value.upper()}{RESET}\n")
        
        # Individual checks
        print(f"{BOLD}Health Checks:{RESET}")
        print("─" * 60)
        
        for check in report.checks:
            color = status_colors[check.status]
            icon = status_icons[check.status]
            print(f"  {color}{icon}{RESET} {check.name}: {check.message} ({check.duration_ms:.0f}ms)")
        
        print()
        
        # Summary
        print(f"{BOLD}Summary:{RESET}")
        print(f"  {GREEN}✓ Healthy:{RESET} {report.summary['healthy']}")
        print(f"  {YELLOW}⚠ Warning:{RESET} {report.summary['warning']}")
        print(f"  {RED}✗ Critical:{RESET} {report.summary['critical']}")
        print(f"  {BLUE}? Unknown:{RESET} {report.summary['unknown']}")
        print()
        
        # Recommendations
        if report.recommendations:
            print(f"{BOLD}Recommendations:{RESET}")
            for rec in report.recommendations:
                print(f"  • {rec}")
            print()
        
        # System info
        print(f"{BOLD}System Information:{RESET}")
        print(f"  Platform: {report.system_info['platform']} {report.system_info['platform_release']}")
        print(f"  Python: {report.system_info['python_version']}")
        print(f"  Host: {report.system_info['hostname']}")
        print(f"  Time: {report.timestamp}")
        print()


# ===========================================
# CLI Interface
# ===========================================

def main():
    """Main CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='LAN Reconnaissance Framework Health Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python health_checker.py              Full health check
  python health_checker.py --quick      Quick essential checks
  python health_checker.py --json       Output as JSON
  python health_checker.py --verbose    Verbose output
        """
    )
    
    parser.add_argument('--quick', '-q', action='store_true',
                        help='Run quick essential checks only')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output as JSON')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    
    args = parser.parse_args()
    
    checker = HealthChecker(verbose=args.verbose)
    
    if args.quick:
        report = checker.quick_check()
    else:
        report = checker.full_health_check()
    
    if args.json:
        print(report.to_json())
    else:
        checker.print_report(report, color=not args.no_color)
    
    # Exit with appropriate code
    if report.overall_status == HealthStatus.CRITICAL:
        sys.exit(2)
    elif report.overall_status == HealthStatus.WARNING:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
