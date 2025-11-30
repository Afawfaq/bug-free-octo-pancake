#!/usr/bin/env python3
"""
Dependency Manager for LAN Reconnaissance Framework v2.5.0

Manages and verifies all framework dependencies including:
- Python packages
- System tools
- Docker images
- Network tools
- Optional components

Usage:
    from dependency_manager import DependencyManager
    
    manager = DependencyManager()
    manager.verify_all()
    manager.install_missing()
"""

import os
import sys
import subprocess
import shutil
import platform
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class DependencyType(Enum):
    """Types of dependencies"""
    PYTHON = "python"
    SYSTEM = "system"
    DOCKER = "docker"
    OPTIONAL = "optional"


class InstallStatus(Enum):
    """Installation status"""
    INSTALLED = "installed"
    MISSING = "missing"
    OUTDATED = "outdated"
    UNAVAILABLE = "unavailable"


@dataclass
class Dependency:
    """Represents a single dependency"""
    name: str
    type: DependencyType
    required: bool = True
    min_version: Optional[str] = None
    install_command: Optional[str] = None
    check_command: Optional[str] = None
    description: str = ""
    status: InstallStatus = InstallStatus.MISSING
    version: Optional[str] = None


class DependencyManager:
    """
    Manages framework dependencies across all categories.
    
    Features:
    - Dependency verification
    - Auto-installation where possible
    - Version checking
    - Platform-specific handling
    - Graceful degradation
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.platform = platform.system().lower()
        self.dependencies: Dict[str, Dependency] = {}
        self._init_dependencies()
    
    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            print(f"[DependencyManager] {message}")
    
    def _init_dependencies(self):
        """Initialize all known dependencies"""
        
        # Python packages (required)
        python_required = [
            ('docker', '5.0.0', 'Docker SDK for Python'),
            ('requests', '2.25.0', 'HTTP library'),
            ('jinja2', '3.0.0', 'Template engine'),
            ('flask', '2.0.0', 'Web framework for API'),
            ('pyyaml', '5.4.0', 'YAML parser'),
            ('networkx', '2.6.0', 'Network graph library'),
        ]
        
        for name, min_ver, desc in python_required:
            self.dependencies[f"python:{name}"] = Dependency(
                name=name,
                type=DependencyType.PYTHON,
                required=True,
                min_version=min_ver,
                install_command=f"pip install {name}>={min_ver}",
                description=desc
            )
        
        # Python packages (optional)
        python_optional = [
            ('psutil', '5.8.0', 'System monitoring'),
            ('netifaces', '0.11.0', 'Network interface detection'),
            ('colorama', '0.4.4', 'Cross-platform colored output'),
            ('python-dotenv', '0.19.0', 'Environment file support'),
            ('watchdog', '2.1.0', 'File system monitoring'),
            ('prometheus-client', '0.12.0', 'Prometheus metrics'),
        ]
        
        for name, min_ver, desc in python_optional:
            self.dependencies[f"python:{name}"] = Dependency(
                name=name,
                type=DependencyType.PYTHON,
                required=False,
                min_version=min_ver,
                install_command=f"pip install {name}>={min_ver}",
                description=desc
            )
        
        # System tools (required)
        system_required = [
            ('docker', 'Docker container runtime'),
            ('git', 'Version control'),
        ]
        
        for name, desc in system_required:
            self.dependencies[f"system:{name}"] = Dependency(
                name=name,
                type=DependencyType.SYSTEM,
                required=True,
                check_command=f"{name} --version",
                description=desc
            )
        
        # System tools (optional but recommended)
        system_optional = [
            ('nmap', 'Network scanner'),
            ('tshark', 'Packet capture'),
            ('arp-scan', 'ARP discovery'),
            ('masscan', 'Fast port scanner'),
            ('nuclei', 'Vulnerability scanner'),
            ('httpx', 'HTTP probe'),
            ('subfinder', 'Subdomain discovery'),
        ]
        
        for name, desc in system_optional:
            self.dependencies[f"system:{name}"] = Dependency(
                name=name,
                type=DependencyType.SYSTEM,
                required=False,
                check_command=f"which {name}",
                description=desc
            )
        
        # Docker images (auto-built)
        docker_images = [
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
        
        for name in docker_images:
            self.dependencies[f"docker:{name}"] = Dependency(
                name=name,
                type=DependencyType.DOCKER,
                required=True,
                install_command="docker compose build",
                description=f"Docker container: {name}"
            )
    
    def _check_python_package(self, name: str, min_version: Optional[str] = None) -> Tuple[InstallStatus, Optional[str]]:
        """Check if a Python package is installed"""
        try:
            pkg = __import__(name.replace('-', '_'))
            version = getattr(pkg, '__version__', None)
            
            if version and min_version:
                from packaging import version as pkg_version
                if pkg_version.parse(version) < pkg_version.parse(min_version):
                    return InstallStatus.OUTDATED, version
            
            return InstallStatus.INSTALLED, version
        except ImportError:
            return InstallStatus.MISSING, None
        except Exception:
            return InstallStatus.UNAVAILABLE, None
    
    def _check_system_command(self, command: str) -> Tuple[InstallStatus, Optional[str]]:
        """Check if a system command is available"""
        try:
            # Extract the command name
            cmd_name = command.split()[0]
            
            # Check if command exists
            if not shutil.which(cmd_name):
                return InstallStatus.MISSING, None
            
            # Try to get version
            try:
                result = subprocess.run(
                    command.split(),
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                version = result.stdout.strip() or result.stderr.strip()
                # Extract version number
                import re
                match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
                version = match.group(1) if match else "unknown"
            except Exception:
                version = "unknown"
            
            return InstallStatus.INSTALLED, version
        except Exception:
            return InstallStatus.UNAVAILABLE, None
    
    def _check_docker_image(self, image_name: str) -> Tuple[InstallStatus, Optional[str]]:
        """Check if a Docker image exists"""
        try:
            result = subprocess.run(
                ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}', image_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return InstallStatus.INSTALLED, result.stdout.strip().split('\n')[0]
            
            # Check if container exists
            result = subprocess.run(
                ['docker', 'ps', '-a', '--filter', f'name={image_name}', '--format', '{{.Names}}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and image_name in result.stdout:
                return InstallStatus.INSTALLED, "container exists"
            
            return InstallStatus.MISSING, None
        except Exception:
            return InstallStatus.UNAVAILABLE, None
    
    def verify_dependency(self, key: str) -> Dependency:
        """Verify a single dependency"""
        if key not in self.dependencies:
            raise KeyError(f"Unknown dependency: {key}")
        
        dep = self.dependencies[key]
        
        if dep.type == DependencyType.PYTHON:
            dep.status, dep.version = self._check_python_package(dep.name, dep.min_version)
        elif dep.type == DependencyType.SYSTEM:
            if dep.check_command:
                dep.status, dep.version = self._check_system_command(dep.check_command)
            else:
                dep.status, dep.version = self._check_system_command(f"{dep.name} --version")
        elif dep.type == DependencyType.DOCKER:
            dep.status, dep.version = self._check_docker_image(dep.name)
        
        self._log(f"Checked {key}: {dep.status.value}")
        return dep
    
    def verify_all(self) -> Dict[str, Dependency]:
        """Verify all dependencies"""
        for key in self.dependencies:
            self.verify_dependency(key)
        return self.dependencies
    
    def get_missing(self, include_optional: bool = False) -> List[Dependency]:
        """Get list of missing dependencies"""
        missing = []
        for dep in self.dependencies.values():
            if dep.status in (InstallStatus.MISSING, InstallStatus.OUTDATED):
                if dep.required or include_optional:
                    missing.append(dep)
        return missing
    
    def install_python_package(self, name: str, min_version: Optional[str] = None) -> bool:
        """Install a Python package"""
        try:
            cmd = [sys.executable, '-m', 'pip', 'install']
            if min_version:
                cmd.append(f"{name}>={min_version}")
            else:
                cmd.append(name)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return result.returncode == 0
        except Exception as e:
            self._log(f"Failed to install {name}: {e}")
            return False
    
    def install_missing_python(self) -> Dict[str, bool]:
        """Install all missing Python packages"""
        results = {}
        
        for key, dep in self.dependencies.items():
            if dep.type == DependencyType.PYTHON and dep.status == InstallStatus.MISSING:
                success = self.install_python_package(dep.name, dep.min_version)
                results[dep.name] = success
                if success:
                    dep.status = InstallStatus.INSTALLED
        
        return results
    
    def generate_requirements_txt(self, include_optional: bool = False) -> str:
        """Generate requirements.txt content"""
        lines = []
        
        for key, dep in sorted(self.dependencies.items()):
            if dep.type == DependencyType.PYTHON:
                if dep.required or include_optional:
                    if dep.min_version:
                        lines.append(f"{dep.name}>={dep.min_version}")
                    else:
                        lines.append(dep.name)
        
        return '\n'.join(lines)
    
    def print_status(self, show_all: bool = False):
        """Print dependency status to console"""
        # Color codes
        if sys.stdout.isatty():
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            RED = '\033[91m'
            RESET = '\033[0m'
            BOLD = '\033[1m'
        else:
            GREEN = YELLOW = RED = RESET = BOLD = ''
        
        status_colors = {
            InstallStatus.INSTALLED: GREEN,
            InstallStatus.MISSING: RED,
            InstallStatus.OUTDATED: YELLOW,
            InstallStatus.UNAVAILABLE: RED
        }
        
        status_icons = {
            InstallStatus.INSTALLED: '✓',
            InstallStatus.MISSING: '✗',
            InstallStatus.OUTDATED: '↑',
            InstallStatus.UNAVAILABLE: '?'
        }
        
        print(f"\n{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}║              Dependency Status Report                         ║{RESET}")
        print(f"{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}\n")
        
        # Group by type
        by_type: Dict[DependencyType, List[Dependency]] = {}
        for dep in self.dependencies.values():
            if dep.type not in by_type:
                by_type[dep.type] = []
            by_type[dep.type].append(dep)
        
        type_names = {
            DependencyType.PYTHON: "Python Packages",
            DependencyType.SYSTEM: "System Tools",
            DependencyType.DOCKER: "Docker Images",
            DependencyType.OPTIONAL: "Optional Components"
        }
        
        for dep_type, deps in by_type.items():
            print(f"{BOLD}{type_names.get(dep_type, dep_type.value)}:{RESET}")
            print("─" * 50)
            
            for dep in sorted(deps, key=lambda x: x.name):
                if not show_all and dep.status == InstallStatus.INSTALLED and not dep.required:
                    continue
                
                color = status_colors[dep.status]
                icon = status_icons[dep.status]
                required = "(required)" if dep.required else "(optional)"
                version = f" v{dep.version}" if dep.version else ""
                
                print(f"  {color}{icon}{RESET} {dep.name}{version} {required}")
            
            print()
        
        # Summary
        installed = sum(1 for d in self.dependencies.values() if d.status == InstallStatus.INSTALLED)
        missing = sum(1 for d in self.dependencies.values() if d.status == InstallStatus.MISSING and d.required)
        total = len(self.dependencies)
        
        print(f"{BOLD}Summary:{RESET}")
        print(f"  Total: {total}")
        print(f"  {GREEN}Installed:{RESET} {installed}")
        print(f"  {RED}Missing (required):{RESET} {missing}")


# ===========================================
# CLI Interface
# ===========================================

def main():
    """Main CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='LAN Reconnaissance Framework Dependency Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('action', nargs='?', default='check',
                        choices=['check', 'install', 'requirements'],
                        help='Action to perform')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Include optional dependencies')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    
    args = parser.parse_args()
    
    manager = DependencyManager(verbose=args.verbose)
    manager.verify_all()
    
    if args.action == 'check':
        manager.print_status(show_all=args.all)
        
        missing = manager.get_missing()
        if missing:
            print("\nTo install missing Python packages, run:")
            print("  python dependency_manager.py install")
            sys.exit(1)
    
    elif args.action == 'install':
        print("Installing missing Python packages...")
        results = manager.install_missing_python()
        
        for name, success in results.items():
            status = "✓" if success else "✗"
            print(f"  {status} {name}")
        
        if all(results.values()):
            print("\nAll packages installed successfully!")
        else:
            print("\nSome packages failed to install.")
            sys.exit(1)
    
    elif args.action == 'requirements':
        print(manager.generate_requirements_txt(include_optional=args.all))


if __name__ == '__main__':
    main()
