#!/usr/bin/env python3
"""
LAN Reconnaissance Framework Orchestrator
==========================================

Coordinates all reconnaissance modules in a multi-phase pipeline.
Supports parallel execution for independent phases to improve performance.

Version: 2.0.0
Author: LAN Recon Team
"""

import os
import sys
import time
import json
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# ANSI color codes for enhanced output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ReconOrchestrator:
    """
    Main orchestrator for the LAN Reconnaissance Framework.
    
    Coordinates multiple containerized scanning modules through
    sequential and parallel execution phases.
    """
    
    VERSION = "2.0.0"
    
    # Container names as class constants for maintainability
    CONTAINERS = [
        "recon-passive",
        "recon-discovery",
        "recon-fingerprint",
        "recon-iot",
        "recon-nuclei",
        "recon-webshot",
        "recon-report",
        "recon-advanced-monitor",
        "recon-attack-surface",
        "recon-credential-attacks",
        "recon-patch-cadence",
        "recon-data-flow",
        "recon-wifi-attacks"
        "recon-trust-mapping"
    ]
    
    def __init__(self):
        self.output_dir = "/output"
        self.target_network = os.getenv("TARGET_NETWORK", "192.168.68.0/24")
        self.router_ip = os.getenv("ROUTER_IP", "192.168.68.1")
        self.chromecast_ip = os.getenv("CHROMECAST_IP", "192.168.68.56")
        self.tv_ip = os.getenv("TV_IP", "192.168.68.62")
        self.printer_ip = os.getenv("PRINTER_IP", "192.168.68.54")
        self.dlna_ips = os.getenv("DLNA_IPS", "192.168.68.52,192.168.68.62")
        
        # Configuration options
        self.passive_duration = int(os.getenv("PASSIVE_DURATION", "30"))
        self.parallel_execution = os.getenv("PARALLEL_EXECUTION", "true").lower() == "true"
        self.verbose = os.getenv("VERBOSE", "false").lower() == "true"
        self.timeout = int(os.getenv("SCAN_TIMEOUT", "1200"))
        self.focused_scan = os.getenv("FOCUSED_SCAN", "false").lower() == "true"
        
        # Phase statistics
        self.phase_stats = {}
        self.errors = []
        
    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with timestamps and color support."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        color_map = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.WARNING,
            "ERROR": Colors.FAIL,
            "HEADER": Colors.HEADER + Colors.BOLD,
        }
        
        color = color_map.get(level, "")
        reset = Colors.ENDC if color else ""
        
        print(f"{color}[{timestamp}] [{level}] {message}{reset}", flush=True)
    
    def run_container_command(self, container: str, command: str, 
                               timeout: Optional[int] = None) -> Tuple[bool, str, str]:
        """
        Execute command in a container with enhanced error handling.
        
        Args:
            container: Name of the Docker container
            command: Command to execute
            timeout: Optional timeout override
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        timeout = timeout or self.timeout
        
        if self.verbose:
            self.log(f"Executing in {container}: {command}")
        
        try:
            result = subprocess.run(
                ["docker", "exec", container, "bash", "-c", command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            success = result.returncode == 0
            if not success and self.verbose:
                self.log(f"Command failed with code {result.returncode}", "WARNING")
                
            return success, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out after {timeout}s in {container}", "WARNING")
            return False, "", "Timeout"
        except Exception as e:
            self.log(f"Error running command in {container}: {e}", "ERROR")
            self.errors.append({"container": container, "error": str(e)})
            return False, "", str(e)
    
    def check_container_health(self, container: str) -> bool:
        """Check if a container is running and healthy."""
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container],
                capture_output=True,
                text=True
            )
            return result.returncode == 0 and result.stdout.strip() == "true"
        except Exception:
            return False
    
    def wait_for_containers(self) -> bool:
        """Wait for all containers to be ready with progress indicator."""
        self.log("Waiting for containers to be ready...", "INFO")
        
        max_attempts = 30
        for attempt in range(max_attempts):
            ready_containers = []
            not_ready = []
            
            for container in self.CONTAINERS:
                if self.check_container_health(container):
                    ready_containers.append(container)
                else:
                    not_ready.append(container)
            
            progress = len(ready_containers) / len(self.CONTAINERS) * 100
            self.log(f"Container readiness: {progress:.0f}% ({len(ready_containers)}/{len(self.CONTAINERS)})", "INFO")
            
            if len(ready_containers) == len(self.CONTAINERS):
                self.log("All containers are ready!", "SUCCESS")
                return True
            
            time.sleep(2)
        
        if not_ready:
            self.log(f"Warning: These containers did not become ready: {', '.join(not_ready)}", "WARNING")
        
        return len(ready_containers) > 0
    
    def phase_1_passive_recon(self) -> Dict:
        """Phase 1: Passive reconnaissance - non-intrusive network discovery."""
        phase_name = "Passive Reconnaissance"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 1: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-passive",
            f"/usr/local/bin/passive_scan.sh /output/passive {self.passive_duration}"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_1"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 1 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_1"]
    
    def phase_2_active_discovery(self) -> Dict:
        """Phase 2: Active host discovery - port scanning and enumeration."""
        phase_name = "Active Host Discovery"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 2: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        # In focused scan mode, scan only known device IPs instead of full network
        if self.focused_scan:
            # Build list of known device IPs, filtering out empty/None values
            known_ips = []
            for ip in [self.router_ip, self.chromecast_ip, self.tv_ip, self.printer_ip]:
                if ip and ip.strip():
                    known_ips.append(ip.strip())
            # Add DLNA IPs
            if self.dlna_ips:
                for ip in self.dlna_ips.split(','):
                    if ip and ip.strip():
                        known_ips.append(ip.strip())
            # Remove duplicates
            known_ips = list(set(known_ips))
            
            if not known_ips:
                self.log("Warning: No valid device IPs found for focused scan, falling back to full network scan", "WARNING")
                target = self.target_network
            else:
                target = ",".join(known_ips)
                self.log(f"Focused scan mode: scanning {len(known_ips)} known devices", "INFO")
        else:
            target = self.target_network
        
        success, stdout, stderr = self.run_container_command(
            "recon-discovery",
            f"/usr/local/bin/discovery_scan.sh {target} /output/discovery"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_2"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed,
            "focused_scan": self.focused_scan
        }
        
        self.log(f"Phase 2 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_2"]
    
    def phase_3_fingerprinting(self) -> Dict:
        """Phase 3: Service fingerprinting - OS and service identification."""
        phase_name = "Service Fingerprinting"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 3: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-fingerprint",
            "/usr/local/bin/fingerprint_scan.sh /output/discovery/discovered_hosts.json /output/fingerprint"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_3"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 3 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_3"]
    
    def phase_4_iot_enumeration(self) -> Dict:
        """Phase 4: IoT device enumeration - specialized IoT scanning."""
        phase_name = "IoT/UPnP Device Enumeration"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 4: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-iot",
            "/usr/local/bin/iot_scan.sh /output/iot"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_4"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 4 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_4"]
    
    def phase_5_nuclei_scan(self) -> Dict:
        """Phase 5: Nuclei security scanning - vulnerability detection."""
        phase_name = "Nuclei Security Scanning"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 5: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-nuclei",
            "/usr/local/bin/nuclei_scan.sh /output/discovery/discovered_hosts.json /output/nuclei"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_5"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 5 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_5"]
    
    def phase_6_web_screenshots(self) -> Dict:
        """Phase 6: Web interface screenshots - visual reconnaissance."""
        phase_name = "Web Interface Screenshots"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 6: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-webshot",
            "/usr/local/bin/webshot_scan.sh /output/discovery/discovered_hosts.json /output/webshot"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_6"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 6 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_6"]
    
    def phase_7_advanced_monitoring(self) -> Dict:
        """Phase 7: Advanced monitoring - PKI, DHCP profiling, DNS analysis."""
        phase_name = "Advanced Monitoring"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 7: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-advanced-monitor",
            "/usr/local/bin/advanced_scan.sh /output/advanced"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_7"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 7 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_7"]
    
    def phase_8_attack_surface(self) -> Dict:
        """Phase 8: Attack surface analysis - stress testing and trust assumptions."""
        phase_name = "Attack Surface Analysis"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 8: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-attack-surface",
            "/usr/local/bin/attack_surface_scan.sh /output/attack-surface"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_8"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 8 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_8"]
    
    def phase_9_credential_attacks(self) -> Dict:
        """Phase 9: Credential lifecycle weakness assessment."""
        phase_name = "Credential Attacks"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 9: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        # Get discovered IPs for credential testing
        discovered_ips = "/output/discovery/discovered_ips.txt"
        
        success, stdout, stderr = self.run_container_command(
            "recon-credential-attacks",
            f"/usr/local/bin/credential_scan.sh /output/credential-attacks {discovered_ips}"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_9"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 9 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_9"]
    
    def phase_10_patch_cadence(self) -> Dict:
        """Phase 10: Device update and patch cadence mapping."""
        phase_name = "Patch Cadence Analysis"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 10: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        # Get discovered IPs for patch analysis
        discovered_ips = "/output/discovery/discovered_ips.txt"
        
        success, stdout, stderr = self.run_container_command(
            "recon-patch-cadence",
            f"/usr/local/bin/patch_scan.sh /output/patch-cadence {discovered_ips}"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_10"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 10 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_10"]
    
    def phase_11_report_generation(self) -> Dict:
        """Phase 11: Report generation - consolidate all findings."""
        phase_name = "Report Generation"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 11: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        success, stdout, stderr = self.run_container_command(
            "recon-report",
            "/usr/local/bin/report_builder.py /output"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_11"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 11 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_11"]
    
    def phase_12_data_flow_analysis(self) -> Dict:
        """Phase 12: Data flow graphing and anomaly detection."""
        phase_name = "Data Flow Analysis"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 12: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        # Get capture duration from environment or use default
        capture_duration = os.getenv("CAPTURE_DURATION", "300")
        
        success, stdout, stderr = self.run_container_command(
            "recon-data-flow",
            f"/usr/local/bin/data_flow_scan.sh /output/data-flow {capture_duration}"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_12"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 12 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_12"]
    
    def phase_13_wifi_attack_surface(self) -> Dict:
        """Phase 13: WiFi and RF attack surface analysis."""
        phase_name = "WiFi Attack Surface"
        self.log("=" * 60, "HEADER")
        self.log(f"PHASE 13: {phase_name.upper()}", "HEADER")
        self.log("=" * 60, "HEADER")
        
        start_time = time.time()
        
        # Get WiFi interface and timeout from environment or use defaults
        wifi_interface = os.getenv("WIFI_INTERFACE", "wlan0")
        pmkid_timeout = os.getenv("PMKID_TIMEOUT", "60")
        ble_duration = os.getenv("BLE_DURATION", "10")
        
        success, stdout, stderr = self.run_container_command(
            "recon-wifi-attacks",
        "recon-trust-mapping"
            f"/usr/local/bin/wifi_scan.sh /output/wifi-attacks {wifi_interface} {pmkid_timeout} {ble_duration}"
        )
        
        elapsed = time.time() - start_time
        self.phase_stats["phase_13"] = {
            "name": phase_name,
            "success": success,
            "duration": elapsed
        }
        
        self.log(f"Phase 13 complete in {elapsed:.2f}s", "SUCCESS" if success else "WARNING")
        return self.phase_stats["phase_13"]
    
    
    def phase_14_trust_mapping(self) -> Dict:
        """
        Phase 14: Trust Mapping & Attack Path Analysis
        
        Maps Windows trust relationships, SMB connections, and synthesizes
        complete attack chains for lateral movement analysis.
        """
        phase_name = "Trust Mapping & Attack Path Analysis"
        self.log(f"Starting Phase 14: {phase_name}", "HEADER")
        
        start_time = time.time()
        
        network_range = self.target_network
        output_dir = f"{self.output_dir}/trust-mapping"
        
        cmd = f"{network_range} {self.output_dir}"
        
        success, stdout, stderr = self.run_container_command(
            "recon-trust-mapping",
            cmd,
            timeout=600
        )
        
        duration = time.time() - start_time
        
        if not success:
            self.log(f"Trust mapping completed with warnings (may need Windows environment)", "WARNING")
        else:
            self.log(f"Trust mapping completed successfully", "SUCCESS")
        
        return {
            "phase": 14,
            "name": phase_name,
            "success": True,  # Always succeed even if no Windows hosts found
            "duration": duration,
            "output_dir": output_dir
        }
    def run_parallel_phases(self, phases: List[callable]) -> List[Dict]:
        """Execute multiple phases in parallel for better performance."""
        results = []
        
        with ThreadPoolExecutor(max_workers=len(phases)) as executor:
            futures = {executor.submit(phase): phase.__name__ for phase in phases}
            
            for future in as_completed(futures):
                phase_name = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.log(f"Error in parallel phase {phase_name}: {e}", "ERROR")
                    results.append({"name": phase_name, "success": False, "error": str(e)})
        
        return results
    
    def run(self):
        """
        Run the complete reconnaissance workflow.
        
        Executes all phases in the optimal order, with support for
        parallel execution of independent phases.
        """
        self.log("🚀 STARTING LAN RECONNAISSANCE FRAMEWORK v" + self.VERSION, "HEADER")
        self.log(f"Target Network: {self.target_network}")
        self.log(f"Router IP: {self.router_ip}")
        self.log(f"Chromecast IP: {self.chromecast_ip}")
        self.log(f"TV IP: {self.tv_ip}")
        self.log(f"Printer IP: {self.printer_ip}")
        self.log(f"DLNA IPs: {self.dlna_ips}")
        self.log(f"Scan Timeout: {self.timeout}s")
        self.log(f"Focused Scan: {self.focused_scan}")
        self.log(f"Parallel Execution: {self.parallel_execution}")
        
        # Wait for containers
        if not self.wait_for_containers():
            self.log("Warning: Proceeding with available containers", "WARNING")
        
        # Execute reconnaissance phases
        start_time = time.time()
        
        try:
            # Phase 1: Passive Recon (must be first)
            self.phase_1_passive_recon()
            
            # Phase 2: Active Discovery (must come after passive)
            self.phase_2_active_discovery()
            
            # Phase 3: Fingerprinting (depends on discovery)
            self.phase_3_fingerprinting()
            
            # Phases 4-6 can run in parallel if enabled
            if self.parallel_execution:
                self.log("Running phases 4-6 in parallel...", "INFO")
                self.run_parallel_phases([
                    self.phase_4_iot_enumeration,
                    self.phase_5_nuclei_scan,
                    self.phase_6_web_screenshots
                ])
            else:
                self.phase_4_iot_enumeration()
                self.phase_5_nuclei_scan()
                self.phase_6_web_screenshots()
            
            # Phases 7-8: Advanced analysis can also run in parallel
            if self.parallel_execution:
                self.log("Running phases 7-8 in parallel...", "INFO")
                self.run_parallel_phases([
                    self.phase_7_advanced_monitoring,
                    self.phase_8_attack_surface
                ])
            else:
                self.phase_7_advanced_monitoring()
                self.phase_8_attack_surface()
            
            # Phases 9-10: Offensive modules can run in parallel
            if self.parallel_execution:
                self.log("Running phases 9-10 in parallel...", "INFO")
                self.run_parallel_phases([
                    self.phase_9_credential_attacks,
                    self.phase_10_patch_cadence
                ])
            else:
                self.phase_9_credential_attacks()
                self.phase_10_patch_cadence()
            
            # Phases 12-13: Network analysis modules can run in parallel
            if self.parallel_execution:
                self.log("Running phases 12-13 in parallel...", "INFO")
                self.run_parallel_phases([
                    self.phase_12_data_flow_analysis,
                    self.phase_13_wifi_attack_surface
                ])
            else:
                self.phase_12_data_flow_analysis()
                self.phase_13_wifi_attack_surface()
            phases.append((14, self.phase_14_trust_mapping))
            
            # Phase 11: Report generation (must be last)
            self.phase_11_report_generation()
            
        except KeyboardInterrupt:
            self.log("Reconnaissance interrupted by user", "WARNING")
            sys.exit(1)
        except Exception as e:
            self.log(f"Error during reconnaissance: {e}", "ERROR")
            sys.exit(1)
        
        elapsed = time.time() - start_time
        self.log("=" * 60, "HEADER")
        self.log(f"✅ RECONNAISSANCE COMPLETE in {elapsed:.2f} seconds", "SUCCESS")
        self.log(f"📁 Results available in: {self.output_dir}", "INFO")
        self.log("=" * 60, "HEADER")
        
        # Print summary
        self.print_summary()
        
        # Save execution statistics
        self.save_execution_stats(elapsed)
    
    def print_summary(self):
        """Print comprehensive reconnaissance summary."""
        self.log("\n" + "=" * 60, "HEADER")
        self.log("RECONNAISSANCE SUMMARY", "HEADER")
        self.log("=" * 60, "HEADER")
        
        # Count discovered hosts
        hosts_file = os.path.join(self.output_dir, "discovery", "discovered_hosts.json")
        hosts_count = 0
        if os.path.exists(hosts_file):
            try:
                with open(hosts_file) as f:
                    hosts = json.load(f)
                    hosts_count = len(hosts)
                    self.log(f"📊 Discovered Hosts: {hosts_count}", "INFO")
            except Exception as e:
                self.log(f"Could not read hosts file: {e}", "WARNING")
        
        # Count nuclei findings
        nuclei_file = os.path.join(self.output_dir, "nuclei", "nuclei_results.json")
        findings_count = 0
        if os.path.exists(nuclei_file):
            try:
                with open(nuclei_file) as f:
                    findings = [json.loads(line) for line in f if line.strip()]
                    findings_count = len(findings)
                    self.log(f"🛡️  Security Findings: {findings_count}", "INFO")
                    
                    # Count by severity
                    severity_counts = {}
                    for finding in findings:
                        sev = finding.get("info", {}).get("severity", "unknown")
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    
                    for sev, count in sorted(severity_counts.items()):
                        self.log(f"   - {sev.upper()}: {count}", "INFO")
            except Exception as e:
                self.log(f"Could not read nuclei results: {e}", "WARNING")
        
        # Print phase statistics
        self.log("\n📈 Phase Statistics:", "INFO")
        total_duration = 0
        for phase_id, stats in sorted(self.phase_stats.items()):
            status = "✅" if stats.get("success") else "❌"
            duration = stats.get("duration", 0)
            total_duration += duration
            self.log(f"   {status} {stats.get('name', phase_id)}: {duration:.2f}s", "INFO")
        
        # Print errors if any
        if self.errors:
            self.log(f"\n⚠️  Errors encountered: {len(self.errors)}", "WARNING")
            for error in self.errors:
                self.log(f"   - {error['container']}: {error['error']}", "WARNING")
        
        self.log(f"\n📄 HTML Report: {self.output_dir}/report/recon_report.html", "INFO")
        self.log(f"📊 JSON Report: {self.output_dir}/report/recon_report.json", "INFO")
        self.log(f"🌐 Network Graph: {self.output_dir}/report/network_topology.png", "INFO")
        self.log("=" * 60 + "\n", "HEADER")
    
    def save_execution_stats(self, total_duration: float):
        """Save execution statistics to a JSON file for analysis."""
        stats = {
            "version": self.VERSION,
            "timestamp": datetime.now().isoformat(),
            "target_network": self.target_network,
            "total_duration_seconds": total_duration,
            "phases": self.phase_stats,
            "errors": self.errors,
            "configuration": {
                "router_ip": self.router_ip,
                "chromecast_ip": self.chromecast_ip,
                "tv_ip": self.tv_ip,
                "printer_ip": self.printer_ip,
                "dlna_ips": self.dlna_ips,
                "passive_duration": self.passive_duration,
                "scan_timeout": self.timeout,
                "focused_scan": self.focused_scan,
                "parallel_execution": self.parallel_execution
            }
        }
        
        stats_file = os.path.join(self.output_dir, "execution_stats.json")
        try:
            os.makedirs(os.path.dirname(stats_file), exist_ok=True)
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
            self.log(f"Execution stats saved to {stats_file}", "INFO")
        except Exception as e:
            self.log(f"Could not save execution stats: {e}", "WARNING")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="LAN Reconnaissance Framework Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                      # Run with default settings
  python run.py --verbose            # Run with verbose output
  python run.py --no-parallel        # Disable parallel execution
  python run.py --timeout 1800       # Set extended 30-minute timeout
  python run.py --focused            # Scan only known device IPs

Troubleshooting:
  If Active Host Discovery times out on large networks:
    1. Use --timeout 1800 or higher for larger networks
    2. Use --focused to scan only known device IPs
    3. Reduce the network range (e.g., 192.168.68.0/28 for 16 hosts)
        """
    )
    
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"LAN Reconnaissance Framework v{ReconOrchestrator.VERSION}"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Disable parallel phase execution"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=1200,
        help="Command timeout in seconds (default: 1200)"
    )
    
    parser.add_argument(
        "--focused",
        action="store_true",
        help="Scan only known device IPs instead of full network (faster, more reliable)"
    )
    
    parser.add_argument(
        "--passive-duration",
        type=int,
        default=30,
        help="Duration for passive scanning in seconds (default: 30)"
    )
    
    args = parser.parse_args()
    
    # Override environment variables with CLI arguments
    if args.verbose:
        os.environ["VERBOSE"] = "true"
    if args.no_parallel:
        os.environ["PARALLEL_EXECUTION"] = "false"
    if args.timeout:
        os.environ["SCAN_TIMEOUT"] = str(args.timeout)
    if args.focused:
        os.environ["FOCUSED_SCAN"] = "true"
    if args.passive_duration:
        os.environ["PASSIVE_DURATION"] = str(args.passive_duration)
    
    orchestrator = ReconOrchestrator()
    orchestrator.run()
