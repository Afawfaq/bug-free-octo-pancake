#!/usr/bin/env python3

import os
import sys
import time
import json
import subprocess
from datetime import datetime

class ReconOrchestrator:
    def __init__(self):
        self.output_dir = "/output"
        self.target_network = os.getenv("TARGET_NETWORK", "192.168.68.0/24")
        self.router_ip = os.getenv("ROUTER_IP", "192.168.68.1")
        self.chromecast_ip = os.getenv("CHROMECAST_IP", "192.168.68.56")
        self.tv_ip = os.getenv("TV_IP", "192.168.68.62")
        self.printer_ip = os.getenv("PRINTER_IP", "192.168.68.54")
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}", flush=True)
    
    def run_container_command(self, container, command):
        """Execute command in a container"""
        self.log(f"Running command in {container}: {command}")
        try:
            result = subprocess.run(
                ["docker", "exec", container, "bash", "-c", command],
                capture_output=True,
                text=True,
                timeout=600
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out in {container}")
            return False
        except Exception as e:
            self.log(f"Error running command in {container}: {e}")
            return False
    
    def wait_for_containers(self):
        """Wait for all containers to be ready"""
        self.log("Waiting for containers to be ready...")
        containers = [
            "recon-passive",
            "recon-discovery", 
            "recon-fingerprint",
            "recon-iot",
            "recon-nuclei",
            "recon-webshot",
            "recon-report"
        ]
        
        max_attempts = 30
        for attempt in range(max_attempts):
            all_ready = True
            for container in containers:
                result = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Running}}", container],
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0 or result.stdout.strip() != "true":
                    all_ready = False
                    break
            
            if all_ready:
                self.log("All containers are ready!")
                return True
            
            time.sleep(2)
        
        self.log("Warning: Not all containers became ready")
        return False
    
    def phase_1_passive_recon(self):
        """Phase 1: Passive reconnaissance"""
        self.log("=" * 60)
        self.log("PHASE 1: PASSIVE RECONNAISSANCE")
        self.log("=" * 60)
        
        self.run_container_command(
            "recon-passive",
            "/usr/local/bin/passive_scan.sh /output/passive 30"
        )
        
        self.log("Phase 1 complete")
    
    def phase_2_active_discovery(self):
        """Phase 2: Active host discovery"""
        self.log("=" * 60)
        self.log("PHASE 2: ACTIVE HOST DISCOVERY")
        self.log("=" * 60)
        
        self.run_container_command(
            "recon-discovery",
            f"/usr/local/bin/discovery_scan.sh {self.target_network} /output/discovery"
        )
        
        self.log("Phase 2 complete")
    
    def phase_3_fingerprinting(self):
        """Phase 3: Service fingerprinting"""
        self.log("=" * 60)
        self.log("PHASE 3: SERVICE FINGERPRINTING")
        self.log("=" * 60)
        
        self.run_container_command(
            "recon-fingerprint",
            "/usr/local/bin/fingerprint_scan.sh /output/discovery/discovered_hosts.json /output/fingerprint"
        )
        
        self.log("Phase 3 complete")
    
    def phase_4_iot_enumeration(self):
        """Phase 4: IoT device enumeration"""
        self.log("=" * 60)
        self.log("PHASE 4: IoT/UPnP DEVICE ENUMERATION")
        self.log("=" * 60)
        
        self.run_container_command(
            "recon-iot",
            "/usr/local/bin/iot_scan.sh /output/iot"
        )
        
        self.log("Phase 4 complete")
    
    def phase_5_nuclei_scan(self):
        """Phase 5: Nuclei security scanning"""
        self.log("=" * 60)
        self.log("PHASE 5: NUCLEI SECURITY SCANNING")
        self.log("=" * 60)
        
        self.run_container_command(
            "recon-nuclei",
            "/usr/local/bin/nuclei_scan.sh /output/discovery/discovered_hosts.json /output/nuclei"
        )
        
        self.log("Phase 5 complete")
    
    def phase_6_web_screenshots(self):
        """Phase 6: Web interface screenshots"""
        self.log("=" * 60)
        self.log("PHASE 6: WEB INTERFACE SCREENSHOTS")
        self.log("=" * 60)
        
        self.run_container_command(
            "recon-webshot",
            "/usr/local/bin/webshot_scan.sh /output/discovery/discovered_hosts.json /output/webshot"
        )
        
        self.log("Phase 6 complete")
    
    def phase_7_report_generation(self):
        """Phase 7: Report generation"""
        self.log("=" * 60)
        self.log("PHASE 7: REPORT GENERATION")
        self.log("=" * 60)
        
        self.run_container_command(
            "recon-report",
            "/usr/local/bin/report_builder.py /output"
        )
        
        self.log("Phase 7 complete")
    
    def run(self):
        """Run the complete reconnaissance workflow"""
        self.log("🚀 STARTING LAN RECONNAISSANCE FRAMEWORK")
        self.log(f"Target Network: {self.target_network}")
        self.log(f"Router IP: {self.router_ip}")
        self.log(f"Chromecast IP: {self.chromecast_ip}")
        self.log(f"TV IP: {self.tv_ip}")
        self.log(f"Printer IP: {self.printer_ip}")
        
        # Wait for containers
        if not self.wait_for_containers():
            self.log("Warning: Proceeding with available containers")
        
        # Execute reconnaissance phases
        start_time = time.time()
        
        try:
            self.phase_1_passive_recon()
            self.phase_2_active_discovery()
            self.phase_3_fingerprinting()
            self.phase_4_iot_enumeration()
            self.phase_5_nuclei_scan()
            self.phase_6_web_screenshots()
            self.phase_7_report_generation()
        except KeyboardInterrupt:
            self.log("Reconnaissance interrupted by user")
            sys.exit(1)
        except Exception as e:
            self.log(f"Error during reconnaissance: {e}")
            sys.exit(1)
        
        elapsed = time.time() - start_time
        self.log("=" * 60)
        self.log(f"✅ RECONNAISSANCE COMPLETE in {elapsed:.2f} seconds")
        self.log(f"📁 Results available in: {self.output_dir}")
        self.log("=" * 60)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print reconnaissance summary"""
        self.log("\n" + "=" * 60)
        self.log("RECONNAISSANCE SUMMARY")
        self.log("=" * 60)
        
        # Count discovered hosts
        hosts_file = os.path.join(self.output_dir, "discovery", "discovered_hosts.json")
        if os.path.exists(hosts_file):
            with open(hosts_file) as f:
                hosts = json.load(f)
                self.log(f"📊 Discovered Hosts: {len(hosts)}")
        
        # Count nuclei findings
        nuclei_file = os.path.join(self.output_dir, "nuclei", "nuclei_results.json")
        if os.path.exists(nuclei_file):
            try:
                with open(nuclei_file) as f:
                    findings = [json.loads(line) for line in f]
                    self.log(f"🛡️  Security Findings: {len(findings)}")
            except:
                pass
        
        self.log(f"\n📄 HTML Report: {self.output_dir}/report/recon_report.html")
        self.log(f"📊 JSON Report: {self.output_dir}/report/recon_report.json")
        self.log(f"🌐 Network Graph: {self.output_dir}/report/network_topology.png")
        self.log("=" * 60 + "\n")

if __name__ == "__main__":
    orchestrator = ReconOrchestrator()
    orchestrator.run()
