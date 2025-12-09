#!/usr/bin/env python3
"""
Continuous Monitoring Daemon
Provides 24/7 background operation with incremental scanning
"""

import os
import sys
import time
import json
import signal
import logging
import schedule
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional
import subprocess
import hashlib

class MonitoringDaemon:
    """24/7 continuous monitoring daemon for LAN security assessment"""
    
    def __init__(self, config_path: str = "/etc/lan-recon/monitor.conf"):
        self.config_path = config_path
        self.config = self.load_config()
        self.running = True
        self.output_dir = Path(self.config.get('output_dir', '/output'))
        self.scan_interval = self.config.get('scan_interval_minutes', 60)
        self.incremental_mode = self.config.get('incremental_mode', True)
        self.device_cache = {}
        self.last_scan_results = {}
        
        # Setup logging
        log_file = self.config.get('log_file', '/var/log/lan-recon-monitor.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.logger.info("Monitoring daemon initialized")
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        default_config = {
            'output_dir': '/output',
            'scan_interval_minutes': 60,
            'incremental_mode': True,
            'log_file': '/var/log/lan-recon-monitor.log',
            'modules_enabled': [
                'discovery',
                'credential-attacks',
                'patch-cadence',
                'data-flow',
                'wifi-attacks',
                'trust-mapping',
                'deception'
            ],
            'alert_on_changes': True,
            'alert_threshold': 'MEDIUM'
        }
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}. Using defaults.")
        
        return default_config
    
    def signal_handler(self, signum, frame):
        """Handle termination signals gracefully"""
        self.logger.info(f"Received signal {signum}. Shutting down gracefully...")
        self.running = False
    
    def get_device_fingerprint(self, device_data: Dict) -> str:
        """Generate fingerprint for device to detect changes"""
        key_data = {
            'ip': device_data.get('ip'),
            'mac': device_data.get('mac'),
            'hostname': device_data.get('hostname'),
            'services': sorted(device_data.get('services', []))
        }
        fingerprint_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()
    
    def detect_device_changes(self, current_devices: List[Dict]) -> Dict:
        """Detect new, changed, and removed devices"""
        current_ips = {d['ip'] for d in current_devices if 'ip' in d}
        previous_ips = set(self.device_cache.keys())
        
        changes = {
            'new_devices': [],
            'changed_devices': [],
            'removed_devices': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # New devices
        for device in current_devices:
            ip = device.get('ip')
            if not ip:
                continue
            
            fingerprint = self.get_device_fingerprint(device)
            
            if ip not in previous_ips:
                changes['new_devices'].append(device)
                self.logger.info(f"New device detected: {ip}")
            elif self.device_cache.get(ip) != fingerprint:
                changes['changed_devices'].append(device)
                self.logger.info(f"Device changed: {ip}")
            
            self.device_cache[ip] = fingerprint
        
        # Removed devices
        removed = previous_ips - current_ips
        for ip in removed:
            changes['removed_devices'].append({'ip': ip})
            self.logger.info(f"Device removed: {ip}")
            del self.device_cache[ip]
        
        return changes
    
    def incremental_scan(self) -> Dict:
        """Perform incremental scan (only scan changed devices)"""
        self.logger.info("Starting incremental scan...")
        
        # Quick discovery scan
        discovery_result = self.run_module('discovery', quick=True)
        
        if not discovery_result:
            self.logger.warning("Discovery scan failed")
            return {}
        
        current_devices = discovery_result.get('devices', [])
        changes = self.detect_device_changes(current_devices)
        
        # Only scan new or changed devices
        devices_to_scan = changes['new_devices'] + changes['changed_devices']
        
        if not devices_to_scan:
            self.logger.info("No changes detected. Skipping full scan.")
            return {'status': 'no_changes', 'changes': changes}
        
        self.logger.info(f"Scanning {len(devices_to_scan)} changed devices")
        
        # Run enabled modules on changed devices only
        scan_results = {
            'timestamp': datetime.now().isoformat(),
            'changes': changes,
            'scanned_devices': len(devices_to_scan),
            'module_results': {}
        }
        
        for module in self.config.get('modules_enabled', []):
            if module == 'discovery':
                continue  # Already done
            
            self.logger.info(f"Running module: {module}")
            result = self.run_module(module, target_devices=devices_to_scan)
            scan_results['module_results'][module] = result
        
        return scan_results
    
    def full_scan(self) -> Dict:
        """Perform full scan of all devices"""
        self.logger.info("Starting full scan...")
        
        scan_results = {
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'full',
            'module_results': {}
        }
        
        for module in self.config.get('modules_enabled', []):
            self.logger.info(f"Running module: {module}")
            result = self.run_module(module)
            scan_results['module_results'][module] = result
        
        return scan_results
    
    def run_module(self, module: str, quick: bool = False, 
                   target_devices: Optional[List[Dict]] = None) -> Dict:
        """Run a specific reconnaissance module"""
        try:
            module_script = f"/usr/local/bin/{module.replace('-', '_')}_scan.sh"
            
            if not os.path.exists(module_script):
                self.logger.warning(f"Module script not found: {module_script}")
                return {'status': 'not_found'}
            
            cmd = [module_script, str(self.output_dir / module)]
            
            if quick:
                cmd.append('--quick')
            
            if target_devices:
                # Pass target IPs as environment variable
                target_ips = ','.join([d.get('ip', '') for d in target_devices if 'ip' in d])
                env = os.environ.copy()
                env['TARGET_IPS'] = target_ips
            else:
                env = os.environ.copy()
            
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout per module
            )
            
            return {
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'stdout': result.stdout[-1000:],  # Last 1000 chars
                'stderr': result.stderr[-1000:] if result.stderr else None
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Module {module} timed out")
            return {'status': 'timeout'}
        except Exception as e:
            self.logger.error(f"Error running module {module}: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def save_scan_results(self, results: Dict):
        """Save scan results to disk"""
        output_file = self.output_dir / 'monitor' / f"scan_{results['timestamp'].replace(':', '-')}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Scan results saved to {output_file}")
        
        # Also save as latest
        latest_file = self.output_dir / 'monitor' / 'latest_scan.json'
        with open(latest_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def check_alerts(self, scan_results: Dict):
        """Check scan results for conditions requiring alerts"""
        alerts = []
        threshold = self.config.get('alert_threshold', 'MEDIUM')
        
        # Check for new devices
        changes = scan_results.get('changes', {})
        if changes.get('new_devices'):
            alerts.append({
                'severity': 'HIGH',
                'type': 'new_device',
                'message': f"{len(changes['new_devices'])} new device(s) detected",
                'details': changes['new_devices']
            })
        
        # Check for removed devices
        if changes.get('removed_devices'):
            alerts.append({
                'severity': 'MEDIUM',
                'type': 'removed_device',
                'message': f"{len(changes['removed_devices'])} device(s) disappeared",
                'details': changes['removed_devices']
            })
        
        # Check module results for critical findings
        for module, result in scan_results.get('module_results', {}).items():
            if isinstance(result, dict) and result.get('status') == 'success':
                # Check for critical findings in module output
                if 'CRITICAL' in str(result.get('stdout', '')):
                    alerts.append({
                        'severity': 'CRITICAL',
                        'type': 'critical_finding',
                        'module': module,
                        'message': f"Critical findings in {module}",
                        'details': result
                    })
        
        # Filter alerts by threshold
        severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        threshold_level = severity_levels.get(threshold, 1)
        
        filtered_alerts = [
            a for a in alerts 
            if severity_levels.get(a['severity'], 0) >= threshold_level
        ]
        
        if filtered_alerts:
            self.logger.warning(f"Generated {len(filtered_alerts)} alert(s)")
            self.send_alerts(filtered_alerts)
        
        return filtered_alerts
    
    def send_alerts(self, alerts: List[Dict]):
        """Send alerts (placeholder for alert system integration)"""
        # This will be implemented in alert_integration.py
        alert_file = self.output_dir / 'monitor' / 'alerts.json'
        alert_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing alerts
        existing_alerts = []
        if alert_file.exists():
            with open(alert_file, 'r') as f:
                existing_alerts = json.load(f)
        
        # Add timestamp to new alerts
        for alert in alerts:
            alert['timestamp'] = datetime.now().isoformat()
        
        # Append and save
        existing_alerts.extend(alerts)
        with open(alert_file, 'w') as f:
            json.dump(existing_alerts, f, indent=2)
        
        self.logger.info(f"Alerts saved to {alert_file}")
    
    def scheduled_scan(self):
        """Perform scheduled scan based on configuration"""
        self.logger.info(f"Starting scheduled scan at {datetime.now()}")
        
        try:
            if self.incremental_mode:
                results = self.incremental_scan()
            else:
                results = self.full_scan()
            
            if results:
                self.save_scan_results(results)
                
                if self.config.get('alert_on_changes', True):
                    self.check_alerts(results)
            
            self.logger.info("Scheduled scan completed successfully")
            
        except Exception as e:
            self.logger.error(f"Error during scheduled scan: {e}", exc_info=True)
    
    def run(self):
        """Main daemon loop"""
        self.logger.info("Starting continuous monitoring daemon")
        self.logger.info(f"Scan interval: {self.scan_interval} minutes")
        self.logger.info(f"Incremental mode: {self.incremental_mode}")
        
        # Schedule scans
        schedule.every(self.scan_interval).minutes.do(self.scheduled_scan)
        
        # Run initial scan
        self.scheduled_scan()
        
        # Main loop
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
        
        self.logger.info("Monitoring daemon stopped")

def main():
    """Entry point"""
    config_path = os.environ.get('MONITOR_CONFIG', '/etc/lan-recon/monitor.conf')
    
    daemon = MonitoringDaemon(config_path)
    
    try:
        daemon.run()
    except KeyboardInterrupt:
        daemon.logger.info("Interrupted by user")
    except Exception as e:
        daemon.logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
