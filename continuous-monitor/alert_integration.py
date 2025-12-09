#!/usr/bin/env python3
"""
Alert System Integration - Local Free Alternatives
Provides real-time notifications using local free tools
"""

import os
import json
import logging
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path

class AlertIntegration:
    """Manages alert delivery using local free alternatives"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self.load_config()
        self.logger = logging.getLogger(__name__)
        
        # Local notification methods
        self.syslog_enabled = self.config.get('syslog', {}).get('enabled', True)
        self.file_enabled = self.config.get('file', {}).get('enabled', True)
        self.desktop_enabled = self.config.get('desktop', {}).get('enabled', False)
        self.webhook_enabled = self.config.get('webhook', {}).get('enabled', False)
    
    def load_config(self) -> Dict:
        """Load alert configuration with local defaults"""
        config_file = os.environ.get('ALERT_CONFIG', '/etc/lan-recon/alerts.conf')
        
        default_config = {
            'syslog': {
                'enabled': True,
                'facility': 'local0',
                'priority': 'warning'
            },
            'file': {
                'enabled': True,
                'alert_file': '/var/log/lan-recon-alerts.log',
                'json_file': '/var/log/lan-recon-alerts.json',
                'max_size_mb': 10,
                'rotate': True
            },
            'desktop': {
                'enabled': False,  # Only if running with desktop
                'tool': 'notify-send'  # or 'zenity'
            },
            'webhook': {
                'enabled': False,
                'url': os.environ.get('WEBHOOK_URL', ''),
                'timeout': 5
            },
            'terminal': {
                'enabled': True,
                'use_colors': True
            }
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
            except Exception as e:
                self.logger.warning(f"Failed to load alert config: {e}")
        
        return default_config
    
    def format_alert_message(self, alert: Dict, use_colors: bool = False) -> str:
        """Format alert for human readability"""
        severity = alert.get('severity', 'UNKNOWN')
        alert_type = alert.get('type', 'unknown')
        message = alert.get('message', 'No message')
        timestamp = alert.get('timestamp', datetime.now().isoformat())
        
        # ANSI color codes for terminal
        if use_colors:
            colors = {
                'CRITICAL': '\033[91m',  # Red
                'HIGH': '\033[93m',      # Yellow
                'MEDIUM': '\033[94m',    # Blue
                'LOW': '\033[92m',       # Green
                'RESET': '\033[0m'
            }
            color = colors.get(severity, '')
            reset = colors['RESET']
        else:
            color = reset = ''
        
        formatted = f"""{color}[{severity}] SECURITY ALERT{reset}
Type: {alert_type}
Time: {timestamp}
Message: {message}
"""
        
        if 'module' in alert:
            formatted += f"Module: {alert['module']}\n"
        
        if 'details' in alert and alert['details']:
            details = alert['details']
            if isinstance(details, dict):
                formatted += f"\nDetails:\n"
                for key, value in details.items():
                    formatted += f"  - {key}: {value}\n"
            elif isinstance(details, list) and len(details) > 0:
                formatted += f"\nAffected Items: {len(details)}\n"
                for i, item in enumerate(details[:3], 1):  # Show first 3
                    formatted += f"  {i}. {item}\n"
                if len(details) > 3:
                    formatted += f"  ... and {len(details) - 3} more\n"
        
        return formatted
    
    def send_syslog_alert(self, alert: Dict) -> bool:
        """Send alert to syslog (local, always available)"""
        if not self.syslog_enabled:
            return False
        
        try:
            import syslog
            
            # Map severity to syslog priority
            severity_map = {
                'CRITICAL': syslog.LOG_CRIT,
                'HIGH': syslog.LOG_ERR,
                'MEDIUM': syslog.LOG_WARNING,
                'LOW': syslog.LOG_INFO
            }
            
            priority = severity_map.get(alert.get('severity'), syslog.LOG_WARNING)
            facility = syslog.LOG_LOCAL0
            
            syslog.openlog('lan-recon', syslog.LOG_PID, facility)
            
            message = f"[{alert.get('severity')}] {alert.get('type')}: {alert.get('message')}"
            syslog.syslog(priority, message)
            syslog.closelog()
            
            self.logger.info(f"Syslog alert sent: {alert.get('type')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send syslog alert: {e}")
            return False
    
    def send_file_alert(self, alert: Dict) -> bool:
        """Send alert to local file (always available)"""
        if not self.file_enabled:
            return False
        
        file_config = self.config['file']
        alert_file = Path(file_config['alert_file'])
        json_file = Path(file_config['json_file'])
        
        try:
            # Ensure directory exists
            alert_file.parent.mkdir(parents=True, exist_ok=True)
            json_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write human-readable alert
            with open(alert_file, 'a') as f:
                f.write('=' * 70 + '\n')
                f.write(self.format_alert_message(alert, use_colors=False))
                f.write('=' * 70 + '\n\n')
            
            # Append to JSON file
            alerts = []
            if json_file.exists():
                with open(json_file, 'r') as f:
                    try:
                        alerts = json.load(f)
                    except:
                        alerts = []
            
            alerts.append(alert)
            
            with open(json_file, 'w') as f:
                json.dump(alerts, f, indent=2)
            
            # Check file size and rotate if needed
            if file_config.get('rotate', True):
                self.rotate_log_if_needed(alert_file, file_config.get('max_size_mb', 10))
            
            self.logger.info(f"File alert written to {alert_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to write file alert: {e}")
            return False
    
    def rotate_log_if_needed(self, log_file: Path, max_size_mb: int):
        """Rotate log file if it exceeds size limit"""
        try:
            if not log_file.exists():
                return
            
            size_mb = log_file.stat().st_size / (1024 * 1024)
            if size_mb > max_size_mb:
                # Rotate: move to .1, .2, etc.
                for i in range(5, 0, -1):
                    old = Path(f"{log_file}.{i}")
                    new = Path(f"{log_file}.{i+1}")
                    if old.exists():
                        old.rename(new)
                
                log_file.rename(f"{log_file}.1")
                self.logger.info(f"Rotated log file: {log_file}")
        except Exception as e:
            self.logger.error(f"Log rotation failed: {e}")
    
    def send_desktop_alert(self, alert: Dict) -> bool:
        """Send desktop notification (if desktop environment available)"""
        if not self.desktop_enabled:
            return False
        
        desktop_config = self.config['desktop']
        tool = desktop_config.get('tool', 'notify-send')
        
        try:
            severity = alert.get('severity', 'UNKNOWN')
            title = f"[{severity}] Security Alert"
            message = alert.get('message', 'Security alert detected')
            
            if tool == 'notify-send':
                # Use notify-send (libnotify)
                urgency_map = {
                    'CRITICAL': 'critical',
                    'HIGH': 'critical',
                    'MEDIUM': 'normal',
                    'LOW': 'low'
                }
                urgency = urgency_map.get(severity, 'normal')
                
                subprocess.run([
                    'notify-send',
                    '-u', urgency,
                    '-t', '10000',  # 10 seconds
                    title,
                    message
                ], check=False, timeout=2)
                
            elif tool == 'zenity':
                # Use zenity
                subprocess.run([
                    'zenity',
                    '--warning',
                    '--title', title,
                    '--text', message
                ], check=False, timeout=2)
            
            self.logger.info(f"Desktop notification sent")
            return True
            
        except Exception as e:
            self.logger.debug(f"Desktop notification not available: {e}")
            return False
    
    def send_terminal_alert(self, alert: Dict) -> bool:
        """Print alert to terminal/stdout"""
        terminal_config = self.config.get('terminal', {})
        if not terminal_config.get('enabled', True):
            return False
        
        try:
            use_colors = terminal_config.get('use_colors', True) and sys.stdout.isatty()
            message = self.format_alert_message(alert, use_colors=use_colors)
            print(message, file=sys.stdout)
            sys.stdout.flush()
            return True
        except Exception as e:
            self.logger.error(f"Failed to send terminal alert: {e}")
            return False
    
    def send_webhook_alert(self, alert: Dict) -> bool:
        """Send alert to local webhook (optional)"""
        if not self.webhook_enabled:
            return False
        
        webhook_config = self.config['webhook']
        url = webhook_config.get('url', '')
        
        if not url:
            return False
        
        try:
            import requests
            
            payload = {
                'alert': alert,
                'timestamp': datetime.now().isoformat(),
                'source': 'lan-security-monitor'
            }
            
            response = requests.post(
                url,
                json=payload,
                timeout=webhook_config.get('timeout', 5)
            )
            
            if response.status_code in (200, 201, 202, 204):
                self.logger.info(f"Webhook alert sent")
                return True
            
        except ImportError:
            self.logger.debug("requests library not available for webhook")
        except Exception as e:
            self.logger.debug(f"Webhook failed: {e}")
        
        return False
    
    def send_alert(self, alert: Dict) -> Dict[str, bool]:
        """Send alert to all enabled local channels"""
        results = {
            'syslog': False,
            'file': False,
            'desktop': False,
            'terminal': False,
            'webhook': False
        }
        
        # Local methods (always try)
        if self.syslog_enabled:
            results['syslog'] = self.send_syslog_alert(alert)
        
        if self.file_enabled:
            results['file'] = self.send_file_alert(alert)
        
        if self.desktop_enabled:
            results['desktop'] = self.send_desktop_alert(alert)
        
        # Terminal output
        results['terminal'] = self.send_terminal_alert(alert)
        
        # Optional webhook
        if self.webhook_enabled:
            results['webhook'] = self.send_webhook_alert(alert)
        
        return results
    
    def send_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Send multiple alerts"""
        results = []
        
        for alert in alerts:
            result = self.send_alert(alert)
            results.append({
                'alert': alert,
                'delivery': result
            })
        
        return results

def main():
    """Test alert integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test local alert integration')
    parser.add_argument('--test', action='store_true', help='Send test alert')
    args = parser.parse_args()
    
    if args.test:
        # Setup basic logging
        logging.basicConfig(level=logging.INFO)
        
        alert_system = AlertIntegration()
        
        test_alert = {
            'severity': 'HIGH',
            'type': 'test_alert',
            'message': 'This is a test alert from LAN Security Monitor',
            'timestamp': datetime.now().isoformat(),
            'details': {
                'test': True,
                'purpose': 'Verify local alert integration'
            }
        }
        
        print("Sending test alert to local channels...")
        results = alert_system.send_alert(test_alert)
        print(f"\nResults: {json.dumps(results, indent=2)}")
        print(f"\nCheck logs at:")
        print(f"  - /var/log/syslog (or journalctl -f)")
        print(f"  - {alert_system.config['file']['alert_file']}")
        print(f"  - {alert_system.config['file']['json_file']}")

if __name__ == '__main__':
    import sys
    main()
