#!/usr/bin/env python3
"""
Notification Module for LAN Reconnaissance Framework
=====================================================

Sends notifications about scan findings through various channels:
- Slack webhooks
- Discord webhooks
- Email (SMTP)
- Custom webhooks

Usage:
    from notifications import NotificationManager
    
    nm = NotificationManager()
    nm.send_finding_notification(finding)
    nm.send_scan_complete_notification(summary)
"""

import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError


class NotificationManager:
    """Manages notifications for scan findings and events."""
    
    def __init__(self):
        # Load configuration from environment
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.discord_webhook = os.getenv("DISCORD_WEBHOOK_URL")
        self.custom_webhook = os.getenv("CUSTOM_WEBHOOK_URL")
        
        # Email configuration
        self.smtp_server = os.getenv("SMTP_SERVER")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.email_from = os.getenv("EMAIL_FROM")
        email_to_str = os.getenv("EMAIL_TO", "")
        self.email_to = [e.strip() for e in email_to_str.split(",") if e.strip()]
        
        # Notification settings
        self.min_severity = os.getenv("NOTIFY_MIN_SEVERITY", "high")
        self.enabled = os.getenv("NOTIFICATIONS_ENABLED", "false").lower() == "true"
        self.webhook_timeout = int(os.getenv("WEBHOOK_TIMEOUT", "10"))
        
        self.severity_levels = ["info", "low", "medium", "high", "critical"]
    
    def should_notify(self, severity: str) -> bool:
        """Check if severity meets minimum threshold for notification."""
        if not self.enabled:
            return False
        
        try:
            finding_level = self.severity_levels.index(severity.lower())
            min_level = self.severity_levels.index(self.min_severity.lower())
            return finding_level >= min_level
        except ValueError:
            return False
    
    def send_slack_notification(self, message: Dict) -> bool:
        """Send notification to Slack webhook."""
        if not self.slack_webhook:
            return False
        
        payload = {
            "text": message.get("title", "LAN Recon Alert"),
            "attachments": [{
                "color": self._get_severity_color(message.get("severity", "info")),
                "fields": [
                    {"title": "Target", "value": message.get("target", "Unknown"), "short": True},
                    {"title": "Severity", "value": message.get("severity", "info").upper(), "short": True},
                    {"title": "Details", "value": message.get("description", "No details"), "short": False}
                ],
                "footer": "LAN Reconnaissance Framework",
                "ts": int(datetime.now().timestamp())
            }]
        }
        
        return self._send_webhook(self.slack_webhook, payload)
    
    def send_discord_notification(self, message: Dict) -> bool:
        """Send notification to Discord webhook."""
        if not self.discord_webhook:
            return False
        
        payload = {
            "embeds": [{
                "title": message.get("title", "LAN Recon Alert"),
                "description": message.get("description", ""),
                "color": self._get_severity_color_int(message.get("severity", "info")),
                "fields": [
                    {"name": "Target", "value": message.get("target", "Unknown"), "inline": True},
                    {"name": "Severity", "value": message.get("severity", "info").upper(), "inline": True},
                ],
                "footer": {"text": "LAN Reconnaissance Framework"},
                "timestamp": datetime.now().isoformat()
            }]
        }
        
        return self._send_webhook(self.discord_webhook, payload)
    
    def send_email_notification(self, message: Dict) -> bool:
        """Send notification via email."""
        if not all([self.smtp_server, self.email_from, self.email_to]):
            return False
        
        try:
            msg = MIMEMultipart()
            msg["From"] = self.email_from
            msg["To"] = ", ".join(self.email_to)
            msg["Subject"] = f"[LAN Recon] {message.get('severity', 'INFO').upper()}: {message.get('title', 'Alert')}"
            
            body = f"""
LAN Reconnaissance Framework Alert
===================================

Title: {message.get('title', 'Alert')}
Severity: {message.get('severity', 'info').upper()}
Target: {message.get('target', 'Unknown')}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Details:
{message.get('description', 'No details available')}

---
This is an automated message from LAN Reconnaissance Framework.
            """
            
            msg.attach(MIMEText(body, "plain"))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            return True
        except Exception as e:
            print(f"Email notification failed: {e}")
            return False
    
    def send_custom_webhook(self, message: Dict) -> bool:
        """Send notification to custom webhook."""
        if not self.custom_webhook:
            return False
        
        payload = {
            "event": "lan_recon_alert",
            "timestamp": datetime.now().isoformat(),
            "data": message
        }
        
        return self._send_webhook(self.custom_webhook, payload)
    
    def send_finding_notification(self, finding: Dict) -> Dict[str, bool]:
        """Send notification about a security finding to all configured channels."""
        severity = finding.get("info", {}).get("severity", finding.get("severity", "info"))
        
        if not self.should_notify(severity):
            return {"skipped": True}
        
        message = {
            "title": finding.get("info", {}).get("name", finding.get("name", "Security Finding")),
            "severity": severity,
            "target": finding.get("host", finding.get("target", "Unknown")),
            "description": finding.get("info", {}).get("description", finding.get("description", ""))
        }
        
        results = {
            "slack": self.send_slack_notification(message),
            "discord": self.send_discord_notification(message),
            "email": self.send_email_notification(message),
            "webhook": self.send_custom_webhook(message)
        }
        
        return results
    
    def send_scan_complete_notification(self, summary: Dict) -> Dict[str, bool]:
        """Send notification when scan is complete."""
        message = {
            "title": "Scan Complete",
            "severity": "info",
            "target": summary.get("target_network", "Unknown network"),
            "description": f"""
Scan completed successfully.

Hosts discovered: {summary.get('hosts_count', 0)}
Vulnerabilities found: {summary.get('vulnerabilities_count', 0)}
Critical findings: {summary.get('critical_count', 0)}
High findings: {summary.get('high_count', 0)}
Duration: {summary.get('duration', 'Unknown')}

Report available at: {summary.get('report_path', 'output/report/')}
            """
        }
        
        results = {
            "slack": self.send_slack_notification(message),
            "discord": self.send_discord_notification(message),
            "email": self.send_email_notification(message),
            "webhook": self.send_custom_webhook(message)
        }
        
        return results
    
    def _send_webhook(self, url: str, payload: Dict) -> bool:
        """Send POST request to webhook URL."""
        try:
            data = json.dumps(payload).encode("utf-8")
            req = Request(url, data=data, headers={"Content-Type": "application/json"})
            urlopen(req, timeout=self.webhook_timeout)
            return True
        except URLError as e:
            print(f"Webhook notification failed: {e}")
            return False
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color code for Slack attachment based on severity."""
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8"
        }
        return colors.get(severity.lower(), "#6c757d")
    
    def _get_severity_color_int(self, severity: str) -> int:
        """Get color code for Discord embed based on severity."""
        colors = {
            "critical": 0xdc3545,
            "high": 0xfd7e14,
            "medium": 0xffc107,
            "low": 0x28a745,
            "info": 0x17a2b8
        }
        return colors.get(severity.lower(), 0x6c757d)


def main():
    """Test notification system."""
    nm = NotificationManager()
    
    # Test finding
    test_finding = {
        "info": {
            "name": "Test Finding",
            "severity": "high",
            "description": "This is a test notification from LAN Recon Framework"
        },
        "host": "192.168.1.100"
    }
    
    print("Testing notification system...")
    results = nm.send_finding_notification(test_finding)
    print(f"Results: {results}")


if __name__ == "__main__":
    main()
