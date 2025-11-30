"""
Unit tests for the Notifications module.
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime


class TestNotificationManagerInitialization:
    """Test NotificationManager initialization and configuration."""
    
    def test_default_initialization(self):
        """Test that default values are set correctly."""
        with patch.dict(os.environ, {}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm.slack_webhook is None
            assert nm.discord_webhook is None
            assert nm.custom_webhook is None
            assert nm.smtp_server is None
            assert nm.enabled == False
            assert nm.min_severity == "high"
            assert nm.webhook_timeout == 10
    
    def test_custom_initialization(self):
        """Test initialization with custom environment variables."""
        custom_env = {
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/test",
            "DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test",
            "CUSTOM_WEBHOOK_URL": "https://example.com/webhook",
            "SMTP_SERVER": "smtp.example.com",
            "SMTP_PORT": "465",
            "EMAIL_FROM": "test@example.com",
            "EMAIL_TO": "recipient1@example.com, recipient2@example.com",
            "NOTIFICATIONS_ENABLED": "true",
            "NOTIFY_MIN_SEVERITY": "medium",
            "WEBHOOK_TIMEOUT": "30"
        }
        
        with patch.dict(os.environ, custom_env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm.slack_webhook == "https://hooks.slack.com/test"
            assert nm.discord_webhook == "https://discord.com/api/webhooks/test"
            assert nm.custom_webhook == "https://example.com/webhook"
            assert nm.smtp_server == "smtp.example.com"
            assert nm.smtp_port == 465
            assert nm.email_from == "test@example.com"
            assert len(nm.email_to) == 2
            assert nm.enabled == True
            assert nm.min_severity == "medium"
            assert nm.webhook_timeout == 30


class TestShouldNotify:
    """Test the should_notify method."""
    
    def test_notifications_disabled(self):
        """Test that notifications are skipped when disabled."""
        with patch.dict(os.environ, {"NOTIFICATIONS_ENABLED": "false"}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm.should_notify("critical") == False
            assert nm.should_notify("high") == False
            assert nm.should_notify("info") == False
    
    def test_severity_threshold_high(self):
        """Test severity threshold with high minimum."""
        env = {"NOTIFICATIONS_ENABLED": "true", "NOTIFY_MIN_SEVERITY": "high"}
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm.should_notify("critical") == True
            assert nm.should_notify("high") == True
            assert nm.should_notify("medium") == False
            assert nm.should_notify("low") == False
            assert nm.should_notify("info") == False
    
    def test_severity_threshold_medium(self):
        """Test severity threshold with medium minimum."""
        env = {"NOTIFICATIONS_ENABLED": "true", "NOTIFY_MIN_SEVERITY": "medium"}
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm.should_notify("critical") == True
            assert nm.should_notify("high") == True
            assert nm.should_notify("medium") == True
            assert nm.should_notify("low") == False
            assert nm.should_notify("info") == False
    
    def test_invalid_severity(self):
        """Test handling of invalid severity level."""
        env = {"NOTIFICATIONS_ENABLED": "true", "NOTIFY_MIN_SEVERITY": "high"}
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm.should_notify("unknown") == False
            assert nm.should_notify("CRITICAL") == True  # Case insensitive


class TestSeverityColors:
    """Test severity color methods."""
    
    def test_get_severity_color(self):
        """Test Slack color codes."""
        with patch.dict(os.environ, {}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm._get_severity_color("critical") == "#dc3545"
            assert nm._get_severity_color("high") == "#fd7e14"
            assert nm._get_severity_color("medium") == "#ffc107"
            assert nm._get_severity_color("low") == "#28a745"
            assert nm._get_severity_color("info") == "#17a2b8"
            assert nm._get_severity_color("unknown") == "#6c757d"
    
    def test_get_severity_color_int(self):
        """Test Discord color codes."""
        with patch.dict(os.environ, {}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            assert nm._get_severity_color_int("critical") == 0xdc3545
            assert nm._get_severity_color_int("high") == 0xfd7e14
            assert nm._get_severity_color_int("medium") == 0xffc107
            assert nm._get_severity_color_int("low") == 0x28a745
            assert nm._get_severity_color_int("info") == 0x17a2b8
            assert nm._get_severity_color_int("unknown") == 0x6c757d


class TestSlackNotifications:
    """Test Slack notification sending."""
    
    def test_slack_notification_no_webhook(self):
        """Test that Slack notification returns False when no webhook is set."""
        with patch.dict(os.environ, {}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            message = {"title": "Test", "severity": "high", "target": "192.168.1.1"}
            result = nm.send_slack_notification(message)
            
            assert result == False
    
    def test_slack_notification_with_webhook(self):
        """Test Slack notification with webhook configured."""
        env = {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            with patch.object(nm, '_send_webhook', return_value=True) as mock_send:
                message = {
                    "title": "Test Alert",
                    "severity": "high",
                    "target": "192.168.1.1",
                    "description": "Test description"
                }
                result = nm.send_slack_notification(message)
                
                assert result == True
                mock_send.assert_called_once()
                call_args = mock_send.call_args[0]
                assert call_args[0] == "https://hooks.slack.com/test"


class TestDiscordNotifications:
    """Test Discord notification sending."""
    
    def test_discord_notification_no_webhook(self):
        """Test that Discord notification returns False when no webhook is set."""
        with patch.dict(os.environ, {}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            message = {"title": "Test", "severity": "high", "target": "192.168.1.1"}
            result = nm.send_discord_notification(message)
            
            assert result == False
    
    def test_discord_notification_with_webhook(self):
        """Test Discord notification with webhook configured."""
        env = {"DISCORD_WEBHOOK_URL": "https://discord.com/api/webhooks/test"}
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            with patch.object(nm, '_send_webhook', return_value=True) as mock_send:
                message = {
                    "title": "Test Alert",
                    "severity": "critical",
                    "target": "192.168.1.1",
                    "description": "Test description"
                }
                result = nm.send_discord_notification(message)
                
                assert result == True
                mock_send.assert_called_once()


class TestEmailNotifications:
    """Test email notification sending."""
    
    def test_email_notification_missing_config(self):
        """Test that email notification returns False when config is missing."""
        with patch.dict(os.environ, {}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            message = {"title": "Test", "severity": "high", "target": "192.168.1.1"}
            result = nm.send_email_notification(message)
            
            assert result == False
    
    def test_email_notification_with_config(self):
        """Test email notification with SMTP configured."""
        env = {
            "SMTP_SERVER": "smtp.example.com",
            "SMTP_PORT": "587",
            "EMAIL_FROM": "test@example.com",
            "EMAIL_TO": "recipient@example.com",
            "SMTP_USERNAME": "user",
            "SMTP_PASSWORD": "pass"
        }
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            with patch('smtplib.SMTP') as mock_smtp:
                mock_server = MagicMock()
                mock_smtp.return_value.__enter__.return_value = mock_server
                
                message = {
                    "title": "Test Alert",
                    "severity": "high",
                    "target": "192.168.1.1",
                    "description": "Test description"
                }
                result = nm.send_email_notification(message)
                
                assert result == True
                mock_smtp.assert_called_once_with("smtp.example.com", 587)


class TestCustomWebhook:
    """Test custom webhook notifications."""
    
    def test_custom_webhook_no_url(self):
        """Test that custom webhook returns False when no URL is set."""
        with patch.dict(os.environ, {}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            message = {"title": "Test", "severity": "high", "target": "192.168.1.1"}
            result = nm.send_custom_webhook(message)
            
            assert result == False
    
    def test_custom_webhook_with_url(self):
        """Test custom webhook with URL configured."""
        env = {"CUSTOM_WEBHOOK_URL": "https://example.com/webhook"}
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            with patch.object(nm, '_send_webhook', return_value=True) as mock_send:
                message = {"title": "Test Alert", "severity": "high"}
                result = nm.send_custom_webhook(message)
                
                assert result == True
                mock_send.assert_called_once()


class TestFindingNotification:
    """Test the send_finding_notification method."""
    
    def test_finding_notification_skipped(self):
        """Test that notifications are skipped for low severity."""
        with patch.dict(os.environ, {"NOTIFICATIONS_ENABLED": "true", "NOTIFY_MIN_SEVERITY": "high"}, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            finding = {
                "info": {
                    "name": "Test Finding",
                    "severity": "low",
                    "description": "Test"
                },
                "host": "192.168.1.1"
            }
            
            results = nm.send_finding_notification(finding)
            
            assert results.get("skipped") == True
    
    def test_finding_notification_sent(self):
        """Test that notifications are sent for high severity."""
        env = {
            "NOTIFICATIONS_ENABLED": "true",
            "NOTIFY_MIN_SEVERITY": "high",
            "SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"
        }
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            with patch.object(nm, '_send_webhook', return_value=True):
                finding = {
                    "info": {
                        "name": "Critical Finding",
                        "severity": "critical",
                        "description": "Important security issue"
                    },
                    "host": "192.168.1.1"
                }
                
                results = nm.send_finding_notification(finding)
                
                assert "skipped" not in results
                assert "slack" in results


class TestScanCompleteNotification:
    """Test the send_scan_complete_notification method."""
    
    def test_scan_complete_notification(self):
        """Test scan complete notification."""
        env = {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}
        
        with patch.dict(os.environ, env, clear=True):
            from notifications import NotificationManager
            
            nm = NotificationManager()
            
            with patch.object(nm, '_send_webhook', return_value=True):
                summary = {
                    "target_network": "192.168.1.0/24",
                    "hosts_count": 10,
                    "vulnerabilities_count": 5,
                    "critical_count": 1,
                    "high_count": 2,
                    "duration": "5m 30s",
                    "report_path": "/output/report/"
                }
                
                results = nm.send_scan_complete_notification(summary)
                
                assert "slack" in results
