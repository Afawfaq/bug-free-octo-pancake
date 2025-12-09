#!/bin/bash
"""
Startup script for monitoring daemon
"""

# Start rsyslog for local logging
service rsyslog start

# Wait for rsyslog to be ready
sleep 2

# Start monitoring daemon
exec python3 /usr/local/bin/monitor_daemon.py
