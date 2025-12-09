# Continuous Monitoring Module

## Overview

24/7 continuous monitoring daemon for LAN security assessment with incremental scanning and local alert integration.

## Features

### Continuous Monitoring
- **24/7 Operation**: Background daemon mode
- **Incremental Scanning**: Only scan changed/new devices
- **Device Fingerprinting**: Detect configuration changes
- **Scheduled Scans**: Configurable interval (default: hourly)
- **Graceful Shutdown**: Signal handling (SIGTERM, SIGINT)

### Incremental Scanning
- **Device Change Detection**:
  - New devices appearing on network
  - Devices disappearing
  - Configuration changes (services, hostnames)
- **Smart Scanning**: Only full-scan changed devices
- **Resource Efficient**: Avoid redundant scans

### Alert Integration (Local Free Alternatives)

All alerting uses **free, local tools** - no external services required:

#### 1. Syslog Integration
- **Tool**: Built-in syslog
- **Location**: `/var/log/syslog` or `journalctl -f`
- **Severity Mapping**:
  - CRITICAL → LOG_CRIT
  - HIGH → LOG_ERR
  - MEDIUM → LOG_WARNING
  - LOW → LOG_INFO
- **Always Available**: Standard on all Linux systems

#### 2. File Logging
- **Human-Readable**: `/var/log/lan-recon-alerts.log`
- **JSON Format**: `/var/log/lan-recon-alerts.json`
- **Auto-Rotation**: Size-based (default: 10MB)
- **Persistent**: Survives restarts

#### 3. Terminal Output
- **Real-time**: Stdout/stderr
- **Color-Coded**: ANSI colors for severity
- **Always Available**: No dependencies

#### 4. Desktop Notifications (Optional)
- **Tool**: notify-send (libnotify) or zenity
- **Only if**: Running with desktop environment
- **Urgency Levels**: Maps to alert severity
- **Non-blocking**: Won't fail if unavailable

#### 5. Local Webhook (Optional)
- **For**: Custom local integrations
- **Example**: Local dashboard, monitoring tools
- **No Cloud**: Stays on your network

## Configuration

### monitor.conf

```json
{
  "output_dir": "/output",
  "scan_interval_minutes": 60,
  "incremental_mode": true,
  "modules_enabled": [
    "discovery",
    "credential-attacks",
    "patch-cadence",
    "data-flow",
    "wifi-attacks",
    "trust-mapping",
    "deception"
  ],
  "alert_on_changes": true,
  "alert_threshold": "MEDIUM",
  "syslog": {
    "enabled": true
  },
  "file": {
    "enabled": true,
    "alert_file": "/var/log/lan-recon-alerts.log",
    "max_size_mb": 10,
    "rotate": true
  },
  "terminal": {
    "enabled": true,
    "use_colors": true
  }
}
```

### Alert Threshold Levels
- **LOW**: All alerts
- **MEDIUM**: Medium, High, Critical
- **HIGH**: High and Critical only
- **CRITICAL**: Critical only

## Usage

### Docker Compose Integration

```yaml
continuous-monitor:
  build: ./continuous-monitor
  container_name: recon-monitor
  network_mode: host
  volumes:
    - ./output:/output
    - ./continuous-monitor/monitor.conf:/etc/lan-recon/monitor.conf:ro
  environment:
    - MONITOR_CONFIG=/etc/lan-recon/monitor.conf
  restart: unless-stopped
```

### Start Monitoring

```bash
# Start as daemon
docker-compose up -d continuous-monitor

# View logs
docker-compose logs -f continuous-monitor

# View real-time alerts
tail -f output/monitor/alerts.json

# View syslog
docker-compose exec continuous-monitor tail -f /var/log/syslog
```

### Stop Monitoring

```bash
# Graceful shutdown
docker-compose stop continuous-monitor

# Force stop
docker-compose kill continuous-monitor
```

### Test Alerts

```bash
# Send test alert
docker-compose exec continuous-monitor \
  python3 /usr/local/bin/alert_integration.py --test
```

## Output Structure

```
/output/monitor/
├── scan_2025-12-09T01-00-00.json  # Timestamped scans
├── scan_2025-12-09T02-00-00.json
├── latest_scan.json                # Most recent scan
├── alerts.json                     # Alert history
└── device_cache.json               # Device fingerprints

/var/log/
├── lan-recon-monitor.log           # Daemon log
├── lan-recon-alerts.log            # Human-readable alerts
├── lan-recon-alerts.json           # JSON alerts
└── syslog                          # System log
```

## Alert Examples

### New Device Alert

```
[HIGH] SECURITY ALERT
Type: new_device
Time: 2025-12-09T01:23:45
Message: 1 new device(s) detected

Details:
  - ip: 192.168.1.150
  - mac: AA:BB:CC:DD:EE:FF
  - hostname: unknown-device
```

### Critical Finding Alert

```
[CRITICAL] SECURITY ALERT
Type: critical_finding
Time: 2025-12-09T01:30:00
Module: credential-attacks
Message: Critical findings in credential-attacks

Details:
  - Default credentials found on 3 devices
```

## Monitoring the Monitor

### Check Status

```bash
# Is daemon running?
docker-compose ps continuous-monitor

# View recent logs
docker-compose logs --tail=50 continuous-monitor

# Check last scan
cat output/monitor/latest_scan.json | jq '.timestamp'

# Count alerts
cat output/monitor/alerts.json | jq 'length'
```

### View System Logs

```bash
# Syslog entries
docker-compose exec continuous-monitor \
  grep lan-recon /var/log/syslog | tail -20

# Or use journalctl (if host system)
journalctl -t lan-recon -f
```

### Alert Log

```bash
# View recent alerts (human-readable)
docker-compose exec continuous-monitor \
  tail -30 /var/log/lan-recon-alerts.log

# View alerts (JSON)
cat output/monitor/alerts.json | jq '.[-5:]'  # Last 5 alerts

# Count by severity
cat output/monitor/alerts.json | \
  jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

## Performance

### Resource Usage
- **CPU**: Low (idle between scans)
- **Memory**: ~50-100MB base + scan results
- **Disk**: Depends on scan frequency and retention
- **Network**: Only during scans

### Scan Times (Typical)
- **Quick Discovery**: 30-60 seconds
- **Incremental Scan** (5 changed devices): 2-5 minutes
- **Full Scan** (all modules, 50 devices): 15-30 minutes

### Optimization
- **Incremental Mode**: Recommended for frequent scans
- **Module Selection**: Disable unused modules
- **Scan Interval**: Adjust based on network size
  - Small (< 20 devices): Every 30 minutes
  - Medium (20-100 devices): Every hour
  - Large (> 100 devices): Every 2-4 hours

## Troubleshooting

### Daemon Not Starting

```bash
# Check logs
docker-compose logs continuous-monitor

# Verify config
docker-compose exec continuous-monitor \
  cat /etc/lan-recon/monitor.conf | python3 -m json.tool
```

### No Alerts Generated

```bash
# Check alert threshold
grep alert_threshold output/monitor/latest_scan.json

# Verify alert config
docker-compose exec continuous-monitor \
  python3 /usr/local/bin/alert_integration.py --test
```

### High Resource Usage

```bash
# Check scan frequency
grep scan_interval /etc/lan-recon/monitor.conf

# Disable modules
# Edit monitor.conf and remove unused modules from modules_enabled

# Switch to full scans only (less frequent)
# Set: "incremental_mode": false
```

## Security Considerations

### Local Only
- ✅ No external services (Slack, email servers)
- ✅ No cloud dependencies
- ✅ All data stays on your network
- ✅ No API keys or credentials needed

### Log Security
- **Rotation**: Prevents disk fill
- **Permissions**: Restrict log file access
- **Retention**: Configure as needed
- **Sensitive Data**: Alerts may contain IPs, hostnames

### Network Access
- Requires host network mode for scanning
- Can restrict to specific interfaces
- No outbound internet required

## Integration Examples

### Custom Dashboard

Read alerts from local JSON file:

```python
import json

with open('/output/monitor/alerts.json') as f:
    alerts = json.load(f)
    
critical = [a for a in alerts if a['severity'] == 'CRITICAL']
print(f"Critical alerts: {len(critical)}")
```

### Local Webhook Receiver

```python
from flask import Flask, request
app = Flask(__name__)

@app.route('/alerts', methods=['POST'])
def receive_alert():
    alert = request.json
    print(f"Received: {alert['alert']['message']}")
    return {'status': 'received'}

app.run(host='localhost', port=8080)
```

Configure webhook:
```json
{
  "webhook": {
    "enabled": true,
    "url": "http://localhost:8080/alerts"
  }
}
```

## Future Enhancements

- **Performance Caching**: Cache scan results for faster incremental scans
- **Parallel Module Execution**: Run modules concurrently
- **Advanced Filtering**: Suppress known/expected changes
- **Correlation Engine**: Link related alerts
- **Baseline Learning**: AI-based anomaly detection

## License

Part of LAN Security Assessment Framework
See parent project LICENSE
