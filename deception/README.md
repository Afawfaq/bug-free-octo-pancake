# Deception Module

## Overview

The Deception Module deploys honeypots and decoy services to detect and trap unauthorized access attempts, providing early warning of lateral movement and reconnaissance activities.

## Components

### 1. SMB Share Honeypot (`smb_honeypot.py`)
Simulates Windows file sharing with tempting share names.

**Features:**
- Fake shares: backup$, passwords, confidential, finance, hr-docs
- Credential capture (NTLM hashes)
- Connection and authentication logging
- Enumeration detection

**Alerts:**
- HIGH: Authentication attempts
- HIGH: File access attempts
- MEDIUM: Share enumeration

### 2. IPP Printer Honeypot (`ipp_honeypot.py`)
Simulates a Brother HL-L2350DW network printer.

**Features:**
- CUPS/IPP protocol support
- Print job capture
- Discovery logging
- Job metadata tracking

**Alerts:**
- MEDIUM: Printer discovery
- HIGH: Print job submission (potential exfiltration)

### 3. Chromecast Honeypot (`chromecast_honeypot.py`)
Simulates Google Cast device.

**Features:**
- DIAL/SSDP advertisement
- Cast request logging
- App launch detection
- Media URL tracking

**Alerts:**
- MEDIUM: Device discovery
- MEDIUM: Cast attempts
- MEDIUM: App launch attempts

### 4. SSDP Media Device Honeypot (`ssdp_honeypot.py`)
Simulates UPnP/DLNA media devices.

**Features:**
- Multi-device simulation (TV, receiver, speaker)
- UPnP service discovery
- Control attempt tracking
- Subscription monitoring

**Alerts:**
- LOW: Device discovery
- MEDIUM: Service enumeration
- MEDIUM: Control attempts

### 5. Alert System (`alert_system.py`)
Centralizes alert management and correlation.

**Features:**
- Alert aggregation from all honeypots
- Severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Source IP tracking
- Pattern detection
- Actionable recommendations

**Patterns Detected:**
- Coordinated lateral movement (multiple honeypots)
- Rapid enumeration (high event rate)
- Credential spraying (multiple auth attempts)

## Usage

### Docker Compose
```bash
docker-compose up deception
```

### Direct Invocation
```bash
# Start all honeypots (1 hour)
./deception_scan.sh /output/deception 3600

# Start individual honeypot
python3 smb_honeypot.py /output/deception 3600 445
```

## Output Structure

```
/output/deception/
├── smb_honeypot.json        # SMB activity log
├── ipp_honeypot.json        # IPP printer log
├── chromecast_honeypot.json # Chromecast log
├── ssdp_honeypot.json       # SSDP/UPnP log
├── alerts.json              # Aggregated alerts
├── deception_summary.txt    # Human-readable summary
└── *.log                    # Honeypot execution logs
```

## Alert Severity Levels

- **CRITICAL**: Coordinated attacks, brute force patterns
- **HIGH**: Authentication attempts, file access, large print jobs
- **MEDIUM**: Enumeration, cast attempts, service discovery
- **LOW**: Routine discovery, low-risk probing

## Security Considerations

### Safety Measures
- Honeypots run in isolated containers
- Read-only file systems prevent compromise
- No sensitive data in honeypots
- Resource limits prevent DOS

### Legal Compliance
- Banner warnings on all services
- Comply with monitoring/wiretapping laws
- Obtain proper authorization
- Document all activities
- Avoid entrapment scenarios

### Best Practices
- Deploy on isolated network segment
- Enable network IDS/IPS
- Integrate with SIEM
- Regular log review
- Coordinate with security team

## Integration

### SIEM Integration
Alerts can be forwarded to SIEM systems via:
- Syslog
- JSON file monitoring
- Webhook notifications (customize alert_system.py)

### Orchestrator Integration
- Phase: 15 (after trust-mapping)
- Duration: Configurable (default 1 hour)
- Parallel: Can run alongside other monitoring

## Example Alert

```json
{
  "alert_id": "smb_001",
  "timestamp": "2025-12-09T00:15:30Z",
  "honeypot": "smb",
  "severity": "HIGH",
  "alert_type": "authentication_attempt",
  "source_ip": "192.168.1.50",
  "username": "admin",
  "password_hash": "NTLM:5f4dcc3b5aa765d61d8327deb882cf99",
  "target_share": "passwords",
  "description": "Authentication attempt on high-value share"
}
```

## Attack Pattern Examples

### Pattern 1: Coordinated Lateral Movement
- Source triggers multiple honeypots (SMB + IPP + Chromecast)
- Indicates active lateral movement
- Severity: CRITICAL
- Recommendation: Isolate source immediately

### Pattern 2: Credential Spraying
- Multiple authentication attempts on SMB
- Same source, different usernames
- Severity: HIGH
- Recommendation: Review credential policies

### Pattern 3: Service Enumeration
- Rapid discovery across all honeypots
- Automated scanning behavior
- Severity: MEDIUM
- Recommendation: Enable rate limiting

## Future Enhancements

1. **Additional Honeypots**
   - SSH honeypot
   - RDP honeypot
   - Web application honeypot
   - Database honeypot

2. **Advanced Analytics**
   - Machine learning for anomaly detection
   - Behavioral profiling
   - Time-series analysis
   - Threat intelligence integration

3. **Response Actions**
   - Automated firewall rules
   - Active deception (fake data responses)
   - Attacker profiling
   - Attribution tracking

4. **Integration**
   - SOAR platform integration
   - Real-time dashboards
   - Mobile alerts
   - Incident response automation

## Troubleshooting

### Ports Already in Use
If honeypots fail to start due to port conflicts:
```bash
# Check for conflicting services
netstat -tulpn | grep -E "445|631|1900|8008"

# Stop conflicting services or change honeypot ports
```

### Permission Denied
Ensure container has proper capabilities:
```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
privileged: true  # For low ports like 445
```

### No Alerts Generated
- Verify honeypots are accessible from network
- Check firewall rules
- Confirm network mode is 'host'
- Review honeypot logs

## License

Part of the LAN Reconnaissance Framework. See main repository LICENSE.
