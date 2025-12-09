# 🛡️ Advanced Security Modules

Comprehensive documentation for the research-based security enhancements added to the LAN Reconnaissance Framework.

## Overview

This framework now includes **8 advanced security modules** based on 100+ years of security research (1920s-2024), implementing techniques from foundational cryptography to modern ML-based threat detection.

## Table of Contents

- [Module Overview](#module-overview)
- [Quick Start](#quick-start)
- [Individual Modules](#individual-modules)
- [Integration](#integration)
- [Configuration](#configuration)
- [Research Background](#research-background)

## Module Overview

| Module | Location | Purpose | Research Base |
|--------|----------|---------|---------------|
| ML Anomaly Detection | `orchestrator/ml_anomaly_detector.py` | Behavioral analysis and anomaly detection | 2024-2025 ML/DL research |
| Adaptive Honeypot | `deception/adaptive_honeypot.py` | Attacker profiling with adaptive responses | HoneyIoT (arXiv:2305.06430) |
| UPnP Vulnerability Scanner | `iot/upnp_vulnerability_scanner.py` | Detects 9 CVEs in libupnp | Rapid7, CERT research |
| ARP Spoofing Detector | `passive/arp_spoofing_detector.py` | Layer 2 MITM detection | ARP spoofing methodologies |
| TCP/IP Protocol Analyzer | `passive/tcp_ip_analyzer.py` | Classic protocol attack detection | Anderson (1980), Morris Worm (1988) |
| Audit Log Analyzer | `continuous-monitor/audit_log_analyzer.py` | Statistical IDS based on logs | Denning (1987), SRI IDES (1985) |
| Threat Intelligence Feed | `orchestrator/threat_intelligence_feed.py` | STIX/TAXII integration | STIX 2.1/TAXII 2.1 standards |
| DNS Tunnel Detector | `passive/dns_tunnel_detector.py` | Covert channel detection | Fidelis, arXiv:2507.10267v1 |

## Quick Start

### Using the Integration Module

```python
from orchestrator.advanced_security_integration import AdvancedSecurityOrchestrator

# Initialize orchestrator
orchestrator = AdvancedSecurityOrchestrator(
    output_dir='./data/advanced-security'
)

# Initialize all modules
orchestrator.initialize_modules()

# Process reconnaissance data
recon_data = {
    'discovered_hosts': [...],
    'dns_queries': [...],
    'arp_table': [...]
}

analysis = orchestrator.process_reconnaissance_data(recon_data)

# Generate comprehensive report
report = orchestrator.generate_comprehensive_report()
```

### Running Individual Modules

```python
# ML Anomaly Detection
from orchestrator.ml_anomaly_detector import AnomalyDetector

detector = AnomalyDetector(sensitivity=0.7)
detector.train_baseline(historical_data)
anomaly = detector.detect_anomaly(observation)

# Threat Intelligence
from orchestrator.threat_intelligence_feed import ThreatIntelligenceFeed

feed = ThreatIntelligenceFeed()
feed.parse_stix_bundle(stix_data)
correlation = feed.correlate_finding(security_finding)

# DNS Tunnel Detection
from passive.dns_tunnel_detector import DNSTunnelDetector

detector = DNSTunnelDetector()
detections = detector.process_query(dns_query)
```

## Individual Modules

### 1. ML Anomaly Detection

**Purpose**: Statistical behavioral analysis with baseline profiling

**Features**:
- Baseline traffic profiling
- Multi-factor anomaly scoring (port rarity, protocol analysis, connection rates)
- Real-time detection with severity classification
- Automated recommendations

**Usage**:
```python
detector = AnomalyDetector(sensitivity=0.7)

# Train on historical data
historical_data = [
    {'port': 80, 'protocol': 'HTTP', 'ip': '192.168.1.10', 'service': 'web'},
    # ... more observations
]
detector.train_baseline(historical_data)

# Detect anomalies
observation = {'port': 31337, 'protocol': 'TCP', 'ip': '192.168.1.50'}
anomaly = detector.detect_anomaly(observation)

if anomaly:
    print(f"Anomaly detected: {anomaly['severity']}")
    print(f"Reasons: {anomaly['reasons']}")
```

**Output**: JSON report with anomalies, severity, and recommendations

---

### 2. Adaptive Honeypot

**Purpose**: Attacker profiling with skill-based adaptive responses

**Features**:
- Attacker skill level classification (ADVANCED/INTERMEDIATE/NOVICE/SCANNER)
- Intent detection (reconnaissance/exploitation/data theft)
- Adaptive responses based on behavior
- Honeytokens for tracking
- Anti-fingerprinting techniques

**Usage**:
```python
honeypot = AdaptiveHoneypot(service_type='web', realism_level=0.8)

# Handle attacker interaction
action = {
    'type': 'directory_enumeration',
    'technique': 'RECONNAISSANCE'
}
response = honeypot.handle_interaction('192.168.1.100', action)

# Get statistics
stats = honeypot.get_statistics()
```

**Supported Services**: `web`, `ssh`, `smb`

---

### 3. UPnP Vulnerability Scanner

**Purpose**: Detect critical CVEs in UPnP/SSDP implementations

**CVEs Detected**:
- CVE-2012-5958 through CVE-2012-5965 (libupnp buffer overflows)
- CVE-2025-27484 (Windows UPnP memory corruption)

**Features**:
- SSDP multicast discovery
- Vulnerability detection with confidence scoring
- WAN exposure detection
- Buffer overflow resilience testing

**Usage**:
```python
scanner = UPnPVulnerabilityScanner()

# Discover devices
devices = scanner.scan_ssdp_multicast(timeout=5)

# Check for vulnerabilities
for device in devices:
    vulns = scanner.check_device_vulnerabilities(device)
    if vulns:
        print(f"Found {len(vulns)} vulnerabilities")

scanner.save_report()
```

---

### 4. ARP Spoofing Detector

**Purpose**: Detect ARP poisoning and MITM attacks

**Features**:
- Passive ARP table monitoring
- Duplicate IP/MAC detection
- Gratuitous ARP flood detection
- Vendor OUI validation (20+ vendors)
- Locally administered MAC detection

**Usage**:
```python
detector = ARPSpoofingDetector()

# Process ARP entries
alerts = detector.process_arp_entry('192.168.1.1', '00:11:22:33:44:55')

if alerts:
    for alert in alerts:
        print(f"Alert: {alert['type']}")
        print(f"Severity: {alert['severity']}")
```

---

### 5. TCP/IP Protocol Analyzer

**Purpose**: Detect classic TCP/IP protocol attacks

**Detection Capabilities**:
- SYN flood attacks
- IP spoofing
- Fragment overlap attacks (Teardrop, Bonk)
- Port scanning (NULL, XMAS, etc.)
- Session hijacking vulnerabilities
- Predictable sequence numbers

**Usage**:
```python
analyzer = TCPIPVulnerabilityAnalyzer()

# Analyze TCP flags
anomalies = analyzer.analyze_tcp_flags({'SYN': True, 'FIN': True})

# Detect IP spoofing
spoof = analyzer.detect_ip_spoofing('0.0.0.0', ttl=5, window_size=32768)

# Detect port scanning
scan = analyzer.detect_port_scan('192.168.1.100', ports=[1-100], time_window=30.0)
```

---

### 6. Audit Log Analyzer

**Purpose**: Statistical IDS based on Anderson and Denning models

**Features**:
- Statistical anomaly detection (Anderson 1980)
- Behavioral profile analysis (Denning 1987)
- Rule-based expert system (SRI IDES 1985)
- Subject-Object-Action modeling
- Temporal pattern analysis
- Privilege escalation monitoring

**Usage**:
```python
analyzer = AuditLogAnalyzer()

# Build baseline
historical_logs = [
    {'user': 'alice', 'action': 'read', 'object': '/home/alice/doc.txt'},
    # ... more logs
]
analyzer.build_baseline(historical_logs)

# Analyze new logs
log = {'user': 'charlie', 'action': 'read', 'object': '/etc/shadow'}
anomaly = analyzer.analyze_log(log)

# Apply rule-based detection
detections = analyzer.apply_rule_based_detection(logs)
```

---

### 7. Threat Intelligence Feed

**Purpose**: STIX/TAXII integration for threat intelligence

**Features**:
- STIX 2.1 bundle parsing
- IoC extraction (IPv4, IPv6, domains, URLs, file hashes)
- Threat actor and malware tracking
- MITRE ATT&CK integration
- Automated correlation engine
- TAXII-compatible export

**Usage**:
```python
feed = ThreatIntelligenceFeed()

# Parse STIX bundle
stix_data = {...}
feed.parse_stix_bundle(stix_data)

# Add custom IoCs
feed.add_ioc('ipv4', '192.0.2.1')
feed.add_ioc('domain', 'evil.example.com')

# Correlate findings
finding = {'src_ip': '192.0.2.1', 'dst_ip': '10.0.0.1'}
correlation = feed.correlate_finding(finding)

# Export as STIX
bundle = feed.export_stix_bundle()
```

---

### 8. DNS Tunnel Detector

**Purpose**: Detect DNS tunneling and covert channels

**Detection Methods**:
- Shannon entropy analysis (>3.5 threshold)
- Query length anomalies (>52 chars)
- Suspicious record types (TXT, NULL, CNAME)
- Traffic pattern analysis
- C2 beaconing detection
- Base64/hex encoding detection

**Usage**:
```python
detector = DNSTunnelDetector()

# Process DNS queries
query = {
    'domain': 'long-encoded-subdomain.evil.com',
    'type': 'TXT',
    'response_size': 250,
    'timestamp': '2025-12-09T21:00:00Z',
    'source_ip': '192.168.1.100'
}

detections = detector.process_query(query)

# Analyze traffic patterns
pattern_detections = detector.analyze_traffic_patterns(queries, time_window=60)
```

## Integration

### With Main Reconnaissance Framework

The advanced security modules integrate with the main framework through the `AdvancedSecurityOrchestrator`:

```python
# In orchestrator/run.py
from orchestrator.advanced_security_integration import AdvancedSecurityOrchestrator

# After reconnaissance phases
security_orch = AdvancedSecurityOrchestrator()
security_orch.initialize_modules()

# Process reconnaissance results
analysis = security_orch.process_reconnaissance_data(recon_results)

# Generate report
security_report = security_orch.generate_comprehensive_report()
```

### Docker Integration

Add to `docker-compose.yml`:

```yaml
services:
  recon-advanced-security:
    build: ./orchestrator
    volumes:
      - ./data:/output
    environment:
      - ENABLE_ML_ANOMALY=true
      - ENABLE_THREAT_INTEL=true
      - SENSITIVITY=0.7
    networks:
      - recon-network
```

## Configuration

### Global Configuration

Create `config/advanced_security.json`:

```json
{
  "modules": {
    "ml_anomaly": {
      "enabled": true,
      "sensitivity": 0.7,
      "baseline_size": 1000
    },
    "adaptive_honeypot": {
      "enabled": true,
      "service_type": "web",
      "realism_level": 0.8
    },
    "upnp_vuln": {
      "enabled": true,
      "scan_timeout": 5
    },
    "arp_spoof": {
      "enabled": true,
      "ip_change_threshold": 300
    },
    "tcpip_analyzer": {
      "enabled": true,
      "syn_flood_threshold": 100
    },
    "audit_log": {
      "enabled": true,
      "baseline_required": true
    },
    "threat_intel": {
      "enabled": true,
      "stix_feeds": [
        "https://example.com/stix/feed.json"
      ]
    },
    "dns_tunnel": {
      "enabled": true,
      "entropy_threshold": 3.5,
      "query_length_threshold": 52
    }
  },
  "output": {
    "directory": "./data/advanced-security",
    "format": "json",
    "include_raw_data": false
  },
  "reporting": {
    "generate_executive_summary": true,
    "include_recommendations": true,
    "severity_threshold": "MEDIUM"
  }
}
```

### Module-Specific Configuration

Each module can be configured individually. See module docstrings for all available parameters.

## Research Background

### Research Timeline

- **1920s-1960s**: Cryptography foundations (Enigma, military ciphers)
- **1970s**: TCP/IP protocols, DES encryption (1977)
- **1980**: James Anderson - "Computer Security Threat Monitoring and Surveillance"
- **1985**: SRI International - IDES (Intrusion Detection Expert System)
- **1987**: Dorothy Denning - "An Intrusion-Detection Model"
- **1988**: Morris Worm - First major internet worm, exploitation analysis
- **1990s**: SYN floods, Teardrop attack, Nmap, Mitnick session hijacking
- **2000-2024**: ML/DL anomaly detection, adaptive honeypots, modern vulnerability research
- **2020-2024**: STIX/TAXII standards, DNS tunneling detection, SOAR automation

### Key Research Papers

1. **Anderson, J.P.** (1980). "Computer Security Threat Monitoring and Surveillance"
2. **Denning, D.** (1987). "An Intrusion-Detection Model"
3. **HoneyIoT** (2023). arXiv:2305.06430 - "Adaptive High-Interaction Honeypot for IoT Devices"
4. **Rapid7** (2013). "Security Flaws in Universal Plug and Play"
5. **Fidelis Security** (2024). "DNS Tunneling Detection and Mitigation"
6. **STIX/TAXII Standards** (2021). OASIS Open specifications

### Academic Citations

For academic use, cite as:

```
Bug-Free-Octo-Pancake Contributors (2024). 
"Advanced Security Modules for LAN Reconnaissance Framework: 
Implementing 100 Years of Security Research"
GitHub Repository: https://github.com/Afawfaq/bug-free-octo-pancake
```

## Performance Considerations

- **ML Anomaly Detection**: O(n) for baseline training, O(1) for detection
- **DNS Tunnel Detector**: Entropy calculation is O(n) where n is domain length
- **ARP Spoofing**: O(1) lookup for each ARP entry
- **Threat Intelligence**: O(1) IoC lookups using set data structures

## Troubleshooting

### Common Issues

**Import Errors**:
```bash
# Ensure all modules are in Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**Permission Errors**:
```bash
# Create output directories with proper permissions
mkdir -p ./data/advanced-security
chmod 755 ./data/advanced-security
```

**Module Not Loading**:
```python
# Check module is enabled in configuration
orchestrator.enabled_modules['ml_anomaly'] = True
```

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review existing documentation in `/docs`
- Check the main `README.md` for general framework usage

## License

All advanced security modules are released under the same license as the main framework. See `LICENSE` file for details.

---

**Version**: 1.0.0  
**Last Updated**: December 2024  
**Maintainers**: LAN Recon Security Team
