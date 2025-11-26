# 🏗️ Architecture Documentation

## System Overview

The LAN Reconnaissance Framework is a microservices-based security scanner built with Docker containers. Each module is isolated and communicates through shared volumes, coordinated by a central orchestrator.

## Container Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Container                    │
│                   (Coordination & Control)                   │
└────────────────────┬────────────────────────────────────────┘
                     │
      ┌──────────────┼──────────────┐
      │              │              │
      ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Passive  │  │Discovery │  │Fingerprint│  │   IoT    │
│  Recon   │  │  Scan    │  │   Scan   │  │  Enum    │
└─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘
      │             │              │             │
      │             │              │             │
      └─────────────┴──────────────┴─────────────┘
                     │
                     ▼
              ┌────────────┐
              │   Shared   │
              │   Volume   │
              │  /output   │
              └─────┬──────┘
                     │
      ┌──────────────┼──────────────┐
      │              │              │
      ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐
│  Nuclei  │  │ Webshot  │  │  Report  │
│   Scan   │  │ Capture  │  │ Builder  │
└──────────┘  └──────────┘  └──────────┘
```

## Data Flow

### Phase 1: Passive Reconnaissance
```
Host Network → Passive Container → ARP/mDNS/SSDP
                                  ↓
                            discovered_ips.txt
```

### Phase 2: Active Discovery
```
discovered_ips.txt → Discovery Container → naabu/rustscan/masscan
                                         ↓
                                   discovered_hosts.json
```

### Phase 3: Fingerprinting
```
discovered_hosts.json → Fingerprint Container → nmap/httpx/whatweb
                                              ↓
                                        Service Details
```

### Phase 4: IoT Enumeration
```
Target IPs → IoT Container → Custom Python Scripts
                           ↓
                     Device-Specific Data
```

### Phase 5: Security Scanning
```
discovered_hosts.json → Nuclei Container → Templates
                                         ↓
                                    Vulnerabilities
```

### Phase 6: Web Screenshots
```
Web Services → Webshot Container → Aquatone/EyeWitness
                                 ↓
                             Screenshots
```

### Phase 7: Report Generation
```
All Output Data → Report Container → Jinja2/NetworkX
                                   ↓
                          HTML + JSON + Graph
```

## Network Configuration

### Host Mode Networking
All containers use `network_mode: host` to:
- Access raw sockets for packet capture
- Perform ARP scanning
- Send multicast packets (mDNS/SSDP)
- Avoid NAT/port forwarding complexity

### Required Capabilities
```yaml
cap_add:
  - NET_ADMIN  # Network administration
  - NET_RAW    # Raw socket access
```

## Storage Architecture

### Volume Mounts
```yaml
volumes:
  - ./output:/output        # Scan results
  - ./templates:/templates  # Report templates
  - /var/run/docker.sock:/var/run/docker.sock  # Docker control
```

### Directory Layout
```
output/
├── passive/          # Phase 1 output
├── discovery/        # Phase 2 output
├── fingerprint/      # Phase 3 output
├── iot/             # Phase 4 output
├── nuclei/          # Phase 5 output
├── webshot/         # Phase 6 output
└── report/          # Phase 7 output
```

## Orchestration Logic

### Execution Sequence
```python
1. wait_for_containers()      # Health check
2. phase_1_passive_recon()    # 30s passive listening
3. phase_2_active_discovery()  # Port scanning
4. phase_3_fingerprinting()    # Service enumeration
5. phase_4_iot_enumeration()   # Device-specific checks
6. phase_5_nuclei_scan()       # Vulnerability scanning
7. phase_6_web_screenshots()   # Visual reconnaissance
8. phase_7_report_generation() # Consolidate results
```

### Container Communication
Containers don't communicate directly. Instead:
1. Each writes to `/output/<module>/`
2. Orchestrator coordinates execution order
3. Later phases read from earlier phases' output

## Module Details

### Passive Container
**Base Image**: ubuntu:22.04
**Key Tools**:
- tshark: Packet capture
- p0f: Passive OS fingerprinting
- arp-scan: ARP discovery
- avahi-utils: mDNS discovery
- gupnp-tools: SSDP/UPnP discovery

**Capabilities Required**: NET_ADMIN, NET_RAW

### Discovery Container
**Base Image**: ubuntu:22.04
**Key Tools**:
- naabu: Fast port scanner (Go)
- rustscan: Parallel port scanner (Rust)
- masscan: Mass port scanner (C)

**Port Scanning Strategy**:
1. naabu: Full port range, TCP SYN
2. rustscan: Quick TCP connect scan
3. masscan: Low-rate comprehensive scan

### Fingerprint Container
**Base Image**: ubuntu:22.04
**Key Tools**:
- nmap: OS detection, service versioning
- httpx: HTTP service enumeration
- WhatWeb: Web technology fingerprinting
- snmpwalk: SNMP enumeration
- smbclient: SMB shares enumeration

**Scan Intensity**: Maximum (-A, --version-intensity 9)

### IoT Container
**Base Image**: ubuntu:22.04
**Custom Scripts**:
- `chromecast_enum.py`: Chromecast API enumeration
- `dlna_enum.py`: DLNA/MediaServer discovery
- `printer_enum.py`: Printer service mapping

**Libraries**:
- requests: HTTP requests
- pychromecast: Chromecast control
- upnpy: UPnP library

### Nuclei Container
**Base Image**: projectdiscovery/nuclei:latest
**Template Categories**:
- Default templates (updated automatically)
- Custom IoT templates
- UPnP misconfiguration checks
- Default credential tests

**Severity Filtering**: critical, high, medium

### Webshot Container
**Base Image**: ubuntu:22.04
**Tools**:
- Aquatone: Lightweight screenshot tool
- EyeWitness: Comprehensive web reporting
- Chromium: Headless browser

**Screenshot Strategy**:
1. Extract web services from discovery
2. Generate URLs (http/https)
3. Capture screenshots in parallel
4. Generate HTML galleries

### Report Container
**Base Image**: ubuntu:22.04
**Libraries**:
- Jinja2: Template engine
- NetworkX: Graph generation
- Matplotlib: Visualization
- Graphviz: Network diagrams

**Output Formats**:
1. HTML: Human-readable report
2. JSON: Machine-parseable data
3. PNG: Network topology graph

## Security Considerations

### Container Isolation
- Each container has minimal toolset
- No internet access required (except tool downloads during build)
- Runs with least privilege except network capabilities

### Data Sensitivity
- All data stored locally in `/output`
- No external reporting/phoning home
- Credentials never logged or transmitted

### Scan Safety
- Rate limiting in masscan (--rate=1000)
- Timeout controls on all operations
- Safe nmap options (no aggressive timing)

## Extensibility

### Adding New Modules
1. Create directory: `mkdir mymodule`
2. Add Dockerfile: `mymodule/Dockerfile`
3. Add script: `mymodule/myscan.sh`
4. Update docker-compose.yml
5. Add phase to orchestrator

### Custom Templates
```yaml
# nuclei/custom-templates/my-check.yaml
id: my-custom-check
info:
  name: My Check
  severity: high
requests:
  - method: GET
    path: ["{{BaseURL}}/test"]
```

### Report Customization
Edit `report/report_template.html`:
```html
<h2>My Custom Section</h2>
{{ data.custom_data }}
```

## Performance Tuning

### Scan Speed
- **Passive**: Adjust duration (default 30s)
- **Discovery**: Increase masscan rate
- **Fingerprint**: Use -T4 instead of -T3 in nmap

### Resource Limits
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 4G
```

### Parallel Execution
Consider running independent phases in parallel:
- Fingerprinting + IoT enumeration
- Nuclei + Web screenshots

## Troubleshooting

### Container Won't Start
- Check Docker logs: `docker logs recon-<module>`
- Verify permissions: containers need NET_ADMIN
- Check disk space: `docker system df`

### No Network Access
- Verify `network_mode: host`
- Check firewall rules
- Test with `docker exec recon-passive ping <target>`

### Slow Performance
- Reduce scan scope
- Increase rate limits
- Skip expensive phases
- Use quick-scan.sh

## Monitoring

### Real-time Logs
```bash
docker-compose logs -f orchestrator
```

### Container Status
```bash
docker ps -a --filter "name=recon-"
```

### Resource Usage
```bash
docker stats --filter "name=recon-"
```

## Future Enhancements

Potential improvements:
- Kubernetes deployment
- Distributed scanning
- Real-time dashboards
- Database backend
- API interface
- Continuous monitoring mode
- Machine learning for anomaly detection

---

**Architecture designed for modularity, extensibility, and security.**