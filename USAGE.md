# 📖 Detailed Usage Guide

## Installation

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install docker.io docker-compose

# Fedora/RHEL
sudo dnf install docker docker-compose

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### Clone and Setup
```bash
git clone https://github.com/Afawfaq/bug-free-octo-pancake.git
cd bug-free-octo-pancake
chmod +x start.sh stop.sh clean.sh
```

## Running Scans

### Basic Scan (Default Network)
```bash
./start.sh
```
This uses default configuration:
- Network: 192.168.68.0/24
- Router: 192.168.68.1
- Chromecast: 192.168.68.56
- TV: 192.168.68.62
- Printer: 192.168.68.54

### Custom Network Scan
```bash
./start.sh 192.168.1.0/24 192.168.1.1 192.168.1.100 192.168.1.101 192.168.1.50
```

### Manual Container Execution
```bash
# Start containers without running orchestrator
docker-compose up -d

# Run individual phases
docker exec recon-orchestrator python3 /usr/local/bin/orchestrator

# Or run specific modules
docker exec recon-passive /usr/local/bin/passive_scan.sh /output/passive 60
docker exec recon-discovery /usr/local/bin/discovery_scan.sh 192.168.1.0/24 /output/discovery
```

## Understanding the Output

### Directory Structure
```
output/
├── passive/                    # Passive reconnaissance results
│   ├── arp_scan.txt           # ARP discovery
│   ├── mdns_discovery.txt     # mDNS/Bonjour devices
│   ├── ssdp_discovery.txt     # UPnP/SSDP discovery
│   ├── upnp_devices.txt       # UPnP device list
│   ├── passive_capture.pcap   # Network capture
│   └── discovered_ips.txt     # All discovered IPs
│
├── discovery/                  # Active scanning results
│   ├── naabu_results.json     # Naabu port scan
│   ├── rustscan_results.txt   # RustScan results
│   ├── masscan_results.json   # Masscan results
│   └── discovered_hosts.json  # Combined host/port map
│
├── fingerprint/                # Service fingerprinting
│   ├── nmap_fingerprint.xml   # Nmap detailed scan
│   ├── nmap_fingerprint.txt   # Nmap text output
│   ├── httpx_results.json     # HTTP service info
│   ├── whatweb_*.json         # WhatWeb results per host
│   ├── snmp_*.txt             # SNMP enumeration
│   └── smb_*.txt              # SMB enumeration
│
├── iot/                        # IoT device enumeration
│   ├── router_upnp_desc.xml   # Router UPnP description
│   ├── router_upnp_list.txt   # UPnP services list
│   ├── chromecast_info.json   # Chromecast details
│   ├── chromecast_eureka.json # Chromecast API data
│   ├── dlna_tv_info.json      # DLNA/TV information
│   ├── printer_info.json      # Printer enumeration
│   ├── printer_web.html       # Printer web interface
│   └── printer_jetdirect.txt  # JetDirect banner
│
├── nuclei/                     # Security findings
│   ├── nuclei_results.json    # Main findings
│   ├── nuclei_iot_results.json # IoT-specific checks
│   └── nuclei_upnp_results.json # UPnP checks
│
├── webshot/                    # Web screenshots
│   ├── aquatone/              # Aquatone screenshots
│   │   ├── aquatone_report.html
│   │   └── screenshots/*.png
│   └── eyewitness/            # EyeWitness screenshots
│       └── screens/*.png
│
└── report/                     # Final reports
    ├── recon_report.html      # Main HTML report
    ├── recon_report.json      # Machine-readable JSON
    └── network_topology.png   # Network graph
```

## Advanced Usage

### Custom Nuclei Templates

Create custom security checks:

```bash
# Add template
cat > nuclei/custom-templates/my-iot-check.yaml << 'EOF'
id: my-custom-iot-check

info:
  name: My Custom IoT Vulnerability
  author: your-name
  severity: high
  description: Custom check for specific IoT vulnerability
  tags: iot,custom

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/endpoint"
    
    matchers:
      - type: word
        words:
          - "vulnerable_string"
      - type: status
        status:
          - 200
EOF

# Rebuild nuclei container
docker-compose build nuclei
```

### Extending IoT Enumeration

Add custom device enumeration:

```python
# iot/my_device_enum.py
#!/usr/bin/env python3
import sys
import json
import requests

def enumerate_device(ip, output_file):
    results = {"ip": ip, "device_type": "my_device"}
    
    # Your enumeration logic here
    try:
        response = requests.get(f"http://{ip}/device-info", timeout=5)
        results["info"] = response.json()
    except Exception as e:
        results["error"] = str(e)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    enumerate_device(sys.argv[1], sys.argv[2])
```

Update `iot/iot_scan.sh`:
```bash
# Add to iot_scan.sh
MY_DEVICE_IP=${MY_DEVICE_IP:-192.168.68.100}
if [ -n "$MY_DEVICE_IP" ]; then
    echo "[*] Enumerating custom device at $MY_DEVICE_IP..."
    my_device_enum.py "$MY_DEVICE_IP" "$OUTPUT_DIR/my_device_info.json"
fi
```

### Modifying Scan Phases

Edit `orchestrator/run.py` to customize:

```python
# Add custom phase
def phase_8_custom_scan(self):
    """Phase 8: Custom scanning"""
    self.log("PHASE 8: CUSTOM SCANNING")
    self.run_container_command(
        "recon-custom",
        "/usr/local/bin/custom_scan.sh"
    )

# Update run() method
def run(self):
    # ... existing phases ...
    self.phase_7_report_generation()
    self.phase_8_custom_scan()  # Add here
```

## Troubleshooting

### Issue: No Devices Discovered

**Check network interface:**
```bash
# List interfaces
ip addr show

# Update passive/passive_scan.sh and fingerprint/fingerprint_scan.sh
# Change eth0 to your interface (e.g., ens33, wlan0)
sed -i 's/eth0/ens33/g' passive/passive_scan.sh
```

**Verify network access:**
```bash
# Test from host
nmap -sn 192.168.68.0/24

# Test from container
docker exec recon-passive ping -c 3 192.168.68.1
```

### Issue: Permission Denied

**Run with elevated privileges:**
```bash
sudo ./start.sh
```

**Or add user to docker group:**
```bash
sudo usermod -aG docker $USER
newgrp docker  # Activate group
./start.sh
```

### Issue: Container Build Failures

**Check Docker disk space:**
```bash
docker system df
docker system prune -a  # Clean up
```

**Build individual containers:**
```bash
cd passive
docker build -t recon-passive .
cd ..
```

**Check logs:**
```bash
docker-compose logs passive
docker-compose logs discovery
```

### Issue: Slow Scans

**Reduce scan scope:**
```bash
# Smaller network
./start.sh 192.168.68.0/28  # Only 16 hosts

# Or edit discovery/discovery_scan.sh
# Reduce masscan rate: --rate=1000 -> --rate=500
```

**Skip phases:**
```bash
# Edit orchestrator/run.py, comment out phases:
# self.phase_6_web_screenshots()  # Skip if not needed
```

## Integration with Other Tools

### Export to CSV
```python
import json
import csv

with open('output/report/recon_report.json') as f:
    data = json.load(f)

with open('hosts.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['IP', 'Ports'])
    for ip, ports in data['discovery']['hosts'].items():
        writer.writerow([ip, ','.join(map(str, ports))])
```

### Import to Metasploit
```bash
# Convert nmap results
msfdb init
msfconsole
msf6 > db_import output/fingerprint/nmap_fingerprint.xml
msf6 > hosts
msf6 > services
```

### Feed to Custom Scripts
```bash
# Extract all web URLs
jq -r '.fingerprint.httpx[].url' output/report/recon_report.json > web_urls.txt

# Get all high severity findings
jq -r '.nuclei.findings[] | select(.info.severity == "high")' output/nuclei/nuclei_results.json
```

## Performance Tuning

### Faster Scans
```bash
# Edit discovery/discovery_scan.sh
# Increase rates (careful with network saturation)
masscan --rate=5000  # from 1000
naabu -rate 5000     # from default
```

### Resource Limits
```yaml
# Add to docker-compose.yml services
services:
  discovery:
    # ... existing config ...
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

## Scheduled Scans

### Cron Job
```bash
# Add to crontab
crontab -e

# Run daily at 2 AM
0 2 * * * cd /path/to/bug-free-octo-pancake && ./start.sh >> /var/log/recon.log 2>&1
```

### Systemd Timer
```ini
# /etc/systemd/system/recon.timer
[Unit]
Description=Daily LAN Recon

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## Best Practices

1. **Always get authorization** before scanning networks
2. **Start with passive scans** to minimize detection
3. **Review reports regularly** for new devices
4. **Keep templates updated**: `docker exec recon-nuclei nuclei -update-templates`
5. **Archive old scans**: `mv output output_$(date +%Y%m%d)`
6. **Monitor resource usage**: `docker stats`
7. **Test on isolated network first**
8. **Document findings properly**

## Getting Help

- Check logs: `docker-compose logs -f`
- Verify containers: `docker ps -a`
- Test connectivity: `docker exec recon-passive ping 192.168.68.1`
- Review individual outputs in `output/` directories
- Consult tool documentation for specific modules

---

**Need more help? Check the main README.md or open an issue on GitHub.**