# 🔍 LAN Reconnaissance Framework

A complete, containerized reconnaissance framework for comprehensive LAN network analysis. This suite performs passive and active discovery, service fingerprinting, IoT device enumeration, security scanning, and generates detailed reports.

**✅ Cross-Platform: Works on Linux, Windows (WSL2/Native), and macOS**

## 🎯 Features

### **Complete Network Analysis Suite**
- **Passive Reconnaissance**: ARP scanning, mDNS/SSDP discovery, UPnP enumeration, packet capture
- **Active Discovery**: Port scanning with naabu, rustscan, and masscan
- **Service Fingerprinting**: OS detection, HTTP service analysis, SNMP/SMB enumeration
- **IoT/UPnP Adversary Tools**: Specialized enumeration for routers, Chromecasts, smart TVs, DLNA servers, and printers
- **Security Scanning**: Nuclei vulnerability scanning with custom IoT templates
- **Web Screenshots**: Automated screenshot capture of all web interfaces
- **Report Generation**: HTML and JSON reports with network topology graphs

### **Targeted Device Support**
- **UPnP/IGD Gateways**: Complete SOAP service enumeration, port forwarding detection
- **Chromecast Devices**: Eureka API, DIAL protocol, Cast endpoint analysis
- **Smart TVs**: DLNA/MediaServer enumeration, Netflix MDX endpoints
- **Network Printers**: Web interface scraping, JetDirect banner grabbing, IPP enumeration
- **DLNA Media Servers**: Service discovery and content enumeration

## 📋 Prerequisites

- Docker (20.10+) or Docker Desktop
- Docker Compose (1.29+)
- **Linux**: Host network access (containers run with `network_mode: host`)
- **Windows/macOS**: Docker Desktop with WSL2 (recommended) or bridged networking
- Root/admin privileges for network operations

## 🖥️ Platform Support

| Platform | Method | Full Support |
|----------|--------|--------------|
| Linux (Ubuntu/Debian) | Native Docker | ✅ Yes |
| Windows 10/11 | Docker Desktop + WSL2 | ✅ Yes |
| Windows (Native) | Docker Desktop + PowerShell | ⚠️ Limited |
| macOS | Docker Desktop | ⚠️ Limited |

> **Note**: For full network scanning capabilities on Windows, use WSL2. See [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) for detailed setup instructions.

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/Afawfaq/bug-free-octo-pancake.git
cd bug-free-octo-pancake
```

### 2. Run the Framework

**Linux/macOS (Bash):**
```bash
./start.sh [TARGET_NETWORK] [ROUTER_IP] [CHROMECAST_IP] [TV_IP] [PRINTER_IP]
```

**Windows (PowerShell):**
```powershell
.\start.ps1 -TargetNetwork "192.168.1.0/24" -RouterIP "192.168.1.1"
```

**Example:**
```bash
# Linux/macOS
./start.sh 192.168.68.0/24 192.168.68.1 192.168.68.56 192.168.68.62 192.168.68.54

# Windows
.\start.ps1 -TargetNetwork "192.168.68.0/24" -RouterIP "192.168.68.1"
```

**Default values:**
```bash
./start.sh  # Uses defaults: 192.168.68.0/24 network
```

**Quick Scan Mode:**
```bash
# Linux/macOS
./start.sh --quick

# Windows
.\start.ps1 -Quick
```

**Focused Scan Mode (faster, more reliable):**
```bash
# Linux/macOS - scan only known device IPs
./start.sh --focused

# Windows
.\start.ps1 -Focused

# With custom timeout for larger networks
./start.sh --timeout 1800
```

### 3. View Results
```bash
# HTML Report
open output/report/recon_report.html

# JSON Report (machine-readable)
cat output/report/recon_report.json

# Network Topology Graph
open output/report/network_topology.png
```

## 🏗️ Architecture

The framework consists of 8 containerized modules:

### 1. **Passive Reconnaissance Container**
- **Tools**: tshark, p0f, arp-scan, avahi-utils, gupnp-tools
- **Purpose**: Non-intrusive network discovery via ARP, mDNS, SSDP/UPnP

### 2. **Active Discovery Container**
- **Tools**: naabu, rustscan, masscan
- **Purpose**: Fast port scanning and host enumeration

### 3. **Fingerprinting Container**
- **Tools**: nmap, httpx, WhatWeb, SNMP, SMB tools
- **Purpose**: OS detection and service identification

### 4. **IoT/UPnP Adversary Container**
- **Tools**: Custom Python scripts, miniupnpc, pychromecast
- **Purpose**: Specialized IoT device enumeration
- **Targets**:
  - Router IGD services
  - Chromecast APIs
  - Smart TV DLNA/Netflix endpoints
  - Printer web interfaces and JetDirect

### 5. **Nuclei Security Scanner**
- **Tools**: Nuclei with custom templates
- **Purpose**: Vulnerability detection
- **Custom Templates**:
  - UPnP misconfigurations
  - Printer default credentials
  - Chromecast exposed APIs
  - DLNA information disclosure

### 6. **Web Screenshot Container**
- **Tools**: Aquatone, EyeWitness
- **Purpose**: Visual reconnaissance of all web interfaces

### 7. **Report Builder Container**
- **Tools**: Python, Jinja2, NetworkX, Graphviz
- **Purpose**: Generate comprehensive reports with network graphs

### 8. **Orchestrator Container**
- **Purpose**: Coordinates all modules in sequential phases
- **Workflow**:
  1. Passive reconnaissance (30s)
  2. Active host discovery
  3. Service fingerprinting
  4. IoT device enumeration
  5. Security scanning
  6. Web screenshots
  7. Report generation

## 📁 Directory Structure

```
bug-free-octo-pancake/
├── docker-compose.yml          # Main orchestration file
├── start.sh                    # Startup script
├── stop.sh                     # Stop all containers
├── clean.sh                    # Cleanup script
│
├── orchestrator/               # Coordination module
│   ├── Dockerfile
│   └── run.py
│
├── passive/                    # Passive recon module
│   ├── Dockerfile
│   └── passive_scan.sh
│
├── discovery/                  # Active discovery module
│   ├── Dockerfile
│   └── discovery_scan.sh
│
├── fingerprint/                # Fingerprinting module
│   ├── Dockerfile
│   └── fingerprint_scan.sh
│
├── iot/                        # IoT enumeration module
│   ├── Dockerfile
│   ├── iot_scan.sh
│   ├── chromecast_enum.py
│   ├── dlna_enum.py
│   └── printer_enum.py
│
├── nuclei/                     # Security scanning module
│   ├── Dockerfile
│   ├── nuclei_scan.sh
│   └── custom-templates/
│       ├── upnp-misconfig.yaml
│       ├── printer-default-creds.yaml
│       ├── chromecast-exposed.yaml
│       └── dlna-info-disclosure.yaml
│
├── webshot/                    # Screenshot module
│   ├── Dockerfile
│   └── webshot_scan.sh
│
├── report/                     # Report generation module
│   ├── Dockerfile
│   ├── report_builder.py
│   └── report_template.html
│
└── output/                     # Results directory (created on run)
    ├── passive/
    ├── discovery/
    ├── fingerprint/
    ├── iot/
    ├── nuclei/
    ├── webshot/
    └── report/
```

## 🔧 Configuration

### Environment Variables

Edit `docker-compose.yml` to customize:

```yaml
environment:
  - TARGET_NETWORK=192.168.68.0/24
  - ROUTER_IP=192.168.68.1
  - CHROMECAST_IP=192.168.68.56
  - TV_IP=192.168.68.62
  - DLNA_IPS=192.168.68.52,192.168.68.62
  - PRINTER_IP=192.168.68.54
```

### Custom Nuclei Templates

Add your own templates to `nuclei/custom-templates/`:

```yaml
id: my-custom-check
info:
  name: Custom IoT Check
  severity: high
  tags: iot
requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
```

## 📊 Output

### HTML Report Features
- Executive summary with statistics
- Network topology graph
- Passive discovery results
- Active host enumeration
- Service fingerprinting details
- IoT device information
- Security findings with severity ratings
- Screenshot gallery links

### JSON Report
Machine-readable format for integration with other tools:
```json
{
  "scan_time": "2025-11-24 12:00:00",
  "passive": { ... },
  "discovery": { ... },
  "fingerprint": { ... },
  "iot": { ... },
  "nuclei": { ... }
}
```

## 🛡️ Security Considerations

**⚠️ WARNING: This tool is designed for authorized security assessments only.**

- Only use on networks you own or have explicit permission to test
- The framework runs with elevated privileges (network_mode: host, NET_ADMIN, NET_RAW)
- Some scans are intrusive and may trigger IDS/IPS alerts
- Default credentials testing may trigger account lockouts
- Be aware of rate limits to avoid overwhelming devices

## 🎯 Use Cases

### Home Network Security Audit
- Identify exposed IoT devices
- Check for default credentials
- Find misconfigured services
- Map network topology

### Penetration Testing
- Initial reconnaissance phase
- Attack surface mapping
- Vulnerability identification
- Report generation for clients

### Network Inventory
- Automated device discovery
- Service documentation
- Network diagram generation
- Ongoing monitoring baseline

## 🔍 Troubleshooting

### Containers Not Starting
```bash
# Check Docker logs
docker-compose logs

# Verify Docker daemon
docker ps

# Check permissions
sudo ./start.sh
```

### Active Host Discovery Timeout
If Phase 2 (Active Host Discovery) times out on larger networks:

**Option 1: Increase the timeout**
```bash
# Increase timeout to 30 minutes (1800 seconds)
./start.sh --timeout 1800

# Or set in .env file
echo "SCAN_TIMEOUT=1800" >> .env
```

**Option 2: Use focused scan mode**
```bash
# Scan only known device IPs (faster and more reliable)
./start.sh --focused
```

**Option 3: Reduce the network range**
```bash
# Scan a smaller subnet (e.g., 16 hosts instead of 254)
./start.sh 192.168.68.0/28
```

### No Devices Found
- Verify network settings in docker-compose.yml
- Check network interface (may need to change from eth0)
- Ensure containers have host network access
- Verify firewall rules

### Permission Denied
```bash
# Run with sudo
sudo ./start.sh

# Or add user to docker group
sudo usermod -aG docker $USER
```

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional IoT device scripts
- More Nuclei templates
- Enhanced report visualizations
- Additional scanning tools
- Performance optimizations

## 📄 License

This project is for educational and authorized security testing purposes only.

## 🙏 Acknowledgments

Built with:
- [Nmap](https://nmap.org/)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [Naabu](https://github.com/projectdiscovery/naabu)
- [RustScan](https://github.com/bee-san/RustScan)
- [Aquatone](https://github.com/michenriksen/aquatone)
- [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)
- [Masscan](https://github.com/robertdavidgraham/masscan)

---

**🔒 Use Responsibly | Authorized Testing Only**