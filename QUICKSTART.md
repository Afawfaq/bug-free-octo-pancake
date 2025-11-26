# ⚡ Quick Start Guide

Get up and running with the LAN Reconnaissance Framework in 5 minutes.

## 📦 Installation

### Prerequisites
- Docker 20.10+
- Docker Compose 1.29+
- 4GB RAM minimum
- Root/sudo access

### Step 1: Install Docker (if not already installed)

**Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker
```

**macOS:**
```bash
brew install docker docker-compose
```

**Windows:**
Download [Docker Desktop](https://www.docker.com/products/docker-desktop/)

### Step 2: Clone Repository
```bash
git clone https://github.com/Afawfaq/bug-free-octo-pancake.git
cd bug-free-octo-pancake
```

## 🚀 Running Your First Scan

### Basic Scan (Default Configuration)
```bash
./start.sh
```

This will:
1. Build all Docker containers (~5-10 minutes first time)
2. Run comprehensive network reconnaissance
3. Generate reports in `./output/`

**Default targets:**
- Network: 192.168.68.0/24
- Router: 192.168.68.1
- Chromecast: 192.168.68.56
- Smart TV: 192.168.68.62
- Printer: 192.168.68.54

### Custom Network Scan
```bash
./start.sh 192.168.1.0/24 192.168.1.1 192.168.1.50 192.168.1.51 192.168.1.100
```

### Quick Scan (Faster, Less Comprehensive)
```bash
./quick-scan.sh 192.168.1.0/24
```

## 📊 Viewing Results

### Open HTML Report
```bash
./view-report.sh
```

Or manually:
```bash
open output/report/recon_report.html
# or
firefox output/report/recon_report.html
```

### View JSON Data
```bash
cat output/report/recon_report.json | jq
```

### Check Network Graph
```bash
open output/report/network_topology.png
```

## 📁 Output Structure

```
output/
├── passive/              # Passive discovery results
├── discovery/            # Port scanning results
├── fingerprint/          # Service fingerprinting
├── iot/                  # IoT device enumeration
├── nuclei/              # Security findings
├── webshot/             # Web screenshots
└── report/              # Final reports
    ├── recon_report.html
    ├── recon_report.json
    └── network_topology.png
```

## 🛑 Stopping the Scan

### Stop All Containers
```bash
./stop.sh
```

### Clean Up Everything
```bash
./clean.sh
```

## ⚙️ Configuration

### Method 1: Environment File
```bash
# Copy example configuration
cp .env.example .env

# Edit configuration
nano .env

# Run scan (will use .env automatically)
./start.sh
```

### Method 2: Command Line Arguments
```bash
./start.sh [NETWORK] [ROUTER] [CHROMECAST] [TV] [PRINTER]
```

### Method 3: Edit docker-compose.yml
```yaml
environment:
  - TARGET_NETWORK=192.168.1.0/24
  - ROUTER_IP=192.168.1.1
  - CHROMECAST_IP=192.168.1.50
  - TV_IP=192.168.1.51
  - PRINTER_IP=192.168.1.100
```

## 🎯 Common Use Cases

### Home Network Audit
```bash
# Scan your home network
./start.sh 192.168.1.0/24

# View report
./view-report.sh
```

### Enterprise Network Discovery
```bash
# Large network scan (be careful with rate limits!)
./start.sh 10.0.0.0/16
```

### IoT Device Analysis
```bash
# Focus on specific IoT devices
./start.sh 192.168.1.0/24 192.168.1.1 192.168.1.50 192.168.1.51
```

### Quick Security Check
```bash
# Fast scan for vulnerabilities
./quick-scan.sh 192.168.1.0/24
```

## 🔍 Understanding the Scan Phases

The framework runs 7 phases automatically:

1. **Passive Recon** (30s): ARP, mDNS, SSDP discovery
2. **Active Discovery** (~5 min): Port scanning
3. **Fingerprinting** (~10 min): OS and service detection
4. **IoT Enumeration** (~5 min): Device-specific checks
5. **Security Scanning** (~5 min): Nuclei vulnerability scan
6. **Web Screenshots** (~5 min): Capture web interfaces
7. **Report Generation** (~1 min): Build HTML/JSON reports

**Total time:** ~30-45 minutes for default network

## 📊 What You'll Get

### HTML Report Includes:
- Executive summary with statistics
- Network topology graph
- All discovered hosts and ports
- Service fingerprints
- IoT device details
- Security vulnerabilities
- Web interface screenshots

### JSON Report Includes:
- Machine-readable data
- All scan results
- Easy to parse and integrate
- Perfect for automation

## 🐛 Troubleshooting

### Containers Won't Build
```bash
# Check Docker status
docker ps

# Check disk space
docker system df

# Clean up and retry
docker system prune -a
./start.sh
```

### No Devices Found
```bash
# Verify network
ip addr show

# Test connectivity
ping 192.168.1.1

# Check Docker network mode
docker-compose config
```

### Permission Denied
```bash
# Run with sudo
sudo ./start.sh

# Or fix Docker permissions
sudo usermod -aG docker $USER
newgrp docker
```

### Scan is Slow
```bash
# Use quick scan mode
./quick-scan.sh

# Or reduce network scope
./start.sh 192.168.1.0/28  # Only 16 hosts
```

## 📚 Next Steps

### Learn More
- Read [README.md](README.md) for full documentation
- Check [USAGE.md](USAGE.md) for advanced usage
- Review [ARCHITECTURE.md](ARCHITECTURE.md) for technical details

### Customize
- Add custom Nuclei templates in `nuclei/custom-templates/`
- Create new scanning modules (see [CONTRIBUTING.md](CONTRIBUTING.md))
- Modify report template in `report/report_template.html`

### Automate
```bash
# Schedule daily scans
crontab -e
# Add: 0 2 * * * cd /path/to/bug-free-octo-pancake && ./start.sh
```

## ⚠️ Important Warnings

1. **Only scan networks you own or have permission to test**
2. **Some scans may be detected by IDS/IPS**
3. **Rate limits may affect scan accuracy**
4. **Ensure adequate disk space for output**
5. **Review local laws before scanning**

## 🆘 Getting Help

### Check Logs
```bash
docker-compose logs -f orchestrator
docker-compose logs | grep ERROR
```

### Verify Installation
```bash
docker --version
docker-compose --version
ls -la
```

### Common Issues
- **Port 80/443 already in use**: Stop other web servers
- **Out of memory**: Close other applications
- **Network unreachable**: Check firewall settings

## 🎉 Success Indicators

You'll know the scan succeeded when you see:
```
✅ RECONNAISSANCE COMPLETE
📁 Results available in: ./output
```

Then check:
- `output/report/recon_report.html` exists
- `output/discovery/discovered_hosts.json` has data
- No errors in `docker-compose logs`

## 💡 Pro Tips

1. **Save time**: First run takes longest (Docker builds). Subsequent runs are faster.
2. **Compare scans**: Archive old results: `mv output output_$(date +%Y%m%d)`
3. **Focus scans**: Target specific IPs for faster results
4. **Monitor progress**: Watch logs: `docker-compose logs -f orchestrator`
5. **Batch scans**: Create script to scan multiple networks

## 🔗 Quick Links

- [Full Documentation](README.md)
- [Advanced Usage](USAGE.md)
- [Architecture Details](ARCHITECTURE.md)
- [Contributing Guide](CONTRIBUTING.md)
- [License](LICENSE)

---

**Ready to scan? Run: `./start.sh`** 🚀

**Questions? Check the [USAGE.md](USAGE.md) or open an issue on GitHub.**
