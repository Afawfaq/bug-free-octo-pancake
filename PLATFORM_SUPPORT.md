# Platform Support Guide

This guide covers running the LAN Reconnaissance Framework on different operating systems.

## Quick Reference

| Platform | Recommended Setup | Full Support |
|----------|------------------|--------------|
| Ubuntu/Debian | Native Docker | ✅ Yes |
| Other Linux | Native Docker | ✅ Yes |
| Windows 10/11 | Docker Desktop + WSL2 | ✅ Yes |
| Windows (Native) | Docker Desktop | ⚠️ Limited |
| macOS | Docker Desktop | ⚠️ Limited |

## Linux (Ubuntu/Debian) - Full Support

### Prerequisites

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Log out and back in, then verify
docker --version
docker compose version
```

### Running the Framework

```bash
# Clone repository
git clone https://github.com/Afawfaq/bug-free-octo-pancake.git
cd bug-free-octo-pancake

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env

# Start framework
./start.sh

# Or use make
make build
make run
```

### Linux-Specific Features

- Full `network_mode: host` support for accurate network scanning
- Native raw socket access for passive monitoring
- ARP scanning works natively
- No port mapping required

---

## Windows - WSL2 (Recommended)

WSL2 provides the best Windows experience with full Linux compatibility.

### Step 1: Enable WSL2

```powershell
# Run as Administrator
wsl --install

# Restart computer, then set default version
wsl --set-default-version 2
```

### Step 2: Install Ubuntu

```powershell
# Install Ubuntu from Microsoft Store or command line
wsl --install -d Ubuntu
```

### Step 3: Install Docker Desktop

1. Download [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
2. During installation, enable WSL2 backend
3. In Docker Desktop Settings:
   - Go to Resources → WSL Integration
   - Enable integration with your Ubuntu distro

### Step 4: Run in WSL2

```bash
# Open Ubuntu terminal (from Start menu or `wsl` command)
cd ~

# Clone repository
git clone https://github.com/Afawfaq/bug-free-octo-pancake.git
cd bug-free-octo-pancake

# Configure and run
cp .env.example .env
./start.sh
```

### WSL2 Network Access

For the framework to scan your LAN from WSL2:

```bash
# Find your Windows host IP (usually the gateway from WSL perspective)
cat /etc/resolv.conf | grep nameserver

# Your LAN is accessible through the Windows host
# Set TARGET_NETWORK to your actual network
export TARGET_NETWORK=192.168.1.0/24
```

---

## Windows - Native (PowerShell)

For running directly on Windows without WSL2.

### Prerequisites

1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
2. Ensure Docker is running (check system tray icon)

### Running with PowerShell

```powershell
# Clone repository
git clone https://github.com/Afawfaq/bug-free-octo-pancake.git
cd bug-free-octo-pancake

# Copy environment template
Copy-Item .env.example .env

# Edit configuration (use your favorite editor)
notepad .env

# Start framework
.\start.ps1

# Or with options
.\start.ps1 -TargetNetwork "192.168.1.0/24" -RouterIP "192.168.1.1"
.\start.ps1 -Quick
.\start.ps1 -Help
```

### Available PowerShell Scripts

| Script | Description |
|--------|-------------|
| `start.ps1` | Start the framework |
| `stop.ps1` | Stop all containers |
| `clean.ps1` | Clean up containers and output |
| `quick-scan.ps1` | Run quick scan mode |
| `view-report.ps1` | Open the HTML report |

### Windows Limitations

When running natively on Windows (not WSL2):

1. **Network Mode**: Uses bridged networking instead of host mode
   - Some passive network monitoring features may be limited
   - ARP scanning may not see all devices

2. **Web Dashboard**: Access via `http://localhost:8080`

3. **Port Mapping**: The Windows compose file maps:
   - `8080` - Web Dashboard
   - `5000` - REST API
   - `9090` - Prometheus Metrics

---

## macOS

### Prerequisites

1. Install [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop)
2. Allocate sufficient resources in Docker Desktop Preferences

### Running on macOS

```bash
# Clone repository
git clone https://github.com/Afawfaq/bug-free-octo-pancake.git
cd bug-free-octo-pancake

# The start.sh script auto-detects macOS
./start.sh

# Or use PowerShell Core if installed
pwsh start.ps1
```

### macOS Limitations

Similar to Windows native mode:
- Uses bridged networking
- Some network scanning features limited
- Access dashboard at `http://localhost:8080`

### Recommended: Linux VM

For full functionality on macOS, consider:

1. **UTM** (free): Run Ubuntu VM with full Docker support
2. **Parallels**: Commercial VM with excellent performance
3. **VirtualBox**: Free, cross-platform VM

---

## Docker Compose Files

| File | Use Case |
|------|----------|
| `docker-compose.yml` | Linux (full host networking) |
| `docker-compose.windows.yml` | Windows/macOS (bridged networking) |

The start scripts automatically select the appropriate file based on your platform.

### Manual Selection

```bash
# Linux
docker compose -f docker-compose.yml up

# Windows/macOS
docker compose -f docker-compose.windows.yml up
```

---

## Troubleshooting

### Docker Not Running

**Windows/macOS**: Start Docker Desktop from the Start menu/Applications

**Linux**:
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

### Permission Denied

**Linux**:
```bash
sudo usermod -aG docker $USER
# Log out and back in
```

**Windows**: Run PowerShell as Administrator

### Network Scanning Not Working

1. Verify your TARGET_NETWORK is correct:
   ```bash
   # Linux/macOS
   ip route | grep default
   
   # Windows
   ipconfig
   ```

2. On Windows/macOS, some features require WSL2 or a Linux VM

### WSL2 Cannot Access LAN

Enable mirrored networking in `.wslconfig`:

```ini
# %USERPROFILE%\.wslconfig
[wsl2]
networkingMode=mirrored
```

Then restart WSL:
```powershell
wsl --shutdown
```

### Container Build Failures

```bash
# Clean and rebuild
docker compose down -v --rmi all
docker compose build --no-cache
```

---

## Feature Compatibility Matrix

| Feature | Linux | WSL2 | Windows Native | macOS |
|---------|-------|------|----------------|-------|
| Full network scan | ✅ | ✅ | ⚠️ | ⚠️ |
| ARP scanning | ✅ | ✅ | ❌ | ❌ |
| Passive monitoring | ✅ | ✅ | ⚠️ | ⚠️ |
| Web dashboard | ✅ | ✅ | ✅ | ✅ |
| REST API | ✅ | ✅ | ✅ | ✅ |
| Report generation | ✅ | ✅ | ✅ | ✅ |
| Nuclei scanning | ✅ | ✅ | ✅ | ✅ |
| IoT enumeration | ✅ | ✅ | ✅ | ✅ |
| Scheduled scans | ✅ | ✅ | ✅ | ✅ |

Legend:
- ✅ Full support
- ⚠️ Limited/partial support
- ❌ Not supported

---

## Recommended Configurations

### Home Network (Any Platform)

```env
TARGET_NETWORK=192.168.1.0/24
ROUTER_IP=192.168.1.1
PASSIVE_DURATION=30
```

### Enterprise Network (Linux/WSL2 Recommended)

```env
TARGET_NETWORK=10.0.0.0/16
PASSIVE_DURATION=120
PARALLEL_EXECUTION=true
SCAN_TIMEOUT=3600
```

### Quick Assessment (Any Platform)

```bash
# Linux/macOS
./start.sh --quick

# Windows
.\start.ps1 -Quick
```
