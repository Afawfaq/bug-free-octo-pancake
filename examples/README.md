# Example Configurations

This directory contains sample configuration files for different scanning scenarios.

## Available Configurations

| File | Use Case | Description |
|------|----------|-------------|
| `home-network.env` | Home Security | Conservative scan for residential networks |
| `enterprise-network.env` | Corporate | Thorough scan with authorization |
| `quick-scan.env` | Fast Recon | Minimal footprint, quick results |
| `iot-focused.env` | Smart Home | Extended IoT device discovery |

## Usage

1. Copy the appropriate example to `.env` in the project root:
   ```bash
   cp examples/home-network.env ../.env
   ```

2. Edit the configuration to match your network:
   ```bash
   nano ../.env
   ```

3. Run the scan:
   ```bash
   cd ..
   ./start.sh
   ```

## Configuration Reference

### Network Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_NETWORK` | Network CIDR to scan | `192.168.1.0/24` |
| `ROUTER_IP` | Gateway/router IP | `192.168.1.1` |
| `CHROMECAST_IP` | Chromecast device IP | `192.168.1.100` |
| `TV_IP` | Smart TV IP | `192.168.1.101` |
| `PRINTER_IP` | Network printer IP | `192.168.1.102` |
| `DLNA_IPS` | DLNA servers (comma-separated) | `192.168.1.103,192.168.1.104` |

### Scan Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PASSIVE_DURATION` | Passive scan duration (seconds) | `30` |
| `DISCOVERY_RATE` | Masscan packets per second | `1000` |
| `NUCLEI_SEVERITY` | Severity levels to report | `critical,high,medium` |

### Performance Options

| Variable | Description | Default |
|----------|-------------|---------|
| `PARALLEL_EXECUTION` | Run independent phases in parallel | `true` |
| `VERBOSE` | Enable verbose logging | `false` |
| `SCAN_TIMEOUT` | Command timeout (seconds) | `600` |

### Feature Toggles

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_ATTACK_SURFACE` | Run attack surface analysis | `true` |
| `ENABLE_ADVANCED_MONITOR` | Run advanced monitoring | `true` |

## Creating Custom Configurations

1. Start with the closest example to your use case
2. Adjust network settings for your environment
3. Tune scan settings based on:
   - Available time
   - Network size
   - Required depth of analysis
   - Acceptable network impact

## Tips

- **Home Networks**: Use lower discovery rates to avoid disrupting devices
- **Enterprise**: Always get written authorization first
- **Quick Scans**: Disable advanced modules for faster completion
- **IoT Focus**: Extend passive duration to catch periodic broadcasts
