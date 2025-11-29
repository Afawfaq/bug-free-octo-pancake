# Changelog

All notable changes to the LAN Reconnaissance Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2025-11-29

### Added
- **Plugin Architecture**: Modular plugin system for extending functionality:
  - Base plugin classes (PluginBase, ScannerPlugin, AnalyzerPlugin, ReporterPlugin)
  - Plugin lifecycle management (load, unload, enable, disable)
  - Hook system for scan events (pre_scan, post_discovery, on_finding, etc.)
  - Plugin configuration support
  - Example plugin template generator
- **REST API Server**: Full-featured API for programmatic access:
  - Health check and status endpoints
  - Scan control (start, stop, progress)
  - Results retrieval and history
  - Configuration management
  - Plugin management endpoints
  - Prometheus metrics endpoint
  - CORS support for web integration
- **Database Integration**: Persistent storage with SQLite:
  - Scan result persistence with full history
  - Host inventory tracking across scans
  - Finding storage with severity tracking
  - Configuration snapshots
  - Scan comparison for change detection
  - Automatic cleanup of old data
- **Retry & Recovery System**: Robust error handling:
  - Multiple retry strategies (fixed, linear, exponential, exponential with jitter)
  - Circuit breaker pattern for failing services
  - Checkpoint/resume for long-running scans
  - Graceful degradation with fallback handlers
  - Retry decorator for easy integration
- **Configuration Validation**: Schema-based validation:
  - JSON Schema-like validation
  - Custom validators for IPs, CIDRs, emails
  - Environment variable expansion (${VAR:-default} syntax)
  - Default value injection
  - Configuration migration support
  - Example configuration generator
- **Metrics & Monitoring**: Prometheus-compatible metrics:
  - Counter, Gauge, Histogram, Summary metric types
  - Pre-defined scan, phase, finding, and container metrics
  - Prometheus text format export
  - JSON export for dashboards
  - Timer context manager for easy timing
  - API request metrics

### Changed
- Framework is now fully modular with well-defined interfaces
- All components can be extended without modifying core code
- Improved error handling throughout the framework

## [2.1.0] - 2025-11-29

### Added
- **Notification System**: Multi-channel alerting via:
  - Slack webhooks
  - Discord webhooks
  - Email (SMTP)
  - Custom webhooks
  - Configurable severity thresholds
- **Default Credentials Database**: Comprehensive database covering:
  - Routers (ASUS, TP-Link, Netgear, Linksys, D-Link, Ubiquiti, Cisco, etc.)
  - Printers (HP, Epson, Brother, Canon, Lexmark, Xerox, Samsung, Ricoh)
  - NAS devices (Synology, QNAP, Western Digital, NETGEAR, Buffalo, Drobo)
  - IP Cameras (Hikvision, Dahua, Axis, Foscam, Reolink, Amcrest)
  - Smart home devices, switches, access points, VoIP phones
- **Scan Profiles System**: Predefined profiles for different use cases:
  - Quick, Standard, Thorough, Stealth, IoT-Focused, Vulnerability, Compliance
- **New Nuclei Templates**:
  - `router-admin-panel.yaml` - Router admin panel detection
  - `smart-tv-debug.yaml` - Smart TV debug endpoint exposure
  - `nas-exposure.yaml` - NAS device vulnerability detection
  - `ip-camera-exposure.yaml` - IP camera exposure and RTSP detection
  - `iot-telnet-access.yaml` - IoT Telnet service detection
- **Enhanced Report Builder v2.0.0**:
  - Executive summary with risk scoring (0-100)
  - Severity breakdown visualization
  - Device type classification in network graph
  - CSV export for spreadsheet analysis
  - Improved network topology with device type colors
  - Default HTML template included
- **Data Directory**: Centralized data storage with documentation

### Changed
- Report builder now calculates risk scores based on vulnerability weights
- Network topology graph now classifies devices by type (server, printer, IoT, etc.)
- Improved report template with modern styling

## [2.0.0] - 2025-11-29

### Added
- **Parallel Execution**: Independent phases now run in parallel for significantly faster scans
- **Advanced Monitoring Phase**: New Phase 7 integrates PKI monitoring, DHCP profiling, DNS analysis, and protocol guilt analysis
- **Attack Surface Phase**: New Phase 8 for stress testing, forgotten protocol scanning, and trust assumption testing
- **Enhanced Orchestrator v2.0.0**:
  - Color-coded logging with severity levels
  - CLI argument support (`--verbose`, `--no-parallel`, `--timeout`, `--passive-duration`)
  - Phase timing statistics
  - Execution stats JSON export
  - Better error handling and reporting
- **CI/CD Pipeline**: GitHub Actions workflow for:
  - Code linting (flake8, black, shellcheck)
  - Unit testing with pytest
  - Security scanning with Trivy
  - Docker container builds
  - Docker Compose validation
  - Documentation checks
  - Automated releases
- **Health Checks**: Container health monitoring with progress indicators
- **Execution Statistics**: Detailed JSON output of scan performance metrics

### Changed
- Orchestrator now coordinates 9 phases instead of 7
- Improved container readiness checking with percentage progress
- Enhanced summary output with severity breakdown for findings
- Better timeout handling with configurable values

### Fixed
- Container wait logic now checks all containers including advanced ones
- More robust error handling in phase execution

## [1.0.0] - 2025-11-24

### Added
- Initial release of LAN Reconnaissance Framework
- **Core Containers**:
  - Passive reconnaissance (ARP, mDNS, SSDP)
  - Active discovery (naabu, rustscan, masscan)
  - Service fingerprinting (nmap, httpx, WhatWeb)
  - IoT enumeration (Chromecast, printers, TVs, DLNA)
  - Nuclei security scanning
  - Web screenshots (Aquatone, EyeWitness)
  - Report generation (HTML, JSON, network graphs)
  - Main orchestrator
- **Advanced Containers**:
  - Advanced monitoring (PKI, DHCP, DNS, metadata, protocol guilt)
  - Attack surface analysis (stress, forgotten protocols, entropy, trust)
- **Custom Nuclei Templates**:
  - UPnP misconfiguration detection
  - Printer default credential testing
  - Chromecast exposed API checks
  - DLNA information disclosure
- **Documentation**:
  - README.md - Main documentation
  - USAGE.md - Detailed usage guide
  - ARCHITECTURE.md - Technical architecture
  - CONTRIBUTING.md - Contribution guidelines
  - QUICKSTART.md - Quick start guide
  - FEATURES.md - Complete feature list
  - ZERODAY_FRAMEWORK.md - Research framework architecture
  - COMPLETE_ATTACK_SURFACE.md - Practical attack techniques
  - ADVERSARIAL_THINKING.md - Offensive mindset documentation
  - PROJECT_STATUS.md - Current status
- **Scripts**:
  - start.sh - Main launcher
  - stop.sh - Container shutdown
  - clean.sh - Cleanup script
  - quick-scan.sh - Fast scan mode
  - view-report.sh - Report viewer

### Security
- All containers run with minimal required capabilities
- No external data transmission
- Local-only result storage
- Rate limiting on aggressive scans

---

## Roadmap

### [2.1.0] - Planned
- Web-based dashboard for real-time monitoring
- REST API for programmatic access
- Webhook notifications for findings
- Database backend for result persistence

### [3.0.0] - Future
- Zero-day research framework integration
- ML-based anomaly detection
- Distributed scanning capabilities
- Full fuzzing framework (boofuzz, AFL++)

---

## Migration Guide

### From 1.0.0 to 2.0.0

1. **Update docker-compose.yml**: The orchestrator now depends on advanced-monitor and attack-surface containers.

2. **Environment Variables**: New optional variables:
   ```bash
   PARALLEL_EXECUTION=true  # Enable/disable parallel execution
   VERBOSE=false            # Enable verbose logging
   SCAN_TIMEOUT=600         # Command timeout in seconds
   ```

3. **Output Changes**: New `execution_stats.json` file in output directory.

4. **Phase Numbers Changed**: 
   - Old Phase 7 (Report) → New Phase 9
   - New Phase 7: Advanced Monitoring
   - New Phase 8: Attack Surface Analysis
