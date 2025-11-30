# Changelog

All notable changes to the LAN Reconnaissance Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.1] - 2025-11-30

### Fixed
- **Docker Build Fix**: Updated `discovery/Dockerfile` to use Go 1.24.3 (required by naabu v2.3.7+)
  - Removed deprecated `golang-go` package from apt
  - Installed Go 1.24.3 from official Go downloads
  - Set proper GOPATH and PATH environment variables

### Changed
- Removed deprecated `version` attribute from `docker-compose.yml` and `docker-compose.windows.yml`

### Added
- **Comprehensive Unit Test Suite**: Added 105+ new unit tests covering:
  - `test_notifications.py`: NotificationManager tests (Slack, Discord, Email, webhooks)
  - `test_database.py`: Database module tests (scans, hosts, findings, configs)
  - `test_config_validator.py`: ConfigValidator tests (validation, defaults, env expansion)
  - `test_retry.py`: Retry system tests (retry handler, circuit breaker, checkpoints)
- Total test count now 115 tests

## [2.5.0] - 2025-11-30

### Added
- **Health Checker Module** (`health_checker.py`): Comprehensive system health monitoring:
  - Docker environment verification
  - Container health status monitoring
  - Network connectivity tests
  - Disk space and memory monitoring
  - Dependency verification
  - Service availability tests
  - Quick check vs full check modes
  - JSON and CLI output formats
  - Actionable recommendations
- **Dependency Manager** (`dependency_manager.py`): Automated dependency management:
  - Python package verification and installation
  - System tool availability checks
  - Docker image verification
  - Version checking with minimum requirements
  - Auto-generation of requirements.txt
  - Platform-specific handling
- **Integration Module** (`integration.py`): Unified framework interface:
  - Single entry point for all framework features
  - Programmatic API for automation
  - Context manager support (`with LANReconFramework() as fw:`)
  - Event callbacks (on_scan_start, on_scan_complete, etc.)
  - Configuration from environment or code
  - Scheduled scan support
  - Export/import integration
  - Quick scan convenience function
- **requirements.txt**: Complete Python dependency specification
- **Full compatibility verification** for all platforms

### Changed
- Framework now provides a single unified API via `integration.py`
- All modules can be verified before running with health checker
- Improved first-time user experience with dependency verification

## [2.4.0] - 2025-11-30

### Added
- **Cross-Platform Support**: Full Windows and macOS compatibility:
  - PowerShell scripts for Windows (`start.ps1`, `stop.ps1`, `clean.ps1`, `quick-scan.ps1`, `view-report.ps1`)
  - Windows/macOS-compatible Docker Compose file (`docker-compose.windows.yml`)
  - Auto-detection of platform and compose file selection
  - Comprehensive platform support documentation (`PLATFORM_SUPPORT.md`)
  - WSL2 integration guide for best Windows experience
  - Port mapping configuration for Docker Desktop
- **Platform-Aware Scripts**: Shell scripts now detect platform and adjust behavior
- **Bridged Network Mode**: Alternative networking for Docker Desktop compatibility

### Changed
- Start scripts now auto-detect and use appropriate compose file
- README updated with cross-platform instructions
- All shell scripts now have PowerShell equivalents

## [2.3.0] - 2025-11-29

### Added
- **Scan Scheduler**: Full-featured job scheduling system:
  - Cron-style scheduling expressions
  - One-time scheduled scans
  - Recurring scans with configurable intervals
  - Daily and weekly scheduling
  - Job management (add, remove, pause, resume)
  - Scan history tracking per job
  - Notification integration for job completion/failure
  - Persistence across restarts (SQLite)
- **Export/Import System**: Data portability and backup:
  - Multiple export formats (JSON, CSV, XML, YAML)
  - Selective data export (scans, hosts, findings)
  - Data anonymization for sharing
  - Compression support (gzip)
  - Import validation and merging
  - CLI interface for export/import operations
- **Anomaly Detection**: ML-based network behavior analysis:
  - Statistical anomaly detection (z-score based)
  - Device behavior baselines
  - New host/missing host detection
  - Port usage pattern analysis
  - Service change detection
  - OS/device type change alerts
  - Suspicious port/service detection
  - Time-based pattern recognition
  - Anomaly history tracking
  - Configurable detection thresholds
- **Enhanced CLI Tool**: Unified command-line interface:
  - Comprehensive command structure (scan, status, stop, logs, results, config, etc.)
  - Interactive shell mode with command history
  - Multiple output formats (table, JSON, CSV)
  - Configuration profile management
  - Batch job execution
  - Color-coded output with severity indicators
  - Tab completion support
- **Web Dashboard**: Browser-based monitoring interface:
  - Real-time scan status and progress
  - Interactive network topology visualization
  - Finding severity breakdown charts
  - Host inventory table
  - Live scan logs
  - Scan history with comparison
  - Start/stop scan controls
  - Dark theme with responsive design
  - REST API integration

### Changed
- CLI now supports all major framework operations from a single entry point
- Improved data organization with dedicated database per module

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
