# 🔬 LAN Zero-Day Research Framework

**A modular, extensible, automated system for discovering unknown vulnerabilities in controlled LAN environments.**

⚠️ **CRITICAL SECURITY NOTICE:** This framework is designed for authorized security research only. Use on networks you own or have explicit written permission to test. Unauthorized use is illegal.

---

## Architecture Overview

### 7-Subsystem Pipeline

```
┌─────────────────┐
│ Passive Recon   │──┐
└─────────────────┘  │
                     ├──> ┌──────────────────┐
┌─────────────────┐  │    │   Orchestrator   │
│ Active Recon    │──┤    │   (Controller)   │
└─────────────────┘  │    └──────────────────┘
                     │              │
┌─────────────────┐  │              ├──> ┌─────────────────┐
│ Firmware Extract│──┤              │    │ Crash Triage    │
└─────────────────┘  │              │    └─────────────────┘
                     │              │              │
┌─────────────────┐  │              │              ▼
│ Protocol Fuzzing│──┤              │    ┌─────────────────┐
└─────────────────┘  │              │    │  Zero-Day DB    │
                     │              │    └─────────────────┘
┌─────────────────┐  │              │
│ Behavior Monitor│──┤              │
└─────────────────┘  │              │
                     │              ▼
┌─────────────────┐  │    ┌─────────────────┐
│ Reporting       │──┘    │  Reports/Alerts │
└─────────────────┘       └─────────────────┘
```

---

## Subsystem 1: Passive Recon Module

**Purpose:** Establish baseline, fingerprint devices, detect anomalies

### Components

- **zeek-passive** - Deep packet inspection and protocol analysis
- **arkime-pcap** - Full packet capture with indexing
- **tshark-lite** - Real-time traffic summaries
- **p0f-fingerprint** - Passive OS fingerprinting

### Outputs
```json
{
  "device_fingerprints": {
    "192.168.1.100": {
      "os": "Linux 4.x",
      "services": ["http", "ssh", "upnp"],
      "protocols": ["TCP", "UDP", "IGMP"],
      "behavior_baseline": {...}
    }
  },
  "protocol_inventory": [...],
  "service_flow_graph": {...},
  "anomaly_markers": [...]
}
```

### Container
- **Image:** `zeek/zeek:latest`
- **Network:** host mode
- **Capabilities:** NET_ADMIN, NET_RAW
- **Volume:** `/nsm/zeek/logs`

---

## Subsystem 2: Active Recon Module

**Purpose:** Map services via controlled scanning

### Tools
- nmap NSE (comprehensive service detection)
- Masscan (fast port scanning)
- RustScan (parallel scanner)
- naabu (Go-based port scanner)

### Outputs
```json
{
  "service_map": {
    "192.168.1.50": {
      "ports": {
        "80": {"service": "http", "version": "nginx/1.18.0"},
        "9100": {"service": "jetdirect", "banner": "HP LaserJet"}
      }
    }
  },
  "protocol_capabilities": {
    "upnp": ["SOAP", "SUBSCRIBE", "NOTIFY"],
    "ipp": ["CUPS-Get-Printers", "Print-Job"]
  }
}
```

---

## Subsystem 3: Firmware & Binary Extraction

**Purpose:** Extract code for analysis and fuzzing

### Workflow

1. **Firmware Acquisition**
   - Web UI downloads
   - TFTP extraction
   - Memory dumps
   - Update server MitM

2. **Extraction**
   ```bash
   binwalk -e firmware.bin
   unsquashfs filesystem.squashfs
   ```

3. **Emulation**
   ```bash
   firmadyne.sh import firmware.bin
   qemu-system-mips -M malta -kernel vmlinux ...
   ```

### Components

- **binwalk** - Firmware analysis tool
- **Firmadyne** - Automated firmware emulation
- **QEMU** - CPU emulator
- **squashfs-tools** - Filesystem extraction

### Outputs
- Emulated firmware instances
- Extracted binary list
- Protocol handler identification
- Shared library inventory

---

## Subsystem 4: Protocol Fuzzing Module

**Purpose:** Discover crash-triggering inputs

### Fuzzer Matrix

| Protocol | Primary Fuzzer | Secondary | Target Devices |
|----------|---------------|-----------|----------------|
| IPP      | boofuzz       | AFL++     | Printers       |
| UPnP/SSDP| boofuzz       | Sulley    | Routers, TVs   |
| mDNS     | boofuzz       | Custom    | All IoT        |
| DHCP     | Sulley        | boofuzz   | Network infra  |
| HTTP     | AFL++         | Peach     | Web interfaces |
| MQTT     | boofuzz       | Custom    | IoT devices    |
| RTSP     | boofuzz       | Peach     | Cameras        |

### Fuzzing Strategy

1. **Smart Generation**
   - Protocol-aware mutations
   - State machine tracking
   - Coverage-guided (AFL++)

2. **Delivery**
   - Controlled rate limiting
   - Session management
   - Timing analysis

3. **Monitoring**
   - Response validation
   - Crash detection
   - Hang detection

### Configuration Example
```yaml
fuzzing_profiles:
  printer_ipp:
    protocol: IPP
    fuzzer: boofuzz
    target_port: 631
    mutations:
      - header_overflow
      - version_fuzzing
      - attribute_injection
    rate_limit: 10/second
    timeout: 5s
    
  upnp_ssdp:
    protocol: SSDP
    fuzzer: boofuzz
    target_port: 1900
    mutations:
      - msearch_malformed
      - notify_overflow
      - location_injection
    rate_limit: 5/second
```

---

## Subsystem 5: Behavior Monitor Module

**Purpose:** Detect instability and crashes

### Monitoring Stack

1. **Network Layer**
   - Zeek event hooks
   - Packet loss detection
   - Connection state anomalies

2. **System Layer** (for accessible hosts)
   - Falco syscall monitoring
   - Core dump collection
   - Process crash detection

3. **Application Layer**
   - Service availability polling
   - HTTP status monitoring
   - SNMP trap collection

### Detection Mechanisms

```python
# Crash indicators
indicators = {
    "network": {
        "tcp_reset_spike": threshold > 10/min,
        "connection_refused": after_successful_connection,
        "udp_icmp_unreachable": unexpected_port_closed
    },
    "service": {
        "ping_timeout": 3_consecutive_failures,
        "http_500_errors": sudden_increase,
        "service_unavailable": expected_port_closed
    },
    "system": {
        "core_dump_created": detected_in_watch_dir,
        "segfault_log": syslog_pattern_match,
        "oom_killer": kernel_log_event
    }
}
```

### Outputs
- Crash timestamps with microsecond precision
- PCAP slices around crash events
- System call traces (if available)
- Service unavailability logs

---

## Subsystem 6: Crash Triage Module

**Purpose:** Analyze and reproduce crashes

### Analysis Pipeline

1. **Crash Collection**
   ```bash
   # Gather artifacts
   - fuzzer_input_seed
   - pcap_slice (-5s to +5s around crash)
   - core_dump (if available)
   - device_logs
   ```

2. **Reproduction Attempt**
   ```bash
   # Replay attack
   tcpreplay -i eth0 crash_packets.pcap
   # Monitor for crash
   ```

3. **Forensics**
   ```bash
   # For emulated targets
   gdb firmware_binary core.dump
   (gdb) bt full
   (gdb) x/100x $rsp
   
   # For QEMU instances
   qemu-system -S -gdb tcp::1234
   gdb -ex "target remote :1234"
   ```

4. **Classification**
   - Memory corruption (buffer overflow, heap overflow)
   - Null pointer dereference
   - Integer overflow
   - Logic error
   - Denial of service

### Exploit Development Workflow

```
Crash → Reproduce → Root Cause → Exploit Dev → PoC → Report
  ↓         ↓           ↓            ↓          ↓       ↓
Input   PCAP+Core   Disasm+GDB   Shellcode   Demo   CVE
```

---

## Subsystem 7: Orchestration Layer

**Purpose:** Automate entire pipeline

### Controller Architecture

```python
class ZeroDayOrchestrator:
    def __init__(self):
        self.discovery_engine = PassiveRecon() + ActiveRecon()
        self.firmware_lab = FirmwareExtractor()
        self.fuzzing_pool = FuzzerCluster()
        self.monitor = BehaviorMonitor()
        self.triage = CrashTriageEngine()
        
    async def run_cycle(self):
        # 1. Discovery
        devices = await self.discovery_engine.scan()
        
        # 2. Profiling
        for device in devices:
            profile = await self.build_fuzzing_profile(device)
            
            # 3. Firmware extraction (if possible)
            firmware = await self.firmware_lab.extract(device)
            if firmware:
                await self.firmware_lab.emulate(firmware)
            
            # 4. Fuzzing
            fuzzer = self.fuzzing_pool.assign(profile)
            fuzzer.start_async()
        
        # 5. Monitoring
        while self.fuzzing_pool.active():
            events = await self.monitor.check_all()
            for event in events:
                if event.is_crash():
                    await self.triage.analyze(event)
        
        # 6. Reporting
        await self.generate_report()
```

### Configuration
```yaml
orchestrator:
  discovery:
    passive_duration: 300  # 5 minutes
    active_scan_rate: moderate
  
  fuzzing:
    parallel_jobs: 4
    max_duration: 86400  # 24 hours
    auto_restart: true
  
  monitoring:
    check_interval: 5
    alert_threshold: immediate
  
  triage:
    auto_reproduce: true
    save_artifacts: true
    max_attempts: 3
```

---

## Deployment

### Docker Compose Structure

```yaml
version: '3.8'

services:
  zeek:
    build: ./zerodav-framework/zeek
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./data/zeek:/nsm/zeek
  
  arkime:
    build: ./zerodav-framework/arkime
    network_mode: host
    volumes:
      - ./data/pcap:/data/pcap
  
  boofuzz:
    build: ./zerodav-framework/fuzzers/boofuzz
    network_mode: host
    volumes:
      - ./data/crashes:/crashes
  
  aflpp:
    build: ./zerodav-framework/fuzzers/aflpp
    volumes:
      - ./data/afl:/afl
  
  firmadyne:
    build: ./zerodav-framework/firmware-lab/firmadyne
    privileged: true
    volumes:
      - ./data/firmware:/firmware
  
  monitor:
    build: ./zerodav-framework/behavior-monitor
    network_mode: host
    volumes:
      - ./data/logs:/logs
  
  triage:
    build: ./zerodav-framework/crash-triage
    volumes:
      - ./data/crashes:/crashes
      - ./data/analysis:/analysis
  
  orchestrator:
    build: ./zerodav-framework/orchestrator-zeroday
    depends_on: [zeek, boofuzz, aflpp, monitor, triage]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/data
    environment:
      - TARGET_NETWORK=192.168.1.0/24
```

---

## Usage

### Quick Start
```bash
# Initialize framework
./zeroday-init.sh

# Start all services
docker-compose -f docker-compose-zeroday.yml up -d

# Monitor orchestrator
docker logs -f zeroday-orchestrator

# View discovered crashes
./zeroday-report.sh --crashes

# Analyze specific crash
./zeroday-triage.sh --crash-id 12345
```

### Custom Fuzzing Campaign
```bash
# Target specific device
./zeroday-fuzz.sh --target 192.168.1.50 --protocol ipp

# Resume campaign
./zeroday-fuzz.sh --resume campaign_20250124

# Export results
./zeroday-export.sh --format json --output results.json
```

---

## Data Directory Structure

```
data/
├── zeek/           # Zeek logs and analytics
├── pcap/           # Full packet captures
├── firmware/       # Extracted firmware images
├── crashes/        # Crash artifacts
│   ├── inputs/     # Fuzzer inputs that caused crashes
│   ├── pcaps/      # Network traffic during crash
│   └── cores/      # Core dumps (if available)
├── analysis/       # Triage results
└── reports/        # Generated reports
```

---

## Extensibility

### Plugin Architecture

```python
# Custom fuzzer plugin
class CustomProtocolFuzzer(FuzzerPlugin):
    def __init__(self):
        self.protocol = "CUSTOM"
        self.port = 12345
    
    def generate_mutations(self, seed):
        # Your mutation logic
        pass
    
    def is_crash(self, response):
        # Your crash detection
        pass

# Register plugin
orchestrator.register_plugin(CustomProtocolFuzzer())
```

### Future Modules

- **ML-based anomaly detection**
- **Automated exploit generation**
- **BLE/Wireless fuzzing**
- **TR-064 router exploitation**
- **USB fuzzing for printers**
- **Ghidra/angr integration**

---

## Safety Protocols

1. **Isolated Network** - Use VLAN or physical separation
2. **Rate Limiting** - Prevent accidental DoS
3. **Automated Backups** - Device configuration backups before testing
4. **Kill Switch** - Emergency stop for all fuzzing
5. **Logging** - Comprehensive audit trail

---

## Responsible Disclosure

If you discover vulnerabilities:

1. **Document thoroughly** - Reproduction steps, impact analysis
2. **Contact vendor** - Through security contact or CERT
3. **Wait for patch** - 90-day disclosure timeline standard
4. **Publish responsibly** - After vendor confirmation

---

## Legal Considerations

- ✅ Test only authorized networks
- ✅ Obtain written permission
- ✅ Document authorization
- ✅ Follow local laws
- ✅ Respect privacy
- ❌ Never test production systems without approval
- ❌ Never weaponize findings
- ❌ Never sell zero-days

---

## Performance Metrics

Expected throughput:
- **Passive Recon:** Continuous, ~1Gbps
- **Active Scanning:** ~10K ports/sec
- **Fuzzing:** ~100-1000 tests/sec per protocol
- **Crash Detection:** <1 second latency
- **Triage:** ~5 minutes per crash

Resource requirements:
- **CPU:** 8+ cores recommended
- **RAM:** 32GB minimum
- **Storage:** 500GB+ for PCAP/artifacts
- **Network:** Gigabit minimum

---

## Monitoring Dashboard

Access at `http://localhost:3000` (Grafana)

Metrics:
- Devices discovered
- Fuzzing tests executed
- Crashes detected
- Reproduction success rate
- Coverage maps (AFL++)
- Network utilization

---

**For implementation details, see individual module documentation in `zerodav-framework/` directories.**

**Status:** Framework design complete, modules ready for implementation.
