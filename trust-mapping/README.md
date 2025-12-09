# Trust Mapping Module

## Overview

The Trust Mapping module analyzes Windows environments, SMB relationships, and network trust boundaries to identify lateral movement opportunities and attack paths.

## Components

### 1. Windows Trust Graph Builder (`windows_trust_graph.py`)
- Scans for Windows hosts using nmap
- Identifies domain controllers, servers, and workstations
- Maps SMB share relationships
- Analyzes trust boundaries and authentication flows
- Builds attack paths for lateral movement

### 2. SMB Relationship Tracker (`smb_tracker.py`)
- Enumerates SMB shares via null session
- Analyzes share permissions and access patterns
- Identifies administrative shares (C$, ADMIN$, IPC$)
- Flags suspicious shares (backup, password, confidential, etc.)
- Maps lateral movement paths using SMB

### 3. Attack Path Synthesizer (`attack_path_synthesizer.py`)
- Loads reconnaissance data from all modules
- Identifies entry points (default credentials, vulnerabilities, open shares)
- Builds complete attack chains with MITRE ATT&CK mapping
- Prioritizes chains by risk and feasibility
- Generates security recommendations

## Features

- **Windows Host Discovery**: Identifies Windows systems via SMB, LDAP, and Kerberos ports
- **Domain Controller Detection**: Recognizes DCs by port signatures and hostnames
- **SMB Enumeration**: Discovers accessible shares without credentials
- **Trust Analysis**: Maps cross-domain trusts and authentication flows
- **Attack Path Synthesis**: Combines data from all modules to build exploit chains
- **MITRE ATT&CK Mapping**: Links attack steps to standard tactics and techniques
- **Risk Assessment**: Scores attack paths by risk level and difficulty
- **Actionable Recommendations**: Provides prioritized security guidance

## Output

The module generates the following files in `/output/trust-mapping/`:

- `windows_trust_graph.json` - Complete Windows environment mapping
- `smb_relationships.json` - SMB share access patterns
- `attack_paths.json` - Synthesized attack chains with recommendations
- `trust_mapping_summary.txt` - Human-readable summary

## Attack Path Examples

### Entry Points Identified:
1. **Default Credentials** (CRITICAL)
   - Service: HTTP/SSH/FTP with known defaults
   - Difficulty: LOW

2. **Vulnerabilities** (HIGH)
   - CVE with CVSS ≥ 7.0
   - Difficulty: MEDIUM

3. **Open SMB Shares** (HIGH/MEDIUM)
   - Null session accessible shares
   - Administrative shares (C$, ADMIN$)
   - Difficulty: LOW

### Attack Chain Structure:
```json
{
  "entry_point": {
    "type": "default_credential",
    "target": "192.168.1.100",
    "risk": "CRITICAL"
  },
  "steps": [
    {"step": 1, "action": "Exploit default credential", "technique": "T1078"},
    {"step": 2, "action": "Harvest credentials", "technique": "T1003"},
    {"step": 3, "action": "Lateral movement via SMB", "technique": "T1021"},
    {"step": 4, "action": "Privilege escalation", "technique": "T1068"},
    {"step": 5, "action": "Establish persistence", "technique": "T1053"}
  ],
  "priority_score": 95
}
```

## Requirements

- Network access to target Windows hosts
- Port access: 445 (SMB), 139 (NetBIOS), 135 (RPC), 389 (LDAP), 88 (Kerberos)
- Nmap with OS detection and SMB scripts
- smbclient for share enumeration

## Usage

Via orchestrator (automatic):
```bash
./start.sh
```

Direct invocation:
```bash
docker-compose run trust-mapping <output_dir> <network_range> <recon_dir>
```

## Security Considerations

**Defensive Tool**: This module is designed for authorized security assessment only.

**Requires Authorization**: Written permission required before use.

**Legal Compliance**: Ensure compliance with CFAA and local laws.

**Ethical Guidelines**:
- Only scan authorized networks
- Minimize disruption to services
- Protect discovered information
- Follow responsible disclosure

## Integration

**Orchestrator Phase**: 14 (after WiFi attacks, before report generation)

**Dependencies**: 
- Credential attacks module (for entry points)
- Patch cadence module (for vulnerabilities)
- Service discovery (for host inventory)

**Parallel Execution**: Can run in parallel with other offensive modules

## Recommendations Output

The module generates prioritized recommendations:

1. **CRITICAL**: Change all default credentials immediately
2. **HIGH**: Apply security patches to vulnerable systems
3. **HIGH**: Restrict SMB share access and disable null sessions
4. **MEDIUM**: Implement network segmentation to prevent lateral movement
5. **MEDIUM**: Deploy endpoint detection and response (EDR)

## MITRE ATT&CK Coverage

- **T1078**: Valid Accounts
- **T1190**: Exploit Public-Facing Application
- **T1021.002**: SMB/Windows Admin Shares
- **T1003**: OS Credential Dumping
- **T1021**: Remote Services
- **T1068**: Exploitation for Privilege Escalation
- **T1053**: Scheduled Task/Job

## Performance

- **Scan Time**: 2-10 minutes (depends on network size)
- **Timeout**: 600 seconds (10 minutes)
- **Resource Usage**: Low CPU, moderate network bandwidth

## Limitations

- Requires Windows hosts on network for meaningful results
- Null session enumeration may be blocked by modern Windows
- Domain trust analysis limited to multi-domain environments
- Attack path synthesis quality depends on reconnaissance data completeness

## Future Enhancements

- Active Directory enumeration via LDAP
- Kerberos ticket analysis
- PowerShell remoting detection
- WMI/DCOM lateral movement paths
- BloodHound integration
- Real-time trust monitoring
