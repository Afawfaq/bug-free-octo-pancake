# Environment Manipulation Module

**DEFENSIVE SECURITY TOOL - Authorization Required**

## Overview

The Environment Manipulation module tests network resilience by analyzing response to manipulated core network services. This is a **defensive security assessment tool** designed to identify vulnerabilities in network infrastructure.

## Components

### 1. Fake NTP Server (`fake_ntp_server.py`)
Tests NTP security by responding with manipulated time.

**Attack Scenarios:**
- Time-warp attacks (past/future)
- Certificate validation bypass
- License expiration bypass
- Kerberos authentication disruption

### 2. DNS Sinkhole (`dns_sinkhole.py`)
Tests DNS security by intercepting queries.

**Attack Scenarios:**
- Update server blocking
- Telemetry endpoint redirection
- DNS-based command and control
- Data exfiltration via DNS

### 3. DHCP Manipulator (`dhcp_manipulator.py`)
Tests DHCP security (DISABLED BY DEFAULT).

**Attack Scenarios:**
- Gateway hijacking
- DNS poisoning via DHCP
- WPAD proxy injection
- DHCP starvation

### 4. IPv6 RA Injector (`ipv6_ra_injector.py`)
Tests IPv6 security (DISABLED BY DEFAULT).

**Attack Scenarios:**
- IPv6 MITM via fake gateway
- DNS hijacking via IPv6
- MTU manipulation DoS
- RA flooding

### 5. UPnP Override (`upnp_override.py`)
Tests UPnP security.

**Attack Scenarios:**
- Port forwarding hijacking
- Firewall bypass
- NAT traversal manipulation

## Safety Features

**Risk Levels:**
- **LOW (Enabled)**: NTP, UPnP - passive response only
- **MEDIUM (Use caution)**: DNS - can disrupt resolution
- **HIGH (Disabled)**: DHCP, IPv6 RA - can disrupt connectivity

**Safety Controls:**
- Dangerous modules disabled by default
- Configurable test duration
- Graceful cleanup on exit
- Comprehensive logging

## Usage

```bash
# Safe testing (NTP + UPnP only)
docker-compose up environment-manipulation

# With DNS (use caution)
ENABLE_DNS=true docker-compose up environment-manipulation

# Never enable DHCP/IPv6 in production!
```

## Authorization Requirements

✅ Written authorization required
✅ Controlled environment only
✅ Document all activities
✅ Follow responsible disclosure

## Legal Notice

Use only in authorized, controlled environments. Unauthorized use may violate laws.
