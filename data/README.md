# Data Directory

This directory contains reference data and configuration files used by the LAN Reconnaissance Framework.

## Files

### `default-credentials.json`
A comprehensive database of default credentials for common network devices:

- **Routers**: ASUS, TP-Link, Netgear, Linksys, D-Link, Ubiquiti, MikroTik, Cisco, ZyXEL
- **Printers**: HP, Epson, Brother, Canon, Lexmark, Xerox, Samsung, Ricoh
- **NAS Devices**: Synology, QNAP, Western Digital, NETGEAR ReadyNAS, Buffalo, Drobo
- **IP Cameras**: Hikvision, Dahua, Axis, Foscam, Reolink, Amcrest, Vivotek, Hanwha
- **Smart Home**: Philips Hue, Samsung SmartThings, TP-Link Kasa, Wyze, Ring
- **Switches**: Cisco, HP ProCurve, Netgear, D-Link, TP-Link
- **Access Points**: Ubiquiti, Aruba, Ruckus, Cisco Aironet, Meraki
- **VoIP Phones**: Cisco SPA, Polycom, Grandstream, Yealink, Avaya

### `scan-profiles.json`
Predefined scan profiles for different use cases:

| Profile | Description | Estimated Time |
|---------|-------------|----------------|
| `quick` | Fast scan with minimal footprint | 5-10 minutes |
| `standard` | Balanced scan for home/small office | 30-45 minutes |
| `thorough` | Comprehensive analysis | 1-2 hours |
| `stealth` | Low-profile scanning | 2-4 hours |
| `iot_focused` | Specialized for IoT devices | 45-60 minutes |
| `vulnerability` | Prioritizes vulnerability detection | 20-30 minutes |
| `compliance` | Security compliance checks | 45-60 minutes |

## Usage

### Default Credentials
```python
import json

with open('data/default-credentials.json') as f:
    creds = json.load(f)

# Get printer credentials
printer_creds = creds['printers']['hp']
for cred in printer_creds:
    print(f"Username: {cred['username']}, Password: {cred['password']}")
```

### Scan Profiles
```python
import json

with open('data/scan-profiles.json') as f:
    profiles = json.load(f)

# Load standard profile settings
standard = profiles['profiles']['standard']
print(f"Profile: {standard['name']}")
print(f"Estimated time: {standard['estimated_time']}")
```

## Adding Custom Data

### Custom Credentials
Add your own device credentials by editing `default-credentials.json`:

```json
{
  "custom_devices": {
    "my_device": [
      {"username": "admin", "password": "mypassword"}
    ]
  }
}
```

### Custom Scan Profiles
Create custom profiles in `scan-profiles.json`:

```json
{
  "profiles": {
    "my_custom_profile": {
      "name": "My Custom Scan",
      "description": "Custom scan configuration",
      "settings": {
        "PASSIVE_DURATION": 60,
        "DISCOVERY_RATE": 1500
      },
      "phases": {
        "passive": true,
        "discovery": true
      }
    }
  }
}
```

## Security Notice

⚠️ **WARNING**: This data is for authorized security testing only.

- Only use on networks you own or have explicit permission to test
- Default credentials are publicly known but still require authorization to test
- Unauthorized access to computer systems is illegal

## Contributing

To add new device credentials or scan profiles:

1. Verify the credentials are publicly documented
2. Add to the appropriate category in the JSON file
3. Include manufacturer/device model information
4. Submit a pull request with your changes

## References

- [Default Password Database](https://www.routerpasswords.com/)
- [CISA Security Advisories](https://www.cisa.gov/uscert/ncas)
- [CVE Database](https://cve.mitre.org/)
