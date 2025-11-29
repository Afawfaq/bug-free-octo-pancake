# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

**⚠️ Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in the LAN Reconnaissance Framework, please follow these steps:

### 1. Private Disclosure

Send an email to the maintainers with:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

### 2. Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### 3. What to Expect

1. Confirmation that your report was received
2. Assessment of the vulnerability
3. Regular updates on progress
4. Credit in the security advisory (if desired)

## Security Considerations

### Authorized Use Only

This framework is designed for **authorized security testing only**. Users must:

- ✅ Only scan networks they own
- ✅ Obtain written permission for client networks
- ✅ Comply with all applicable laws and regulations
- ✅ Use responsibly and ethically

### Container Security

Our containers are designed with security in mind:

- Minimal base images
- No unnecessary packages
- No hardcoded credentials
- Regular vulnerability scanning with Trivy

### Network Capabilities

Some containers require elevated network capabilities:
- `NET_ADMIN`: Network administration
- `NET_RAW`: Raw socket access

These are required for legitimate scanning functions (ARP, packet capture, etc.).

### Data Handling

- All scan results are stored locally
- No data is transmitted externally
- No telemetry or analytics
- Users should secure their output directories

## Security Best Practices

When using this framework:

1. **Isolate the scanning host** - Use a dedicated machine or VM
2. **Secure output directory** - Protect scan results from unauthorized access
3. **Review before sharing** - Redact sensitive information from reports
4. **Update regularly** - Keep containers updated with latest security patches
5. **Monitor scans** - Be aware of what's being scanned and when

## Known Limitations

- Containers run with host networking for accuracy
- Some tools require root/admin privileges
- Rate limiting may not prevent all network impacts

## Security Updates

Security updates are published through:
- GitHub Security Advisories
- CHANGELOG.md updates
- Release notes

## Acknowledgments

We thank the security research community for responsible disclosure.
