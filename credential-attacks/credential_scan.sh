#!/bin/bash

OUTPUT_DIR=${1:-/output/credential-attacks}
TARGET_IPS_FILE=${2:-/output/discovery/discovered_ips.txt}
SNIFF_DURATION=${3:-60}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting credential lifecycle weakness assessment..."

# Check if target IPs file exists
if [ ! -f "$TARGET_IPS_FILE" ]; then
    echo "[!] Target IPs file not found: $TARGET_IPS_FILE"
    echo "[!] Creating empty file for testing..."
    mkdir -p "$(dirname "$TARGET_IPS_FILE")"
    touch "$TARGET_IPS_FILE"
fi

# Test default credentials
echo "[*] Testing default credentials on discovered devices..."
if [ -s "$TARGET_IPS_FILE" ]; then
    default_creds_tester.py "$TARGET_IPS_FILE" "$OUTPUT_DIR/default_creds_results.json" 2>&1 | tee "$OUTPUT_DIR/default_creds.log"
else
    echo "[!] No target IPs found. Skipping default credential testing."
    echo '{"tested_targets": 0, "successful_auths": 0, "findings": []}' > "$OUTPUT_DIR/default_creds_results.json"
fi

# Cleartext protocol sniffing
echo "[*] Starting cleartext protocol sniffing (${SNIFF_DURATION}s)..."
cleartext_sniffer.py "$OUTPUT_DIR/cleartext_creds.json" "$SNIFF_DURATION" eth0 2>&1 | tee "$OUTPUT_DIR/cleartext_sniff.log"

# SSH enumeration
echo "[*] Enumerating SSH hosts and configurations..."
if [ -s "$TARGET_IPS_FILE" ]; then
    ssh_harvester.py "$TARGET_IPS_FILE" "$OUTPUT_DIR/ssh_analysis.json" 2>&1 | tee "$OUTPUT_DIR/ssh_harvest.log"
else
    echo "[!] No target IPs found. Skipping SSH harvesting."
    echo '{"ssh_hosts_found": 0, "ssh_hosts": [], "security_checks": []}' > "$OUTPUT_DIR/ssh_analysis.json"
fi

# Generate summary report
echo "[*] Generating credential attack surface summary..."

cat > "$OUTPUT_DIR/credential_summary.txt" << EOF
==================================================
Credential Lifecycle Weakness Assessment Summary
==================================================

1. Default Credentials Testing
   - Targets tested: $(jq -r '.tested_targets // 0' "$OUTPUT_DIR/default_creds_results.json" 2>/dev/null || echo "0")
   - Successful authentications: $(jq -r '.successful_auths // 0' "$OUTPUT_DIR/default_creds_results.json" 2>/dev/null || echo "0")
   - Severity: CRITICAL (if any found)

2. Cleartext Protocol Analysis
   - Credentials captured: $(jq -r '.total_findings // 0' "$OUTPUT_DIR/cleartext_creds.json" 2>/dev/null || echo "0")
   - Protocols monitored: FTP, Telnet, HTTP Basic Auth, SNMP
   - Severity: CRITICAL (if credentials found)

3. SSH Configuration Analysis
   - SSH hosts found: $(jq -r '.ssh_hosts_found // 0' "$OUTPUT_DIR/ssh_analysis.json" 2>/dev/null || echo "0")
   - Security checks performed: Configuration analysis
   - Severity: INFO to HIGH

Key Findings:
-------------
$(jq -r '.findings[]? | "  - \(.ip):\(.service) - \(.username):\(.password)"' "$OUTPUT_DIR/default_creds_results.json" 2>/dev/null || echo "  No default credentials found")

Recommendations:
----------------
  - Change all default credentials immediately
  - Disable cleartext protocols (FTP, Telnet, HTTP Basic Auth)
  - Use SSH key-based authentication
  - Implement strong password policies
  - Enable multi-factor authentication where possible
  - Regularly audit and rotate credentials

==================================================
EOF

cat "$OUTPUT_DIR/credential_summary.txt"

echo ""
echo "[+] Credential attack surface assessment complete."
echo "[+] Results saved to: $OUTPUT_DIR/"
echo "[+] Summary: $OUTPUT_DIR/credential_summary.txt"
