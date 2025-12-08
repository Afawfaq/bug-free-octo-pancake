#!/bin/bash

OUTPUT_DIR=${1:-/output/patch-cadence}
TARGET_IPS_FILE=${2:-/output/discovery/discovered_ips.txt}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting device update & patch cadence analysis..."

# Check if target IPs file exists
if [ ! -f "$TARGET_IPS_FILE" ]; then
    echo "[!] Target IPs file not found: $TARGET_IPS_FILE"
    echo "[!] Creating empty file for testing..."
    mkdir -p "$(dirname "$TARGET_IPS_FILE")"
    touch "$TARGET_IPS_FILE"
fi

# Step 1: Firmware version fingerprinting
echo "[*] Step 1: Fingerprinting firmware versions..."
if [ -s "$TARGET_IPS_FILE" ]; then
    firmware_fingerprinter.py "$TARGET_IPS_FILE" "$OUTPUT_DIR/firmware_versions.json" 2>&1 | tee "$OUTPUT_DIR/firmware_fingerprint.log"
else
    echo "[!] No target IPs found. Creating empty firmware data."
    echo '{"total_devices": 0, "devices_with_firmware_info": 0, "devices": []}' > "$OUTPUT_DIR/firmware_versions.json"
fi

# Step 2: Update server reachability
echo ""
echo "[*] Step 2: Testing update server reachability..."
update_reachability.py "$OUTPUT_DIR/update_reachability.json" 2>&1 | tee "$OUTPUT_DIR/update_reachability.log"

# Step 3: CVE matching
echo ""
echo "[*] Step 3: Matching devices to known CVEs..."
cve_matcher.py "$OUTPUT_DIR/firmware_versions.json" "$OUTPUT_DIR/cve_matches.json" 2>&1 | tee "$OUTPUT_DIR/cve_matching.log"

# Step 4: Device aging score
echo ""
echo "[*] Step 4: Calculating device aging scores..."
aging_scorer.py "$OUTPUT_DIR/firmware_versions.json" "$OUTPUT_DIR/aging_scores.json" 2>&1 | tee "$OUTPUT_DIR/aging_scoring.log"

# Generate summary report
echo ""
echo "[*] Generating patch cadence analysis summary..."

cat > "$OUTPUT_DIR/patch_cadence_summary.txt" << EOF
==================================================
Device Update & Patch Cadence Analysis Summary
==================================================

1. Firmware Version Fingerprinting
   - Total devices scanned: $(jq -r '.total_devices // 0' "$OUTPUT_DIR/firmware_versions.json" 2>/dev/null || echo "0")
   - Devices with firmware info: $(jq -r '.devices_with_firmware_info // 0' "$OUTPUT_DIR/firmware_versions.json" 2>/dev/null || echo "0")

2. Update Server Reachability
   - Servers tested: $(jq -r '.total_servers_tested // 0' "$OUTPUT_DIR/update_reachability.json" 2>/dev/null || echo "0")
   - Reachable servers: $(jq -r '.reachable_servers // 0' "$OUTPUT_DIR/update_reachability.json" 2>/dev/null || echo "0")
   - Reachability rate: $(jq -r '.reachability_rate // "N/A"' "$OUTPUT_DIR/update_reachability.json" 2>/dev/null)

3. CVE Vulnerability Matching
   - Total CVEs found: $(jq -r '.total_cves_found // 0' "$OUTPUT_DIR/cve_matches.json" 2>/dev/null || echo "0")
   - Critical CVEs: $(jq -r '.critical_cves // 0' "$OUTPUT_DIR/cve_matches.json" 2>/dev/null || echo "0")
   - High CVEs: $(jq -r '.high_cves // 0' "$OUTPUT_DIR/cve_matches.json" 2>/dev/null || echo "0")
   - Exploitable CVEs: $(jq -r '.exploitable_cves // 0' "$OUTPUT_DIR/cve_matches.json" 2>/dev/null || echo "0")

4. Device Aging Score
   - Devices scored: $(jq -r '.total_devices_scored // 0' "$OUTPUT_DIR/aging_scores.json" 2>/dev/null || echo "0")
   - Average aging score: $(jq -r '.average_aging_score // 0' "$OUTPUT_DIR/aging_scores.json" 2>/dev/null || echo "0")/100
   - Critical risk devices: $(jq -r '.critical_risk_devices // 0' "$OUTPUT_DIR/aging_scores.json" 2>/dev/null || echo "0")
   - High risk devices: $(jq -r '.high_risk_devices // 0' "$OUTPUT_DIR/aging_scores.json" 2>/dev/null || echo "0")

Key Findings:
-------------
Top Vulnerabilities:
$(jq -r '.cve_matches[]? | select(.severity == "CRITICAL") | "  - \(.device_ip): \(.cve_id) (\(.description))"' "$OUTPUT_DIR/cve_matches.json" 2>/dev/null | head -5 || echo "  No critical CVEs found")

High-Risk Aging Devices:
$(jq -r '.device_scores[]? | select(.risk_level == "CRITICAL" or .risk_level == "HIGH") | "  - \(.device_ip): Score \(.total_score)/100 (\(.risk_level))"' "$OUTPUT_DIR/aging_scores.json" 2>/dev/null | head -5 || echo "  No high-risk devices found")

Recommendations:
----------------
  1. Prioritize patching devices with CRITICAL CVEs
  2. Update firmware on devices with aging scores > 75
  3. Verify network connectivity to update servers
  4. Implement automated patch management
  5. Schedule regular firmware updates
  6. Replace devices with EOL vendor support
  7. Disable deprecated protocols (SSLv3, TLSv1.0)
  8. Monitor vendor security advisories

==================================================
EOF

cat "$OUTPUT_DIR/patch_cadence_summary.txt"

echo ""
echo "[+] Patch cadence analysis complete."
echo "[+] Results saved to: $OUTPUT_DIR/"
echo "[+] Summary: $OUTPUT_DIR/patch_cadence_summary.txt"
