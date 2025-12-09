#!/bin/bash

OUTPUT_DIR=${1:-/output/wifi-attacks}
INTERFACE=${2:-wlan0}
PMKID_TIMEOUT=${3:-60}
BLE_DURATION=${4:-10}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting WiFi attack surface assessment..."
echo "[*] Interface: ${INTERFACE}"
echo "[*] Note: This is a security analysis framework, not an active attack tool"

# Step 1: Spectrum scanning
echo ""
echo "[*] Step 1: Scanning WiFi spectrum..."
spectrum_scanner.py "$OUTPUT_DIR/spectrum_analysis.json" "$INTERFACE" 2>&1 | tee "$OUTPUT_DIR/spectrum_scan.log"

# Check if spectrum analysis was successful
if [ ! -f "$OUTPUT_DIR/spectrum_analysis.json" ]; then
    echo "[!] Spectrum analysis file not created. Creating empty file."
    echo '{"interface_available": false, "networks": []}' > "$OUTPUT_DIR/spectrum_analysis.json"
fi

# Step 2: PMKID harvesting analysis
echo ""
echo "[*] Step 2: PMKID harvesting analysis..."
pmkid_harvester.py "$OUTPUT_DIR/pmkid_analysis.json" "$INTERFACE" "$PMKID_TIMEOUT" 2>&1 | tee "$OUTPUT_DIR/pmkid.log"

# Check if PMKID analysis was created
if [ ! -f "$OUTPUT_DIR/pmkid_analysis.json" ]; then
    echo "[!] PMKID analysis file not created. Creating empty file."
    echo '{"analysis": {"pmkids_captured": 0}}' > "$OUTPUT_DIR/pmkid_analysis.json"
fi

# Step 3: WPS enumeration
echo ""
echo "[*] Step 3: WPS security analysis..."
wps_attacker.py "$OUTPUT_DIR/wps_analysis.json" "$INTERFACE" 2>&1 | tee "$OUTPUT_DIR/wps.log"

# Check if WPS analysis was created
if [ ! -f "$OUTPUT_DIR/wps_analysis.json" ]; then
    echo "[!] WPS analysis file not created. Creating empty file."
    echo '{"wps_networks": []}' > "$OUTPUT_DIR/wps_analysis.json"
fi

# Step 4: Evil twin analysis
echo ""
echo "[*] Step 4: Evil twin opportunity analysis..."
evil_twin_analyzer.py "$OUTPUT_DIR/spectrum_analysis.json" "$OUTPUT_DIR/evil_twin_analysis.json" 2>&1 | tee "$OUTPUT_DIR/evil_twin.log"

# Check if evil twin analysis was created
if [ ! -f "$OUTPUT_DIR/evil_twin_analysis.json" ]; then
    echo "[!] Evil twin analysis file not created. Creating empty file."
    echo '{"networks_analyzed": 0}' > "$OUTPUT_DIR/evil_twin_analysis.json"
fi

# Step 5: BLE device scanning
echo ""
echo "[*] Step 5: Scanning BLE devices..."
ble_scanner.py "$OUTPUT_DIR/ble_devices.json" "$BLE_DURATION" 2>&1 | tee "$OUTPUT_DIR/ble_scan.log"

# Check if BLE scan was created
if [ ! -f "$OUTPUT_DIR/ble_devices.json" ]; then
    echo "[!] BLE scan file not created. Creating empty file."
    echo '{"devices": []}' > "$OUTPUT_DIR/ble_devices.json"
fi

# Generate summary report
echo ""
echo "[*] Generating WiFi attack surface summary..."

cat > "$OUTPUT_DIR/wifi_attack_summary.txt" << EOF
==================================================
WiFi Attack Surface Assessment Summary
==================================================

Interface: ${INTERFACE}
Scan Date: $(date)

1. Spectrum Analysis
   - Interface available: $(jq -r '.interface_available // false' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "false")
   - Networks found: $(jq -r '.analysis.total_networks // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - 2.4 GHz networks: $(jq -r '.analysis.band_distribution."2.4GHz".count // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - 5 GHz networks: $(jq -r '.analysis.band_distribution."5GHz".count // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - 6 GHz networks: $(jq -r '.analysis.band_distribution."6GHz".count // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - Hidden networks: $(jq -r '.analysis.hidden_networks // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - Most congested 2.4GHz channel: $(jq -r '.analysis.most_congested_24ghz // "N/A"' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null)
   - Most congested 5GHz channel: $(jq -r '.analysis.most_congested_5ghz // "N/A"' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null)

2. Encryption Analysis
   - WPA3 networks: $(jq -r '.analysis.encryption_distribution.WPA3 // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - WPA2 networks: $(jq -r '.analysis.encryption_distribution.WPA2 // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - WPA networks: $(jq -r '.analysis.encryption_distribution.WPA // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")
   - Open networks: $(jq -r '.analysis.encryption_distribution.Open // 0' "$OUTPUT_DIR/spectrum_analysis.json" 2>/dev/null || echo "0")

3. PMKID Analysis
   - Duration: ${PMKID_TIMEOUT}s
   - PMKIDs captured: $(jq -r '.analysis.pmkids_captured // 0' "$OUTPUT_DIR/pmkid_analysis.json" 2>/dev/null || echo "0")
   - Networks targeted: $(jq -r '.analysis.networks_targeted // 0' "$OUTPUT_DIR/pmkid_analysis.json" 2>/dev/null || echo "0")

4. WPS Analysis
   - WPS-enabled networks: $(jq -r '.analysis.total_wps_networks // 0' "$OUTPUT_DIR/wps_analysis.json" 2>/dev/null || echo "0")
   - Vulnerable to Pixie Dust: $(jq -r '.analysis.vulnerable_to_pixie_dust // 0' "$OUTPUT_DIR/wps_analysis.json" 2>/dev/null || echo "0")
   - Locked networks: $(jq -r '.analysis.locked_networks // 0' "$OUTPUT_DIR/wps_analysis.json" 2>/dev/null || echo "0")

5. Evil Twin Analysis
   - Networks analyzed: $(jq -r '.networks_analyzed // 0' "$OUTPUT_DIR/evil_twin_analysis.json" 2>/dev/null || echo "0")
   - Optimal 2.4GHz channels: $(jq -r '.channel_analysis.optimal_24ghz_channels[]? // "N/A"' "$OUTPUT_DIR/evil_twin_analysis.json" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
   - Optimal 5GHz channels: $(jq -r '.channel_analysis.optimal_5ghz_channels[]? // "N/A"' "$OUTPUT_DIR/evil_twin_analysis.json" 2>/dev/null | tr '\n' ',' | sed 's/,$//')

6. BLE Device Scan
   - Scan duration: ${BLE_DURATION}s
   - BLE devices found: $(jq -r '.analysis.total_devices // 0' "$OUTPUT_DIR/ble_devices.json" 2>/dev/null || echo "0")
   - Unnamed devices: $(jq -r '.analysis.unnamed_devices // 0' "$OUTPUT_DIR/ble_devices.json" 2>/dev/null || echo "0")

Security Recommendations:
-------------------------
  - Upgrade to WPA3 where possible
  - Disable WPS if not actively used
  - Use strong, unique passphrases (>20 characters)
  - Enable Protected Management Frames (PMF/802.11w)
  - Monitor for rogue access points
  - Educate users about evil twin attacks
  - Implement 802.1X authentication for enterprise networks
  - Regularly audit wireless security posture
  - Disable Bluetooth when not in use
  - Use address randomization to prevent tracking

==================================================
EOF

cat "$OUTPUT_DIR/wifi_attack_summary.txt"

echo ""
echo "[+] WiFi attack surface assessment complete."
echo "[+] Results saved to: $OUTPUT_DIR/"
echo "[+] Summary: $OUTPUT_DIR/wifi_attack_summary.txt"
