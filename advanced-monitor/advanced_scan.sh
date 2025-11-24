#!/bin/bash

OUTPUT_DIR=${1:-/output/advanced}
DURATION=${2:-60}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting advanced monitoring suite..."

# PKI monitoring
echo "[*] Scanning for PKI issues..."
if [ -f /output/fingerprint/targets.txt ]; then
    /usr/local/bin/pki_monitor.py /output/fingerprint/targets.txt "$OUTPUT_DIR/pki_analysis.json" 2>&1 || true
fi

# DHCP profiling
echo "[*] Profiling DHCP traffic..."
/usr/local/bin/dhcp_profiler.py "$DURATION" "$OUTPUT_DIR/dhcp_profiles.json" 2>&1 || true

# DNS mapping
echo "[*] Mapping DNS queries..."
/usr/local/bin/dns_mapper.py "$DURATION" "$OUTPUT_DIR/dns_map.json" 2>&1 || true

# Metadata extraction
echo "[*] Extracting metadata ghosts..."
/usr/local/bin/metadata_extractor.py "$DURATION" "$OUTPUT_DIR/metadata.json" 2>&1 || true

# Protocol guilt analysis (requires combined data)
echo "[*] Calculating protocol guilt scores..."
# Combine data from various sources
python3 -c "
import json
import os

combined = {}

# Load metadata
try:
    with open('$OUTPUT_DIR/metadata.json') as f:
        meta = json.load(f)
        for ip, data in meta.get('metadata', {}).items():
            combined[ip] = data
except:
    pass

# Load IoT data
try:
    with open('/output/iot/chromecast_info.json') as f:
        cc = json.load(f)
        ip = cc.get('ip')
        if ip:
            if ip not in combined:
                combined[ip] = {}
            combined[ip]['chromecast_api'] = True
except:
    pass

# Save combined
with open('$OUTPUT_DIR/combined_device_data.json', 'w') as f:
    json.dump(combined, f, indent=2)
" 2>&1 || true

if [ -f "$OUTPUT_DIR/combined_device_data.json" ]; then
    /usr/local/bin/protocol_guilt.py "$OUTPUT_DIR/combined_device_data.json" "$OUTPUT_DIR/protocol_guilt.json" 2>&1 || true
fi

echo "[+] Advanced monitoring complete."
echo "    Results in: $OUTPUT_DIR"
