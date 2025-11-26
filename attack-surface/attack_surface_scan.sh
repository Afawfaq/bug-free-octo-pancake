#!/bin/bash

OUTPUT_DIR=${1:-/output/attack-surface}
DURATION=${2:-60}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting attack surface analysis..."

# Create targets file if it doesn't exist
if [ -f /output/fingerprint/targets.txt ]; then
    cp /output/fingerprint/targets.txt "$OUTPUT_DIR/targets.txt"
elif [ -f /output/discovery/discovered_hosts.json ]; then
    python3 -c "
import json
with open('/output/discovery/discovered_hosts.json') as f:
    hosts = json.load(f)
    with open('$OUTPUT_DIR/targets.txt', 'w') as out:
        for ip in hosts.keys():
            out.write(ip + '\n')
" || true
fi

# Stress profiling
if [ -f "$OUTPUT_DIR/targets.txt" ]; then
    echo "[*] Running stress profiler..."
    /usr/local/bin/stress_profiler.py "$OUTPUT_DIR/targets.txt" "$OUTPUT_DIR/stress_profile.json" 2>&1 || true
fi

# Forgotten protocols
if [ -f "$OUTPUT_DIR/targets.txt" ]; then
    echo "[*] Scanning forgotten protocols..."
    /usr/local/bin/forgotten_protocols.py "$OUTPUT_DIR/targets.txt" "$OUTPUT_DIR/forgotten_protocols.json" 2>&1 || true
fi

# Ignored ports
if [ -f "$OUTPUT_DIR/targets.txt" ]; then
    echo "[*] Scanning ignored ports..."
    /usr/local/bin/ignored_ports.py "$OUTPUT_DIR/targets.txt" "$OUTPUT_DIR/ignored_ports.json" 2>&1 || true
fi

# Dependency mapping
echo "[*] Mapping dependencies..."
/usr/local/bin/dependency_mapper.py "$DURATION" "$OUTPUT_DIR/dependencies.json" 2>&1 || true

# Entropy analysis (requires combined data)
if [ -f /output/iot/chromecast_info.json ] || [ -f /output/advanced/metadata.json ]; then
    echo "[*] Analyzing entropy..."
    
    # Combine device data for entropy analysis
    python3 -c "
import json
import os

combined = {}

# Load IoT data
for filename in os.listdir('/output/iot'):
    if filename.endswith('.json'):
        try:
            with open(os.path.join('/output/iot', filename)) as f:
                data = json.load(f)
                if 'ip' in data:
                    combined[data['ip']] = data
        except:
            pass

# Save combined
with open('$OUTPUT_DIR/device_entropy_data.json', 'w') as f:
    json.dump(combined, f, indent=2)
" 2>&1 || true
    
    if [ -f "$OUTPUT_DIR/device_entropy_data.json" ]; then
        /usr/local/bin/entropy_analyzer.py "$OUTPUT_DIR/device_entropy_data.json" "$OUTPUT_DIR/entropy_analysis.json" 2>&1 || true
    fi
fi

# Trust assumptions testing
if [ -f "$OUTPUT_DIR/targets.txt" ]; then
    echo "[*] Testing trust assumptions..."
    /usr/local/bin/trust_assumptions.py "$OUTPUT_DIR/targets.txt" "$OUTPUT_DIR/trust_assumptions.json" 2>&1 || true
fi

echo "[+] Attack surface analysis complete."
echo "    Results in: $OUTPUT_DIR"
