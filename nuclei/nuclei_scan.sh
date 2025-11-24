#!/bin/bash

INPUT_FILE=${1:-/output/discovery/discovered_hosts.json}
OUTPUT_DIR=${2:-/output/nuclei}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Nuclei security scan..."

# Extract targets for nuclei
python3 -c "
import json
with open('$INPUT_FILE') as f:
    hosts = json.load(f)
    with open('$OUTPUT_DIR/targets.txt', 'w') as out:
        for ip in hosts.keys():
            out.write(f'http://{ip}\n')
            out.write(f'https://{ip}\n')
" 2>&1 || true

if [ ! -f "$OUTPUT_DIR/targets.txt" ]; then
    echo "[-] No targets found"
    exit 1
fi

# Run nuclei with all templates
echo "[*] Running Nuclei with default templates..."
nuclei -l "$OUTPUT_DIR/targets.txt" \
    -severity critical,high,medium \
    -json -o "$OUTPUT_DIR/nuclei_results.json" 2>&1 || true

# Run custom IoT templates
echo "[*] Running custom IoT templates..."
nuclei -l "$OUTPUT_DIR/targets.txt" \
    -t /root/nuclei-templates/custom/ \
    -json -o "$OUTPUT_DIR/nuclei_iot_results.json" 2>&1 || true

# Run specific technology templates
echo "[*] Running UPnP templates..."
nuclei -l "$OUTPUT_DIR/targets.txt" \
    -t /root/nuclei-templates/exposures/ \
    -t /root/nuclei-templates/misconfiguration/ \
    -tags upnp,iot,printer \
    -json -o "$OUTPUT_DIR/nuclei_upnp_results.json" 2>&1 || true

echo "[+] Nuclei scan complete."
