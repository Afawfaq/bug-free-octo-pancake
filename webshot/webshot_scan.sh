#!/bin/bash

INPUT_FILE=${1:-/output/discovery/discovered_hosts.json}
OUTPUT_DIR=${2:-/output/webshot}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting web screenshot capture..."

# Extract web targets
python3 -c "
import json
with open('$INPUT_FILE') as f:
    hosts = json.load(f)
    with open('$OUTPUT_DIR/web_targets.txt', 'w') as out:
        for ip, ports in hosts.items():
            # Check for common web ports
            if 80 in ports or 443 in ports or 8008 in ports or 8080 in ports or 8443 in ports:
                if 80 in ports:
                    out.write(f'http://{ip}\n')
                if 443 in ports:
                    out.write(f'https://{ip}\n')
                if 8008 in ports:
                    out.write(f'http://{ip}:8008\n')
                if 8080 in ports:
                    out.write(f'http://{ip}:8080\n')
                if 8443 in ports:
                    out.write(f'https://{ip}:8443\n')
" 2>&1 || true

if [ ! -f "$OUTPUT_DIR/web_targets.txt" ]; then
    echo "[-] No web targets found"
    exit 1
fi

# Run Aquatone
echo "[*] Running Aquatone..."
cat "$OUTPUT_DIR/web_targets.txt" | aquatone -out "$OUTPUT_DIR/aquatone" 2>&1 || true

# Run EyeWitness
echo "[*] Running EyeWitness..."
python3 /opt/EyeWitness/Python/EyeWitness.py \
    -f "$OUTPUT_DIR/web_targets.txt" \
    --web \
    --no-prompt \
    -d "$OUTPUT_DIR/eyewitness" 2>&1 || true

echo "[+] Web screenshot capture complete."
