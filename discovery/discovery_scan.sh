#!/bin/bash

TARGET=${1:-192.168.68.0/24}
OUTPUT_DIR=${2:-/output/discovery}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting active host discovery on $TARGET..."

# Fast SYN scan with naabu
echo "[*] Running naabu port scan..."
naabu -host "$TARGET" -p - -json -o "$OUTPUT_DIR/naabu_results.json" 2>&1 || true

# Quick rustscan
echo "[*] Running rustscan..."
rustscan -a "$TARGET" --ulimit 5000 --greppable > "$OUTPUT_DIR/rustscan_results.txt" 2>&1 || true

# Masscan for top ports (safe rate)
echo "[*] Running masscan..."
masscan "$TARGET" -p1-65535 --rate=1000 -oJ "$OUTPUT_DIR/masscan_results.json" 2>&1 || true

# Combine and parse results
echo "[*] Parsing discovery results..."
python3 -c "
import json
import os

output_dir = '$OUTPUT_DIR'
hosts = {}

# Parse naabu
try:
    with open(os.path.join(output_dir, 'naabu_results.json')) as f:
        for line in f:
            try:
                data = json.loads(line)
                ip = data.get('host', data.get('ip', ''))
                port = data.get('port', 0)
                if ip and port:
                    if ip not in hosts:
                        hosts[ip] = []
                    hosts[ip].append(port)
            except:
                pass
except:
    pass

# Parse masscan
try:
    with open(os.path.join(output_dir, 'masscan_results.json')) as f:
        data = json.load(f)
        for item in data:
            if 'ip' in item and 'ports' in item:
                ip = item['ip']
                if ip not in hosts:
                    hosts[ip] = []
                for port in item['ports']:
                    if 'port' in port:
                        hosts[ip].append(port['port'])
except:
    pass

# Write discovered hosts
with open(os.path.join(output_dir, 'discovered_hosts.json'), 'w') as f:
    json.dump(hosts, f, indent=2)

print(f'[+] Discovered {len(hosts)} hosts with open ports')
" 2>&1 || true

echo "[+] Active discovery complete."
