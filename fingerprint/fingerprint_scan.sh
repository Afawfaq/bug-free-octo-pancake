#!/bin/bash

INPUT_FILE=${1:-/output/discovery/discovered_hosts.json}
OUTPUT_DIR=${2:-/output/fingerprint}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting fingerprinting scan..."

# Extract IPs from discovery results
python3 -c "
import json
with open('$INPUT_FILE') as f:
    hosts = json.load(f)
    with open('$OUTPUT_DIR/targets.txt', 'w') as out:
        for ip in hosts.keys():
            out.write(ip + '\n')
" 2>&1 || true

if [ ! -f "$OUTPUT_DIR/targets.txt" ]; then
    echo "[-] No targets found"
    exit 1
fi

# Nmap comprehensive scan
echo "[*] Running nmap OS and service detection..."
nmap -sV -O -A --osscan-guess --version-intensity 9 \
    -iL "$OUTPUT_DIR/targets.txt" \
    -oX "$OUTPUT_DIR/nmap_fingerprint.xml" \
    -oN "$OUTPUT_DIR/nmap_fingerprint.txt" 2>&1 || true

# HTTP service discovery
echo "[*] Running httpx on web services..."
cat "$OUTPUT_DIR/targets.txt" | httpx -silent -json -o "$OUTPUT_DIR/httpx_results.json" 2>&1 || true

# WhatWeb fingerprinting
echo "[*] Running WhatWeb..."
while IFS= read -r ip; do
    whatweb -a 3 --log-json="$OUTPUT_DIR/whatweb_${ip}.json" "http://$ip" 2>&1 || true
    whatweb -a 3 --log-json="$OUTPUT_DIR/whatweb_${ip}_https.json" "https://$ip" 2>&1 || true
done < "$OUTPUT_DIR/targets.txt"

# SNMP enumeration
echo "[*] Running SNMP enumeration..."
while IFS= read -r ip; do
    snmpwalk -v2c -c public "$ip" > "$OUTPUT_DIR/snmp_${ip}.txt" 2>&1 || true
done < "$OUTPUT_DIR/targets.txt"

# SMB enumeration
echo "[*] Running SMB enumeration..."
while IFS= read -r ip; do
    smbclient -L "$ip" -N > "$OUTPUT_DIR/smb_${ip}.txt" 2>&1 || true
done < "$OUTPUT_DIR/targets.txt"

echo "[+] Fingerprinting complete."
