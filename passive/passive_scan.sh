#!/bin/bash

OUTPUT_DIR=${1:-/output/passive}
DURATION=${2:-30}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting passive reconnaissance for ${DURATION} seconds..."

# ARP scan
echo "[*] Running ARP scan..."
arp-scan --interface=eth0 --localnet > "$OUTPUT_DIR/arp_scan.txt" 2>&1 || true

# mDNS discovery
echo "[*] Running mDNS discovery..."
timeout 15 avahi-browse -a -t -r > "$OUTPUT_DIR/mdns_discovery.txt" 2>&1 || true

# SSDP/UPnP discovery
echo "[*] Running SSDP/UPnP discovery..."
timeout 15 gssdp-discover -t 15 --timeout=15 > "$OUTPUT_DIR/ssdp_discovery.txt" 2>&1 || true

# UPnP device enumeration
echo "[*] Enumerating UPnP devices..."
upnpc -l > "$OUTPUT_DIR/upnp_devices.txt" 2>&1 || true

# Passive packet capture (limited duration)
echo "[*] Starting passive packet capture..."
timeout "$DURATION" tshark -i eth0 -w "$OUTPUT_DIR/passive_capture.pcap" \
    -f "not port 22" 2>&1 || true

# Extract discovered IPs
echo "[*] Extracting discovered IPs..."
(cat "$OUTPUT_DIR/arp_scan.txt" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true) > "$OUTPUT_DIR/discovered_ips.txt"
(cat "$OUTPUT_DIR/mdns_discovery.txt" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true) >> "$OUTPUT_DIR/discovered_ips.txt"
(cat "$OUTPUT_DIR/ssdp_discovery.txt" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true) >> "$OUTPUT_DIR/discovered_ips.txt"

sort -u "$OUTPUT_DIR/discovered_ips.txt" -o "$OUTPUT_DIR/discovered_ips.txt"

echo "[+] Passive reconnaissance complete. Found $(wc -l < "$OUTPUT_DIR/discovered_ips.txt") unique IPs."
