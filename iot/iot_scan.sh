#!/bin/bash

OUTPUT_DIR=${1:-/output/iot}
ROUTER_IP=${ROUTER_IP:-192.168.68.1}
CHROMECAST_IP=${CHROMECAST_IP:-192.168.68.56}
TV_IP=${TV_IP:-192.168.68.62}
PRINTER_IP=${PRINTER_IP:-192.168.68.54}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting IoT/UPnP adversary scan..."

# UPnP/IGD Gateway enumeration
if [ -n "$ROUTER_IP" ]; then
    echo "[*] Enumerating UPnP/IGD on router $ROUTER_IP..."
    
    # Get IGD device description
    curl -s "http://$ROUTER_IP:5000/rootDesc.xml" > "$OUTPUT_DIR/router_upnp_desc.xml" 2>&1 || true
    curl -s "http://$ROUTER_IP/zetna/rootDesc.xml" > "$OUTPUT_DIR/router_zetna_desc.xml" 2>&1 || true
    
    # UPnP commands
    upnpc -l > "$OUTPUT_DIR/router_upnp_list.txt" 2>&1 || true
    upnpc -s > "$OUTPUT_DIR/router_upnp_status.txt" 2>&1 || true
    
    # SOAP action enumeration
    nmap -p 5000,5001 --script upnp-info "$ROUTER_IP" -oN "$OUTPUT_DIR/router_upnp_nmap.txt" 2>&1 || true
fi

# Chromecast enumeration
if [ -n "$CHROMECAST_IP" ]; then
    echo "[*] Enumerating Chromecast at $CHROMECAST_IP..."
    chromecast_enum.py "$CHROMECAST_IP" "$OUTPUT_DIR/chromecast_info.json" 2>&1 || true
    
    # DIAL discovery
    curl -s "http://$CHROMECAST_IP:8008/ssdp/device-desc.xml" > "$OUTPUT_DIR/chromecast_dial.xml" 2>&1 || true
    
    # Eureka info
    curl -s "http://$CHROMECAST_IP:8008/setup/eureka_info" > "$OUTPUT_DIR/chromecast_eureka.json" 2>&1 || true
fi

# DLNA enumeration
if [ -n "$TV_IP" ]; then
    echo "[*] Enumerating DLNA/TV at $TV_IP..."
    dlna_enum.py "$TV_IP" "$OUTPUT_DIR/dlna_tv_info.json" 2>&1 || true
    
    # Netflix MDX endpoints
    curl -s "http://$TV_IP:8008/ssdp/device-desc.xml" > "$OUTPUT_DIR/tv_mdx.xml" 2>&1 || true
    
    # DLNA SOAP
    nmap -p 8008,8009,8080 --script upnp-info "$TV_IP" -oN "$OUTPUT_DIR/tv_upnp_nmap.txt" 2>&1 || true
fi

# Printer enumeration
if [ -n "$PRINTER_IP" ]; then
    echo "[*] Enumerating printer at $PRINTER_IP..."
    printer_enum.py "$PRINTER_IP" "$OUTPUT_DIR/printer_info.json" 2>&1 || true
    
    # Web interface scraping
    curl -s "http://$PRINTER_IP" > "$OUTPUT_DIR/printer_web.html" 2>&1 || true
    curl -s "http://$PRINTER_IP:631" > "$OUTPUT_DIR/printer_ipp.html" 2>&1 || true
    
    # JetDirect banner
    timeout 5 nc "$PRINTER_IP" 9100 < /dev/null > "$OUTPUT_DIR/printer_jetdirect.txt" 2>&1 || true
fi

echo "[+] IoT/UPnP adversary scan complete."
