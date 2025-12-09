#!/bin/bash
#
# Deception Module - Main Orchestration Script
# Deploys and manages all honeypots
#

set -e

OUTPUT_DIR="${1:-/output/deception}"
DURATION="${2:-3600}"  # Default 1 hour

echo "[Deception] Starting honeypot deployment"
echo "[Deception] Output directory: $OUTPUT_DIR"
echo "[Deception] Duration: $DURATION seconds"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Start all honeypots in background
echo "[Deception] Starting SMB honeypot..."
python3 /usr/local/bin/smb_honeypot.py "$OUTPUT_DIR" "$DURATION" 445 > "$OUTPUT_DIR/smb.log" 2>&1 &
SMB_PID=$!

echo "[Deception] Starting IPP honeypot..."
python3 /usr/local/bin/ipp_honeypot.py "$OUTPUT_DIR" "$DURATION" 631 > "$OUTPUT_DIR/ipp.log" 2>&1 &
IPP_PID=$!

echo "[Deception] Starting Chromecast honeypot..."
python3 /usr/local/bin/chromecast_honeypot.py "$OUTPUT_DIR" "$DURATION" > "$OUTPUT_DIR/chromecast.log" 2>&1 &
CHROMECAST_PID=$!

echo "[Deception] Starting SSDP honeypot..."
python3 /usr/local/bin/ssdp_honeypot.py "$OUTPUT_DIR" "$DURATION" > "$OUTPUT_DIR/ssdp.log" 2>&1 &
SSDP_PID=$!

echo "[Deception] All honeypots started"
echo "[Deception] SMB PID: $SMB_PID"
echo "[Deception] IPP PID: $IPP_PID"
echo "[Deception] Chromecast PID: $CHROMECAST_PID"
echo "[Deception] SSDP PID: $SSDP_PID"

# Wait for all honeypots to complete
echo "[Deception] Monitoring honeypots for $DURATION seconds..."
wait $SMB_PID
wait $IPP_PID
wait $CHROMECAST_PID
wait $SSDP_PID

echo "[Deception] All honeypots completed"

# Aggregate alerts
echo "[Deception] Aggregating alerts..."
python3 /usr/local/bin/alert_system.py "$OUTPUT_DIR"

echo "[Deception] Deception module complete"
echo "[Deception] Results saved to $OUTPUT_DIR"
