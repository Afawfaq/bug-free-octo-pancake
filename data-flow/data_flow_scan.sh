#!/bin/bash

OUTPUT_DIR=${1:-/output/data-flow}
CAPTURE_DURATION=${2:-300}
INTERFACE=${3:-eth0}

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting data flow analysis..."
echo "[*] Capture duration: ${CAPTURE_DURATION}s"
echo "[*] Interface: ${INTERFACE}"

# Step 1: Build traffic baseline
echo ""
echo "[*] Step 1: Building traffic baseline..."
traffic_baseline.py "$OUTPUT_DIR/baseline.json" "$CAPTURE_DURATION" "$INTERFACE" 2>&1 | tee "$OUTPUT_DIR/baseline.log"

# Check if baseline was created
if [ ! -f "$OUTPUT_DIR/baseline.json" ]; then
    echo "[!] Baseline file not created. Creating empty baseline."
    echo '{"capture_duration_seconds": 0, "devices_profiled": 0, "baselines": {}}' > "$OUTPUT_DIR/baseline.json"
fi

# Step 2: Create device fingerprints
echo ""
echo "[*] Step 2: Creating device fingerprints..."
chatter_fingerprinter.py "$OUTPUT_DIR/baseline.json" "$OUTPUT_DIR/fingerprints.json" 2>&1 | tee "$OUTPUT_DIR/fingerprints.log"

# Check if fingerprints were created
if [ ! -f "$OUTPUT_DIR/fingerprints.json" ]; then
    echo "[!] Fingerprints file not created. Creating empty fingerprints."
    echo '{"total_devices": 0, "fingerprints": {}}' > "$OUTPUT_DIR/fingerprints.json"
fi

# Step 3: Detect anomalies
echo ""
echo "[*] Step 3: Detecting anomalies..."
anomaly_detector.py "$OUTPUT_DIR/baseline.json" "$OUTPUT_DIR/fingerprints.json" "$OUTPUT_DIR/anomalies.json" 2>&1 | tee "$OUTPUT_DIR/anomalies.log"

# Check if anomalies were detected
if [ ! -f "$OUTPUT_DIR/anomalies.json" ]; then
    echo "[!] Anomalies file not created. Creating empty anomalies."
    echo '{"total_anomalies": 0, "anomalies": []}' > "$OUTPUT_DIR/anomalies.json"
fi

# Step 4: Generate flow graph
echo ""
echo "[*] Step 4: Generating flow graph..."
flow_graph_builder.py "$OUTPUT_DIR/baseline.json" "$OUTPUT_DIR/anomalies.json" "$OUTPUT_DIR" 2>&1 | tee "$OUTPUT_DIR/flow_graph.log"

# Step 5: Analyze time series
echo ""
echo "[*] Step 5: Analyzing temporal patterns..."
time_series_analyzer.py "$OUTPUT_DIR/baseline.json" "$OUTPUT_DIR/time_series.json" 2>&1 | tee "$OUTPUT_DIR/time_series.log"

# Generate summary report
echo ""
echo "[*] Generating data flow analysis summary..."

cat > "$OUTPUT_DIR/data_flow_summary.txt" << EOF
==================================================
Data Flow Analysis Summary
==================================================

1. Traffic Baseline
   - Capture duration: $(jq -r '.capture_duration_seconds // 0' "$OUTPUT_DIR/baseline.json" 2>/dev/null || echo "0")s
   - Devices profiled: $(jq -r '.devices_profiled // 0' "$OUTPUT_DIR/baseline.json" 2>/dev/null || echo "0")
   - Most active device: $(jq -r '.summary.most_active_device // "None"' "$OUTPUT_DIR/baseline.json" 2>/dev/null)

2. Device Fingerprinting
   - Total devices: $(jq -r '.total_devices // 0' "$OUTPUT_DIR/fingerprints.json" 2>/dev/null || echo "0")
   - Devices with anomaly indicators: $(jq -r '.devices_with_anomalies // 0' "$OUTPUT_DIR/fingerprints.json" 2>/dev/null || echo "0")

3. Anomaly Detection
   - Total anomalies: $(jq -r '.total_anomalies // 0' "$OUTPUT_DIR/anomalies.json" 2>/dev/null || echo "0")
   - Devices with anomalies: $(jq -r '.devices_with_anomalies // 0' "$OUTPUT_DIR/anomalies.json" 2>/dev/null || echo "0")
   - CRITICAL: $(jq -r '.severity_breakdown.CRITICAL // 0' "$OUTPUT_DIR/anomalies.json" 2>/dev/null || echo "0")
   - HIGH: $(jq -r '.severity_breakdown.HIGH // 0' "$OUTPUT_DIR/anomalies.json" 2>/dev/null || echo "0")
   - MEDIUM: $(jq -r '.severity_breakdown.MEDIUM // 0' "$OUTPUT_DIR/anomalies.json" 2>/dev/null || echo "0")
   - LOW: $(jq -r '.severity_breakdown.LOW // 0' "$OUTPUT_DIR/anomalies.json" 2>/dev/null || echo "0")

4. Flow Graph
   - Generated: $([ -f "$OUTPUT_DIR"_flow_graph.png ] && echo "Yes" || echo "No")
   - Nodes: $(jq -r '.statistics.total_nodes // 0' "$OUTPUT_DIR"_flow_graph.json 2>/dev/null || echo "0")
   - Edges: $(jq -r '.statistics.total_edges // 0' "$OUTPUT_DIR"_flow_graph.json 2>/dev/null || echo "0")
   - Anomalous edges: $(jq -r '.statistics.anomalous_edges // 0' "$OUTPUT_DIR"_flow_graph.json 2>/dev/null || echo "0")

5. Time Series Analysis
   - Devices with temporal patterns: $(jq -r '.devices_with_patterns // 0' "$OUTPUT_DIR/time_series.json" 2>/dev/null || echo "0")

Top Anomalies:
--------------
$(jq -r '.anomalies[]? | select(.severity == "CRITICAL" or .severity == "HIGH") | "  [\(.severity)] \(.device_ip): \(.description)"' "$OUTPUT_DIR/anomalies.json" 2>/dev/null | head -10 || echo "  No critical or high severity anomalies found")

Recommendations:
----------------
  - Investigate all CRITICAL anomalies immediately
  - Review HIGH severity anomalies within 24 hours
  - Monitor devices with beaconing patterns for C2 activity
  - Check new destinations against threat intelligence feeds
  - Correlate unusual hours activity with legitimate business operations

==================================================
EOF

cat "$OUTPUT_DIR/data_flow_summary.txt"

echo ""
echo "[+] Data flow analysis complete."
echo "[+] Results saved to: $OUTPUT_DIR/"
echo "[+] Summary: $OUTPUT_DIR/data_flow_summary.txt"
echo "[+] Flow graph: ${OUTPUT_DIR}_flow_graph.png"
