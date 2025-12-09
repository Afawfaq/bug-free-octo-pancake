#!/bin/bash
# Trust Mapping & Attack Path Synthesis Orchestration Script
set -e
OUTPUT_DIR="$1"
PARENT_OUTPUT="${OUTPUT_DIR%/*}"

echo "[*] Trust mapping and attack path synthesis initiated..."
echo "[+] Output: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Run Windows trust graph analysis
echo "[*] Analyzing Windows trust relationships..."
python3 /usr/local/bin/windows_trust_graph.py "$PARENT_OUTPUT" 2>&1 | tee "$OUTPUT_DIR/windows_trust.log" || true

# Run SMB relationship tracking
echo "[*] Tracking SMB relationships..."
python3 /usr/local/bin/smb_tracker.py "$PARENT_OUTPUT" 2>&1 | tee "$OUTPUT_DIR/smb_tracker.log" || true

# Run attack path synthesizer (integrates all reconnaissance data)
echo "[*] Synthesizing attack paths from all reconnaissance modules..."
python3 /usr/local/bin/attack_path_synthesizer.py "$PARENT_OUTPUT" 2>&1 | tee "$OUTPUT_DIR/attack_synthesis.log" || true

# Generate summary
echo "[*] Generating trust mapping summary..."
cat > "$OUTPUT_DIR/trust_mapping_summary.txt" << EOF
Trust Mapping & Attack Path Analysis Summary
Generated: $(date -u +%Y-%m-%dT%H:%M:%S)

This module has:
1. Mapped Windows trust relationships
2. Tracked SMB access patterns
3. Synthesized attack paths from ALL reconnaissance modules:
   - credential-attacks
   - patch-cadence
   - data-flow
   - wifi-attacks
   - deception

Results include:
- Entry point identification
- Multi-step attack chain generation
- MITRE ATT&CK technique mapping
- Priority-based risk scoring
- Actionable security recommendations

Check attack_paths.json for detailed analysis.
EOF

echo "[+] Trust mapping and attack path synthesis complete"
echo '{"status": "complete", "modules": ["trust-mapping", "attack-path-synthesis"], "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S)'"}' > "$OUTPUT_DIR/trust_mapping_status.json"
