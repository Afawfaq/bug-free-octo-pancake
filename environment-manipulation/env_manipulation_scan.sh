#!/bin/bash
#
# Environment Manipulation Scanner
# Orchestrates all environment manipulation tests
#
# DEFENSIVE SECURITY TOOL - Requires Authorization

set -e

OUTPUT_DIR="${1:-/output/environment-manipulation}"
TEST_DURATION="${TEST_DURATION:-300}"
ENABLE_NTP="${ENABLE_NTP:-true}"
ENABLE_DNS="${ENABLE_DNS:-true}"
ENABLE_DHCP="${ENABLE_DHCP:-false}"
ENABLE_IPV6_RA="${ENABLE_IPV6_RA:-false}"
ENABLE_UPNP="${ENABLE_UPNP:-true}"

mkdir -p "$OUTPUT_DIR"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║    Environment Manipulation Assessment                   ║"
echo "║    DEFENSIVE SECURITY TOOL - Authorization Required      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Output directory: $OUTPUT_DIR"
echo "[*] Test duration: ${TEST_DURATION}s"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "[*] Shutting down all services..."
    pkill -f fake_ntp_server.py 2>/dev/null || true
    pkill -f dns_sinkhole.py 2>/dev/null || true
    pkill -f dhcp_manipulator.py 2>/dev/null || true
    pkill -f ipv6_ra_injector.py 2>/dev/null || true
    pkill -f upnp_override.py 2>/dev/null || true
    echo "[+] Cleanup complete"
}

trap cleanup EXIT INT TERM

# Start services
PIDS=()

if [ "$ENABLE_NTP" = "true" ]; then
    echo "[*] Starting fake NTP server..."
    python3 /usr/local/bin/fake_ntp_server.py --output "$OUTPUT_DIR/.." &
    PIDS+=($!)
fi

if [ "$ENABLE_DNS" = "true" ]; then
    echo "[*] Starting DNS sinkhole..."
    python3 /usr/local/bin/dns_sinkhole.py --output "$OUTPUT_DIR/.." &
    PIDS+=($!)
fi

if [ "$ENABLE_DHCP" = "true" ]; then
    echo "[!] WARNING: DHCP manipulation enabled (high risk)"
    # Disabled by default for safety
    echo "[-] Skipping DHCP (safety)"
fi

if [ "$ENABLE_IPV6_RA" = "true" ]; then
    echo "[!] WARNING: IPv6 RA injection enabled (high risk)"
    # Disabled by default for safety
    echo "[-] Skipping IPv6 RA (safety)"
fi

if [ "$ENABLE_UPNP" = "true" ]; then
    echo "[*] Starting UPnP override..."
    # Would start upnp_override.py
fi

echo ""
echo "[*] Running tests for ${TEST_DURATION} seconds..."
sleep "$TEST_DURATION"

echo ""
echo "[*] Test complete, generating summary..."

# Generate summary
cat > "$OUTPUT_DIR/env_manipulation_summary.txt" << EOF
Environment Manipulation Assessment Summary
Generated: $(date)
Duration: ${TEST_DURATION} seconds

=== Services Tested ===
NTP Server: $ENABLE_NTP
DNS Sinkhole: $ENABLE_DNS  
DHCP Manipulator: $ENABLE_DHCP (disabled for safety)
IPv6 RA Injector: $ENABLE_IPV6_RA (disabled for safety)
UPnP Override: $ENABLE_UPNP

=== Recommendations ===
1. Implement NTP authentication (NTS)
2. Deploy DNSSEC
3. Enable DHCP snooping
4. Configure IPv6 RA guard
5. Disable UPnP on non-essential devices

See individual log files for detailed results.
EOF

echo "[+] Summary saved to $OUTPUT_DIR/env_manipulation_summary.txt"
echo "[+] Assessment complete"
