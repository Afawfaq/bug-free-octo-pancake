#!/bin/bash

# Quick scan mode - faster, less comprehensive
# Useful for rapid network assessment

set -e

echo "⚡ QUICK SCAN MODE"
echo "Running abbreviated reconnaissance..."
echo ""

TARGET_NETWORK="${1:-192.168.68.0/24}"

export TARGET_NETWORK

# Build only essential containers
echo "🔧 Building essential containers..."
if docker compose version &> /dev/null; then
    docker compose build passive discovery nuclei report
else
    docker-compose build passive discovery nuclei report
fi

# Start containers
if docker compose version &> /dev/null; then
    docker compose up -d passive discovery nuclei report
else
    docker-compose up -d passive discovery nuclei report
fi

echo ""
echo "🔍 Running quick passive scan..."
docker exec recon-passive /usr/local/bin/passive_scan.sh /output/passive 15

echo ""
echo "🔍 Running quick discovery..."
docker exec recon-discovery /usr/local/bin/discovery_scan.sh "$TARGET_NETWORK" /output/discovery

echo ""
echo "🔍 Running security scan..."
docker exec recon-nuclei /usr/local/bin/nuclei_scan.sh /output/discovery/discovered_hosts.json /output/nuclei

echo ""
echo "📊 Generating report..."
docker exec recon-report /usr/local/bin/report_builder.py /output

echo ""
echo "✅ Quick scan complete!"
echo "📁 Results: ./output/report/recon_report.html"
echo ""

# Stop containers
if docker compose version &> /dev/null; then
    docker compose down
else
    docker-compose down
fi
