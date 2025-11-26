#!/bin/bash

set -e

echo "=========================================="
echo "  LAN RECONNAISSANCE FRAMEWORK"
echo "  Containerized Network Security Scanner"
echo "=========================================="
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Error: Docker Compose is not installed"
    echo "Please install Docker Compose first"
    exit 1
fi

# Parse command line arguments
TARGET_NETWORK="${1:-192.168.68.0/24}"
ROUTER_IP="${2:-192.168.68.1}"
CHROMECAST_IP="${3:-192.168.68.56}"
TV_IP="${4:-192.168.68.62}"
PRINTER_IP="${5:-192.168.68.54}"

echo "🎯 Configuration:"
echo "   Target Network: $TARGET_NETWORK"
echo "   Router IP: $ROUTER_IP"
echo "   Chromecast IP: $CHROMECAST_IP"
echo "   TV IP: $TV_IP"
echo "   Printer IP: $PRINTER_IP"
echo ""

# Export environment variables
export TARGET_NETWORK
export ROUTER_IP
export CHROMECAST_IP
export TV_IP
export PRINTER_IP

# Create output directory
mkdir -p output

echo "🔧 Building Docker containers..."
if docker compose version &> /dev/null; then
    docker compose build
else
    docker-compose build
fi

echo ""
echo "🚀 Starting reconnaissance framework..."
echo ""

# Start containers
if docker compose version &> /dev/null; then
    docker compose up
else
    docker-compose up
fi

echo ""
echo "✅ Reconnaissance complete!"
echo "📁 Results are available in the ./output directory"
echo ""
