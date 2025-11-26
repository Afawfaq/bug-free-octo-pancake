#!/bin/bash

echo "🧹 Cleaning up LAN Reconnaissance Framework..."

# Stop containers
if docker compose version &> /dev/null; then
    docker compose down -v
else
    docker-compose down -v
fi

# Remove output directory
read -p "Do you want to remove the output directory? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf output
    echo "✅ Output directory removed"
fi

echo "✅ Cleanup complete"
