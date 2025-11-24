#!/bin/bash

echo "🛑 Stopping LAN Reconnaissance Framework..."

if docker compose version &> /dev/null; then
    docker compose down
else
    docker-compose down
fi

echo "✅ All containers stopped"
