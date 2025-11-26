#!/bin/bash

REPORT_FILE="./output/report/recon_report.html"

if [ ! -f "$REPORT_FILE" ]; then
    echo "❌ Report not found: $REPORT_FILE"
    echo "Run ./start.sh first to generate the report"
    exit 1
fi

echo "📊 Opening reconnaissance report..."

# Try different browsers
if command -v xdg-open &> /dev/null; then
    xdg-open "$REPORT_FILE"
elif command -v open &> /dev/null; then
    open "$REPORT_FILE"
elif command -v firefox &> /dev/null; then
    firefox "$REPORT_FILE"
elif command -v chromium-browser &> /dev/null; then
    chromium-browser "$REPORT_FILE"
elif command -v google-chrome &> /dev/null; then
    google-chrome "$REPORT_FILE"
else
    echo "✅ Report location: $REPORT_FILE"
    echo "Please open it manually in your browser"
fi
