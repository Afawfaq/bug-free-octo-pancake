<#
.SYNOPSIS
    View the reconnaissance report

.DESCRIPTION
    Opens the HTML report in the default browser
#>

$ReportFile = ".\output\report\recon_report.html"

if (-not (Test-Path $ReportFile)) {
    Write-Host "❌ Report not found: $ReportFile" -ForegroundColor Red
    Write-Host "Run .\start.ps1 first to generate the report" -ForegroundColor Yellow
    exit 1
}

Write-Host "📊 Opening reconnaissance report..." -ForegroundColor Blue

# Open in default browser
try {
    Start-Process $ReportFile
}
catch {
    Write-Host "📍 Report location: $ReportFile" -ForegroundColor Green
    Write-Host "Please open it manually in your browser" -ForegroundColor Yellow
}
