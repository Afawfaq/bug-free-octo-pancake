<#
.SYNOPSIS
    Quick scan mode for LAN Reconnaissance Framework

.DESCRIPTION
    Runs an abbreviated reconnaissance scan with reduced scope for rapid network assessment

.PARAMETER TargetNetwork
    Network CIDR to scan (default: 192.168.68.0/24)
#>

[CmdletBinding()]
param(
    [string]$TargetNetwork = "192.168.68.0/24"
)

Write-Host "⚡ QUICK SCAN MODE" -ForegroundColor Yellow
Write-Host "Running abbreviated reconnaissance..." -ForegroundColor White
Write-Host ""

$env:TARGET_NETWORK = $TargetNetwork

# Get compose command
$composeCmd = $null
try {
    $null = docker compose version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $composeCmd = "docker compose"
    }
}
catch {}

if (-not $composeCmd) {
    try {
        $null = docker-compose --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $composeCmd = "docker-compose"
        }
    }
    catch {}
}

if (-not $composeCmd) {
    Write-Host "❌ Error: Docker Compose not found" -ForegroundColor Red
    exit 1
}

# Determine compose file
$composeFile = "docker-compose.yml"
if (($IsWindows -or $env:OS -eq "Windows_NT" -or $IsMacOS) -and (Test-Path "docker-compose.windows.yml")) {
    $composeFile = "docker-compose.windows.yml"
}

# Build only essential containers
Write-Host "🔧 Building essential containers..." -ForegroundColor Green
Invoke-Expression "$composeCmd -f $composeFile build passive discovery nuclei report"

# Start containers
Invoke-Expression "$composeCmd -f $composeFile up -d passive discovery nuclei report"

Write-Host ""
Write-Host "🔍 Running quick passive scan..." -ForegroundColor Blue
docker exec recon-passive /usr/local/bin/passive_scan.sh /output/passive 15

Write-Host ""
Write-Host "🔍 Running quick discovery..." -ForegroundColor Blue
docker exec recon-discovery /usr/local/bin/discovery_scan.sh $TargetNetwork /output/discovery

Write-Host ""
Write-Host "🔍 Running security scan..." -ForegroundColor Blue
docker exec recon-nuclei /usr/local/bin/nuclei_scan.sh /output/discovery/discovered_hosts.json /output/nuclei

Write-Host ""
Write-Host "📊 Generating report..." -ForegroundColor Blue
docker exec recon-report /usr/local/bin/report_builder.py /output

Write-Host ""
Write-Host "✅ Quick scan complete!" -ForegroundColor Green
Write-Host "📁 Results: ./output/report/recon_report.html" -ForegroundColor Cyan
Write-Host ""

# Stop containers
Invoke-Expression "$composeCmd -f $composeFile down"
