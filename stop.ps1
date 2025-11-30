<#
.SYNOPSIS
    Stop the LAN Reconnaissance Framework

.DESCRIPTION
    Stops all running containers from the LAN Reconnaissance Framework
#>

Write-Host "🛑 Stopping LAN Reconnaissance Framework..." -ForegroundColor Yellow

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

Invoke-Expression "$composeCmd -f $composeFile down"

Write-Host "✅ All containers stopped" -ForegroundColor Green
