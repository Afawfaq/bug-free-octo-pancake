<#
.SYNOPSIS
    Clean up the LAN Reconnaissance Framework

.DESCRIPTION
    Stops containers, removes volumes, and optionally cleans output directory

.PARAMETER Force
    Skip confirmation prompts
#>

[CmdletBinding()]
param(
    [switch]$Force
)

Write-Host "🧹 Cleaning up LAN Reconnaissance Framework..." -ForegroundColor Yellow

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

# Stop containers and remove volumes
Invoke-Expression "$composeCmd -f $composeFile down -v"

# Ask about output directory
if (Test-Path "output") {
    $removeOutput = $Force
    if (-not $Force) {
        $response = Read-Host "Do you want to remove the output directory? (y/N)"
        $removeOutput = $response -match "^[Yy]"
    }
    
    if ($removeOutput) {
        Remove-Item -Path "output" -Recurse -Force
        Write-Host "✅ Output directory removed" -ForegroundColor Green
    }
}

Write-Host "✅ Cleanup complete" -ForegroundColor Green
