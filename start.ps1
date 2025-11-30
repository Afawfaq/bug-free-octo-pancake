<#
.SYNOPSIS
    LAN Reconnaissance Framework - Start Script (Windows PowerShell)

.DESCRIPTION
    Cross-platform PowerShell script to start the LAN Reconnaissance Framework.
    Works on Windows (PowerShell 5.1+) and PowerShell Core (7+) on any platform.

.PARAMETER TargetNetwork
    Network CIDR to scan (default: 192.168.68.0/24)

.PARAMETER RouterIP
    Router/gateway IP address

.PARAMETER ChromecastIP
    Chromecast device IP

.PARAMETER TvIP
    Smart TV IP address

.PARAMETER PrinterIP
    Network printer IP

.PARAMETER Quick
    Run quick scan mode (reduced scope)

.PARAMETER Verbose
    Enable verbose output

.PARAMETER NoParallel
    Disable parallel execution

.PARAMETER Help
    Show help message

.EXAMPLE
    .\start.ps1
    Run with default settings

.EXAMPLE
    .\start.ps1 -TargetNetwork "192.168.1.0/24" -RouterIP "192.168.1.1"
    Run with custom network settings

.EXAMPLE
    .\start.ps1 -Quick
    Run quick scan mode
#>

[CmdletBinding()]
param(
    [string]$TargetNetwork,
    [string]$RouterIP,
    [string]$ChromecastIP,
    [string]$TvIP,
    [string]$PrinterIP,
    [switch]$Quick,
    [switch]$VerboseOutput,
    [switch]$NoParallel,
    [switch]$Help
)

# Version
$Version = "2.4.0"

# Colors (using Write-Host with -ForegroundColor)
function Write-Banner {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║         LAN RECONNAISSANCE FRAMEWORK v$Version            ║" -ForegroundColor Cyan
    Write-Host "║       Containerized Network Security Scanner             ║" -ForegroundColor Cyan
    Write-Host "║              Windows/Linux/macOS Compatible              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Help {
    Write-Banner
    Write-Host "Usage: .\start.ps1 [OPTIONS]" -ForegroundColor White
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -Help              Show this help message"
    Write-Host "  -Quick             Run quick scan (reduced scope)"
    Write-Host "  -VerboseOutput     Enable verbose output"
    Write-Host "  -NoParallel        Disable parallel execution"
    Write-Host ""
    Write-Host "Parameters:" -ForegroundColor Yellow
    Write-Host "  -TargetNetwork     Network CIDR to scan (default: 192.168.68.0/24)"
    Write-Host "  -RouterIP          Router/gateway IP"
    Write-Host "  -ChromecastIP      Chromecast device IP"
    Write-Host "  -TvIP              Smart TV IP"
    Write-Host "  -PrinterIP         Network printer IP"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\start.ps1"
    Write-Host "  .\start.ps1 -TargetNetwork '192.168.1.0/24' -RouterIP '192.168.1.1'"
    Write-Host "  .\start.ps1 -Quick"
    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Copy .env.example to .env and customize for persistent configuration."
    Write-Host "  See examples/ directory for sample configurations."
    Write-Host ""
}

function Test-DockerInstalled {
    try {
        $null = docker --version 2>&1
        return $true
    }
    catch {
        return $false
    }
}

function Test-DockerRunning {
    try {
        $null = docker info 2>&1
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Get-DockerComposeCommand {
    # Try docker compose (v2)
    try {
        $null = docker compose version 2>&1
        if ($LASTEXITCODE -eq 0) {
            return "docker compose"
        }
    }
    catch {}
    
    # Try docker-compose (v1)
    try {
        $null = docker-compose --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            return "docker-compose"
        }
    }
    catch {}
    
    return $null
}

function Get-Platform {
    if ($IsWindows -or $env:OS -eq "Windows_NT") {
        return "Windows"
    }
    elseif ($IsMacOS) {
        return "macOS"
    }
    else {
        return "Linux"
    }
}

function Get-ComposeFile {
    $platform = Get-Platform
    
    # On Windows/macOS with Docker Desktop, use the Windows compose file
    if ($platform -eq "Windows" -or $platform -eq "macOS") {
        if (Test-Path "docker-compose.windows.yml") {
            return "docker-compose.windows.yml"
        }
    }
    
    return "docker-compose.yml"
}

function Import-EnvFile {
    if (Test-Path ".env") {
        Write-Host "📋 Loading configuration from .env file" -ForegroundColor Blue
        Get-Content ".env" | ForEach-Object {
            if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
                $name = $matches[1].Trim()
                $value = $matches[2].Trim()
                # Remove quotes if present
                $value = $value -replace '^["'']|["'']$', ''
                [Environment]::SetEnvironmentVariable($name, $value, "Process")
            }
        }
    }
}

function Set-Defaults {
    if (-not $script:TargetNetwork) {
        $script:TargetNetwork = if ($env:TARGET_NETWORK) { $env:TARGET_NETWORK } else { "192.168.68.0/24" }
    }
    if (-not $script:RouterIP) {
        $script:RouterIP = if ($env:ROUTER_IP) { $env:ROUTER_IP } else { "192.168.68.1" }
    }
    if (-not $script:ChromecastIP) {
        $script:ChromecastIP = if ($env:CHROMECAST_IP) { $env:CHROMECAST_IP } else { "192.168.68.56" }
    }
    if (-not $script:TvIP) {
        $script:TvIP = if ($env:TV_IP) { $env:TV_IP } else { "192.168.68.62" }
    }
    if (-not $script:PrinterIP) {
        $script:PrinterIP = if ($env:PRINTER_IP) { $env:PRINTER_IP } else { "192.168.68.54" }
    }
    
    $script:DlnaIPs = if ($env:DLNA_IPS) { $env:DLNA_IPS } else { "192.168.68.52,192.168.68.62" }
    $script:PassiveDuration = if ($env:PASSIVE_DURATION) { $env:PASSIVE_DURATION } else { "30" }
    $script:ParallelExecution = if ($NoParallel) { "false" } else { "true" }
    $script:VerboseSetting = if ($VerboseOutput) { "true" } else { "false" }
    
    if ($Quick) {
        $script:PassiveDuration = "15"
        Write-Host "⚡ Quick scan mode enabled" -ForegroundColor Yellow
    }
}

function Set-EnvironmentVariables {
    $env:TARGET_NETWORK = $script:TargetNetwork
    $env:ROUTER_IP = $script:RouterIP
    $env:CHROMECAST_IP = $script:ChromecastIP
    $env:TV_IP = $script:TvIP
    $env:PRINTER_IP = $script:PrinterIP
    $env:DLNA_IPS = $script:DlnaIPs
    $env:PASSIVE_DURATION = $script:PassiveDuration
    $env:PARALLEL_EXECUTION = $script:ParallelExecution
    $env:VERBOSE = $script:VerboseSetting
}

function Write-Configuration {
    Write-Host "🎯 Configuration:" -ForegroundColor Green
    Write-Host "   Target Network: $($script:TargetNetwork)" -ForegroundColor Cyan
    Write-Host "   Router IP:      $($script:RouterIP)" -ForegroundColor Cyan
    Write-Host "   Chromecast IP:  $($script:ChromecastIP)" -ForegroundColor Cyan
    Write-Host "   TV IP:          $($script:TvIP)" -ForegroundColor Cyan
    Write-Host "   Printer IP:     $($script:PrinterIP)" -ForegroundColor Cyan
    Write-Host "   DLNA IPs:       $($script:DlnaIPs)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "⚙️  Options:" -ForegroundColor Green
    Write-Host "   Passive Duration:   $($script:PassiveDuration)s" -ForegroundColor Cyan
    Write-Host "   Parallel Execution: $($script:ParallelExecution)" -ForegroundColor Cyan
    Write-Host "   Verbose:            $($script:VerboseSetting)" -ForegroundColor Cyan
    Write-Host "   Platform:           $(Get-Platform)" -ForegroundColor Cyan
    Write-Host ""
}

# Main execution
function Main {
    if ($Help) {
        Write-Help
        return
    }
    
    Write-Banner
    
    # Check Docker
    if (-not (Test-DockerInstalled)) {
        Write-Host "❌ Error: Docker is not installed" -ForegroundColor Red
        Write-Host "Please install Docker Desktop: https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
        exit 1
    }
    
    if (-not (Test-DockerRunning)) {
        Write-Host "❌ Error: Docker daemon is not running" -ForegroundColor Red
        Write-Host "Please start Docker Desktop and try again." -ForegroundColor Yellow
        exit 1
    }
    
    $composeCmd = Get-DockerComposeCommand
    if (-not $composeCmd) {
        Write-Host "❌ Error: Docker Compose is not installed" -ForegroundColor Red
        Write-Host "Docker Compose should be included with Docker Desktop." -ForegroundColor Yellow
        exit 1
    }
    
    # Load configuration
    Import-EnvFile
    Set-Defaults
    Set-EnvironmentVariables
    Write-Configuration
    
    # Get appropriate compose file
    $composeFile = Get-ComposeFile
    Write-Host "📄 Using compose file: $composeFile" -ForegroundColor Blue
    
    # Create output directory
    if (-not (Test-Path "output")) {
        New-Item -ItemType Directory -Path "output" | Out-Null
    }
    
    Write-Host "🔧 Building Docker containers..." -ForegroundColor Green
    Invoke-Expression "$composeCmd -f $composeFile build"
    
    Write-Host ""
    Write-Host "🚀 Starting reconnaissance framework..." -ForegroundColor Green
    Write-Host ""
    
    # Start containers
    Invoke-Expression "$composeCmd -f $composeFile up"
    
    Write-Host ""
    Write-Host "✅ Reconnaissance complete!" -ForegroundColor Green
    Write-Host "📁 Results are available in the ./output directory" -ForegroundColor Blue
    Write-Host ""
    
    # Show report locations
    if (Test-Path "output/report/recon_report.html") {
        Write-Host "📄 HTML Report: output/report/recon_report.html" -ForegroundColor Cyan
    }
    if (Test-Path "output/report/recon_report.json") {
        Write-Host "📊 JSON Report: output/report/recon_report.json" -ForegroundColor Cyan
    }
    if (Test-Path "output/execution_stats.json") {
        Write-Host "📈 Stats: output/execution_stats.json" -ForegroundColor Cyan
    }
}

# Run main
Main
