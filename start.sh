#!/bin/bash

# ============================================
# LAN Reconnaissance Framework - Start Script
# ============================================
# Version: 2.0.0
# 
# Usage:
#   ./start.sh [TARGET_NETWORK] [ROUTER_IP] [CHROMECAST_IP] [TV_IP] [PRINTER_IP]
#   ./start.sh --quick       # Quick scan mode
#   ./start.sh --help        # Show help
# ============================================

set -e

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Version
VERSION="2.0.0"

# Print banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         LAN RECONNAISSANCE FRAMEWORK v${VERSION}            ║"
    echo "║       Containerized Network Security Scanner             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print help
print_help() {
    print_banner
    echo "Usage: $0 [OPTIONS] [TARGET_NETWORK] [ROUTER_IP] [CHROMECAST_IP] [TV_IP] [PRINTER_IP]"
    echo ""
    echo "Options:"
    echo "  --help, -h       Show this help message"
    echo "  --version, -v    Show version"
    echo "  --quick          Run quick scan (reduced scope)"
    echo "  --verbose        Enable verbose output"
    echo "  --no-parallel    Disable parallel execution"
    echo ""
    echo "Arguments (all optional with defaults from .env or built-in):"
    echo "  TARGET_NETWORK   Network CIDR to scan (default: 192.168.68.0/24)"
    echo "  ROUTER_IP        Router/gateway IP"
    echo "  CHROMECAST_IP    Chromecast device IP"
    echo "  TV_IP            Smart TV IP"
    echo "  PRINTER_IP       Network printer IP"
    echo ""
    echo "Examples:"
    echo "  $0                                        # Use defaults or .env"
    echo "  $0 192.168.1.0/24 192.168.1.1             # Custom network"
    echo "  $0 --quick                                # Quick scan mode"
    echo ""
    echo "Configuration:"
    echo "  Copy .env.example to .env and customize for persistent configuration."
    echo "  See examples/ directory for sample configurations."
    echo ""
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Error: Docker is not installed${NC}"
        echo "Please install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        echo -e "${RED}❌ Error: Docker daemon is not running${NC}"
        echo "Please start Docker and try again."
        exit 1
    fi
}

# Check if Docker Compose is installed
check_docker_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        echo -e "${RED}❌ Error: Docker Compose is not installed${NC}"
        echo "Please install Docker Compose first"
        exit 1
    fi
}

# Load environment from .env file if it exists
load_env() {
    if [ -f ".env" ]; then
        echo -e "${BLUE}📋 Loading configuration from .env file${NC}"
        set -a
        source .env
        set +a
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                print_help
                exit 0
                ;;
            --version|-v)
                echo "LAN Reconnaissance Framework v${VERSION}"
                exit 0
                ;;
            --quick)
                PASSIVE_DURATION=15
                ENABLE_ATTACK_SURFACE=false
                ENABLE_ADVANCED_MONITOR=false
                echo -e "${YELLOW}⚡ Quick scan mode enabled${NC}"
                shift
                ;;
            --verbose)
                export VERBOSE=true
                echo -e "${YELLOW}📝 Verbose mode enabled${NC}"
                shift
                ;;
            --no-parallel)
                export PARALLEL_EXECUTION=false
                echo -e "${YELLOW}🔄 Parallel execution disabled${NC}"
                shift
                ;;
            *)
                # Positional arguments
                if [ -z "$TARGET_NETWORK" ]; then
                    TARGET_NETWORK="$1"
                elif [ -z "$ROUTER_IP" ]; then
                    ROUTER_IP="$1"
                elif [ -z "$CHROMECAST_IP" ]; then
                    CHROMECAST_IP="$1"
                elif [ -z "$TV_IP" ]; then
                    TV_IP="$1"
                elif [ -z "$PRINTER_IP" ]; then
                    PRINTER_IP="$1"
                fi
                shift
                ;;
        esac
    done
}

# Set defaults if not provided
set_defaults() {
    TARGET_NETWORK="${TARGET_NETWORK:-192.168.68.0/24}"
    ROUTER_IP="${ROUTER_IP:-192.168.68.1}"
    CHROMECAST_IP="${CHROMECAST_IP:-192.168.68.56}"
    TV_IP="${TV_IP:-192.168.68.62}"
    PRINTER_IP="${PRINTER_IP:-192.168.68.54}"
    DLNA_IPS="${DLNA_IPS:-192.168.68.52,192.168.68.62}"
    PASSIVE_DURATION="${PASSIVE_DURATION:-30}"
    PARALLEL_EXECUTION="${PARALLEL_EXECUTION:-true}"
    VERBOSE="${VERBOSE:-false}"
}

# Export environment variables
export_env() {
    export TARGET_NETWORK
    export ROUTER_IP
    export CHROMECAST_IP
    export TV_IP
    export PRINTER_IP
    export DLNA_IPS
    export PASSIVE_DURATION
    export PARALLEL_EXECUTION
    export VERBOSE
}

# Print configuration
print_config() {
    echo -e "${GREEN}🎯 Configuration:${NC}"
    echo -e "   Target Network: ${CYAN}$TARGET_NETWORK${NC}"
    echo -e "   Router IP:      ${CYAN}$ROUTER_IP${NC}"
    echo -e "   Chromecast IP:  ${CYAN}$CHROMECAST_IP${NC}"
    echo -e "   TV IP:          ${CYAN}$TV_IP${NC}"
    echo -e "   Printer IP:     ${CYAN}$PRINTER_IP${NC}"
    echo -e "   DLNA IPs:       ${CYAN}$DLNA_IPS${NC}"
    echo ""
    echo -e "${GREEN}⚙️  Options:${NC}"
    echo -e "   Passive Duration:   ${CYAN}${PASSIVE_DURATION}s${NC}"
    echo -e "   Parallel Execution: ${CYAN}$PARALLEL_EXECUTION${NC}"
    echo -e "   Verbose:            ${CYAN}$VERBOSE${NC}"
    echo ""
}

# Main execution
main() {
    print_banner
    
    check_docker
    check_docker_compose
    
    load_env
    parse_args "$@"
    set_defaults
    export_env
    
    print_config
    
    # Create output directory
    mkdir -p output
    
    echo -e "${GREEN}🔧 Building Docker containers...${NC}"
    $COMPOSE_CMD build
    
    echo ""
    echo -e "${GREEN}🚀 Starting reconnaissance framework...${NC}"
    echo ""
    
    # Start containers
    $COMPOSE_CMD up
    
    echo ""
    echo -e "${GREEN}✅ Reconnaissance complete!${NC}"
    echo -e "${BLUE}📁 Results are available in the ./output directory${NC}"
    echo ""
    
    # Show quick summary
    if [ -f "output/report/recon_report.html" ]; then
        echo -e "${CYAN}📄 HTML Report: output/report/recon_report.html${NC}"
    fi
    if [ -f "output/report/recon_report.json" ]; then
        echo -e "${CYAN}📊 JSON Report: output/report/recon_report.json${NC}"
    fi
    if [ -f "output/execution_stats.json" ]; then
        echo -e "${CYAN}📈 Stats: output/execution_stats.json${NC}"
    fi
}

# Run main function with all arguments
main "$@"
