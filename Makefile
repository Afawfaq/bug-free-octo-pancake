# ============================================
# LAN Reconnaissance Framework Makefile
# Version 2.4.0 - Cross-Platform Support
# ============================================
# 
# Usage:
#   make help        - Show available commands
#   make build       - Build all containers
#   make run         - Run the framework
#   make stop        - Stop all containers
#   make clean       - Clean up everything
# ============================================

.PHONY: help build run stop clean logs test lint security-scan pull push dev

# Default target
.DEFAULT_GOAL := help

# Detect platform and set compose file
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    COMPOSE_FILE := docker-compose.windows.yml
    PLATFORM := macOS
else ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
    COMPOSE_FILE := docker-compose.windows.yml
    PLATFORM := Windows
else ifeq ($(findstring MSYS,$(UNAME_S)),MSYS)
    COMPOSE_FILE := docker-compose.windows.yml
    PLATFORM := Windows
else
    COMPOSE_FILE := docker-compose.yml
    PLATFORM := Linux
endif

# Allow override via environment variable
ifdef COMPOSE_FILE_OVERRIDE
    COMPOSE_FILE := $(COMPOSE_FILE_OVERRIDE)
endif

# Variables
PROJECT_NAME := lan-recon
DOCKER_COMPOSE := docker compose

# Colors for terminal output
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

## help: Show this help message
help:
	@echo ""
	@echo "$(BLUE)╔══════════════════════════════════════════════════════════╗$(RESET)"
	@echo "$(BLUE)║     LAN Reconnaissance Framework - Make Commands         ║$(RESET)"
	@echo "$(BLUE)║              Platform: $(PLATFORM) $(RESET)"
	@echo "$(BLUE)╚══════════════════════════════════════════════════════════╝$(RESET)"
	@echo ""
	@echo "$(GREEN)Using compose file: $(COMPOSE_FILE)$(RESET)"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | column -t -s ':'
	@echo ""
	@echo "$(YELLOW)Override compose file: make COMPOSE_FILE_OVERRIDE=docker-compose.yml build$(RESET)"
	@echo ""

## build: Build all Docker containers
build:
	@echo "$(GREEN)🔧 Building Docker containers...$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) build

## build-no-cache: Build all containers without cache
build-no-cache:
	@echo "$(GREEN)🔧 Building Docker containers (no cache)...$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) build --no-cache

## run: Start the reconnaissance framework
run:
	@echo "$(GREEN)🚀 Starting LAN Reconnaissance Framework...$(RESET)"
	@mkdir -p output
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) up

## run-detached: Start the framework in detached mode
run-detached:
	@echo "$(GREEN)🚀 Starting LAN Reconnaissance Framework (detached)...$(RESET)"
	@mkdir -p output
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) up -d

## stop: Stop all containers
stop:
	@echo "$(YELLOW)🛑 Stopping all containers...$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) down

## restart: Restart all containers
restart: stop run

## logs: Follow container logs
logs:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) logs -f

## logs-orchestrator: Follow orchestrator logs only
logs-orchestrator:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) logs -f orchestrator

## status: Show container status
status:
	@echo "$(BLUE)📊 Container Status:$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) ps

## clean: Remove all containers and output
clean:
	@echo "$(RED)🧹 Cleaning up...$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) down -v --rmi local
	rm -rf output/*
	@echo "$(GREEN)✅ Cleanup complete$(RESET)"

## clean-output: Remove only output files
clean-output:
	@echo "$(YELLOW)🧹 Cleaning output directory...$(RESET)"
	rm -rf output/*
	@echo "$(GREEN)✅ Output cleaned$(RESET)"

## test: Run tests
test:
	@echo "$(BLUE)🧪 Running tests...$(RESET)"
	@if [ -d "tests" ]; then \
		python -m pytest tests/ -v; \
	else \
		echo "$(YELLOW)No tests directory found$(RESET)"; \
	fi

## lint: Run linters
lint:
	@echo "$(BLUE)🔍 Running linters...$(RESET)"
	@command -v flake8 >/dev/null 2>&1 && flake8 --max-line-length=120 orchestrator/*.py || echo "flake8 not installed"
	@command -v shellcheck >/dev/null 2>&1 && find . -name "*.sh" -exec shellcheck {} \; || echo "shellcheck not installed"

## security-scan: Run security scan with Trivy
security-scan:
	@echo "$(BLUE)🔒 Running security scan...$(RESET)"
	@command -v trivy >/dev/null 2>&1 && trivy fs . || echo "$(YELLOW)Trivy not installed. Install with: brew install aquasecurity/trivy/trivy$(RESET)"

## quick-scan: Run quick scan mode
quick-scan:
	@echo "$(GREEN)⚡ Running quick scan...$(RESET)"
	./quick-scan.sh $(ARGS)

## view-report: Open the HTML report
view-report:
	@echo "$(BLUE)📄 Opening report...$(RESET)"
	@if [ -f output/report/recon_report.html ]; then \
		xdg-open output/report/recon_report.html 2>/dev/null || \
		open output/report/recon_report.html 2>/dev/null || \
		echo "Report available at: output/report/recon_report.html"; \
	else \
		echo "$(RED)No report found. Run 'make run' first.$(RESET)"; \
	fi

## shell-orchestrator: Open shell in orchestrator container
shell-orchestrator:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) exec orchestrator /bin/bash

## shell-passive: Open shell in passive container
shell-passive:
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) exec passive /bin/bash

## validate: Validate docker-compose configuration
validate:
	@echo "$(BLUE)✅ Validating docker-compose.yml...$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) config --quiet && echo "$(GREEN)Configuration is valid$(RESET)"

## pull: Pull latest base images
pull:
	@echo "$(BLUE)📥 Pulling latest images...$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) pull

## dev: Start development environment
dev:
	@echo "$(BLUE)🔧 Starting development environment...$(RESET)"
	$(DOCKER_COMPOSE) -f $(COMPOSE_FILE) up --build

## version: Show version information
version:
	@echo "$(BLUE)LAN Reconnaissance Framework$(RESET)"
	@grep -m1 "^## \[" CHANGELOG.md | sed 's/## \[\(.*\)\].*/Version: \1/'

## deps: Install development dependencies
deps:
	@echo "$(BLUE)📦 Installing development dependencies...$(RESET)"
	pip install flake8 pylint black pytest pytest-cov
	@command -v shellcheck >/dev/null 2>&1 || echo "$(YELLOW)Install shellcheck: apt install shellcheck$(RESET)"

## setup: Initial project setup
setup: deps build
	@echo "$(GREEN)✅ Setup complete!$(RESET)"
	@echo "$(BLUE)Copy .env.example to .env and customize, then run 'make run'$(RESET)"
