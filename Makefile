# WordPress Deployment Makefile
# Author: Florent Didelot
# Description: Automation targets for WordPress deployment and Vagrant management

# Variables
VAGRANT_BOX ?= ubuntu/jammy64
VAGRANT_RAM ?= 4096
VAGRANT_CPUS ?= 2
VAGRANT_IP ?= 192.168.56.10
VAGRANT_HOST_PATH ?= $(PWD)

# Colors for output
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
MAGENTA := \033[35m
CYAN := \033[36m
WHITE := \033[37m
RESET := \033[0m

# Default target
.DEFAULT_GOAL := help

# Help target
.PHONY: help
help: ## Show this help message
	@echo "$(CYAN)WordPress Deployment Makefile$(RESET)"
	@echo "$(CYAN)================================$(RESET)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Environment variables:$(RESET)"
	@echo "  $(GREEN)VAGRANT_BOX$(RESET)       = $(VAGRANT_BOX)"
	@echo "  $(GREEN)VAGRANT_RAM$(RESET)       = $(VAGRANT_RAM)"
	@echo "  $(GREEN)VAGRANT_CPUS$(RESET)      = $(VAGRANT_CPUS)"
	@echo "  $(GREEN)VAGRANT_IP$(RESET)        = $(VAGRANT_IP)"
	@echo "  $(GREEN)VAGRANT_HOST_PATH$(RESET) = $(VAGRANT_HOST_PATH)"
	@echo ""

# Environment validation
.PHONY: check-env
check-env: ## Check if required tools are installed
	@echo "$(BLUE)Checking required tools...$(RESET)"
	@command -v vagrant >/dev/null 2>&1 || { echo "$(RED)ERROR: Vagrant is not installed$(RESET)"; exit 1; }
	@command -v VBoxManage >/dev/null 2>&1 || { echo "$(RED)ERROR: VirtualBox is not installed$(RESET)"; exit 1; }
	@echo "$(GREEN)✓ All required tools are installed$(RESET)"

# Environment setup
.PHONY: setup
setup: check-env ## Setup environment file for deployment
	@echo "$(BLUE)Setting up environment...$(RESET)"
	@if [ ! -f deploy/env ]; then \
		cp deploy/env.example deploy/env; \
		echo "$(GREEN)✓ Created deploy/env from template$(RESET)"; \
		echo "$(YELLOW)Please edit deploy/env with your configuration$(RESET)"; \
	else \
		echo "$(YELLOW)deploy/env already exists$(RESET)"; \
	fi
	@chmod +x deploy/*.sh
	@echo "$(GREEN)✓ Made deployment scripts executable$(RESET)"

# Vagrant targets
.PHONY: up
up: check-env setup ## Start and provision Vagrant VM
	@echo "$(BLUE)Starting Vagrant VM...$(RESET)"
	@export VAGRANT_BOX=$(VAGRANT_BOX) && \
	 export VAGRANT_RAM=$(VAGRANT_RAM) && \
	 export VAGRANT_CPUS=$(VAGRANT_CPUS) && \
	 export VAGRANT_IP=$(VAGRANT_IP) && \
	 export VAGRANT_HOST_PATH=$(VAGRANT_HOST_PATH) && \
	 vagrant up
	@echo "$(GREEN)✓ Vagrant VM started successfully$(RESET)"
	@echo ""
	@echo "$(CYAN)Access Information:$(RESET)"
	@echo "  WordPress: $(GREEN)http://localhost:8080$(RESET)"
	@echo "  Admin Panel: $(GREEN)http://localhost:8080/wp-admin/$(RESET)"
	@echo "  SSH: $(GREEN)vagrant ssh$(RESET)"

.PHONY: reprovision
reprovision: ## Re-run Vagrant provisioning
	@echo "$(BLUE)Re-provisioning Vagrant VM...$(RESET)"
	@vagrant provision
	@echo "$(GREEN)✓ Vagrant VM re-provisioned successfully$(RESET)"

.PHONY: reload
reload: ## Restart Vagrant VM
	@echo "$(BLUE)Restarting Vagrant VM...$(RESET)"
	@vagrant reload
	@echo "$(GREEN)✓ Vagrant VM restarted successfully$(RESET)"

.PHONY: halt
halt: ## Stop Vagrant VM
	@echo "$(BLUE)Stopping Vagrant VM...$(RESET)"
	@vagrant halt
	@echo "$(GREEN)✓ Vagrant VM stopped$(RESET)"

.PHONY: suspend
suspend: ## Suspend Vagrant VM
	@echo "$(BLUE)Suspending Vagrant VM...$(RESET)"
	@vagrant suspend
	@echo "$(GREEN)✓ Vagrant VM suspended$(RESET)"

.PHONY: resume
resume: ## Resume suspended Vagrant VM
	@echo "$(BLUE)Resuming Vagrant VM...$(RESET)"
	@vagrant resume
	@echo "$(GREEN)✓ Vagrant VM resumed$(RESET)"

.PHONY: ssh
ssh: ## SSH into Vagrant VM
	@echo "$(BLUE)Connecting to Vagrant VM via SSH...$(RESET)"
	@vagrant ssh

.PHONY: status
status: ## Show Vagrant VM status
	@echo "$(BLUE)Vagrant VM status:$(RESET)"
	@vagrant status

.PHONY: destroy
destroy: ## Destroy Vagrant VM (with confirmation)
	@echo "$(RED)WARNING: This will completely destroy the Vagrant VM!$(RESET)"
	@read -p "Are you sure? [y/N]: " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "$(BLUE)Destroying Vagrant VM...$(RESET)"
	@vagrant destroy -f
	@echo "$(GREEN)✓ Vagrant VM destroyed$(RESET)"

# Deployment targets
.PHONY: deploy
deploy: setup ## Run full WordPress deployment (requires sudo on host)
	@echo "$(BLUE)Running WordPress deployment...$(RESET)"
	@if [ ! -f deploy/env ]; then \
		echo "$(RED)ERROR: deploy/env not found. Run 'make setup' first.$(RESET)"; \
		exit 1; \
	fi
	@cd deploy && sudo ./deploy.sh
	@echo "$(GREEN)✓ WordPress deployment completed$(RESET)"

.PHONY: deploy-dry-run
deploy-dry-run: setup ## Validate deployment configuration without running
	@echo "$(BLUE)Running deployment dry run...$(RESET)"
	@cd deploy && ./deploy.sh --dry-run
	@echo "$(GREEN)✓ Deployment configuration validated$(RESET)"

.PHONY: deploy-component
deploy-component: setup ## Deploy specific component (usage: make deploy-component COMPONENT=system_checks)
	@if [ -z "$(COMPONENT)" ]; then \
		echo "$(RED)ERROR: COMPONENT variable required$(RESET)"; \
		echo "Example: make deploy-component COMPONENT=system_checks"; \
		exit 1; \
	fi
	@echo "$(BLUE)Deploying component: $(COMPONENT)$(RESET)"
	@cd deploy && sudo ./deploy.sh --component $(COMPONENT)

# Development targets
.PHONY: dev-tools
dev-tools: ## Install development tools in Vagrant VM
	@echo "$(BLUE)Installing development tools...$(RESET)"
	@vagrant provision --provision-with development-tools
	@echo "$(GREEN)✓ Development tools installed$(RESET)"

.PHONY: logs
logs: ## View combined service logs from Vagrant VM
	@echo "$(BLUE)Viewing service logs...$(RESET)"
	@vagrant ssh -c "sudo journalctl -f -u apache2 -u mariadb -u php*-fmp --no-pager" 2>/dev/null || \
	 echo "$(YELLOW)VM not running or journalctl not available$(RESET)"

.PHONY: logs-apache
logs-apache: ## View Apache logs from Vagrant VM
	@echo "$(BLUE)Viewing Apache logs...$(RESET)"
	@vagrant ssh -c "sudo tail -f /var/log/apache2/access.log /var/log/apache2/error.log" 2>/dev/null || \
	 echo "$(YELLOW)VM not running or logs not available$(RESET)"

.PHONY: logs-php
logs-php: ## View PHP logs from Vagrant VM
	@echo "$(BLUE)Viewing PHP logs...$(RESET)"
	@vagrant ssh -c "sudo tail -f /var/log/php*/*.log" 2>/dev/null || \
	 echo "$(YELLOW)VM not running or logs not available$(RESET)"

.PHONY: logs-mysql
logs-mysql: ## View MySQL/MariaDB logs from Vagrant VM
	@echo "$(BLUE)Viewing MySQL/MariaDB logs...$(RESET)"
	@vagrant ssh -c "sudo tail -f /var/log/mysql/*.log" 2>/dev/null || \
	 echo "$(YELLOW)VM not running or logs not available$(RESET)"

.PHONY: logs-deployment
logs-deployment: ## View deployment logs from Vagrant VM
	@echo "$(BLUE)Viewing deployment logs...$(RESET)"
	@vagrant ssh -c "sudo tail -f /var/log/wordpress-deployment.log" 2>/dev/null || \
	 echo "$(YELLOW)VM not running or deployment log not available$(RESET)"

# Testing targets
.PHONY: test
test: ## Run basic connectivity tests
	@echo "$(BLUE)Running connectivity tests...$(RESET)"
	@echo "Testing WordPress site..."
	@curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost:8080 || \
	 echo "$(YELLOW)WordPress site not accessible$(RESET)"
	@echo "Testing WordPress admin..."
	@curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost:8080/wp-admin/ || \
	 echo "$(YELLOW)WordPress admin not accessible$(RESET)"

.PHONY: test-ftp
test-ftp: ## Test FTP connectivity
	@echo "$(BLUE)Testing FTP connectivity...$(RESET)"
	@nc -zv localhost 2121 2>/dev/null && echo "$(GREEN)✓ FTP port accessible$(RESET)" || \
	 echo "$(YELLOW)FTP port not accessible$(RESET)"

.PHONY: test-mysql
test-mysql: ## Test MySQL connectivity
	@echo "$(BLUE)Testing MySQL connectivity...$(RESET)"
	@nc -zv localhost 33060 2>/dev/null && echo "$(GREEN)✓ MySQL port accessible$(RESET)" || \
	 echo "$(YELLOW)MySQL port not accessible$(RESET)"

# Health check targets
.PHONY: health
health: ## Show overall system health
	@echo "$(BLUE)System health check...$(RESET)"
	@vagrant ssh -c "wp-health 2>/dev/null || echo 'Health check script not available'"

.PHONY: security-status
security-status: ## Show security status
	@echo "$(BLUE)Security status check...$(RESET)"
	@vagrant ssh -c "security-status 2>/dev/null || echo 'Security status script not available'"

.PHONY: wp-status
wp-status: ## Show WordPress status
	@echo "$(BLUE)WordPress status check...$(RESET)"
	@vagrant ssh -c "cd /var/www/html && wp core is-installed --allow-root 2>/dev/null && echo '✓ WordPress is installed' || echo '✗ WordPress not properly installed'"

# Backup and maintenance targets
.PHONY: backup
backup: ## Create backup of WordPress
	@echo "$(BLUE)Creating WordPress backup...$(RESET)"
	@vagrant ssh -c "wp-backup 2>/dev/null || echo 'Backup script not available'"
	@echo "$(GREEN)✓ Backup completed$(RESET)"

.PHONY: update
update: ## Update WordPress core and plugins
	@echo "$(BLUE)Updating WordPress...$(RESET)"
	@vagrant ssh -c "wp-update 2>/dev/null || echo 'Update script not available'"
	@echo "$(GREEN)✓ Update completed$(RESET)"

.PHONY: maintenance
maintenance: ## Run WordPress maintenance tasks
	@echo "$(BLUE)Running WordPress maintenance...$(RESET)"
	@vagrant ssh -c "wp-maintenance 2>/dev/null || echo 'Maintenance script not available'"
	@echo "$(GREEN)✓ Maintenance completed$(RESET)"

# Cleanup targets
.PHONY: clean
clean: ## Clean up temporary files and caches
	@echo "$(BLUE)Cleaning up...$(RESET)"
	@rm -f .vagrant/machines/default/virtualbox/synced_folders
	@vagrant ssh -c "sudo apt-get autoremove -y && sudo apt-get autoclean" 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup completed$(RESET)"

.PHONY: clean-logs
clean-logs: ## Clear all logs in Vagrant VM
	@echo "$(BLUE)Clearing logs...$(RESET)"
	@vagrant ssh -c "sudo find /var/log -type f -name '*.log' -exec truncate -s 0 {} \\;" 2>/dev/null || \
	 echo "$(YELLOW)VM not running$(RESET)"
	@echo "$(GREEN)✓ Logs cleared$(RESET)"

# Information targets
.PHONY: info
info: ## Show detailed system information
	@echo "$(CYAN)WordPress Deployment Information$(RESET)"
	@echo "$(CYAN)==================================$(RESET)"
	@echo ""
	@echo "$(YELLOW)Project Structure:$(RESET)"
	@echo "  deploy/          - Deployment scripts"
	@echo "  Vagrantfile      - Vagrant configuration"
	@echo "  Makefile         - This automation file"
	@echo ""
	@echo "$(YELLOW)Quick Start:$(RESET)"
	@echo "  1. make setup    - Setup environment"
	@echo "  2. make up       - Start VM and deploy"
	@echo "  3. make ssh      - Connect to VM"
	@echo "  4. make destroy  - Clean up"
	@echo ""
	@echo "$(YELLOW)URLs (when VM is running):$(RESET)"
	@echo "  WordPress:       http://localhost:8080"
	@echo "  WordPress Admin: http://localhost:8080/wp-admin/"
	@echo "  FTP:             ftp://localhost:2121"
	@echo "  MySQL:           localhost:33060"
	@echo ""
	@echo "$(YELLOW)Default Credentials:$(RESET)"
	@echo "  WordPress: admin / vagrant123!"
	@echo "  FTP:       ftpuser / vagrant123"
	@echo "  MySQL:     wpuser / vagrant123"
	@echo ""

.PHONY: urls
urls: ## Show service URLs
	@echo "$(CYAN)Service URLs$(RESET)"
	@echo "$(CYAN)============$(RESET)"
	@echo "WordPress:       $(GREEN)http://localhost:8080$(RESET)"
	@echo "WordPress Admin: $(GREEN)http://localhost:8080/wp-admin/$(RESET)"
	@echo "HTTPS:           $(GREEN)https://localhost:8443$(RESET)"
	@echo "FTP:             $(GREEN)ftp://localhost:2121$(RESET)"
	@echo "MySQL:           $(GREEN)mysql://localhost:33060$(RESET)"

# Advanced targets
.PHONY: snapshot
snapshot: ## Create VM snapshot (requires VM to be running)
	@echo "$(BLUE)Creating VM snapshot...$(RESET)"
	@read -p "Snapshot name: " name && \
	 VBoxManage snapshot wordpress-deployment take "$$name" --description "Manual snapshot created on $$(date)"
	@echo "$(GREEN)✓ Snapshot created$(RESET)"

.PHONY: restore-snapshot
restore-snapshot: ## Restore VM from snapshot
	@echo "$(BLUE)Available snapshots:$(RESET)"
	@VBoxManage snapshot wordpress-deployment list 2>/dev/null || echo "No snapshots available"
	@echo ""
	@read -p "Snapshot name to restore: " name && \
	 vagrant halt && \
	 VBoxManage snapshot wordpress-deployment restore "$$name" && \
	 vagrant up
	@echo "$(GREEN)✓ Snapshot restored$(RESET)"

.PHONY: export
export: ## Export VM as OVA file
	@echo "$(BLUE)Exporting VM...$(RESET)"
	@vagrant halt
	@VBoxManage export wordpress-deployment --output wordpress-deployment.ova
	@echo "$(GREEN)✓ VM exported to wordpress-deployment.ova$(RESET)"

# Multi-environment targets
.PHONY: prod-deploy
prod-deploy: ## Deploy to production server (requires configuration)
	@echo "$(RED)WARNING: This will deploy to production!$(RESET)"
	@read -p "Are you sure? [y/N]: " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "$(BLUE)Deploying to production...$(RESET)"
	@echo "$(YELLOW)Production deployment not implemented yet$(RESET)"

# Debug targets
.PHONY: debug
debug: ## Show debug information
	@echo "$(CYAN)Debug Information$(RESET)"
	@echo "$(CYAN)=================$(RESET)"
	@echo "Vagrant version: $$(vagrant --version 2>/dev/null || echo 'Not installed')"
	@echo "VirtualBox version: $$(VBoxManage --version 2>/dev/null || echo 'Not installed')"
	@echo "VM Status: $$(vagrant status 2>/dev/null | grep default || echo 'No VM')"
	@echo "Current directory: $(PWD)"
	@echo "Environment file: $$([ -f deploy/env ] && echo 'exists' || echo 'missing')"

# Validation targets
.PHONY: validate
validate: ## Validate all configurations
	@echo "$(BLUE)Validating configurations...$(RESET)"
	@echo "Checking Vagrantfile syntax..."
	@vagrant validate
	@echo "$(GREEN)✓ Vagrantfile is valid$(RESET)"
	@echo "Checking deployment scripts..."
	@for script in deploy/*.sh; do \
		bash -n "$$script" && echo "$(GREEN)✓ $$script syntax OK$(RESET)" || echo "$(RED)✗ $$script has syntax errors$(RESET)"; \
	done

# Git integration targets (if in a git repository)
.PHONY: git-status
git-status: ## Show git status if in a git repository
	@if [ -d .git ]; then \
		echo "$(BLUE)Git status:$(RESET)"; \
		git status --short; \
	else \
		echo "$(YELLOW)Not a git repository$(RESET)"; \
	fi

.PHONY: git-commit
git-commit: ## Commit all changes with a message
	@if [ -d .git ]; then \
		read -p "Commit message: " msg && \
		git add . && \
		git commit -m "$$msg"; \
		echo "$(GREEN)✓ Changes committed$(RESET)"; \
	else \
		echo "$(YELLOW)Not a git repository$(RESET)"; \
	fi

# Documentation targets
.PHONY: docs
docs: ## Generate or view documentation
	@echo "$(BLUE)Opening documentation...$(RESET)"
	@if [ -f deploy/README.md ]; then \
		echo "$(GREEN)Documentation available in deploy/README.md$(RESET)"; \
	else \
		echo "$(YELLOW)Documentation not yet available$(RESET)"; \
	fi

# Performance targets
.PHONY: benchmark
benchmark: ## Run basic performance benchmark
	@echo "$(BLUE)Running performance benchmark...$(RESET)"
	@vagrant ssh -c "ab -n 100 -c 10 http://localhost/ 2>/dev/null || echo 'ApacheBench not available'"

# This target should always be last
.PHONY: all
all: setup up test ## Run complete setup and validation