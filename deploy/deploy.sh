#!/bin/bash

# WordPress Deployment Main Script
# Author: Florent Didelot
# Description: Main orchestrator script for complete WordPress deployment on Ubuntu 24.04 LTS

set -Eeuo pipefail

# Script metadata
readonly SCRIPT_NAME="WordPress Deployment"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_AUTHOR="Florent Didelot"
readonly SUPPORTED_OS="Ubuntu 24.04 LTS"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source functions first
if [[ -f "$SCRIPT_DIR/functions.sh" ]]; then
    source "$SCRIPT_DIR/functions.sh"
else
    echo "ERROR: functions.sh not found in $SCRIPT_DIR"
    exit 1
fi

# Load environment variables
if [[ -f "$SCRIPT_DIR/env" ]]; then
    source "$SCRIPT_DIR/env"
    log_info "Environment loaded from $SCRIPT_DIR/env"
else
    log_warn "Environment file not found. Using env.example as template."
    if [[ -f "$SCRIPT_DIR/env.example" ]]; then
        cp "$SCRIPT_DIR/env.example" "$SCRIPT_DIR/env"
        log_info "Created env file from env.example template"
        log_warn "Please edit $SCRIPT_DIR/env with your configuration and run the script again"
        exit 1
    else
        error_exit "Neither env nor env.example found. Cannot continue."
    fi
fi

# Global variables
readonly START_TIME=$(date +%s)
readonly LOG_FILE="/var/log/wordpress-deployment.log"
DEPLOYMENT_PHASE=""
FAILED_COMPONENTS=()
COMPLETED_COMPONENTS=()

# Error trap with cleanup
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Deployment failed during phase: $DEPLOYMENT_PHASE"
        log_error "Failed components: ${FAILED_COMPONENTS[*]:-none}"
        log_error "Check logs for details: $LOG_FILE"
    fi
    
    # Calculate deployment time
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))
    
    log_info "Deployment duration: ${minutes}m ${seconds}s"
    exit $exit_code
}

trap cleanup EXIT ERR

# Deployment phases and components
declare -A DEPLOYMENT_PHASES=(
    ["pre-checks"]="System prerequisites and validation"
    ["infrastructure"]="Core infrastructure setup"
    ["services"]="Service optimization and configuration"
    ["application"]="WordPress installation and configuration"
    ["security"]="Security hardening and SSL setup"
    ["maintenance"]="Cron jobs and maintenance tasks"
    ["validation"]="Final validation and testing"
)

declare -A PHASE_COMPONENTS=(
    ["pre-checks"]="system_checks"
    ["infrastructure"]="optimize_mariadb optimize_php optimize_apache"
    ["services"]="install_ftp"
    ["application"]="install_wp"
    ["security"]="ssl_setup hardening"
    ["maintenance"]="cron_setup"
    ["validation"]="final_checks"
)

main() {
    display_banner
    initialize_deployment
    
    # Run deployment phases
    for phase in pre-checks infrastructure services application security maintenance validation; do
        run_deployment_phase "$phase"
    done
    
    display_deployment_summary
    log_success "WordPress deployment completed successfully!"
}

display_banner() {
    cat << 'EOF'
==============================================================================
 __        __            _  ____                      
 \ \      / /__  _ __ __| |/ ___| _ __  _ __ ___  ___ 
  \ \ /\ / / _ \| '__/ _` | |   | '_ \| '__/ _ \/ __|
   \ V  V / (_) | | | (_| | |___| |_) | | |  __/\__ \
    \_/\_/ \___/|_|  \__,_|\____| .__/|_|  \___||___/
                               |_|                   
                 Deployment Automation Script
==============================================================================
EOF

    echo "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    echo "Author: $SCRIPT_AUTHOR"
    echo "Target: $SUPPORTED_OS"
    echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname: $(hostname)"
    echo "User: $(whoami)"
    echo "Working Directory: $SCRIPT_DIR"
    echo "=============================================================================="
    echo
}

initialize_deployment() {
    log_info "Initializing WordPress deployment..."
    
    # Create deployment log
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    # Log deployment start
    {
        echo "=============================================================================="
        echo "WordPress Deployment Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Script Version: $SCRIPT_VERSION"
        echo "Environment Configuration:"
        echo "- Domain: ${DOMAIN:-localhost}"
        echo "- PHP Version: ${PHP_VERSION:-8.4}"
        echo "- MariaDB Version: ${MARIADB_VERSION:-11.4}"
        echo "- Enable SSL: ${ENABLE_LETSENCRYPT:-false}"
        echo "- Enable UFW: ${ENABLE_UFW:-true}"
        echo "- Enable fail2ban: ${ENABLE_FAIL2BAN:-false}"
        echo "=============================================================================="
    } >> "$LOG_FILE"
    
    # Validate script permissions
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
    
    # Validate environment
    validate_environment
    
    log_info "Deployment initialization completed"
}

validate_environment() {
    log_info "Validating environment configuration..."
    
    # Required variables
    local required_vars=(
        "DOMAIN"
        "WP_DB_NAME"
        "WP_DB_USER"
        "WP_DB_PASSWORD"
        "WP_ADMIN_USER"
        "WP_ADMIN_PASSWORD"
        "WP_ADMIN_EMAIL"
        "MARIADB_ROOT_PASSWORD"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables:"
        for var in "${missing_vars[@]}"; do
            log_error "  - $var"
        done
        error_exit "Please configure missing variables in $SCRIPT_DIR/env"
    fi
    
    log_success "Environment validation completed"
}

run_deployment_phase() {
    local phase="$1"
    DEPLOYMENT_PHASE="$phase"
    
    log_info "Starting deployment phase: $phase"
    echo "=============================================================================="
    echo "PHASE: ${DEPLOYMENT_PHASES[$phase]}"
    echo "=============================================================================="
    
    local components="${PHASE_COMPONENTS[$phase]}"
    local phase_start_time=$(date +%s)
    
    for component in $components; do
        run_component "$component"
    done
    
    local phase_end_time=$(date +%s)
    local phase_duration=$((phase_end_time - phase_start_time))
    
    log_success "Phase '$phase' completed in ${phase_duration}s"
    echo
}

run_component() {
    local component="$1"
    local component_script="$SCRIPT_DIR/${component}.sh"
    
    log_info "Running component: $component"
    
    # Check if component script exists
    if [[ ! -f "$component_script" ]]; then
        if [[ "$component" == "final_checks" ]]; then
            # Special handling for final validation
            run_final_validation
            return 0
        else
            log_error "Component script not found: $component_script"
            FAILED_COMPONENTS+=("$component")
            return 1
        fi
    fi
    
    # Make script executable
    chmod +x "$component_script"
    
    # Run component with timeout and logging
    local component_start_time=$(date +%s)
    
    if timeout 1800 "$component_script" >> "$LOG_FILE" 2>&1; then
        local component_end_time=$(date +%s)
        local component_duration=$((component_end_time - component_start_time))
        
        COMPLETED_COMPONENTS+=("$component")
        log_success "✓ $component completed in ${component_duration}s"
    else
        local exit_code=$?
        log_error "✗ $component failed (exit code: $exit_code)"
        FAILED_COMPONENTS+=("$component")
        
        # Critical components should stop deployment
        case "$component" in
            "system_checks"|"optimize_mariadb"|"optimize_apache"|"optimize_php"|"install_wp")
                error_exit "Critical component '$component' failed. Cannot continue deployment."
                ;;
            *)
                log_warn "Non-critical component '$component' failed. Continuing deployment..."
                ;;
        esac
    fi
}

run_final_validation() {
    log_info "Running final system validation..."
    
    local validation_errors=0
    
    # Test web server response
    log_info "Testing web server response..."
    if test_http_response "http://${DOMAIN}" 200 15; then
        log_success "✓ HTTP response test passed"
    else
        log_error "✗ HTTP response test failed"
        ((validation_errors++))
    fi
    
    # Test critical services
    local services=("apache2" "mariadb" "php${PHP_VERSION:-8.4}-fpm")
    for service in "${services[@]}"; do
        if service_is_active "$service"; then
            log_success "✓ Service $service is running"
        else
            log_error "✗ Service $service is not running"
            ((validation_errors++))
        fi
    done
    
    # Summary of validation
    if [[ $validation_errors -eq 0 ]]; then
        log_success "✓ All validation tests passed"
        COMPLETED_COMPONENTS+=("final_checks")
    else
        log_error "✗ $validation_errors validation tests failed"
        FAILED_COMPONENTS+=("final_checks")
    fi
}

display_deployment_summary() {
    local end_time=$(date +%s)
    local total_duration=$((end_time - START_TIME))
    local minutes=$((total_duration / 60))
    local seconds=$((total_duration % 60))
    
    echo
    echo "=============================================================================="
    echo "                        DEPLOYMENT SUMMARY"
    echo "=============================================================================="
    echo "Deployment Status: $([ ${#FAILED_COMPONENTS[@]} -eq 0 ] && echo "SUCCESS" || echo "PARTIAL SUCCESS")"
    echo "Total Duration: ${minutes}m ${seconds}s"
    echo "Completed: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    
    echo "COMPLETED COMPONENTS (${#COMPLETED_COMPONENTS[@]}):"
    for component in "${COMPLETED_COMPONENTS[@]}"; do
        echo "  ✓ $component"
    done
    
    if [[ ${#FAILED_COMPONENTS[@]} -gt 0 ]]; then
        echo
        echo "FAILED COMPONENTS (${#FAILED_COMPONENTS[@]}):"
        for component in "${FAILED_COMPONENTS[@]}"; do
            echo "  ✗ $component"
        done
    fi
    
    echo
    echo "=============================================================================="
    echo "                        ACCESS INFORMATION"
    echo "=============================================================================="
    
    local protocol="http"
    if [[ "${ENABLE_LETSENCRYPT:-false}" == "true" ]]; then
        protocol="https"
    fi
    
    echo "WordPress Site:"
    echo "  URL: ${protocol}://${DOMAIN}"
    echo "  Admin URL: ${protocol}://${DOMAIN}/wp-admin/"
    echo "  Admin User: ${WP_ADMIN_USER}"
    echo
    
    echo "System Information:"
    echo "  OS: $(lsb_release -d | cut -f2 2>/dev/null || echo "Ubuntu 24.04 LTS")"
    echo "  PHP: $(php -v | head -1 | awk '{print $2}' 2>/dev/null || echo "Not available")"
    echo "  Apache: $(apache2 -v | head -1 | awk '{print $3}' | cut -d'/' -f2 2>/dev/null || echo "Not available")"
    echo
    
    echo "=============================================================================="
    echo "NEXT STEPS: Access your WordPress site and complete the setup"
    echo "=============================================================================="
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            --dry-run)
                log_info "Dry run mode enabled (validation only)"
                validate_environment
                log_success "Environment validation passed. Ready for deployment."
                exit 0
                ;;
            --component)
                if [[ -n "${2:-}" ]]; then
                    log_info "Running single component: $2"
                    run_component "$2"
                    exit $?
                else
                    log_error "Component name required"
                    exit 1
                fi
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
}

show_help() {
    cat << EOF
$SCRIPT_NAME v$SCRIPT_VERSION

USAGE:
    $0 [OPTIONS]

DESCRIPTION:
    Complete WordPress deployment automation for $SUPPORTED_OS

OPTIONS:
    -h, --help              Show this help message
    -v, --version           Show script version
    --dry-run              Validate configuration only
    --component COMPONENT   Run specific component only

EXAMPLES:
    $0                              # Full deployment
    $0 --dry-run                   # Validate configuration only
    $0 --component system_checks   # Run system checks only

CONFIGURATION:
    Edit $SCRIPT_DIR/env before running deployment
EOF
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Parse command line arguments
    parse_arguments "$@"
    
    # Run main deployment
    main
fi