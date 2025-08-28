#!/bin/bash

# System Prerequisites and Health Checks
# Author: Florent Didelot
# Description: Validates system requirements and performs health checks

set -Eeuo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source functions and environment
source "$SCRIPT_DIR/functions.sh"

# Load environment variables
if [[ -f "$SCRIPT_DIR/env" ]]; then
    source "$SCRIPT_DIR/env"
else
    log_warn "Environment file not found, using defaults"
fi

# Error trap
trap 'log_error "System checks failed on line $LINENO"' ERR

main() {
    log_info "Starting system prerequisites and health checks..."
    
    # Basic system checks
    check_os
    check_root
    check_system_resources 2 10
    
    # Network checks
    check_network_connectivity
    check_required_ports
    
    # Software requirements
    check_required_packages
    check_package_repositories
    
    # System configuration
    check_system_limits
    check_filesystem_permissions
    
    # Service checks (if services are installed)
    check_services_health
    
    # Performance checks
    check_system_performance
    
    # Security checks
    check_security_configuration
    
    log_success "System checks completed successfully"
    return 0
}

check_network_connectivity() {
    log_info "Checking network connectivity..."
    
    # Test internet connectivity
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_warn "No internet connectivity detected"
    else
        log_info "Internet connectivity: OK"
    fi
    
    # Test DNS resolution
    if ! nslookup wordpress.org >/dev/null 2>&1; then
        log_warn "DNS resolution issues detected"
    else
        log_info "DNS resolution: OK"
    fi
    
    # Check if we can reach package repositories
    if ! wget --spider --quiet --timeout=10 http://archive.ubuntu.com/ubuntu/ 2>/dev/null; then
        log_warn "Cannot reach Ubuntu package repositories"
    else
        log_info "Package repositories: accessible"
    fi
}

check_required_ports() {
    log_info "Checking port availability..."
    
    local ports_to_check=(
        "${HTTP_PORT:-80}"
        "${HTTPS_PORT:-443}"
        "${FTP_PORT:-21}"
        "3306"  # MySQL/MariaDB
    )
    
    for port in "${ports_to_check[@]}"; do
        if port_in_use "$port"; then
            log_warn "Port $port is already in use"
            netstat -tlnp | grep ":$port " | head -1 | log_info "Port $port usage: $(cat)"
        else
            log_info "Port $port: available"
        fi
    done
    
    # Check FTP passive port range
    local passive_min="${FTP_PASSIVE_MIN:-40000}"
    local passive_max="${FTP_PASSIVE_MAX:-40050}"
    local in_use_count=0
    
    for ((port=passive_min; port<=passive_max; port++)); do
        if port_in_use "$port"; then
            ((in_use_count++))
        fi
    done
    
    if [[ $in_use_count -gt 0 ]]; then
        log_warn "$in_use_count ports in FTP passive range ($passive_min-$passive_max) are in use"
    else
        log_info "FTP passive port range ($passive_min-$passive_max): available"
    fi
}

check_required_packages() {
    log_info "Checking for required system packages..."
    
    local required_packages=(
        "curl"
        "wget"
        "unzip"
        "software-properties-common"
        "apt-transport-https"
        "ca-certificates"
        "gnupg"
        "lsb-release"
        "openssl"
        "net-tools"
        "crudini"
    )
    
    local missing_packages=()
    
    for package in "${required_packages[@]}"; do
        if ! dpkg -l "$package" >/dev/null 2>&1; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_info "Missing packages will be installed: ${missing_packages[*]}"
        apt-get update -qq
        apt-get install -y "${missing_packages[@]}"
    else
        log_info "All required packages are installed"
    fi
}

check_package_repositories() {
    log_info "Checking package repository configuration..."
    
    # Check if we have universe repository enabled
    if ! grep -q "universe" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
        log_info "Enabling universe repository..."
        add-apt-repository universe -y
    fi
    
    # Update package lists
    log_info "Updating package lists..."
    apt-get update -qq
    
    log_info "Package repositories: configured"
}

check_system_limits() {
    log_info "Checking system limits..."
    
    # Check open files limit
    local open_files_limit
    open_files_limit=$(ulimit -n)
    if [[ $open_files_limit -lt 65536 ]]; then
        log_warn "Open files limit is $open_files_limit (recommended: >= 65536)"
    else
        log_info "Open files limit: $open_files_limit (OK)"
    fi
    
    # Check max processes
    local max_processes
    max_processes=$(ulimit -u)
    if [[ $max_processes -lt 32768 ]]; then
        log_warn "Max processes limit is $max_processes (recommended: >= 32768)"
    else
        log_info "Max processes limit: $max_processes (OK)"
    fi
    
    # Check shared memory
    local shmmax
    shmmax=$(cat /proc/sys/kernel/shmmax 2>/dev/null || echo 0)
    if [[ $shmmax -lt 134217728 ]]; then  # 128MB
        log_warn "Shared memory max is $(($shmmax / 1024 / 1024))MB (recommended: >= 128MB)"
    fi
}

check_filesystem_permissions() {
    log_info "Checking filesystem permissions..."
    
    # Check /tmp permissions
    local tmp_perms
    tmp_perms=$(stat -c %a /tmp)
    if [[ "$tmp_perms" != "1777" ]]; then
        log_warn "/tmp permissions are $tmp_perms (should be 1777)"
    else
        log_info "/tmp permissions: OK"
    fi
    
    # Check if /var/www exists and is writable
    if [[ ! -d /var/www ]]; then
        log_info "Creating /var/www directory..."
        mkdir -p /var/www
        chown root:root /var/www
        chmod 755 /var/www
    fi
    
    # Check disk space on /var
    local var_space_gb
    var_space_gb=$(df /var | awk 'NR==2 {print int($4/1024/1024)}')
    if [[ $var_space_gb -lt 5 ]]; then
        log_warn "/var partition has only ${var_space_gb}GB free space (recommended: >= 5GB)"
    else
        log_info "/var partition free space: ${var_space_gb}GB (OK)"
    fi
}

check_services_health() {
    log_info "Checking services health..."
    
    local services_to_check=("apache2" "mysql" "mariadb" "php${PHP_VERSION:-8.4}-fpm" "vsftpd" "ufw")
    
    for service in "${services_to_check[@]}"; do
        if systemctl list-unit-files "$service.service" >/dev/null 2>&1; then
            if service_is_active "$service"; then
                log_info "$service: running"
            else
                log_warn "$service: installed but not running"
            fi
            
            if service_is_enabled "$service"; then
                log_info "$service: enabled"
            else
                log_warn "$service: not enabled for startup"
            fi
        fi
    done
}

check_system_performance() {
    log_info "Checking system performance indicators..."
    
    # CPU information
    local cpu_count
    cpu_count=$(nproc)
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{ print $2 }' | awk '{ print $1 }' | sed 's/,//')
    
    log_info "CPU cores: $cpu_count"
    log_info "Current load average: $load_avg"
    
    if (( $(echo "$load_avg > $cpu_count" | bc -l) )); then
        log_warn "High system load detected (load: $load_avg, cores: $cpu_count)"
    fi
    
    # Memory usage
    local mem_usage
    mem_usage=$(free | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
    log_info "Memory usage: $mem_usage"
    
    # Disk I/O check
    if command_exists iostat; then
        log_info "Disk I/O statistics available"
        iostat -x 1 1 | tail -n +4 | grep -v "^$" | log_info "$(cat)"
    fi
    
    # Check for swap usage
    local swap_used
    swap_used=$(free | awk 'NR==3{print $3}')
    if [[ $swap_used -gt 0 ]]; then
        log_warn "Swap is being used: $(($swap_used / 1024))MB"
    fi
}

check_security_configuration() {
    log_info "Checking security configuration..."
    
    # Check if running latest kernel
    local current_kernel
    current_kernel=$(uname -r)
    local available_kernel
    available_kernel=$(apt list --installed linux-image-generic 2>/dev/null | grep -v "WARNING" | tail -n +2 | awk '{print $2}' || echo "unknown")
    
    log_info "Current kernel: $current_kernel"
    
    # Check for available security updates
    local security_updates
    security_updates=$(apt list --upgradable 2>/dev/null | grep -c "ubuntu.*security" || echo 0)
    if [[ $security_updates -gt 0 ]]; then
        log_warn "$security_updates security updates available"
    else
        log_info "Security updates: up to date"
    fi
    
    # Check SSH configuration
    if [[ -f /etc/ssh/sshd_config ]]; then
        if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
            log_warn "SSH root login is enabled (security risk)"
        fi
        
        if ! grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
            log_warn "SSH password authentication is enabled (consider using key-based auth)"
        fi
    fi
    
    # Check for automatic updates
    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
        log_info "Automatic security updates: configured"
    else
        log_warn "Automatic security updates: not configured"
    fi
}

# Version checking functions
check_installed_versions() {
    log_info "Checking installed software versions..."
    
    # Apache version
    if command_exists apache2; then
        local apache_version
        apache_version=$(apache2 -v | head -1 | awk '{print $3}' | cut -d'/' -f2)
        log_info "Apache version: $apache_version"
    fi
    
    # PHP version
    if command_exists php; then
        local php_version
        php_version=$(php -v | head -1 | awk '{print $2}')
        log_info "PHP version: $php_version"
    fi
    
    # MariaDB/MySQL version
    if command_exists mysql; then
        local mysql_version
        mysql_version=$(mysql --version | awk '{print $5}' | sed 's/,//')
        log_info "MySQL/MariaDB version: $mysql_version"
    fi
    
    # Check PHP modules
    if command_exists php; then
        local required_php_modules=(
            "mysqli"
            "mbstring"
            "xml"
            "gd"
            "curl"
            "zip"
            "opcache"
            "json"
            "fileinfo"
            "openssl"
        )
        
        log_info "Checking PHP modules..."
        for module in "${required_php_modules[@]}"; do
            if php -m | grep -q "$module"; then
                log_info "PHP module $module: installed"
            else
                log_warn "PHP module $module: missing"
            fi
        done
    fi
}

# WordPress specific checks
check_wordpress_requirements() {
    if [[ -f /var/www/html/wp-config.php ]]; then
        log_info "Checking WordPress installation..."
        
        # Check WordPress core files
        local wp_files=("wp-config.php" "wp-load.php" "wp-settings.php" "index.php")
        for file in "${wp_files[@]}"; do
            if [[ -f "/var/www/html/$file" ]]; then
                log_info "WordPress file $file: present"
            else
                log_warn "WordPress file $file: missing"
            fi
        done
        
        # Check WordPress permissions
        local wp_perms
        wp_perms=$(stat -c %U:%G /var/www/html/wp-config.php)
        if [[ "$wp_perms" == "www-data:www-data" ]]; then
            log_info "WordPress file ownership: correct ($wp_perms)"
        else
            log_warn "WordPress file ownership: $wp_perms (should be www-data:www-data)"
        fi
        
        # Test WordPress installation if wp-cli is available
        if command_exists wp && [[ -d /var/www/html ]]; then
            cd /var/www/html
            if sudo -u www-data wp core is-installed 2>/dev/null; then
                log_info "WordPress: properly installed"
                local wp_version
                wp_version=$(sudo -u www-data wp core version 2>/dev/null || echo "unknown")
                log_info "WordPress version: $wp_version"
            else
                log_warn "WordPress: installation incomplete or corrupted"
            fi
        fi
    else
        log_info "WordPress not yet installed"
    fi
}

# Network security checks
check_firewall_status() {
    log_info "Checking firewall configuration..."
    
    if command_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status | head -1 | awk '{print $2}')
        log_info "UFW firewall: $ufw_status"
        
        if [[ "$ufw_status" == "active" ]]; then
            log_info "UFW rules:"
            ufw status numbered | grep -E "^\[ *[0-9]" | while read -r rule; do
                log_info "  $rule"
            done
        fi
    else
        log_warn "UFW firewall not installed"
    fi
    
    # Check for other firewalls
    if systemctl is-active --quiet iptables 2>/dev/null; then
        log_info "iptables service: active"
    fi
}

# Generate system report
generate_system_report() {
    log_info "Generating system report..."
    
    local report_file="/tmp/wordpress_system_report.txt"
    
    {
        echo "WordPress Deployment System Report"
        echo "Generated: $(date)"
        echo "=================================="
        echo
        
        echo "SYSTEM INFORMATION:"
        echo "OS: $(lsb_release -d | cut -f2)"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo "Hostname: $(hostname)"
        echo "Uptime: $(uptime)"
        echo
        
        echo "HARDWARE INFORMATION:"
        echo "CPU: $(nproc) cores"
        echo "Memory: $(free -h | awk 'NR==2{print $2}' | sed 's/i//')"
        echo "Disk: $(df -h / | awk 'NR==2{print $2}' | sed 's/G.*/GB/')"
        echo
        
        echo "NETWORK INFORMATION:"
        echo "IP Address: $(hostname -I | awk '{print $1}')"
        echo "Default Gateway: $(ip route | grep default | awk '{print $3}' | head -1)"
        echo
        
        echo "SERVICES STATUS:"
        systemctl status apache2 --no-pager -l 2>/dev/null | grep -E "(Active|Main PID)" || echo "Apache2: not installed"
        systemctl status mysql mariadb --no-pager -l 2>/dev/null | grep -E "(Active|Main PID)" || echo "MySQL/MariaDB: not installed"
        systemctl status php*-fpm --no-pager -l 2>/dev/null | grep -E "(Active|Main PID)" || echo "PHP-FPM: not installed"
        systemctl status vsftpd --no-pager -l 2>/dev/null | grep -E "(Active|Main PID)" || echo "vsftpd: not installed"
        echo
        
        echo "OPEN PORTS:"
        netstat -tlnp | grep LISTEN
        echo
        
    } > "$report_file"
    
    log_info "System report saved to: $report_file"
    echo "System report location: $report_file"
}

# Run health checks with options
case "${1:-all}" in
    "basic")
        check_os
        check_root
        check_system_resources
        ;;
    "network")
        check_network_connectivity
        check_required_ports
        ;;
    "services")
        check_services_health
        check_installed_versions
        ;;
    "security")
        check_security_configuration
        check_firewall_status
        ;;
    "wordpress")
        check_wordpress_requirements
        ;;
    "report")
        generate_system_report
        ;;
    "all")
        main
        check_installed_versions
        check_wordpress_requirements
        check_firewall_status
        generate_system_report
        ;;
    *)
        echo "Usage: $0 [basic|network|services|security|wordpress|report|all]"
        echo "  basic     - Basic system checks"
        echo "  network   - Network connectivity checks"
        echo "  services  - Service health checks"
        echo "  security  - Security configuration checks"
        echo "  wordpress - WordPress specific checks"
        echo "  report    - Generate system report"
        echo "  all       - Run all checks (default)"
        exit 1
        ;;
esac