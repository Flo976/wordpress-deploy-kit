#!/bin/bash

# Utility functions for WordPress deployment
# Author: Florent Didelot
# Description: Common functions for logging, retries, configuration editing, etc.

set -Eeuo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Log functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

# Error handling
error_exit() {
    log_error "$1"
    exit "${2:-1}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

# Check OS compatibility
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error_exit "Cannot determine OS version"
    fi
    
    . /etc/os-release
    
    if [[ "$ID" != "ubuntu" ]] || [[ "$VERSION_ID" != "24.04" ]]; then
        error_exit "This script only supports Ubuntu 24.04 LTS (detected: $PRETTY_NAME)"
    fi
    
    log_info "OS check passed: $PRETTY_NAME"
}

# Retry function for commands that might fail temporarily
retry() {
    local retries=$1
    shift
    local count=0
    
    until "$@"; do
        exit_code=$?
        count=$((count + 1))
        if [[ $count -lt $retries ]]; then
            log_warn "Command failed (attempt $count/$retries). Retrying in 5 seconds..."
            sleep 5
        else
            log_error "Command failed after $retries attempts"
            return $exit_code
        fi
    done
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if service is running
service_is_active() {
    systemctl is-active --quiet "$1"
}

# Check if service is enabled
service_is_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

# Enable and start service
enable_start_service() {
    local service_name="$1"
    log_info "Enabling and starting $service_name..."
    systemctl enable --now "$service_name"
    
    if service_is_active "$service_name"; then
        log_success "$service_name is running"
    else
        error_exit "Failed to start $service_name"
    fi
}

# Restart service if running
restart_service() {
    local service_name="$1"
    if service_is_active "$service_name"; then
        log_info "Restarting $service_name..."
        systemctl restart "$service_name"
        
        if service_is_active "$service_name"; then
            log_success "$service_name restarted successfully"
        else
            error_exit "Failed to restart $service_name"
        fi
    else
        log_warn "$service_name is not running, starting it..."
        enable_start_service "$service_name"
    fi
}

# Safe INI file editing
ini_set() {
    local file="$1"
    local section="$2"
    local key="$3"
    local value="$4"
    local backup_suffix="${5:-bak}"
    
    if [[ ! -f "$file" ]]; then
        error_exit "File $file does not exist"
    fi
    
    # Create backup
    cp "$file" "$file.$backup_suffix"
    
    # Use crudini if available, otherwise use sed
    if command_exists crudini; then
        crudini --set "$file" "$section" "$key" "$value"
    else
        # Fallback to sed (basic implementation)
        local temp_file
        temp_file=$(mktemp)
        
        if [[ -n "$section" ]]; then
            # With section
            awk -v section="[$section]" -v key="$key" -v value="$value" '
            BEGIN { in_section = 0; found = 0 }
            /^\[.*\]$/ { 
                if (in_section && !found) {
                    print key "=" value
                    found = 1
                }
                in_section = ($0 == section) ? 1 : 0
            }
            in_section && /^'$key'\s*=/ { 
                print key "=" value
                found = 1
                next
            }
            { print }
            END { 
                if (in_section && !found) {
                    print key "=" value
                }
            }
            ' "$file" > "$temp_file"
        else
            # Without section (simple key=value)
            if grep -q "^$key\s*=" "$file"; then
                sed "s|^$key\s*=.*|$key=$value|" "$file" > "$temp_file"
            else
                echo "$key=$value" >> "$file"
                cp "$file" "$temp_file"
            fi
        fi
        
        mv "$temp_file" "$file"
    fi
    
    log_info "Updated $file: [$section] $key = $value"
}

# Safe sysctl editing
sysctl_set() {
    local key="$1"
    local value="$2"
    local config_file="${3:-/etc/sysctl.d/99-wordpress.conf}"
    
    # Set immediately
    sysctl -w "$key=$value" >/dev/null
    
    # Persist in config file
    if [[ -f "$config_file" ]]; then
        if grep -q "^$key\s*=" "$config_file"; then
            sed -i "s|^$key\s*=.*|$key=$value|" "$config_file"
        else
            echo "$key=$value" >> "$config_file"
        fi
    else
        echo "$key=$value" > "$config_file"
    fi
    
    log_info "Set sysctl: $key = $value"
}

# Create user if not exists
create_user() {
    local username="$1"
    local home_dir="$2"
    local shell="${3:-/bin/bash}"
    local create_home="${4:-yes}"
    
    if id "$username" &>/dev/null; then
        log_info "User $username already exists"
        return 0
    fi
    
    local user_opts=("-r" "-s" "$shell")
    if [[ "$create_home" == "yes" ]]; then
        user_opts+=("-m" "-d" "$home_dir")
    else
        user_opts+=("-M")
    fi
    
    useradd "${user_opts[@]}" "$username"
    log_success "Created user: $username"
}

# Generate random password
generate_password() {
    local length="${1:-16}"
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

# Generate WordPress salts
generate_wp_salts() {
    curl -s https://api.wordpress.org/secret-key/1.1/salt/ | sed 's/define(/define(/g'
}

# Check if port is in use
port_in_use() {
    local port="$1"
    netstat -ln | grep -q ":$port "
}

# Wait for service to be ready
wait_for_service() {
    local service="$1"
    local port="$2"
    local timeout="${3:-30}"
    local count=0
    
    log_info "Waiting for $service to be ready on port $port..."
    
    while [[ $count -lt $timeout ]]; do
        if port_in_use "$port"; then
            log_success "$service is ready"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    error_exit "$service did not start within $timeout seconds"
}

# Create directory with proper ownership
create_dir() {
    local dir_path="$1"
    local owner="${2:-root:root}"
    local permissions="${3:-755}"
    
    if [[ ! -d "$dir_path" ]]; then
        mkdir -p "$dir_path"
        chown "$owner" "$dir_path"
        chmod "$permissions" "$dir_path"
        log_info "Created directory: $dir_path ($owner:$permissions)"
    fi
}

# Download file with retry
download_file() {
    local url="$1"
    local destination="$2"
    local retries="${3:-3}"
    
    log_info "Downloading $url to $destination..."
    
    if retry "$retries" wget --no-check-certificate -O "$destination" "$url"; then
        log_success "Downloaded $url"
    else
        error_exit "Failed to download $url after $retries attempts"
    fi
}

# Check system resources
check_system_resources() {
    local min_ram_gb="${1:-2}"
    local min_disk_gb="${2:-10}"
    
    # Check RAM
    local ram_gb
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $ram_gb -lt $min_ram_gb ]]; then
        log_warn "System has ${ram_gb}GB RAM (minimum recommended: ${min_ram_gb}GB)"
    else
        log_info "RAM check passed: ${ram_gb}GB available"
    fi
    
    # Check disk space
    local disk_gb
    disk_gb=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
    if [[ $disk_gb -lt $min_disk_gb ]]; then
        log_warn "System has ${disk_gb}GB free disk space (minimum recommended: ${min_disk_gb}GB)"
    else
        log_info "Disk space check passed: ${disk_gb}GB available"
    fi
}

# Backup file with timestamp
backup_file() {
    local file_path="$1"
    local backup_dir="${2:-$(dirname "$file_path")}"
    
    if [[ -f "$file_path" ]]; then
        local filename
        filename=$(basename "$file_path")
        local timestamp
        timestamp=$(date +%Y%m%d_%H%M%S)
        local backup_path="$backup_dir/${filename}.backup.$timestamp"
        
        cp "$file_path" "$backup_path"
        log_info "Backed up $file_path to $backup_path"
    fi
}

# Test HTTP response
test_http_response() {
    local url="$1"
    local expected_code="${2:-200}"
    local timeout="${3:-10}"
    
    local response_code
    response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url" 2>/dev/null || echo "000")
    
    if [[ "$response_code" == "$expected_code" ]]; then
        log_success "HTTP test passed: $url returned $response_code"
        return 0
    else
        log_error "HTTP test failed: $url returned $response_code (expected $expected_code)"
        return 1
    fi
}

# Export all functions
export -f log_info log_warn log_error log_success error_exit
export -f check_root check_os retry command_exists
export -f service_is_active service_is_enabled enable_start_service restart_service
export -f ini_set sysctl_set create_user generate_password generate_wp_salts
export -f port_in_use wait_for_service create_dir download_file
export -f check_system_resources backup_file test_http_response