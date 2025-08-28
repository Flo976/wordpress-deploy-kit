#!/bin/bash

# vsftpd FTP Server Installation and Configuration Script
# Author: Florent Didelot  
# Description: Install and configure vsftpd with FTPS (explicit TLS) and chroot security

set -Eeuo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source functions and environment
source "$SCRIPT_DIR/functions.sh"

# Load environment variables
if [[ -f "$SCRIPT_DIR/env" ]]; then
    source "$SCRIPT_DIR/env"
else
    error_exit "Environment file not found. Please copy env.example to env and configure."
fi

# Set defaults
FTP_PORT="${FTP_PORT:-21}"
FTP_PASSIVE_MIN="${FTP_PASSIVE_MIN:-40000}"
FTP_PASSIVE_MAX="${FTP_PASSIVE_MAX:-40050}"
FTP_USER="${FTP_USER:-ftpuser}"
FTP_PASSWORD="${FTP_PASSWORD:-changeme}"
FTP_HOME="${FTP_HOME:-/var/www/html}"

# Error trap
trap 'log_error "FTP installation failed on line $LINENO"' ERR

main() {
    log_info "Starting vsftpd installation and configuration..."
    
    # Install vsftpd
    install_vsftpd
    
    # Create FTP user
    create_ftp_user
    
    # Configure vsftpd
    configure_vsftpd
    
    # Setup SSL/TLS certificates
    setup_ftp_ssl
    
    # Configure firewall
    configure_ftp_firewall
    
    # Test configuration
    test_ftp_config
    
    # Start and enable vsftpd
    enable_start_service vsftpd
    
    log_success "vsftpd installation and configuration completed successfully"
    display_ftp_summary
}

install_vsftpd() {
    log_info "Installing vsftpd FTP server..."
    
    # Update package list
    apt-get update -qq
    
    # Install vsftpd and SSL tools
    apt-get install -y vsftpd openssl
    
    # Verify installation
    if command_exists vsftpd; then
        log_success "vsftpd installed successfully"
        vsftpd -v 2>&1 | head -1 | log_info "$(cat)"
    else
        error_exit "vsftpd installation failed"
    fi
}

create_ftp_user() {
    log_info "Creating FTP user..."
    
    # Create FTP user with limited shell
    if ! id "$FTP_USER" &>/dev/null; then
        useradd -m -d "$FTP_HOME" -s /bin/false "$FTP_USER"
        log_success "Created FTP user: $FTP_USER"
    else
        log_info "FTP user already exists: $FTP_USER"
    fi
    
    # Set password
    echo "$FTP_USER:$FTP_PASSWORD" | chpasswd
    log_info "FTP user password set"
    
    # Ensure FTP home directory exists and has correct permissions
    if [[ ! -d "$FTP_HOME" ]]; then
        mkdir -p "$FTP_HOME"
    fi
    
    # Set ownership and permissions
    chown "$FTP_USER:$FTP_USER" "$FTP_HOME"
    chmod 755 "$FTP_HOME"
    
    # Create necessary directories for chroot
    local ftp_dirs=("files" "logs")
    for dir in "${ftp_dirs[@]}"; do
        mkdir -p "$FTP_HOME/$dir"
        chown "$FTP_USER:$FTP_USER" "$FTP_HOME/$dir"
    done
    
    log_info "FTP user home directory configured: $FTP_HOME"
}

configure_vsftpd() {
    log_info "Configuring vsftpd..."
    
    # Backup original configuration
    backup_file /etc/vsftpd.conf
    
    # Create new configuration
    cat > /etc/vsftpd.conf << EOF
# vsftpd Configuration for WordPress FTP Access
# Generated on $(date)

#==============================================
# Basic Settings
#==============================================

# Listen on IPv4
listen=YES
listen_ipv6=NO

# Control the default umask for local users
local_umask=022

# Allow anonymous users (NO for security)
anonymous_enable=NO

# Allow local users
local_enable=YES

# Enable write permissions
write_enable=YES

#==============================================
# Security Settings
#==============================================

# Chroot local users to their home directory
chroot_local_user=YES
chroot_list_enable=NO
allow_writeable_chroot=YES

# Hide IDs from user
hide_ids=YES

# Use local time
use_localtime=YES

# Connection control
max_clients=50
max_per_ip=5

# Timeout settings
idle_session_timeout=300
data_connection_timeout=120

#==============================================
# SSL/TLS Configuration
#==============================================

# Enable SSL
ssl_enable=${FTP_SSL_ENABLE:-YES}
allow_anon_ssl=NO
force_local_data_ssl=${FTP_FORCE_SSL:-YES}
force_local_logins_ssl=${FTP_FORCE_SSL:-YES}

# SSL versions
ssl_tlsv1=${FTP_SSL_TLSV1:-YES}
ssl_sslv2=${FTP_SSL_SSLV2:-NO}
ssl_sslv3=${FTP_SSL_SSLV3:-NO}

# SSL cipher
ssl_ciphers=HIGH

# SSL certificates
rsa_cert_file=/etc/ssl/certs/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.key

# Require SSL reuse (can cause issues with some clients)
require_ssl_reuse=NO

#==============================================
# Passive Mode Configuration
#==============================================

# Enable passive mode
pasv_enable=YES
pasv_min_port=${FTP_PASSIVE_MIN}
pasv_max_port=${FTP_PASSIVE_MAX}

# Advertise the server IP for passive connections
# Uncomment and set if behind NAT/firewall
# pasv_address=YOUR_PUBLIC_IP

#==============================================
# Logging
#==============================================

# Enable logging
xferlog_enable=YES
xferlog_std_format=YES
log_ftp_protocol=YES

# Log file location
xferlog_file=/var/log/vsftpd.log
vsftpd_log_file=/var/log/vsftpd.log

#==============================================
# Directory Listing
#==============================================

# Use ls -la style listing
ls_recurse_enable=NO
dirmessage_enable=YES

#==============================================
# Upload/Download
#==============================================

# Deny anonymous uploads
anon_upload_enable=NO
anon_mkdir_write_enable=NO

# Local user permissions
local_max_rate=0
connect_from_port_20=YES

#==============================================
# Welcome Banner
#==============================================

# Set welcome message
ftpd_banner=Bienvenue sur le serveur FTP WordPress

#==============================================
# User List (if needed)
#==============================================

# Enable user list file
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO

# TCP wrappers
tcp_wrappers=YES

#==============================================
# Additional Security
#==============================================

# Disable certain FTP commands for security
cmds_denied=SITE,MKD,RMD,DELE,RNFR,RNTO

# Port settings
listen_port=${FTP_PORT}
ftp_data_port=20

# Enable virtual users (for future enhancement)
guest_enable=NO

# File permissions
file_open_mode=0666
local_umask=022

#==============================================
# Performance Tuning
#==============================================

# One process per connection
one_process_model=NO

# Enable ASCII mode transfers
ascii_upload_enable=NO
ascii_download_enable=NO

# Optimize for performance
trans_chunk_size=8192
delay_failed_login=3
delay_successful_login=0

EOF

    # Create user list
    echo "$FTP_USER" > /etc/vsftpd.userlist
    
    # Set proper permissions
    chmod 600 /etc/vsftpd.conf
    chmod 600 /etc/vsftpd.userlist
    
    log_info "vsftpd configuration completed"
}

setup_ftp_ssl() {
    log_info "Setting up SSL/TLS certificates for FTP..."
    
    local cert_file="/etc/ssl/certs/vsftpd.pem"
    local key_file="/etc/ssl/private/vsftpd.key"
    
    # Generate self-signed certificate if it doesn't exist
    if [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]]; then
        log_info "Generating self-signed SSL certificate for FTP..."
        
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_file" \
            -out "$cert_file" \
            -subj "/C=FR/ST=France/L=Paris/O=WordPress/OU=IT/CN=${DOMAIN:-localhost}/emailAddress=${WP_ADMIN_EMAIL:-admin@localhost}"
        
        # Set proper permissions
        chmod 600 "$key_file"
        chmod 644 "$cert_file"
        
        log_success "SSL certificate generated for FTP"
    else
        log_info "SSL certificates already exist for FTP"
    fi
    
    # Verify certificate
    if openssl x509 -in "$cert_file" -text -noout >/dev/null 2>&1; then
        log_success "SSL certificate validation passed"
    else
        log_warn "SSL certificate validation failed"
    fi
}

configure_ftp_firewall() {
    if [[ "${ENABLE_UFW:-true}" == "true" ]]; then
        log_info "Configuring UFW firewall for FTP..."
        
        # Allow FTP control port
        ufw allow "$FTP_PORT/tcp" comment "FTP Control"
        
        # Allow passive ports range
        ufw allow "$FTP_PASSIVE_MIN:$FTP_PASSIVE_MAX/tcp" comment "FTP Passive"
        
        # Reload UFW
        ufw --force reload >/dev/null 2>&1 || true
        
        log_info "UFW rules added for FTP (port $FTP_PORT and passive range $FTP_PASSIVE_MIN-$FTP_PASSIVE_MAX)"
    else
        log_info "UFW firewall is disabled, skipping FTP firewall configuration"
    fi
}

test_ftp_config() {
    log_info "Testing vsftpd configuration..."
    
    # Test configuration syntax
    if vsftpd /dev/null 2>&1 | grep -q "500 OOPS"; then
        error_exit "vsftpd configuration test failed"
    fi
    
    # Start vsftpd temporarily to test
    systemctl start vsftpd >/dev/null 2>&1 || true
    
    # Wait for service to start
    sleep 2
    
    # Check if vsftpd is listening
    if port_in_use "$FTP_PORT"; then
        log_success "vsftpd is listening on port $FTP_PORT"
    else
        log_warn "vsftpd is not listening on port $FTP_PORT"
    fi
    
    # Test passive ports
    local passive_test_port=$((FTP_PASSIVE_MIN + 1))
    if [[ $FTP_PASSIVE_MIN -le 40050 ]] && [[ $FTP_PASSIVE_MAX -ge 40000 ]]; then
        log_info "Passive port range configured: $FTP_PASSIVE_MIN-$FTP_PASSIVE_MAX"
    else
        log_warn "Passive port range may be invalid"
    fi
    
    log_info "vsftpd configuration test completed"
}

create_ftp_scripts() {
    log_info "Creating FTP management scripts..."
    
    # Create FTP user management script
    cat > /usr/local/bin/ftp-user-manage << 'EOF'
#!/bin/bash
# FTP User Management Script

FTP_HOME_BASE="/var/www/html"
FTP_CONFIG="/etc/vsftpd.conf"
USER_LIST="/etc/vsftpd.userlist"

show_help() {
    echo "Usage: $0 {add|remove|list|passwd|info} [username] [password]"
    echo "  add     - Add new FTP user"
    echo "  remove  - Remove FTP user"
    echo "  list    - List FTP users"
    echo "  passwd  - Change user password"
    echo "  info    - Show user information"
}

add_user() {
    local username="$1"
    local password="$2"
    
    if [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Error: Username and password required"
        exit 1
    fi
    
    if id "$username" &>/dev/null; then
        echo "User $username already exists"
        exit 1
    fi
    
    # Create user
    useradd -m -d "$FTP_HOME_BASE" -s /bin/false "$username"
    echo "$username:$password" | chpasswd
    
    # Add to user list
    echo "$username" >> "$USER_LIST"
    
    # Set permissions
    chown "$username:$username" "$FTP_HOME_BASE"
    
    echo "FTP user $username created successfully"
}

remove_user() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        echo "Error: Username required"
        exit 1
    fi
    
    if ! id "$username" &>/dev/null; then
        echo "User $username does not exist"
        exit 1
    fi
    
    # Remove user
    userdel -r "$username" 2>/dev/null || userdel "$username"
    
    # Remove from user list
    sed -i "/^$username$/d" "$USER_LIST"
    
    echo "FTP user $username removed successfully"
}

list_users() {
    echo "FTP Users:"
    if [[ -f "$USER_LIST" ]]; then
        cat "$USER_LIST"
    else
        echo "No FTP users found"
    fi
}

change_password() {
    local username="$1"
    local password="$2"
    
    if [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Error: Username and password required"
        exit 1
    fi
    
    if ! id "$username" &>/dev/null; then
        echo "User $username does not exist"
        exit 1
    fi
    
    echo "$username:$password" | chpasswd
    echo "Password changed for user $username"
}

user_info() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        echo "Error: Username required"
        exit 1
    fi
    
    if ! id "$username" &>/dev/null; then
        echo "User $username does not exist"
        exit 1
    fi
    
    echo "User Information for $username:"
    id "$username"
    echo "Home directory: $(getent passwd "$username" | cut -d: -f6)"
    echo "Shell: $(getent passwd "$username" | cut -d: -f7)"
}

case "${1:-help}" in
    "add")
        add_user "$2" "$3"
        ;;
    "remove")
        remove_user "$2"
        ;;
    "list")
        list_users
        ;;
    "passwd")
        change_password "$2" "$3"
        ;;
    "info")
        user_info "$2"
        ;;
    *)
        show_help
        ;;
esac
EOF
    
    # Create FTP status script
    cat > /usr/local/bin/ftp-status << EOF
#!/bin/bash
# FTP Status Script

echo "=== vsftpd Status ==="
systemctl status vsftpd --no-pager

echo -e "\n=== FTP Configuration ==="
echo "FTP Port: $(grep "^listen_port" /etc/vsftpd.conf | cut -d= -f2 || echo "$FTP_PORT")"
echo "Passive Range: $FTP_PASSIVE_MIN-$FTP_PASSIVE_MAX"
echo "SSL Enabled: $(grep "^ssl_enable" /etc/vsftpd.conf | cut -d= -f2 || echo "Unknown")"

echo -e "\n=== Active Connections ==="
netstat -tan | grep ":$FTP_PORT " || echo "No active FTP connections"

echo -e "\n=== FTP Users ==="
if [[ -f /etc/vsftpd.userlist ]]; then
    cat /etc/vsftpd.userlist
else
    echo "No FTP users configured"
fi

echo -e "\n=== Recent FTP Activity ==="
if [[ -f /var/log/vsftpd.log ]]; then
    tail -10 /var/log/vsftpd.log
else
    echo "No FTP log found"
fi

echo -e "\n=== Firewall Status ==="
if command -v ufw >/dev/null 2>&1; then
    ufw status | grep -E "(${FTP_PORT}|${FTP_PASSIVE_MIN}:${FTP_PASSIVE_MAX})" || echo "No FTP rules found in UFW"
else
    echo "UFW not installed"
fi
EOF
    
    # Make scripts executable
    chmod +x /usr/local/bin/ftp-user-manage
    chmod +x /usr/local/bin/ftp-status
    
    log_info "FTP management scripts created"
}

setup_ftp_logging() {
    log_info "Setting up FTP logging..."
    
    # Create log directory
    create_dir "/var/log/ftp" "root:adm" "755"
    
    # Configure logrotate for vsftpd
    cat > /etc/logrotate.d/vsftpd << EOF
/var/log/vsftpd.log {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    copytruncate
    create 640 root adm
}

/var/log/ftp/*.log {
    weekly
    missingok
    rotate 12
    compress
    delaycompress
    notifempty
    copytruncate
    create 640 root adm
}
EOF
    
    # Ensure log files exist with proper permissions
    touch /var/log/vsftpd.log
    chmod 640 /var/log/vsftpd.log
    chown root:adm /var/log/vsftpd.log
    
    log_info "FTP logging configured"
}

display_ftp_summary() {
    log_info "FTP installation summary:"
    
    echo "=================================="
    echo "vsftpd FTP Server Configuration"
    echo "=================================="
    echo "FTP Server: vsftpd"
    echo "FTP Port: $FTP_PORT"
    echo "Passive Ports: $FTP_PASSIVE_MIN-$FTP_PASSIVE_MAX"
    echo "SSL/TLS: Enabled (explicit FTPS)"
    echo "FTP User: $FTP_USER"
    echo "FTP Home: $FTP_HOME"
    echo "Chroot: Enabled (users locked to home directory)"
    echo "=================================="
    echo
    echo "FTP Connection Details:"
    echo "- Host: ${DOMAIN:-localhost}"
    echo "- Port: $FTP_PORT"
    echo "- Username: $FTP_USER"
    echo "- Protocol: FTPS (explicit TLS)"
    echo "- Mode: Passive"
    echo
    echo "Management Commands:"
    echo "- ftp-user-manage  : Manage FTP users"
    echo "- ftp-status       : Check FTP server status"
    echo
    echo "Security Notes:"
    echo "- SSL/TLS encryption is enforced"
    echo "- Users are chrooted to their home directory"
    echo "- Passive mode ports are restricted"
    echo "- Anonymous access is disabled"
    echo "=================================="
}

# Run FTP installation with options
case "${1:-all}" in
    "install")
        install_vsftpd
        ;;
    "user")
        create_ftp_user
        ;;
    "config")
        configure_vsftpd
        ;;
    "ssl")
        setup_ftp_ssl
        ;;
    "firewall")
        configure_ftp_firewall
        ;;
    "scripts")
        create_ftp_scripts
        ;;
    "logging")
        setup_ftp_logging
        ;;
    "test")
        test_ftp_config
        ;;
    "status")
        /usr/local/bin/ftp-status 2>/dev/null || echo "FTP status script not available"
        ;;
    "all")
        main
        create_ftp_scripts
        setup_ftp_logging
        ;;
    *)
        echo "Usage: $0 [install|user|config|ssl|firewall|scripts|logging|test|status|all]"
        echo "  install   - Install vsftpd"
        echo "  user      - Create FTP user"
        echo "  config    - Configure vsftpd"
        echo "  ssl       - Setup SSL certificates"
        echo "  firewall  - Configure firewall rules"
        echo "  scripts   - Create management scripts"
        echo "  logging   - Setup logging"
        echo "  test      - Test configuration"
        echo "  status    - Show FTP status"
        echo "  all       - Run complete installation (default)"
        exit 1
        ;;
esac