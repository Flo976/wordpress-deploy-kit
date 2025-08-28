#!/bin/bash

# System Security Hardening Script
# Author: Florent Didelot
# Description: Comprehensive security hardening for WordPress server (UFW, fail2ban, file permissions, etc.)

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
ENABLE_UFW="${ENABLE_UFW:-true}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-false}"
FAIL2BAN_MAX_RETRY="${FAIL2BAN_MAX_RETRY:-5}"
FAIL2BAN_FIND_TIME="${FAIL2BAN_FIND_TIME:-600}"
FAIL2BAN_BAN_TIME="${FAIL2BAN_BAN_TIME:-3600}"
WP_DIR="${WP_DIR:-/var/www/html}"

# Error trap
trap 'log_error "Security hardening failed on line $LINENO"' ERR

main() {
    log_info "Starting comprehensive security hardening..."
    
    # System-level hardening
    configure_system_hardening
    
    # UFW Firewall setup
    if [[ "$ENABLE_UFW" == "true" ]]; then
        setup_ufw_firewall
    fi
    
    # fail2ban setup
    if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
        setup_fail2ban
    fi
    
    # SSH hardening
    harden_ssh_configuration
    
    # WordPress specific hardening
    harden_wordpress_installation
    
    # File permissions and ownership
    secure_file_permissions
    
    # System updates and security
    configure_automatic_updates
    
    # Disable unnecessary services
    disable_unnecessary_services
    
    # Network security
    configure_network_security
    
    # Log monitoring and rotation
    configure_security_logging
    
    # Create security monitoring
    setup_security_monitoring
    
    log_success "Security hardening completed successfully"
    display_security_summary
}

configure_system_hardening() {
    log_info "Configuring system-level security hardening..."
    
    # Kernel parameters for security
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Security-focused kernel parameters

# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# TCP hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# File system security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Process security
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-security.conf >/dev/null 2>&1
    
    # Configure limits
    cat > /etc/security/limits.d/99-security.conf << 'EOF'
# Security limits configuration

# Prevent fork bombs
*    hard    nproc     32768
*    soft    nproc     16384

# File limits
*    hard    nofile    65536
*    soft    nofile    32768

# Memory limits
*    hard    memlock   unlimited
*    soft    memlock   unlimited

# Core dump restrictions
*    hard    core      0
*    soft    core      0
EOF
    
    # Disable core dumps globally
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    
    # Secure shared memory
    if ! grep -q "tmpfs /run/shm" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi
    
    log_info "System hardening configuration applied"
}

setup_ufw_firewall() {
    log_info "Setting up UFW firewall..."
    
    # Install UFW if not present
    if ! command_exists ufw; then
        apt-get update -qq
        apt-get install -y ufw
    fi
    
    # Reset UFW to defaults
    ufw --force reset >/dev/null
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (be careful not to lock ourselves out)
    ufw allow 22/tcp comment "SSH"
    
    # Allow HTTP and HTTPS
    ufw allow "${HTTP_PORT:-80}/tcp" comment "HTTP"
    ufw allow "${HTTPS_PORT:-443}/tcp" comment "HTTPS"
    
    # Allow FTP if enabled
    if [[ "${FTP_PORT:-}" ]]; then
        ufw allow "${FTP_PORT}/tcp" comment "FTP Control"
        
        # Allow FTP passive ports if defined
        if [[ "${FTP_PASSIVE_MIN:-}" ]] && [[ "${FTP_PASSIVE_MAX:-}" ]]; then
            ufw allow "${FTP_PASSIVE_MIN}:${FTP_PASSIVE_MAX}/tcp" comment "FTP Passive"
        fi
    fi
    
    # Allow MySQL/MariaDB only from localhost
    ufw allow from 127.0.0.1 to any port 3306 comment "MySQL Local"
    
    # Rate limiting for SSH
    ufw limit 22/tcp comment "SSH Rate Limit"
    
    # Custom UFW rules for common attacks
    cat > /etc/ufw/before.rules.custom << 'EOF'
# Custom UFW rules for security

# Drop invalid packets
-A ufw-before-input -m state --state INVALID -j DROP

# Allow ping but limit it
-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 1/sec -j ACCEPT

# Drop excessive RST packets
-A ufw-before-input -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT
-A ufw-before-input -p tcp --tcp-flags RST RST -j DROP
EOF
    
    # Enable UFW
    ufw --force enable
    
    # Verify UFW status
    if ufw status | grep -q "Status: active"; then
        log_success "UFW firewall configured and enabled"
        ufw status numbered | log_info "UFW rules: $(cat)"
    else
        log_warn "UFW firewall setup may have issues"
    fi
}

setup_fail2ban() {
    log_info "Setting up fail2ban intrusion prevention..."
    
    # Install fail2ban
    if ! command_exists fail2ban-server; then
        apt-get update -qq
        apt-get install -y fail2ban
    fi
    
    # Create custom jail configuration
    cat > /etc/fail2ban/jail.local << EOF
# fail2ban local configuration

[DEFAULT]
# Ban settings
bantime = ${FAIL2BAN_BAN_TIME}
findtime = ${FAIL2BAN_FIND_TIME}
maxretry = ${FAIL2BAN_MAX_RETRY}
backend = auto

# Email settings (configure if needed)
# destemail = admin@${DOMAIN}
# sendername = fail2ban
# mta = sendmail

# Action shortcuts
banaction = ufw
action = %(action_)s

# Ignore local IPs
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8

[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache2/access.log
maxretry = 2

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache2/access.log
maxretry = 6

[apache-overflows]
enabled = true
port = http,https
filter = apache-overflows
logpath = /var/log/apache2/access.log
maxretry = 2

[apache-nohome]
enabled = true
port = http,https
filter = apache-nohome
logpath = /var/log/apache2/access.log
maxretry = 2

[wordpress]
enabled = true
port = http,https
filter = wordpress
logpath = /var/log/apache2/access.log
maxretry = 3

[vsftpd]
enabled = $([ "${FTP_PORT:-}" ] && echo "true" || echo "false")
port = ftp,ftp-data,ftps,ftps-data
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = 3
EOF
    
    # Create WordPress filter
    cat > /etc/fail2ban/filter.d/wordpress.conf << 'EOF'
# WordPress fail2ban filter

[Definition]

# WordPress login failures
failregex = <HOST>.*POST.*(wp-login\.php|xmlrpc\.php).* 200
            <HOST>.*POST.*wp-login\.php.* 403
            <HOST>.*POST.*wp-admin.* 403
            <HOST>.*wp-login\.php.*Failed login

# WordPress brute force attempts
            <HOST>.*"POST \/wp-login\.php
            <HOST>.*"POST \/wp-admin
            <HOST>.*"POST \/xmlrpc\.php

ignoreregex =
EOF
    
    # Create custom Apache filters for enhanced security
    cat > /etc/fail2ban/filter.d/apache-badbots.conf << 'EOF'
# Bad bots filter
[Definition]
failregex = <HOST> -.*"(GET|POST).*HTTP.*" (404|403) .*
            <HOST> -.*".*User-Agent: .*bot.*".*
ignoreregex =
EOF
    
    cat > /etc/fail2ban/filter.d/apache-noscript.conf << 'EOF'
# NoScript filter
[Definition]
failregex = <HOST> -.*"(GET|POST).*(\.php|\.asp|\.exe|\.pl|\.cgi|\.scr).*HTTP.*" 404 .*
ignoreregex =
EOF
    
    # Enable and start fail2ban
    enable_start_service fail2ban
    
    # Test fail2ban configuration
    if fail2ban-client status >/dev/null 2>&1; then
        log_success "fail2ban configured successfully"
        fail2ban-client status | log_info "fail2ban status: $(cat)"
    else
        log_warn "fail2ban configuration may have issues"
    fi
}

harden_ssh_configuration() {
    log_info "Hardening SSH configuration..."
    
    # Backup original SSH config
    backup_file /etc/ssh/sshd_config
    
    # Create hardened SSH configuration
    cat > /etc/ssh/sshd_config << 'EOF'
# Hardened SSH Configuration

# Basic settings
Port 22
Protocol 2
ListenAddress 0.0.0.0

# Authentication settings
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
MaxStartups 2

# Password authentication (disable for key-only auth)
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Kerberos and GSSAPI
KerberosAuthentication no
GSSAPIAuthentication no

# Public key authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Host-based authentication
HostbasedAuthentication no
IgnoreUserKnownHosts yes
IgnoreRhosts yes

# Security settings
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd yes
PrintLastLog yes
TCPKeepAlive yes
UsePrivilegeSeparation yes

# Logging
SyslogFacility AUTHPRIV
LogLevel VERBOSE

# Connection settings
ClientAliveInterval 300
ClientAliveCountMax 0

# Disable unused features
GatewayPorts no
PermitTunnel no
Banner /etc/issue.net

# Modern ciphers only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Subsystems
Subsystem sftp /usr/lib/openssh/sftp-server -f AUTHPRIV -l INFO
EOF
    
    # Create SSH banner
    cat > /etc/issue.net << 'EOF'
***************************************************************************
                            AUTHORIZED ACCESS ONLY
    
    This system is for authorized users only. All activities on this
    system are logged and monitored. Unauthorized access is prohibited
    and may result in criminal prosecution.
    
***************************************************************************
EOF
    
    # Test SSH configuration
    if sshd -t; then
        log_success "SSH configuration is valid"
        restart_service ssh
    else
        log_warn "SSH configuration test failed - restoring backup"
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        restart_service ssh
    fi
    
    log_info "SSH hardening completed"
}

harden_wordpress_installation() {
    log_info "Hardening WordPress installation..."
    
    if [[ ! -d "$WP_DIR" ]]; then
        log_warn "WordPress directory not found, skipping WordPress hardening"
        return 0
    fi
    
    cd "$WP_DIR"
    
    # Remove default WordPress files
    local files_to_remove=(
        "readme.html"
        "wp-config-sample.php"
        "license.txt"
        "liesmich.html"
    )
    
    for file in "${files_to_remove[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            log_info "Removed WordPress file: $file"
        fi
    done
    
    # Secure wp-config.php
    if [[ -f "wp-config.php" ]]; then
        chmod 600 wp-config.php
        chown www-data:www-data wp-config.php
    fi
    
    # Create .htaccess security rules (if not exists)
    if [[ ! -f ".htaccess" ]]; then
        cat > .htaccess << 'EOF'
# WordPress Security .htaccess

# Prevent access to sensitive files
<FilesMatch "^(wp-config\.php|\.htaccess|error_log|debug\.log|\.user\.ini)$">
    Require all denied
</FilesMatch>

# Prevent access to wp-content directories
<IfModule mod_alias.c>
    RedirectMatch 403 ^/wp-content/uploads/.*\.php$
    RedirectMatch 403 ^/wp-content/themes/.*\.php$
    RedirectMatch 403 ^/wp-includes/.*\.php$
</IfModule>

# Block suspicious requests
<IfModule mod_rewrite.c>
    RewriteEngine On
    
    # Block access to xmlrpc.php
    RewriteRule ^xmlrpc\.php$ - [F,L]
    
    # Block suspicious query strings
    RewriteCond %{QUERY_STRING} \.\.\/ [NC,OR]
    RewriteCond %{QUERY_STRING} boot\.ini [NC,OR]
    RewriteCond %{QUERY_STRING} tag\= [NC,OR]
    RewriteCond %{QUERY_STRING} ftp\: [NC,OR]
    RewriteCond %{QUERY_STRING} http\: [NC,OR]
    RewriteCond %{QUERY_STRING} https\: [NC,OR]
    RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
    RewriteCond %{QUERY_STRING} mosConfig_[a-zA-Z_]{1,21}(=|\%3D) [NC,OR]
    RewriteCond %{QUERY_STRING} base64_encode.*\(.*\) [NC,OR]
    RewriteCond %{QUERY_STRING} ^.*(\[|\]|\(|\)|<|>|ê|"|;|\?|\*|=$).* [NC]
    RewriteRule ^(.*)$ - [F,L]
    
    # WordPress specific rewrites
    RewriteBase /
    RewriteRule ^index\.php$ - [L]
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule . /index.php [L]
</IfModule>

# Security headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header unset X-Powered-By
    Header unset Server
</IfModule>
EOF
        
        chown www-data:www-data .htaccess
        chmod 644 .htaccess
    fi
    
    # Secure uploads directory
    if [[ -d "wp-content/uploads" ]]; then
        cat > wp-content/uploads/.htaccess << 'EOF'
# Uploads directory security
<Files *.php>
    Require all denied
</Files>

# Allow only specific file types
<FilesMatch "\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|mp3|mp4)$">
    Require all granted
</FilesMatch>
EOF
        
        # Remove any PHP files in uploads
        find wp-content/uploads -name "*.php" -type f -delete 2>/dev/null || true
    fi
    
    # Disable XML-RPC if not needed
    if ! grep -q "add_filter.*xmlrpc_enabled.*__return_false" wp-config.php; then
        sed -i "/wp-settings.php/i add_filter('xmlrpc_enabled', '__return_false');" wp-config.php
    fi
    
    log_info "WordPress hardening completed"
}

secure_file_permissions() {
    log_info "Securing file permissions and ownership..."
    
    # WordPress directory permissions
    if [[ -d "$WP_DIR" ]]; then
        log_info "Setting WordPress file permissions..."
        
        # Set ownership
        chown -R www-data:www-data "$WP_DIR"
        
        # Set directory permissions (755)
        find "$WP_DIR" -type d -exec chmod 755 {} \;
        
        # Set file permissions (644)
        find "$WP_DIR" -type f -exec chmod 644 {} \;
        
        # Special permissions for wp-config.php
        if [[ -f "$WP_DIR/wp-config.php" ]]; then
            chmod 600 "$WP_DIR/wp-config.php"
        fi
        
        # Make sure uploads directory is writable
        if [[ -d "$WP_DIR/wp-content/uploads" ]]; then
            chmod -R 755 "$WP_DIR/wp-content/uploads"
        fi
    fi
    
    # System file permissions
    chmod 644 /etc/passwd
    chmod 600 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    chmod 600 /etc/ssh/ssh_host_*_key
    chmod 644 /etc/ssh/ssh_host_*_key.pub
    
    # Log file permissions
    if [[ -d /var/log/apache2 ]]; then
        chown -R root:adm /var/log/apache2
        chmod -R 640 /var/log/apache2/*.log 2>/dev/null || true
    fi
    
    if [[ -d /var/log/mysql ]]; then
        chown -R mysql:mysql /var/log/mysql
        chmod -R 640 /var/log/mysql/*.log 2>/dev/null || true
    fi
    
    log_info "File permissions and ownership secured"
}

configure_automatic_updates() {
    log_info "Configuring automatic security updates..."
    
    # Install unattended-upgrades
    if ! command_exists unattended-upgrades; then
        apt-get update -qq
        apt-get install -y unattended-upgrades apt-listchanges
    fi
    
    # Configure automatic updates
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Automatic security updates configuration
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}:${distro_codename}-updates";
};

// Packages to never update automatically
Unattended-Upgrade::Package-Blacklist {
    // "vim";
    // "libc6-dev";
};

// Automatically remove unused packages
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatically remove new unused dependencies
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Reboot if needed
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";

// Email notifications (configure if needed)
// Unattended-Upgrade::Mail "admin@domain.com";
Unattended-Upgrade::MailOnlyOnError "true";

// Logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";

// Download and install upgrades
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
EOF
    
    # Enable automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    
    # Enable the service
    enable_start_service unattended-upgrades
    
    log_info "Automatic security updates configured"
}

disable_unnecessary_services() {
    log_info "Disabling unnecessary services..."
    
    # List of services to disable
    local services_to_disable=(
        "bluetooth"
        "cups"
        "avahi-daemon"
        "whoopsie"
        "apport"
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            systemctl disable "$service" >/dev/null 2>&1 || true
            systemctl stop "$service" >/dev/null 2>&1 || true
            log_info "Disabled service: $service"
        fi
    done
    
    # Remove unnecessary packages
    local packages_to_remove=(
        "telnet"
        "rsh-client"
        "talk"
        "ntalk"
        "finger"
        "netcat-openbsd"
    )
    
    for package in "${packages_to_remove[@]}"; do
        if dpkg -l "$package" >/dev/null 2>&1; then
            apt-get remove -y "$package" >/dev/null 2>&1 || true
            log_info "Removed package: $package"
        fi
    done
    
    log_info "Unnecessary services and packages disabled/removed"
}

configure_network_security() {
    log_info "Configuring network security..."
    
    # TCP wrappers configuration
    cat > /etc/hosts.allow << 'EOF'
# Hosts allow configuration
sshd: ALL
vsftpd: ALL
EOF
    
    cat > /etc/hosts.deny << 'EOF'
# Hosts deny configuration
ALL: ALL
EOF
    
    # Secure resolv.conf
    if [[ ! -L /etc/resolv.conf ]]; then
        chattr +i /etc/resolv.conf 2>/dev/null || true
    fi
    
    # Configure iptables if UFW is not used
    if [[ "$ENABLE_UFW" != "true" ]]; then
        log_info "Creating basic iptables rules (UFW not enabled)..."
        
        cat > /etc/iptables.rules << 'EOF'
# Basic iptables rules
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback traffic
-A INPUT -i lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
-A INPUT -p tcp --dport 22 -m state --state NEW -m limit --limit 2/min --limit-burst 2 -j ACCEPT

# Allow HTTP/HTTPS
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow ping with rate limiting
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/sec -j ACCEPT

COMMIT
EOF
        
        # Apply iptables rules
        iptables-restore < /etc/iptables.rules
        
        # Make rules persistent
        cat > /etc/systemd/system/iptables-restore.service << 'EOF'
[Unit]
Description=Restore iptables rules
Before=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables.rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl enable iptables-restore >/dev/null 2>&1
    fi
    
    log_info "Network security configured"
}

configure_security_logging() {
    log_info "Configuring security logging and monitoring..."
    
    # Configure rsyslog for security logging
    cat > /etc/rsyslog.d/50-security.conf << 'EOF'
# Security logging configuration

# Auth logs
auth,authpriv.* /var/log/auth.log

# Kernel messages
kern.* /var/log/kern.log

# Mail system logs
mail.* /var/log/mail.log

# Emergency messages to all users
*.emerg :omusrmsg:*

# Log all security-related messages
local0.* /var/log/security.log
EOF
    
    # Create security log file
    touch /var/log/security.log
    chmod 600 /var/log/security.log
    chown root:root /var/log/security.log
    
    # Configure logrotate for security logs
    cat > /etc/logrotate.d/security << 'EOF'
/var/log/security.log {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 600 root root
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/auth.log {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
    
    # Restart rsyslog
    restart_service rsyslog
    
    log_info "Security logging configured"
}

setup_security_monitoring() {
    log_info "Setting up security monitoring..."
    
    # Create comprehensive security monitoring script
    cat > /usr/local/bin/security-audit << 'EOF'
#!/bin/bash
# Comprehensive Security Audit Script

LOG_FILE="/var/log/security-audit.log"
ALERT_EMAIL=""  # Configure if needed

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_FILE"
}

log_alert() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ALERT: $*" >> "$LOG_FILE"
    if [[ -n "$ALERT_EMAIL" ]]; then
        echo "$*" | mail -s "Security Alert: $(hostname)" "$ALERT_EMAIL"
    fi
}

# Check for failed login attempts
check_failed_logins() {
    local failed_ssh=$(grep "$(date '+%b %d')" /var/log/auth.log 2>/dev/null | grep -c "Failed password" || echo 0)
    local failed_su=$(grep "$(date '+%b %d')" /var/log/auth.log 2>/dev/null | grep -c "su: FAILED" || echo 0)
    
    if [[ $failed_ssh -gt 10 ]]; then
        log_alert "High number of failed SSH attempts: $failed_ssh"
    fi
    
    if [[ $failed_su -gt 5 ]]; then
        log_alert "High number of failed su attempts: $failed_su"
    fi
}

# Check for suspicious network connections
check_network_connections() {
    local suspicious_ports=$(netstat -tln | awk '$4 ~ /:([0-9]{4,5})$/ && $4 !~ /:22$|:80$|:443$|:21$|:3306$/ {print $4}' | wc -l)
    
    if [[ $suspicious_ports -gt 0 ]]; then
        log_alert "Suspicious network ports detected: $suspicious_ports"
    fi
}

# Check for file changes in sensitive directories
check_file_integrity() {
    local sensitive_dirs=("/etc" "/usr/bin" "/usr/sbin" "/bin" "/sbin")
    
    for dir in "${sensitive_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # Simple check for recently modified files
            local recent_files=$(find "$dir" -type f -mtime -1 2>/dev/null | wc -l)
            if [[ $recent_files -gt 50 ]]; then
                log_alert "Many files modified in $dir: $recent_files files"
            fi
        fi
    done
}

# Check system processes
check_processes() {
    # Check for unusual processes
    local high_cpu_procs=$(ps aux | awk '$3 > 80.0 {print $11}' | wc -l)
    if [[ $high_cpu_procs -gt 0 ]]; then
        log_alert "High CPU usage processes detected: $high_cpu_procs"
    fi
    
    # Check for processes running as root
    local root_procs=$(ps aux | grep "^root" | grep -v "\[" | wc -l)
    log_message "Root processes: $root_procs"
}

# Check disk usage
check_disk_usage() {
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 90 ]]; then
        log_alert "High disk usage: ${disk_usage}%"
    fi
}

# Check for rootkits (basic)
check_rootkits() {
    # Check for common rootkit files
    local rootkit_files=(
        "/tmp/.ICE-unix"
        "/tmp/.X11-unix"
        "/dev/shm/.hidden"
        "/usr/bin/..." 
    )
    
    for file in "${rootkit_files[@]}"; do
        if [[ -e "$file" ]]; then
            log_alert "Potential rootkit file detected: $file"
        fi
    done
}

# Main audit function
run_audit() {
    log_message "Starting security audit"
    
    check_failed_logins
    check_network_connections
    check_file_integrity
    check_processes
    check_disk_usage
    check_rootkits
    
    log_message "Security audit completed"
}

# Run the audit
run_audit

# Rotate log if it gets too large
if [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 5242880 ]]; then
    tail -1000 "$LOG_FILE" > "$LOG_FILE.tmp"
    mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/security-audit
    
    # Add security audit to cron (hourly)
    local security_audit_cron="0 */1 * * * /usr/local/bin/security-audit >/dev/null 2>&1"
    (crontab -l 2>/dev/null | grep -v "security-audit" || true; echo "$security_audit_cron") | crontab -
    
    # Create log file
    touch /var/log/security-audit.log
    chmod 600 /var/log/security-audit.log
    
    log_info "Security monitoring configured (hourly audits)"
}

create_hardening_tools() {
    log_info "Creating security hardening management tools..."
    
    # Create security status script
    cat > /usr/local/bin/security-status << 'EOF'
#!/bin/bash
# Security Status Script

echo "=== System Security Status ==="
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime -p)"
echo "Last reboot: $(who -b | awk '{print $3, $4}')"

echo -e "\n=== UFW Firewall Status ==="
if command -v ufw >/dev/null 2>&1; then
    ufw status
else
    echo "UFW not installed"
fi

echo -e "\n=== fail2ban Status ==="
if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status 2>/dev/null || echo "fail2ban not running"
else
    echo "fail2ban not installed"
fi

echo -e "\n=== SSH Configuration ==="
echo "SSH Status: $(systemctl is-active ssh)"
echo "SSH Port: $(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")"
echo "Root Login: $(grep "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' || echo "default")"

echo -e "\n=== System Updates ==="
if command -v apt >/dev/null 2>&1; then
    echo "Available updates: $(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l)"
    echo "Security updates: $(apt list --upgradable 2>/dev/null | grep -c "ubuntu.*security" || echo 0)"
fi

echo -e "\n=== Failed Login Attempts (Today) ==="
if [[ -f /var/log/auth.log ]]; then
    echo "Failed SSH: $(grep "$(date '+%b %d')" /var/log/auth.log 2>/dev/null | grep -c "Failed password" || echo 0)"
    echo "Failed sudo: $(grep "$(date '+%b %d')" /var/log/auth.log 2>/dev/null | grep -c "sudo: FAILED" || echo 0)"
else
    echo "Auth log not available"
fi

echo -e "\n=== Network Connections ==="
echo "Listening ports:"
netstat -tln | grep LISTEN | awk '{print $4}' | sort -u

echo -e "\n=== Disk Usage ==="
df -h / | tail -1

echo -e "\n=== Security Audit Log ==="
if [[ -f /var/log/security-audit.log ]]; then
    echo "Recent security events:"
    tail -5 /var/log/security-audit.log
else
    echo "No security audit log found"
fi
EOF
    
    chmod +x /usr/local/bin/security-status
    
    log_info "Security management tools created"
}

display_security_summary() {
    log_info "Security hardening summary:"
    
    echo "=================================="
    echo "Security Hardening Configuration"
    echo "=================================="
    echo "System Hardening: Enabled"
    echo "UFW Firewall: $ENABLE_UFW"
    echo "fail2ban: $ENABLE_FAIL2BAN"
    echo "SSH Hardening: Enabled"
    echo "WordPress Hardening: Enabled"
    echo "File Permissions: Secured"
    echo "Automatic Updates: Enabled"
    echo "Security Monitoring: Enabled"
    echo "=================================="
    echo
    
    if [[ "$ENABLE_UFW" == "true" ]]; then
        echo "UFW Firewall Rules:"
        ufw status numbered 2>/dev/null | grep -E "^\[.*\]" || echo "No UFW rules found"
        echo
    fi
    
    if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
        echo "fail2ban Jails:"
        fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 || echo "No fail2ban jails found"
        echo
    fi
    
    echo "Security Features:"
    echo "- Kernel parameter hardening"
    echo "- SSH configuration hardening"
    echo "- WordPress security measures"
    echo "- File permission hardening"
    echo "- Network security configuration"
    echo "- Automatic security updates"
    echo "- Security audit logging"
    echo "- Intrusion detection (if fail2ban enabled)"
    echo
    echo "Management Commands:"
    echo "- security-status    : Check security status"
    echo "- security-audit     : Run security audit"
    
    if [[ "$ENABLE_UFW" == "true" ]]; then
        echo "- ufw status         : Check firewall status"
    fi
    
    if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
        echo "- fail2ban-client    : Manage fail2ban"
    fi
    
    echo
    echo "Log Files:"
    echo "- Security audit: /var/log/security-audit.log"
    echo "- Authentication: /var/log/auth.log"
    echo "- System security: /var/log/security.log"
    
    if [[ "$ENABLE_FAIL2BAN" == "true" ]]; then
        echo "- fail2ban: /var/log/fail2ban.log"
    fi
    
    echo "=================================="
    echo
    echo "IMPORTANT SECURITY NOTES:"
    echo "- Change default passwords immediately"
    echo "- Consider disabling SSH password authentication"
    echo "- Regular security audits recommended"
    echo "- Monitor logs for suspicious activity"
    echo "- Keep system updated regularly"
    echo "=================================="
}

# Run hardening with options
case "${1:-all}" in
    "system")
        configure_system_hardening
        ;;
    "ufw")
        setup_ufw_firewall
        ;;
    "fail2ban")
        setup_fail2ban
        ;;
    "ssh")
        harden_ssh_configuration
        ;;
    "wordpress")
        harden_wordpress_installation
        ;;
    "permissions")
        secure_file_permissions
        ;;
    "updates")
        configure_automatic_updates
        ;;
    "services")
        disable_unnecessary_services
        ;;
    "network")
        configure_network_security
        ;;
    "logging")
        configure_security_logging
        ;;
    "monitoring")
        setup_security_monitoring
        ;;
    "tools")
        create_hardening_tools
        ;;
    "status")
        /usr/local/bin/security-status 2>/dev/null || echo "Security status script not available"
        ;;
    "audit")
        /usr/local/bin/security-audit 2>/dev/null || echo "Security audit script not available"
        ;;
    "all")
        main
        create_hardening_tools
        ;;
    *)
        echo "Usage: $0 [system|ufw|fail2ban|ssh|wordpress|permissions|updates|services|network|logging|monitoring|tools|status|audit|all]"
        echo "  system       - Configure system-level hardening"
        echo "  ufw          - Setup UFW firewall"
        echo "  fail2ban     - Setup fail2ban intrusion prevention"
        echo "  ssh          - Harden SSH configuration"
        echo "  wordpress    - Harden WordPress installation"
        echo "  permissions  - Secure file permissions"
        echo "  updates      - Configure automatic updates"
        echo "  services     - Disable unnecessary services"
        echo "  network      - Configure network security"
        echo "  logging      - Setup security logging"
        echo "  monitoring   - Setup security monitoring"
        echo "  tools        - Create security management tools"
        echo "  status       - Show security status"
        echo "  audit        - Run security audit"
        echo "  all          - Run complete hardening (default)"
        exit 1
        ;;
esac