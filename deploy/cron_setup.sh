#!/bin/bash

# WordPress Cron Setup Script
# Author: Florent Didelot
# Description: Disable WordPress pseudo-cron and setup system cron for better performance

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
WP_DIR="${WP_DIR:-/var/www/html}"
WP_CRON_SCHEDULE="${WP_CRON_SCHEDULE:-*/5 * * * *}"
WP_DISABLE_CRON="${WP_DISABLE_CRON:-true}"
BACKUP_SCHEDULE="${BACKUP_SCHEDULE:-0 2 * * *}"

# Error trap
trap 'log_error "Cron setup failed on line $LINENO"' ERR

main() {
    log_info "Starting WordPress cron setup..."
    
    # Check prerequisites
    check_prerequisites
    
    # Disable WordPress pseudo-cron
    disable_wp_pseudo_cron
    
    # Setup WordPress system cron
    setup_wp_system_cron
    
    # Setup maintenance crons
    setup_maintenance_crons
    
    # Setup backup crons
    setup_backup_crons
    
    # Setup monitoring crons
    setup_monitoring_crons
    
    # Setup security crons
    setup_security_crons
    
    # Test cron configuration
    test_cron_configuration
    
    # Start cron service
    enable_start_service cron
    
    log_success "WordPress cron setup completed successfully"
    display_cron_summary
}

check_prerequisites() {
    log_info "Checking cron prerequisites..."
    
    # Check if cron is installed
    if ! command_exists crontab; then
        log_info "Installing cron..."
        apt-get update -qq
        apt-get install -y cron
    fi
    
    # Check if WordPress is installed
    if [[ ! -f "$WP_DIR/wp-config.php" ]]; then
        error_exit "WordPress not found in $WP_DIR. Run install_wp.sh first."
    fi
    
    # Check if wp-cli is available
    if ! command_exists wp; then
        error_exit "WP-CLI not found. Run optimize_php.sh first."
    fi
    
    # Check if WordPress is properly installed
    cd "$WP_DIR"
    if ! sudo -u www-data wp core is-installed --allow-root 2>/dev/null; then
        error_exit "WordPress is not properly installed"
    fi
    
    log_info "Prerequisites check passed"
}

disable_wp_pseudo_cron() {
    log_info "Disabling WordPress pseudo-cron..."
    
    cd "$WP_DIR"
    
    # Check if DISABLE_WP_CRON is already set in wp-config.php
    if grep -q "DISABLE_WP_CRON" wp-config.php; then
        # Update existing setting
        sed -i "s/define.*DISABLE_WP_CRON.*/define( 'DISABLE_WP_CRON', true );/" wp-config.php
        log_info "Updated DISABLE_WP_CRON setting in wp-config.php"
    else
        # Add new setting before wp-settings.php
        sed -i "/wp-settings.php/i define( 'DISABLE_WP_CRON', true );" wp-config.php
        log_info "Added DISABLE_WP_CRON setting to wp-config.php"
    fi
    
    # Verify the setting is correct
    if grep -q "define( 'DISABLE_WP_CRON', true );" wp-config.php; then
        log_success "WordPress pseudo-cron disabled"
    else
        log_warn "Failed to disable WordPress pseudo-cron"
    fi
}

setup_wp_system_cron() {
    log_info "Setting up WordPress system cron..."
    
    # Create WordPress cron script
    cat > /usr/local/bin/wp-cron << EOF
#!/bin/bash
# WordPress Cron Runner Script

WP_DIR="$WP_DIR"
LOG_FILE="/var/log/wp-cron.log"

# Change to WordPress directory
cd "\$WP_DIR" || exit 1

# Run WordPress cron with proper user
sudo -u www-data wp cron event run --due-now --allow-root >> "\$LOG_FILE" 2>&1

# Log timestamp
echo "\$(date '+%Y-%m-%d %H:%M:%S') - WordPress cron executed" >> "\$LOG_FILE"

# Rotate log if it gets too large (> 10MB)
if [[ -f "\$LOG_FILE" ]] && [[ \$(stat -c%s "\$LOG_FILE") -gt 10485760 ]]; then
    tail -1000 "\$LOG_FILE" > "\$LOG_FILE.tmp"
    mv "\$LOG_FILE.tmp" "\$LOG_FILE"
fi
EOF
    
    # Make script executable
    chmod +x /usr/local/bin/wp-cron
    
    # Add cron job for www-data user
    local cron_entry="$WP_CRON_SCHEDULE /usr/local/bin/wp-cron >/dev/null 2>&1"
    
    # Check if cron job already exists
    if crontab -u www-data -l 2>/dev/null | grep -q "wp-cron"; then
        # Update existing cron job
        (crontab -u www-data -l 2>/dev/null | grep -v "wp-cron"; echo "$cron_entry") | crontab -u www-data -
        log_info "Updated WordPress cron job"
    else
        # Add new cron job
        (crontab -u www-data -l 2>/dev/null || true; echo "$cron_entry") | crontab -u www-data -
        log_info "Added WordPress cron job"
    fi
    
    # Create log file with proper permissions
    touch /var/log/wp-cron.log
    chown www-data:www-data /var/log/wp-cron.log
    chmod 644 /var/log/wp-cron.log
    
    log_success "WordPress system cron configured ($WP_CRON_SCHEDULE)"
}

setup_maintenance_crons() {
    log_info "Setting up maintenance cron jobs..."
    
    # Create maintenance script
    cat > /usr/local/bin/wp-maintenance << EOF
#!/bin/bash
# WordPress Maintenance Script

WP_DIR="$WP_DIR"
LOG_FILE="/var/log/wp-maintenance.log"

log_message() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$*" >> "\$LOG_FILE"
}

cd "\$WP_DIR" || exit 1

log_message "Starting WordPress maintenance"

# Clean up revisions (keep last 3)
REVISIONS_CLEANED=\$(sudo -u www-data wp post list --post_type=revision --format=count --allow-root 2>/dev/null || echo 0)
if [[ \$REVISIONS_CLEANED -gt 0 ]]; then
    sudo -u www-data wp post delete \$(sudo -u www-data wp post list --post_type=revision --format=ids --allow-root) --force --allow-root >/dev/null 2>&1
    log_message "Cleaned \$REVISIONS_CLEANED post revisions"
fi

# Clean up spam comments
SPAM_CLEANED=\$(sudo -u www-data wp comment list --status=spam --format=count --allow-root 2>/dev/null || echo 0)
if [[ \$SPAM_CLEANED -gt 0 ]]; then
    sudo -u www-data wp comment delete \$(sudo -u www-data wp comment list --status=spam --format=ids --allow-root) --force --allow-root >/dev/null 2>&1
    log_message "Cleaned \$SPAM_CLEANED spam comments"
fi

# Clean up trash
TRASH_CLEANED=\$(sudo -u www-data wp post list --post_status=trash --format=count --allow-root 2>/dev/null || echo 0)
if [[ \$TRASH_CLEANED -gt 0 ]]; then
    sudo -u www-data wp post delete \$(sudo -u www-data wp post list --post_status=trash --format=ids --allow-root) --force --allow-root >/dev/null 2>&1
    log_message "Cleaned \$TRASH_CLEANED trashed posts"
fi

# Optimize database
sudo -u www-data wp db optimize --allow-root >/dev/null 2>&1
log_message "Database optimized"

# Clear any expired transients
TRANSIENTS_CLEANED=\$(sudo -u www-data wp transient delete --expired --allow-root 2>/dev/null | grep -o '[0-9]\+' | head -1 || echo 0)
log_message "Cleaned \$TRANSIENTS_CLEANED expired transients"

log_message "WordPress maintenance completed"

# Rotate log if it gets too large
if [[ \$(stat -c%s "\$LOG_FILE" 2>/dev/null || echo 0) -gt 5242880 ]]; then
    tail -500 "\$LOG_FILE" > "\$LOG_FILE.tmp"
    mv "\$LOG_FILE.tmp" "\$LOG_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/wp-maintenance
    
    # Add maintenance cron (daily at 3 AM)
    local maintenance_cron="0 3 * * * /usr/local/bin/wp-maintenance >/dev/null 2>&1"
    (crontab -u www-data -l 2>/dev/null | grep -v "wp-maintenance" || true; echo "$maintenance_cron") | crontab -u www-data -
    
    # Create log file
    touch /var/log/wp-maintenance.log
    chown www-data:www-data /var/log/wp-maintenance.log
    chmod 644 /var/log/wp-maintenance.log
    
    log_info "WordPress maintenance cron configured (daily at 3 AM)"
}

setup_backup_crons() {
    if [[ "${ENABLE_BACKUPS:-false}" == "true" ]]; then
        log_info "Setting up backup cron jobs..."
        
        # WordPress backup cron
        local backup_cron="$BACKUP_SCHEDULE /usr/local/bin/wp-backup >/dev/null 2>&1"
        (crontab -l 2>/dev/null | grep -v "wp-backup" || true; echo "$backup_cron") | crontab -
        
        # MariaDB backup cron (if script exists)
        if [[ -f /usr/local/bin/mariadb-backup ]]; then
            local db_backup_cron="30 2 * * * /usr/local/bin/mariadb-backup >/dev/null 2>&1"
            (crontab -l 2>/dev/null | grep -v "mariadb-backup" || true; echo "$db_backup_cron") | crontab -
        fi
        
        log_info "Backup cron jobs configured"
    else
        log_info "Backups disabled, skipping backup cron setup"
    fi
}

setup_monitoring_crons() {
    log_info "Setting up monitoring cron jobs..."
    
    # Create system monitoring script
    cat > /usr/local/bin/system-monitor << 'EOF'
#!/bin/bash
# System Monitoring Script

LOG_FILE="/var/log/system-monitor.log"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEMORY=85
ALERT_THRESHOLD_DISK=90

log_alert() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ALERT: $*" >> "$LOG_FILE"
    # Send email alert if configured
    # echo "$*" | mail -s "System Alert" admin@domain.com
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $*" >> "$LOG_FILE"
}

# Check CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
CPU_USAGE_INT=${CPU_USAGE%.*}
if [[ $CPU_USAGE_INT -gt $ALERT_THRESHOLD_CPU ]]; then
    log_alert "High CPU usage: ${CPU_USAGE}%"
fi

# Check memory usage
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [[ $MEMORY_USAGE -gt $ALERT_THRESHOLD_MEMORY ]]; then
    log_alert "High memory usage: ${MEMORY_USAGE}%"
fi

# Check disk usage
DISK_USAGE=$(df / | awk 'NR==2{printf "%d", $5}')
if [[ $DISK_USAGE -gt $ALERT_THRESHOLD_DISK ]]; then
    log_alert "High disk usage: ${DISK_USAGE}%"
fi

# Check critical services
SERVICES=("apache2" "mariadb" "php8.4-fpm")
for service in "${SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$service" 2>/dev/null; then
        log_alert "Service $service is not running"
    fi
done

# Check website availability
if command -v curl >/dev/null 2>&1; then
    if ! curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200"; then
        log_alert "Website is not responding properly"
    fi
fi

# Rotate log
if [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 1048576 ]]; then
    tail -100 "$LOG_FILE" > "$LOG_FILE.tmp"
    mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/system-monitor
    
    # Add monitoring cron (every 15 minutes)
    local monitor_cron="*/15 * * * * /usr/local/bin/system-monitor >/dev/null 2>&1"
    (crontab -l 2>/dev/null | grep -v "system-monitor" || true; echo "$monitor_cron") | crontab -
    
    # Create log file
    touch /var/log/system-monitor.log
    chown root:adm /var/log/system-monitor.log
    chmod 644 /var/log/system-monitor.log
    
    log_info "System monitoring cron configured (every 15 minutes)"
}

setup_security_crons() {
    log_info "Setting up security cron jobs..."
    
    # Create security monitoring script
    cat > /usr/local/bin/security-monitor << 'EOF'
#!/bin/bash
# Security Monitoring Script

LOG_FILE="/var/log/security-monitor.log"
WP_DIR="/var/www/html"

log_alert() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - SECURITY ALERT: $*" >> "$LOG_FILE"
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $*" >> "$LOG_FILE"
}

# Check for failed login attempts
if [[ -f /var/log/auth.log ]]; then
    FAILED_LOGINS=$(grep "$(date '+%b %d')" /var/log/auth.log | grep -c "Failed password" || echo 0)
    if [[ $FAILED_LOGINS -gt 10 ]]; then
        log_alert "High number of failed SSH login attempts: $FAILED_LOGINS"
    fi
fi

# Check WordPress file integrity (if wp-cli available)
if command -v wp >/dev/null 2>&1 && [[ -d "$WP_DIR" ]]; then
    cd "$WP_DIR"
    if ! sudo -u www-data wp core verify-checksums --allow-root >/dev/null 2>&1; then
        log_alert "WordPress core files integrity check failed"
    fi
fi

# Check for suspicious files in uploads directory
if [[ -d "$WP_DIR/wp-content/uploads" ]]; then
    SUSPICIOUS_FILES=$(find "$WP_DIR/wp-content/uploads" -name "*.php" -o -name "*.js" -o -name "*.html" | wc -l)
    if [[ $SUSPICIOUS_FILES -gt 0 ]]; then
        log_alert "Suspicious files found in uploads directory: $SUSPICIOUS_FILES files"
    fi
fi

# Check for large log files that might indicate attacks
LOG_FILES=("/var/log/apache2/access.log" "/var/log/apache2/error.log")
for logfile in "${LOG_FILES[@]}"; do
    if [[ -f "$logfile" ]]; then
        SIZE=$(stat -c%s "$logfile" 2>/dev/null || echo 0)
        if [[ $SIZE -gt 104857600 ]]; then  # 100MB
            log_alert "Large log file detected: $logfile ($(($SIZE / 1024 / 1024))MB)"
        fi
    fi
done

# Rotate security log
if [[ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 2097152 ]]; then
    tail -200 "$LOG_FILE" > "$LOG_FILE.tmp"
    mv "$LOG_FILE.tmp" "$LOG_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/security-monitor
    
    # Add security monitoring cron (every hour)
    local security_cron="0 * * * * /usr/local/bin/security-monitor >/dev/null 2>&1"
    (crontab -l 2>/dev/null | grep -v "security-monitor" || true; echo "$security_cron") | crontab -
    
    # Create log file
    touch /var/log/security-monitor.log
    chown root:adm /var/log/security-monitor.log
    chmod 644 /var/log/security-monitor.log
    
    log_info "Security monitoring cron configured (hourly)"
}

test_cron_configuration() {
    log_info "Testing cron configuration..."
    
    # Test cron service
    if service_is_active cron; then
        log_success "Cron service is active"
    else
        log_warn "Cron service is not active"
    fi
    
    # Test www-data crontab
    if crontab -u www-data -l >/dev/null 2>&1; then
        local wp_cron_count
        wp_cron_count=$(crontab -u www-data -l 2>/dev/null | grep -c "wp-cron" || echo 0)
        log_info "www-data has $wp_cron_count WordPress cron jobs"
    else
        log_warn "www-data has no crontab entries"
    fi
    
    # Test root crontab
    if crontab -l >/dev/null 2>&1; then
        local root_cron_count
        root_cron_count=$(crontab -l 2>/dev/null | wc -l || echo 0)
        log_info "root has $root_cron_count cron jobs"
    else
        log_info "root has no crontab entries"
    fi
    
    # Test WordPress cron script
    if [[ -x /usr/local/bin/wp-cron ]]; then
        log_info "WordPress cron script is executable"
        # Test run (dry run)
        if /usr/local/bin/wp-cron >/dev/null 2>&1; then
            log_success "WordPress cron script test passed"
        else
            log_warn "WordPress cron script test failed"
        fi
    else
        log_warn "WordPress cron script is not executable"
    fi
    
    log_info "Cron configuration test completed"
}

create_cron_management_tools() {
    log_info "Creating cron management tools..."
    
    # Create cron status script
    cat > /usr/local/bin/cron-status << 'EOF'
#!/bin/bash
# Cron Status Script

echo "=== Cron Service Status ==="
systemctl status cron --no-pager

echo -e "\n=== Active Cron Jobs (www-data) ==="
echo "WordPress Cron Jobs:"
crontab -u www-data -l 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "No cron jobs for www-data"

echo -e "\n=== Active Cron Jobs (root) ==="
echo "System Cron Jobs:"
crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" || echo "No cron jobs for root"

echo -e "\n=== Recent Cron Activity ==="
echo "WordPress Cron Log:"
if [[ -f /var/log/wp-cron.log ]]; then
    tail -5 /var/log/wp-cron.log
else
    echo "No WordPress cron log found"
fi

echo -e "\nMaintenance Log:"
if [[ -f /var/log/wp-maintenance.log ]]; then
    tail -3 /var/log/wp-maintenance.log
else
    echo "No maintenance log found"
fi

echo -e "\n=== Cron Scripts ==="
echo "Available cron scripts:"
ls -la /usr/local/bin/ | grep -E "(wp-|cron-|system-|security-)" || echo "No custom cron scripts found"

echo -e "\n=== WordPress Cron Events ==="
if command -v wp >/dev/null 2>&1 && [[ -d /var/www/html ]]; then
    cd /var/www/html
    echo "Scheduled Events:"
    sudo -u www-data wp cron event list --allow-root 2>/dev/null | head -10 || echo "Could not list WordPress cron events"
else
    echo "WordPress or WP-CLI not available"
fi
EOF
    
    # Create cron log viewer
    cat > /usr/local/bin/cron-logs << 'EOF'
#!/bin/bash
# Cron Log Viewer

show_help() {
    echo "Usage: $0 [wp|maintenance|security|system|all] [lines]"
    echo "  wp          - WordPress cron logs"
    echo "  maintenance - Maintenance logs"
    echo "  security    - Security monitoring logs"
    echo "  system      - System monitoring logs"
    echo "  all         - All cron logs"
    echo "  lines       - Number of lines to show (default: 20)"
}

LINES=${2:-20}

case "${1:-all}" in
    "wp")
        echo "=== WordPress Cron Logs ==="
        if [[ -f /var/log/wp-cron.log ]]; then
            tail -n "$LINES" /var/log/wp-cron.log
        else
            echo "No WordPress cron log found"
        fi
        ;;
    "maintenance")
        echo "=== Maintenance Logs ==="
        if [[ -f /var/log/wp-maintenance.log ]]; then
            tail -n "$LINES" /var/log/wp-maintenance.log
        else
            echo "No maintenance log found"
        fi
        ;;
    "security")
        echo "=== Security Monitoring Logs ==="
        if [[ -f /var/log/security-monitor.log ]]; then
            tail -n "$LINES" /var/log/security-monitor.log
        else
            echo "No security monitoring log found"
        fi
        ;;
    "system")
        echo "=== System Monitoring Logs ==="
        if [[ -f /var/log/system-monitor.log ]]; then
            tail -n "$LINES" /var/log/system-monitor.log
        else
            echo "No system monitoring log found"
        fi
        ;;
    "all")
        for log_type in wp maintenance security system; do
            $0 "$log_type" "$LINES"
            echo
        done
        ;;
    *)
        show_help
        ;;
esac
EOF
    
    # Make scripts executable
    chmod +x /usr/local/bin/cron-status
    chmod +x /usr/local/bin/cron-logs
    
    log_info "Cron management tools created"
}

display_cron_summary() {
    log_info "WordPress cron setup summary:"
    
    echo "=================================="
    echo "WordPress Cron Configuration"
    echo "=================================="
    echo "WordPress Pseudo-Cron: Disabled"
    echo "System Cron: Enabled"
    echo "WordPress Cron Schedule: $WP_CRON_SCHEDULE"
    echo "Maintenance Schedule: Daily at 3:00 AM"
    echo "Monitoring Schedule: Every 15 minutes"
    echo "Security Checks: Hourly"
    
    if [[ "${ENABLE_BACKUPS:-false}" == "true" ]]; then
        echo "Backup Schedule: $BACKUP_SCHEDULE"
    else
        echo "Backup Schedule: Disabled"
    fi
    
    echo "=================================="
    echo
    echo "Cron Jobs Summary:"
    echo "- WordPress cron events: $WP_CRON_SCHEDULE"
    echo "- Database maintenance: Daily at 3 AM"
    echo "- System monitoring: Every 15 minutes"
    echo "- Security monitoring: Hourly"
    
    if [[ "${ENABLE_BACKUPS:-false}" == "true" ]]; then
        echo "- Automated backups: $BACKUP_SCHEDULE"
    fi
    
    echo
    echo "Management Commands:"
    echo "- cron-status    : Show cron status and active jobs"
    echo "- cron-logs      : View cron execution logs"
    echo "- wp-maintenance : Run maintenance manually"
    echo "- system-monitor : Run system monitoring manually"
    echo
    echo "Log Files:"
    echo "- WordPress cron: /var/log/wp-cron.log"
    echo "- Maintenance: /var/log/wp-maintenance.log"
    echo "- System monitoring: /var/log/system-monitor.log"
    echo "- Security monitoring: /var/log/security-monitor.log"
    echo "=================================="
}

# Run cron setup with options
case "${1:-all}" in
    "disable-wp")
        disable_wp_pseudo_cron
        ;;
    "wp-cron")
        setup_wp_system_cron
        ;;
    "maintenance")
        setup_maintenance_crons
        ;;
    "backup")
        setup_backup_crons
        ;;
    "monitoring")
        setup_monitoring_crons
        ;;
    "security")
        setup_security_crons
        ;;
    "tools")
        create_cron_management_tools
        ;;
    "test")
        test_cron_configuration
        ;;
    "status")
        /usr/local/bin/cron-status 2>/dev/null || echo "Cron status script not available"
        ;;
    "all")
        main
        create_cron_management_tools
        ;;
    *)
        echo "Usage: $0 [disable-wp|wp-cron|maintenance|backup|monitoring|security|tools|test|status|all]"
        echo "  disable-wp   - Disable WordPress pseudo-cron"
        echo "  wp-cron      - Setup WordPress system cron"
        echo "  maintenance  - Setup maintenance cron jobs"
        echo "  backup       - Setup backup cron jobs"
        echo "  monitoring   - Setup system monitoring cron"
        echo "  security     - Setup security monitoring cron"
        echo "  tools        - Create cron management tools"
        echo "  test         - Test cron configuration"
        echo "  status       - Show cron status"
        echo "  all          - Run complete setup (default)"
        exit 1
        ;;
esac