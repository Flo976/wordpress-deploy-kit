#!/bin/bash

# PHP 8.4 FPM Optimization Script
# Author: Florent Didelot
# Description: Configure PHP 8.4 FPM with performance tuning, OPcache, and security settings

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
PHP_VERSION="${PHP_VERSION:-8.4}"
PHP_FPM_PM="${PHP_FPM_PM:-dynamic}"
PHP_FPM_PM_MAX_CHILDREN="${PHP_FPM_PM_MAX_CHILDREN:-20}"
PHP_FPM_PM_START_SERVERS="${PHP_FPM_PM_START_SERVERS:-4}"
PHP_FPM_PM_MIN_SPARE_SERVERS="${PHP_FPM_PM_MIN_SPARE_SERVERS:-2}"
PHP_FPM_PM_MAX_SPARE_SERVERS="${PHP_FPM_PM_MAX_SPARE_SERVERS:-6}"
PHP_FPM_PM_MAX_REQUESTS="${PHP_FPM_PM_MAX_REQUESTS:-1000}"
PHP_MEMORY_LIMIT="${PHP_MEMORY_LIMIT:-256M}"
OPCACHE_MEMORY_CONSUMPTION="${OPCACHE_MEMORY_CONSUMPTION:-256}"
OPCACHE_MAX_ACCELERATED_FILES="${OPCACHE_MAX_ACCELERATED_FILES:-100000}"

# Error trap
trap 'log_error "PHP optimization failed on line $LINENO"' ERR

main() {
    log_info "Starting PHP $PHP_VERSION FPM optimization..."
    
    # Check if PHP is installed
    if ! command_exists php; then
        log_info "PHP not installed, installing PHP $PHP_VERSION..."
        install_php
    fi
    
    # Backup existing configuration
    backup_php_configs
    
    # Configure php.ini
    configure_php_ini
    
    # Configure PHP-FPM pool
    configure_php_fpm_pool
    
    # Configure OPcache
    configure_opcache
    
    # Configure session handling
    configure_sessions
    
    # Configure error handling and logging
    configure_error_handling
    
    # Configure security settings
    configure_security_settings
    
    # Create PHP log directories
    setup_php_logging
    
    # Test PHP configuration
    test_php_config
    
    # Restart PHP-FPM
    restart_service "php${PHP_VERSION}-fpm"
    
    log_success "PHP $PHP_VERSION FPM optimization completed successfully"
}

install_php() {
    log_info "Installing PHP $PHP_VERSION and extensions..."
    
    # Add PHP repository if needed
    if [[ ! -f /etc/apt/sources.list.d/ondrej-ubuntu-php-*.list ]]; then
        log_info "Adding Ondřej Surý PHP PPA..."
        add-apt-repository ppa:ondrej/php -y
        apt-get update -qq
    fi
    
    # Install PHP and essential extensions
    local php_packages=(
        "php${PHP_VERSION}-fpm"
        "php${PHP_VERSION}-cli"
        "php${PHP_VERSION}-common"
        "php${PHP_VERSION}-mysql"
        "php${PHP_VERSION}-xml"
        "php${PHP_VERSION}-xmlrpc"
        "php${PHP_VERSION}-curl"
        "php${PHP_VERSION}-gd"
        "php${PHP_VERSION}-imagick"
        "php${PHP_VERSION}-mbstring"
        "php${PHP_VERSION}-zip"
        "php${PHP_VERSION}-opcache"
        "php${PHP_VERSION}-intl"
        "php${PHP_VERSION}-bcmath"
        "php${PHP_VERSION}-soap"
        "php${PHP_VERSION}-readline"
    )
    
    log_info "Installing PHP packages: ${php_packages[*]}"
    apt-get install -y "${php_packages[@]}"
    
    # Install wp-cli
    if ! command_exists wp; then
        log_info "Installing WP-CLI..."
        curl -O https://raw.githubusercontent.com/wp-cli/wp-cli/v2.8.1/utils/wp-cli.phar
        chmod +x wp-cli.phar
        mv wp-cli.phar /usr/local/bin/wp
        
        # Verify installation
        if wp --info >/dev/null 2>&1; then
            log_success "WP-CLI installed successfully"
        else
            log_warn "WP-CLI installation may have issues"
        fi
    fi
}

backup_php_configs() {
    log_info "Backing up PHP configuration files..."
    
    local backup_dir="/etc/php/${PHP_VERSION}/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup main configs
    [[ -f "/etc/php/${PHP_VERSION}/fpm/php.ini" ]] && cp "/etc/php/${PHP_VERSION}/fpm/php.ini" "$backup_dir/"
    [[ -f "/etc/php/${PHP_VERSION}/cli/php.ini" ]] && cp "/etc/php/${PHP_VERSION}/cli/php.ini" "$backup_dir/"
    [[ -d "/etc/php/${PHP_VERSION}/fpm/pool.d" ]] && cp -r "/etc/php/${PHP_VERSION}/fpm/pool.d" "$backup_dir/"
    [[ -d "/etc/php/${PHP_VERSION}/fpm/conf.d" ]] && cp -r "/etc/php/${PHP_VERSION}/fpm/conf.d" "$backup_dir/"
    
    log_info "PHP configs backed up to: $backup_dir"
}

configure_php_ini() {
    log_info "Configuring php.ini for FPM and CLI..."
    
    local fpm_ini="/etc/php/${PHP_VERSION}/fpm/php.ini"
    local cli_ini="/etc/php/${PHP_VERSION}/cli/php.ini"
    
    # Configure FPM php.ini
    if [[ -f "$fpm_ini" ]]; then
        configure_single_php_ini "$fpm_ini" "fpm"
    else
        error_exit "PHP FPM ini file not found: $fmp_ini"
    fi
    
    # Configure CLI php.ini
    if [[ -f "$cli_ini" ]]; then
        configure_single_php_ini "$cli_ini" "cli"
    else
        error_exit "PHP CLI ini file not found: $cli_ini"
    fi
}

configure_single_php_ini() {
    local ini_file="$1"
    local sapi="$2"
    
    log_info "Configuring $ini_file for $sapi..."
    
    # Performance settings
    ini_set "$ini_file" "" "memory_limit" "$PHP_MEMORY_LIMIT"
    ini_set "$ini_file" "" "max_execution_time" "${PHP_MAX_EXECUTION_TIME:-300}"
    ini_set "$ini_file" "" "max_input_time" "${PHP_MAX_INPUT_TIME:-300}"
    ini_set "$ini_file" "" "max_input_vars" "${PHP_MAX_INPUT_VARS:-3000}"
    ini_set "$ini_file" "" "post_max_size" "${PHP_POST_MAX_SIZE:-64M}"
    ini_set "$ini_file" "" "upload_max_filesize" "${PHP_UPLOAD_MAX_FILESIZE:-64M}"
    ini_set "$ini_file" "" "max_file_uploads" "${PHP_MAX_FILE_UPLOADS:-20}"
    
    # Security settings
    ini_set "$ini_file" "" "expose_php" "Off"
    ini_set "$ini_file" "" "display_errors" "${PHP_DISPLAY_ERRORS:-Off}"
    ini_set "$ini_file" "" "display_startup_errors" "${PHP_DISPLAY_STARTUP_ERRORS:-Off}"
    ini_set "$ini_file" "" "log_errors" "${PHP_LOG_ERRORS:-On}"
    ini_set "$ini_file" "" "error_log" "${PHP_ERROR_LOG:-/var/log/php/error.log}"
    ini_set "$ini_file" "" "allow_url_fopen" "Off"
    ini_set "$ini_file" "" "allow_url_include" "Off"
    
    # Realpath cache optimization
    ini_set "$ini_file" "" "realpath_cache_size" "${REALPATH_CACHE_SIZE:-256k}"
    ini_set "$ini_file" "" "realpath_cache_ttl" "${REALPATH_CACHE_TTL:-600}"
    
    # Session settings
    ini_set "$ini_file" "" "session.save_handler" "${SESSION_SAVE_HANDLER:-files}"
    ini_set "$ini_file" "" "session.gc_maxlifetime" "${SESSION_GC_MAXLIFETIME:-7200}"
    ini_set "$ini_file" "" "session.gc_probability" "1"
    ini_set "$ini_file" "" "session.gc_divisor" "100"
    ini_set "$ini_file" "" "session.cookie_httponly" "1"
    ini_set "$ini_file" "" "session.cookie_secure" "1"
    ini_set "$ini_file" "" "session.use_strict_mode" "1"
    
    # Date settings
    ini_set "$ini_file" "" "date.timezone" "${PHP_TIMEZONE:-Europe/Paris}"
    
    # WordPress specific optimizations
    ini_set "$ini_file" "" "default_charset" "UTF-8"
    ini_set "$ini_file" "" "mbstring.internal_encoding" "UTF-8"
    ini_set "$ini_file" "" "mbstring.http_output" "UTF-8"
    
    # Development settings (only if DEV_MODE=true)
    if [[ "${DEV_MODE:-false}" == "true" ]]; then
        ini_set "$ini_file" "" "display_errors" "On"
        ini_set "$ini_file" "" "display_startup_errors" "On"
        ini_set "$ini_file" "" "error_reporting" "E_ALL"
    else
        ini_set "$ini_file" "" "error_reporting" "E_ALL & ~E_DEPRECATED & ~E_STRICT"
    fi
}

configure_opcache() {
    log_info "Configuring OPcache..."
    
    local opcache_ini="/etc/php/${PHP_VERSION}/fpm/conf.d/10-opcache.ini"
    
    # Create or update OPcache configuration
    cat > "$opcache_ini" << EOF
; OPcache Configuration
; Determines if Zend OPCache is enabled
opcache.enable=${OPCACHE_ENABLE:-1}

; Determines if Zend OPCache is enabled for the CLI version of PHP
opcache.enable_cli=0

; The OPcache shared memory consumption, in megabytes
opcache.memory_consumption=${OPCACHE_MEMORY_CONSUMPTION}

; The amount of memory for interned strings, in megabytes
opcache.interned_strings_buffer=${OPCACHE_INTERNED_STRINGS_BUFFER:-64}

; The maximum number of keys (scripts) in the OPcache hash table
opcache.max_accelerated_files=${OPCACHE_MAX_ACCELERATED_FILES}

; When disabled, you must reset the OPcache manually or restart the webserver
opcache.validate_timestamps=${OPCACHE_VALIDATE_TIMESTAMPS:-0}

; How often (in seconds) to check file timestamps for changes to the shared memory
opcache.revalidate_freq=${OPCACHE_REVALIDATE_FREQ:-0}

; Enables and sets the second level cache directory
; opcache.file_cache=/tmp/opcache

; Enables or disables file cache
; opcache.file_cache_only=0

; Enables or disables copying of PHP code (text segment) into HUGE PAGES
opcache.huge_code_pages=1

; Validate cached file permissions
opcache.validate_permission=1

; Prevent caching of files that are less than this number of seconds old
opcache.file_update_protection=2

; Ignore file timestamps
opcache.save_comments=${OPCACHE_SAVE_COMMENTS:-0}

; If enabled, compilation warnings will be recorded and replayed each time a file is included
opcache.record_warnings=0

; Allow file existence override (file_exists, is_file, etc.) performance feature
opcache.enable_file_override=1

; A bitmask, where each bit enables or disables the appropriate OPcache passes
opcache.optimization_level=0x7FFFBFFF

; JIT configuration (PHP 8.0+)
opcache.jit_buffer_size=${OPCACHE_JIT_BUFFER_SIZE:-128M}
opcache.jit=${OPCACHE_JIT:-1255}

; Preload script (uncomment and set path if needed)
; opcache.preload=/var/www/html/preload.php
; opcache.preload_user=www-data

EOF

    # Copy to CLI directory as well
    cp "$opcache_ini" "/etc/php/${PHP_VERSION}/cli/conf.d/10-opcache.ini"
    
    log_info "OPcache configured with ${OPCACHE_MEMORY_CONSUMPTION}MB memory and ${OPCACHE_MAX_ACCELERATED_FILES} max files"
}

configure_php_fpm_pool() {
    log_info "Configuring PHP-FPM pool..."
    
    local pool_config="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
    
    # Backup original pool config
    [[ -f "$pool_config" ]] && backup_file "$pool_config"
    
    cat > "$pool_config" << EOF
; Pool configuration for www
[www]

; Unix user/group of processes
user = www-data
group = www-data

; The address on which to accept FastCGI requests
listen = /run/php/php${PHP_VERSION}-fpm.sock

; Set listen(2) backlog
listen.backlog = 511

; Set permissions for unix socket
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

; Choose how the process manager will control the number of child processes
pm = ${PHP_FPM_PM}

; The number of child processes to be created when pm is set to 'static'
pm.max_children = ${PHP_FPM_PM_MAX_CHILDREN}

; The number of child processes created on startup
pm.start_servers = ${PHP_FPM_PM_START_SERVERS}

; The desired minimum number of idle server processes
pm.min_spare_servers = ${PHP_FPM_PM_MIN_SPARE_SERVERS}

; The desired maximum number of idle server processes
pm.max_spare_servers = ${PHP_FPM_PM_MAX_SPARE_SERVERS}

; The number of requests each child process should execute before respawning
pm.max_requests = ${PHP_FPM_PM_MAX_REQUESTS}

; The URI to view the FPM status page
pm.status_path = /status

; The ping URI to call the monitoring page of FPM
ping.path = /ping

; Process Idle Timeout
pm.process_idle_timeout = 10s

; Request Terminate Timeout
request_terminate_timeout = ${PHP_MAX_EXECUTION_TIME:-300}s

; Request slowlog timeout
request_slowlog_timeout = 5s
slowlog = /var/log/php${PHP_VERSION}-fpm-slow.log

; Limits the extensions of the main script FPM will allow to parse
security.limit_extensions = .php .phtml

; Environment variables
env[HOSTNAME] = \$HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp

; Additional php.ini defines
php_admin_value[sendmail_path] = /usr/sbin/sendmail -t -i -f www@my.domain.com
php_flag[display_errors] = off
php_admin_value[error_log] = /var/log/php${PHP_VERSION}-fpm-error.log
php_admin_flag[log_errors] = on
php_admin_value[memory_limit] = ${PHP_MEMORY_LIMIT}
php_admin_value[max_execution_time] = ${PHP_MAX_EXECUTION_TIME:-300}
php_admin_value[max_input_time] = ${PHP_MAX_INPUT_TIME:-300}
php_admin_value[max_input_vars] = ${PHP_MAX_INPUT_VARS:-3000}
php_admin_value[post_max_size] = ${PHP_POST_MAX_SIZE:-64M}
php_admin_value[upload_max_filesize] = ${PHP_UPLOAD_MAX_FILESIZE:-64M}

; Catch output from PHP code
catch_workers_output = yes

; Clear environment in FPM workers
clear_env = no

; Ensure worker stdout and stderr are sent to the main error log
decorate_workers_output = no

EOF

    log_info "PHP-FPM pool configured with pm=${PHP_FPM_PM}, max_children=${PHP_FPM_PM_MAX_CHILDREN}"
}

configure_sessions() {
    log_info "Configuring PHP session handling..."
    
    # Create session directory with proper permissions
    local session_dir="/var/lib/php/sessions"
    create_dir "$session_dir" "www-data:www-data" "755"
    
    # Configure session cleanup
    cat > "/etc/cron.d/php${PHP_VERSION}-session-cleanup" << EOF
# Clean up PHP session files every 30 minutes
*/30 * * * * root find /var/lib/php/sessions -type f -name 'sess_*' -mmin +$(( ${SESSION_GC_MAXLIFETIME:-7200} / 60 )) -delete
EOF
    
    log_info "PHP session handling configured"
}

configure_error_handling() {
    log_info "Configuring PHP error handling and logging..."
    
    # Create PHP error log configuration
    local error_conf="/etc/php/${PHP_VERSION}/fpm/conf.d/99-error-handling.ini"
    
    cat > "$error_conf" << EOF
; Error handling configuration
log_errors = ${PHP_LOG_ERRORS:-On}
error_log = ${PHP_ERROR_LOG:-/var/log/php/error.log}
display_errors = ${PHP_DISPLAY_ERRORS:-Off}
display_startup_errors = ${PHP_DISPLAY_STARTUP_ERRORS:-Off}
error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT

; WordPress specific error handling
log_errors_max_len = 1024
ignore_repeated_errors = On
ignore_repeated_source = Off
report_memleaks = On
track_errors = Off

; HTML errors (disabled for security)
html_errors = Off
docref_root = ""
docref_ext = ""
EOF

    # Copy to CLI
    cp "$error_conf" "/etc/php/${PHP_VERSION}/cli/conf.d/99-error-handling.ini"
    
    log_info "PHP error handling configured"
}

configure_security_settings() {
    log_info "Configuring PHP security settings..."
    
    local security_conf="/etc/php/${PHP_VERSION}/fpm/conf.d/99-security.ini"
    
    cat > "$security_conf" << EOF
; PHP Security Configuration

; Hide PHP version
expose_php = Off

; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; File upload security
file_uploads = On
upload_max_filesize = ${PHP_UPLOAD_MAX_FILESIZE:-64M}
max_file_uploads = ${PHP_MAX_FILE_UPLOADS:-20}
upload_tmp_dir = /tmp

; Disable remote file inclusion
allow_url_fopen = Off
allow_url_include = Off

; Session security
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
session.cookie_samesite = "Strict"

; Prevent information disclosure
expose_php = Off
mail.add_x_header = Off

; Resource limits
max_input_nesting_level = 64
max_input_vars = ${PHP_MAX_INPUT_VARS:-3000}
memory_limit = ${PHP_MEMORY_LIMIT}

; CGI security
cgi.fix_pathinfo = 0

; Open basedir restriction (uncomment if needed)
; open_basedir = /var/www/html:/tmp:/usr/share/php

EOF

    # Copy to CLI
    cp "$security_conf" "/etc/php/${PHP_VERSION}/cli/conf.d/99-security.ini"
    
    log_info "PHP security settings configured"
}

setup_php_logging() {
    log_info "Setting up PHP logging directories..."
    
    # Create log directory
    create_dir "/var/log/php" "www-data:adm" "750"
    
    # Create log files
    touch "/var/log/php/error.log"
    touch "/var/log/php${PHP_VERSION}-fpm-error.log"
    touch "/var/log/php${PHP_VERSION}-fpm-slow.log"
    
    # Set permissions
    chown www-data:adm "/var/log/php"/*.log
    chmod 640 "/var/log/php"/*.log
    
    # Configure logrotate
    cat > "/etc/logrotate.d/php${PHP_VERSION}-fpm" << EOF
/var/log/php/*.log {
    weekly
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 www-data adm
    postrotate
        /usr/lib/php/php${PHP_VERSION}-fpm-reopenlogs
    endscript
}
EOF
    
    log_info "PHP logging configured"
}

test_php_config() {
    log_info "Testing PHP configuration..."
    
    # Test FPM configuration
    if php-fpm${PHP_VERSION} -t; then
        log_success "PHP-FPM configuration test passed"
    else
        error_exit "PHP-FPM configuration test failed"
    fi
    
    # Test CLI configuration
    if php -m >/dev/null 2>&1; then
        log_success "PHP CLI configuration test passed"
    else
        log_warn "PHP CLI configuration has issues"
    fi
    
    # Check critical modules
    local required_modules=(
        "opcache"
        "mysqli"
        "mbstring"
        "xml"
        "gd"
        "curl"
        "zip"
        "json"
        "fileinfo"
        "openssl"
    )
    
    log_info "Checking required PHP modules..."
    for module in "${required_modules[@]}"; do
        if php -m | grep -q "^$module$"; then
            log_info "PHP module $module: loaded"
        else
            log_warn "PHP module $module: not loaded"
        fi
    done
}

show_php_status() {
    log_info "PHP status and configuration:"
    
    echo "=== PHP Version ==="
    php -v
    echo
    
    echo "=== PHP-FPM Status ==="
    if service_is_active "php${PHP_VERSION}-fpm"; then
        systemctl status "php${PHP_VERSION}-fpm" --no-pager
        echo
    fi
    
    echo "=== PHP Configuration ==="
    php -i | grep -E "(memory_limit|max_execution_time|upload_max_filesize|opcache)" | sort
    echo
    
    echo "=== PHP Modules ==="
    php -m | sort
    echo
    
    echo "=== PHP-FPM Pool Status ==="
    if [[ -S "/run/php/php${PHP_VERSION}-fpm.sock" ]]; then
        echo "PHP-FPM socket: /run/php/php${PHP_VERSION}-fpm.sock (exists)"
        ls -la "/run/php/php${PHP_VERSION}-fpm.sock"
    else
        echo "PHP-FPM socket: not found"
    fi
    echo
    
    echo "=== OPcache Status ==="
    if php -m | grep -q opcache; then
        php -r "print_r(opcache_get_configuration()['directives']);" 2>/dev/null || echo "OPcache not accessible via CLI"
    else
        echo "OPcache not loaded"
    fi
}

create_php_info_page() {
    log_info "Creating PHP info page..."
    
    local phpinfo_file="/var/www/html/phpinfo.php"
    
    cat > "$phpinfo_file" << 'EOF'
<?php
// PHP Information Page
// Remove this file in production for security

// Check if accessed from localhost only
$allowed_ips = ['127.0.0.1', '::1'];
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if (!in_array($client_ip, $allowed_ips)) {
    http_response_code(403);
    die('Access denied');
}

phpinfo();
?>
EOF
    
    chown www-data:www-data "$phpinfo_file"
    chmod 644 "$phpinfo_file"
    
    log_info "PHP info page created at /phpinfo.php (localhost only)"
}

# Create OPcache status page
create_opcache_status_page() {
    log_info "Creating OPcache status page..."
    
    local opcache_file="/var/www/html/opcache-status.php"
    
    cat > "$opcache_file" << 'EOF'
<?php
// OPcache Status Page
// Remove this file in production for security

// Check if accessed from localhost only
$allowed_ips = ['127.0.0.1', '::1'];
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if (!in_array($client_ip, $allowed_ips)) {
    http_response_code(403);
    die('Access denied');
}

if (!extension_loaded('Zend OPcache')) {
    die('OPcache is not loaded');
}

$status = opcache_get_status();
$config = opcache_get_configuration();

echo "<h1>OPcache Status</h1>";
echo "<h2>Configuration</h2>";
echo "<pre>";
print_r($config['directives']);
echo "</pre>";

echo "<h2>Status</h2>";
echo "<pre>";
print_r($status);
echo "</pre>";

if (isset($_GET['reset']) && $_GET['reset'] === '1') {
    if (opcache_reset()) {
        echo "<p><strong>OPcache has been reset successfully!</strong></p>";
    } else {
        echo "<p><strong>Failed to reset OPcache!</strong></p>";
    }
}

echo '<p><a href="?reset=1">Reset OPcache</a></p>';
?>
EOF
    
    chown www-data:www-data "$opcache_file"
    chmod 644 "$opcache_file"
    
    log_info "OPcache status page created at /opcache-status.php (localhost only)"
}

# Run optimization with options
case "${1:-all}" in
    "install")
        install_php
        ;;
    "ini")
        configure_php_ini
        test_php_config
        restart_service "php${PHP_VERSION}-fpm"
        ;;
    "fpm")
        configure_php_fpm_pool
        test_php_config
        restart_service "php${PHP_VERSION}-fpm"
        ;;
    "opcache")
        configure_opcache
        test_php_config
        restart_service "php${PHP_VERSION}-fpm"
        ;;
    "security")
        configure_security_settings
        test_php_config
        restart_service "php${PHP_VERSION}-fpm"
        ;;
    "status")
        show_php_status
        ;;
    "info")
        create_php_info_page
        create_opcache_status_page
        ;;
    "test")
        test_php_config
        ;;
    "all")
        main
        create_php_info_page
        create_opcache_status_page
        ;;
    *)
        echo "Usage: $0 [install|ini|fpm|opcache|security|status|info|test|all]"
        echo "  install   - Install PHP and extensions"
        echo "  ini       - Configure php.ini files"
        echo "  fpm       - Configure PHP-FPM pool"
        echo "  opcache   - Configure OPcache"
        echo "  security  - Configure security settings"
        echo "  status    - Show PHP status and configuration"
        echo "  info      - Create PHP info and OPcache status pages"
        echo "  test      - Test PHP configuration"
        echo "  all       - Run full optimization (default)"
        exit 1
        ;;
esac