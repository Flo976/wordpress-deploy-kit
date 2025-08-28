#!/bin/bash

# Apache 2.4 Optimization Script
# Author: Florent Didelot 
# Description: Configure Apache with MPM Event, HTTP/2, Brotli, SSL, and performance optimizations

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
APACHE_MPM_EVENT_MAX_REQUEST_WORKERS="${APACHE_MPM_EVENT_MAX_REQUEST_WORKERS:-256}"
APACHE_MPM_EVENT_THREADS_PER_CHILD="${APACHE_MPM_EVENT_THREADS_PER_CHILD:-25}"
APACHE_MPM_EVENT_SERVER_LIMIT="${APACHE_MPM_EVENT_SERVER_LIMIT:-16}"
APACHE_MPM_EVENT_THREAD_LIMIT="${APACHE_MPM_EVENT_THREAD_LIMIT:-64}"
ENABLE_HTTP2="${ENABLE_HTTP2:-true}"
ENABLE_BROTLI="${ENABLE_BROTLI:-true}"
APACHE_SERVER_TOKENS="${APACHE_SERVER_TOKENS:-Prod}"
APACHE_SERVER_SIGNATURE="${APACHE_SERVER_SIGNATURE:-Off}"
KEEP_ALIVE="${KEEP_ALIVE:-On}"
KEEP_ALIVE_TIMEOUT="${KEEP_ALIVE_TIMEOUT:-5}"
MAX_KEEP_ALIVE_REQUESTS="${MAX_KEEP_ALIVE_REQUESTS:-100}"

# Error trap
trap 'log_error "Apache optimization failed on line $LINENO"' ERR

main() {
    log_info "Starting Apache optimization..."
    
    # Check if Apache is installed
    if ! command_exists apache2; then
        error_exit "Apache2 is not installed"
    fi
    
    # Backup existing configuration
    backup_apache_configs
    
    # Configure MPM Event
    configure_mpm_event
    
    # Enable required modules
    enable_apache_modules
    
    # Configure performance settings
    configure_performance_settings
    
    # Configure security headers
    configure_security_headers
    
    # Configure SSL/TLS settings
    configure_ssl_settings
    
    # Create virtual hosts
    configure_virtual_hosts
    
    # Configure PHP-FPM integration
    configure_php_fpm_integration
    
    # Configure compression
    configure_compression
    
    # Configure caching headers
    configure_caching_headers
    
    # Optimize directory options
    configure_directory_options
    
    # Test configuration
    test_apache_config
    
    # Restart Apache
    restart_service apache2
    
    log_success "Apache optimization completed successfully"
}

backup_apache_configs() {
    log_info "Backing up Apache configuration files..."
    
    local backup_dir="/etc/apache2/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup main configs
    cp -r /etc/apache2/sites-available "$backup_dir/"
    cp -r /etc/apache2/mods-available "$backup_dir/"
    cp -r /etc/apache2/conf-available "$backup_dir/"
    [[ -f /etc/apache2/apache2.conf ]] && cp /etc/apache2/apache2.conf "$backup_dir/"
    [[ -f /etc/apache2/ports.conf ]] && cp /etc/apache2/ports.conf "$backup_dir/"
    
    log_info "Apache configs backed up to: $backup_dir"
}

configure_mpm_event() {
    log_info "Configuring MPM Event module..."
    
    # Disable prefork and enable event
    a2dismod mpm_prefork 2>/dev/null || true
    a2enmod mpm_event
    
    # Configure MPM Event settings
    local mpm_config="/etc/apache2/mods-available/mpm_event.conf"
    
    cat > "$mpm_config" << EOF
<IfModule mod_mpm_event.c>
    # StartServers: initial number of server processes to start
    StartServers                     2
    
    # MinSpareThreads: minimum number of idle threads to keep alive
    MinSpareThreads                  25
    
    # MaxSpareThreads: maximum number of idle threads
    MaxSpareThreads                  75
    
    # ThreadLimit: maximum number of threads per child process
    ThreadLimit                      $APACHE_MPM_EVENT_THREAD_LIMIT
    
    # ThreadsPerChild: constant number of threads in each child process
    ThreadsPerChild                  $APACHE_MPM_EVENT_THREADS_PER_CHILD
    
    # MaxRequestWorkers: maximum number of simultaneous requests
    MaxRequestWorkers                $APACHE_MPM_EVENT_MAX_REQUEST_WORKERS
    
    # ServerLimit: maximum number of child processes
    ServerLimit                      $APACHE_MPM_EVENT_SERVER_LIMIT
    
    # MaxConnectionsPerChild: maximum number of requests a child process handles
    MaxConnectionsPerChild           10000
    
    # AsyncRequestWorkerFactor: async connections multiplier
    AsyncRequestWorkerFactor         2
</IfModule>
EOF

    log_info "MPM Event configured with MaxRequestWorkers: $APACHE_MPM_EVENT_MAX_REQUEST_WORKERS"
}

enable_apache_modules() {
    log_info "Enabling Apache modules..."
    
    # Essential modules
    local modules=(
        "rewrite"
        "headers"
        "expires"
        "ssl"
        "proxy"
        "proxy_fcgi"
        "setenvif"
        "remoteip"
        "status"
        "info"
    )
    
    # HTTP/2 module
    if [[ "$ENABLE_HTTP2" == "true" ]]; then
        modules+=("http2")
    fi
    
    # Compression modules
    if [[ "$ENABLE_BROTLI" == "true" ]]; then
        # Check if brotli module is available
        if [[ -f /etc/apache2/mods-available/brotli.load ]]; then
            modules+=("brotli")
        elif [[ -f /usr/lib/apache2/modules/mod_brotli.so ]]; then
            # Create brotli module config if module exists but not configured
            create_brotli_module_config
            modules+=("brotli")
        else
            log_warn "Brotli module not found, will use deflate instead"
            modules+=("deflate")
        fi
    else
        modules+=("deflate")
    fi
    
    # Enable modules
    for module in "${modules[@]}"; do
        if a2enmod "$module" >/dev/null 2>&1; then
            log_info "Enabled module: $module"
        else
            log_warn "Failed to enable module: $module (may not be available)"
        fi
    done
}

create_brotli_module_config() {
    log_info "Creating Brotli module configuration..."
    
    cat > /etc/apache2/mods-available/brotli.load << EOF
LoadModule brotli_module /usr/lib/apache2/modules/mod_brotli.so
EOF

    cat > /etc/apache2/mods-available/brotli.conf << EOF
<IfModule mod_brotli.c>
    # Enable brotli compression
    BrotliCompressionLevel 6
    BrotliCompressionWindowSize 18
    BrotliCompressionMemLevel 6
    
    # Compress specific MIME types
    BrotliFilter text/html text/plain text/xml text/css text/javascript
    BrotliFilter application/x-javascript application/javascript application/ecmascript
    BrotliFilter application/rss+xml application/xml application/json
    BrotliFilter image/svg+xml
</IfModule>
EOF
}

configure_performance_settings() {
    log_info "Configuring Apache performance settings..."
    
    # Main Apache configuration
    local apache_conf="/etc/apache2/apache2.conf"
    
    # Server signature and tokens
    if ! grep -q "ServerTokens" "$apache_conf"; then
        echo "ServerTokens $APACHE_SERVER_TOKENS" >> "$apache_conf"
    else
        sed -i "s/^ServerTokens.*/ServerTokens $APACHE_SERVER_TOKENS/" "$apache_conf"
    fi
    
    if ! grep -q "ServerSignature" "$apache_conf"; then
        echo "ServerSignature $APACHE_SERVER_SIGNATURE" >> "$apache_conf"
    else
        sed -i "s/^ServerSignature.*/ServerSignature $APACHE_SERVER_SIGNATURE/" "$apache_conf"
    fi
    
    # Keep alive settings
    create_performance_conf
    
    log_info "Performance settings configured"
}

create_performance_conf() {
    cat > /etc/apache2/conf-available/performance.conf << EOF
# Apache Performance Configuration

# Keep alive settings
KeepAlive $KEEP_ALIVE
KeepAliveTimeout $KEEP_ALIVE_TIMEOUT
MaxKeepAliveRequests $MAX_KEEP_ALIVE_REQUESTS

# Timeout settings
Timeout 60
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500

# Hostname lookups
HostnameLookups Off

# Hide server information
ServerTokens $APACHE_SERVER_TOKENS
ServerSignature $APACHE_SERVER_SIGNATURE

# Disable server info
<Location "/server-status">
    SetHandler server-status
    Require local
</Location>

<Location "/server-info">
    SetHandler server-info
    Require local
</Location>

# File upload limits
LimitRequestBody 104857600  # 100MB

# Disable TRACE method
TraceEnable Off
EOF

    a2enconf performance
}

configure_security_headers() {
    log_info "Configuring security headers..."
    
    cat > /etc/apache2/conf-available/security-headers.conf << EOF
# Security Headers Configuration

<IfModule mod_headers.c>
    # Remove server information
    Header always unset "Server"
    Header always unset "X-Powered-By"
    
    # Content Security Policy (basic)
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
    
    # Other security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()"
    
    # Remove sensitive headers
    Header always unset "X-Pingback"
    Header always unset "Link"
    Header always unset "ETag"
    
    # HSTS header (only for HTTPS and non-.local domains)
    <If "%{HTTPS} == 'on' && !(%{HTTP_HOST} =~ /\.local$/)">
        Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    </If>
</IfModule>
EOF

    a2enconf security-headers
}

configure_ssl_settings() {
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]] || [[ -f "/etc/ssl/certs/ssl-cert-snakeoil.pem" ]]; then
        log_info "Configuring SSL/TLS settings..."
        
        cat > /etc/apache2/conf-available/ssl-params.conf << EOF
# SSL Configuration

<IfModule mod_ssl.c>
    # SSL Protocol Support
    SSLProtocol ${SSL_PROTOCOL:-TLSv1.2 TLSv1.3}
    
    # SSL Cipher Suite
    SSLCipherSuite ${SSL_CIPHER_SUITE:-ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384}
    
    # Prefer server ciphers
    SSLHonorCipherOrder On
    
    # SSL compression (disable for security)
    SSLCompression Off
    
    # SSL session cache
    SSLSessionCache shmcb:/var/run/apache2/ssl_scache(512000)
    SSLSessionCacheTimeout 300
    
    # SSL stapling
    SSLUseStapling On
    SSLStaplingCache shmcb:/var/run/apache2/ssl_stapling_cache(128000)
    
    # SSL options
    SSLOptions +StrictRequire
    
    # Headers for SSL
    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" env=HTTPS
    </IfModule>
</IfModule>
EOF

        a2enconf ssl-params
    else
        log_info "SSL not configured (ENABLE_LETSENCRYPT=false and no SSL cert found)"
    fi
}

configure_virtual_hosts() {
    log_info "Configuring virtual hosts..."
    
    local domain="${DOMAIN:-localhost}"
    local http_port="${HTTP_PORT:-80}"
    local https_port="${HTTPS_PORT:-443}"
    
    # HTTP virtual host
    cat > "/etc/apache2/sites-available/000-default.conf" << EOF
<VirtualHost *:$http_port>
    ServerName $domain
    DocumentRoot /var/www/html
    
    # Logging
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
    
    # PHP-FPM integration
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php${PHP_VERSION:-8.4}-fpm.sock|fcgi://localhost/"
    </FilesMatch>
    
    # WordPress specific settings
    <Directory "/var/www/html">
        AllowOverride All
        Options -Indexes +FollowSymLinks
        Require all granted
        
        # WordPress permalink structure
        <IfModule mod_rewrite.c>
            RewriteEngine On
            RewriteBase /
            RewriteRule ^index\.php$ - [L]
            RewriteCond %{REQUEST_FILENAME} !-f
            RewriteCond %{REQUEST_FILENAME} !-d
            RewriteRule . /index.php [L]
        </IfModule>
    </Directory>
    
    # Deny access to sensitive files
    <Files "wp-config.php">
        Require all denied
    </Files>
    
    <Files ".htaccess">
        Require all denied
    </Files>
    
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>
    
    # Redirect to HTTPS if SSL is enabled
    <IfDefine SSL_ENABLED>
        RewriteEngine On
        RewriteCond %{HTTPS} off
        RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
    </IfDefine>
</VirtualHost>
EOF

    # HTTPS virtual host (if SSL is enabled)
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]] || [[ -f "/etc/ssl/certs/ssl-cert-snakeoil.pem" ]]; then
        create_https_virtualhost
    fi
    
    # Disable default sites and enable our configuration
    a2dissite 000-default 2>/dev/null || true
    a2dissite default-ssl 2>/dev/null || true
    a2ensite 000-default
    
    if [[ -f "/etc/apache2/sites-available/000-default-ssl.conf" ]]; then
        a2ensite 000-default-ssl
    fi
}

create_https_virtualhost() {
    log_info "Creating HTTPS virtual host..."
    
    local domain="${DOMAIN:-localhost}"
    local https_port="${HTTPS_PORT:-443}"
    
    cat > "/etc/apache2/sites-available/000-default-ssl.conf" << EOF
<VirtualHost *:$https_port>
    ServerName $domain
    DocumentRoot /var/www/html
    
    # SSL Configuration
    SSLEngine on
    
    # SSL Certificate paths (will be updated by Let's Encrypt or use snakeoil)
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    
    # HTTP/2 Support
    <IfModule mod_http2.c>
        Protocols h2 http/1.1
        H2Direct on
        H2Upgrade on
        H2Push on
        
        # HTTP/2 settings
        H2MaxSessionStreams 100
        H2SessionExtraFiles 10
        H2StreamMaxMemSize 65536
    </IfModule>
    
    # Logging
    ErrorLog \${APACHE_LOG_DIR}/ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/ssl_access.log combined
    
    # PHP-FPM integration
    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php${PHP_VERSION:-8.4}-fpm.sock|fcgi://localhost/"
    </FilesMatch>
    
    # WordPress specific settings
    <Directory "/var/www/html">
        AllowOverride All
        Options -Indexes +FollowSymLinks
        Require all granted
        
        # WordPress permalink structure
        <IfModule mod_rewrite.c>
            RewriteEngine On
            RewriteBase /
            RewriteRule ^index\.php$ - [L]
            RewriteCond %{REQUEST_FILENAME} !-f
            RewriteCond %{REQUEST_FILENAME} !-d
            RewriteRule . /index.php [L]
        </IfModule>
    </Directory>
    
    # Deny access to sensitive files
    <Files "wp-config.php">
        Require all denied
    </Files>
    
    <Files ".htaccess">
        Require all denied
    </Files>
    
    <FilesMatch "^\.">
        Require all denied
    </FilesMatch>
</VirtualHost>

# Enable SSL define
Define SSL_ENABLED
EOF
}

configure_php_fpm_integration() {
    log_info "Configuring PHP-FPM integration..."
    
    # Create PHP-FPM status page configuration
    cat > /etc/apache2/conf-available/php-fpm-status.conf << EOF
# PHP-FPM Status Page

<Location "/fpm-status">
    SetHandler "proxy:unix:/run/php/php${PHP_VERSION:-8.4}-fpm.sock|fcgi://localhost/status"
    Require local
    # Uncomment below for basic auth protection
    # AuthType Basic
    # AuthName "FPM Status"
    # AuthUserFile /etc/apache2/.htpasswd
    # Require valid-user
</Location>

<Location "/fpm-ping">
    SetHandler "proxy:unix:/run/php/php${PHP_VERSION:-8.4}-fpm.sock|fcgi://localhost/ping"
    Require local
</Location>
EOF

    a2enconf php-fpm-status
}

configure_compression() {
    log_info "Configuring compression..."
    
    if [[ "$ENABLE_BROTLI" == "true" ]] && a2enmod brotli >/dev/null 2>&1; then
        cat > /etc/apache2/conf-available/brotli-compression.conf << EOF
# Brotli Compression Configuration

<IfModule mod_brotli.c>
    # Enable brotli for specific file types
    <Location />
        SetOutputFilter BROTLI_COMPRESS
        SetEnvIfNoCase Request_URI \
            \.(?:gif|jpe?g|png|ico|bmp|webp|svg)$ no-brotli dont-vary
        SetEnvIfNoCase Request_URI \
            \.(?:exe|t?gz|zip|bz2|sit|rar|7z)$ no-brotli dont-vary
    </Location>
    
    # Brotli compression level (1-11, 6 is good balance)
    BrotliCompressionLevel 6
    
    # File types to compress
    BrotliFilter text/html text/plain text/xml text/css text/javascript
    BrotliFilter application/x-javascript application/javascript application/ecmascript
    BrotliFilter application/rss+xml application/xml application/json
    BrotliFilter application/x-font-ttf application/vnd.ms-fontobject
    BrotliFilter font/opentype image/svg+xml image/x-icon
</IfModule>
EOF
        a2enconf brotli-compression
    else
        # Fallback to deflate compression
        cat > /etc/apache2/conf-available/deflate-compression.conf << EOF
# Deflate Compression Configuration

<IfModule mod_deflate.c>
    # Compress specific file types
    <Location />
        SetOutputFilter DEFLATE
        SetEnvIfNoCase Request_URI \
            \.(?:gif|jpe?g|png|ico|bmp|webp)$ no-gzip dont-vary
        SetEnvIfNoCase Request_URI \
            \.(?:exe|t?gz|zip|bz2|sit|rar|7z)$ no-gzip dont-vary
    </Location>
    
    # Compression level (1-9)
    DeflateCompressionLevel 6
    
    # File types to compress
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE text/javascript
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
    AddOutputFilterByType DEFLATE application/json
    AddOutputFilterByType DEFLATE image/svg+xml
    AddOutputFilterByType DEFLATE application/x-font-ttf
    AddOutputFilterByType DEFLATE font/opentype
</IfModule>
EOF
        a2enconf deflate-compression
    fi
}

configure_caching_headers() {
    log_info "Configuring caching headers..."
    
    cat > /etc/apache2/conf-available/caching.conf << EOF
# Browser Caching Configuration

<IfModule mod_expires.c>
    ExpiresActive On
    
    # Default expiration
    ExpiresDefault "${EXPIRES_DEFAULT:-access plus 1 month}"
    
    # HTML documents
    ExpiresByType text/html "${EXPIRES_TEXT:-access plus 1 week}"
    
    # CSS and JavaScript
    ExpiresByType text/css "access plus 1 year"
    ExpiresByType application/javascript "access plus 1 year"
    ExpiresByType text/javascript "access plus 1 year"
    
    # Images
    ExpiresByType image/png "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/jpg "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/jpeg "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/gif "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/ico "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/icon "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/x-icon "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/webp "${EXPIRES_IMAGES:-access plus 1 year}"
    ExpiresByType image/svg+xml "${EXPIRES_IMAGES:-access plus 1 year}"
    
    # Fonts
    ExpiresByType font/truetype "access plus 1 year"
    ExpiresByType font/opentype "access plus 1 year"
    ExpiresByType application/x-font-woff "access plus 1 year"
    ExpiresByType application/x-font-woff2 "access plus 1 year"
    
    # Media files
    ExpiresByType video/mp4 "access plus 1 year"
    ExpiresByType audio/mpeg "access plus 1 year"
    
    # Archives
    ExpiresByType application/zip "access plus 1 month"
    ExpiresByType application/pdf "access plus 1 month"
</IfModule>

<IfModule mod_headers.c>
    # Cache-Control headers
    <FilesMatch "\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|otf)$">
        Header set Cache-Control "max-age=31536000, public, immutable"
    </FilesMatch>
    
    <FilesMatch "\.(html|htm)$">
        Header set Cache-Control "max-age=3600, public, must-revalidate"
    </FilesMatch>
    
    # ETags (disable for better caching)
    Header unset ETag
    FileETag None
</IfModule>
EOF

    a2enconf caching
}

configure_directory_options() {
    log_info "Configuring directory options and security..."
    
    cat > /etc/apache2/conf-available/directory-security.conf << EOF
# Directory Security Configuration

# Disable server signature in error pages
ServerSignature Off

# Disable directory browsing
Options -Indexes

# Disable server-side includes and CGI
Options -Includes -ExecCGI

# Deny access to .htaccess and other sensitive files
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

# Deny access to backup and temporary files
<FilesMatch "\.(bak|backup|swp|tmp|temp)$">
    Require all denied
</FilesMatch>

# Deny access to configuration files
<FilesMatch "^(wp-config|config|configuration)\.(php|inc|conf)$">
    Require all denied
</FilesMatch>

# Restrict access to wp-content uploads (prevent PHP execution)
<Directory "/var/www/html/wp-content/uploads">
    <Files "*.php">
        Require all denied
    </Files>
</Directory>

# Protect wp-admin
<Directory "/var/www/html/wp-admin">
    # Add IP restrictions here if needed
    # Require ip 192.168.1.0/24
</Directory>

# Limit HTTP methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# Disable HTTP TRACE method
TraceEnable Off

# Set security headers
<IfModule mod_headers.c>
    # Prevent clickjacking
    Header always append X-Frame-Options SAMEORIGIN
    
    # Prevent MIME type sniffing
    Header always set X-Content-Type-Options nosniff
    
    # Enable XSS protection
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
EOF

    a2enconf directory-security
}

test_apache_config() {
    log_info "Testing Apache configuration..."
    
    if apache2ctl configtest; then
        log_success "Apache configuration test passed"
    else
        error_exit "Apache configuration test failed"
    fi
    
    # Check for syntax warnings
    local config_test_output
    config_test_output=$(apache2ctl configtest 2>&1)
    
    if echo "$config_test_output" | grep -q "warn"; then
        log_warn "Apache configuration warnings detected:"
        echo "$config_test_output" | grep -i "warn" | while read -r line; do
            log_warn "$line"
        done
    fi
}

# Utility functions for manual operations
show_apache_status() {
    log_info "Apache status and configuration:"
    
    echo "=== Apache Version ==="
    apache2 -v
    echo
    
    echo "=== Enabled Modules ==="
    apache2ctl -M | sort
    echo
    
    echo "=== Enabled Sites ==="
    apache2ctl -S
    echo
    
    echo "=== Virtual Hosts ==="
    apache2ctl -t -D DUMP_VHOSTS
    echo
    
    echo "=== Apache Process ==="
    ps aux | grep apache2 | grep -v grep
    echo
    
    if service_is_active apache2; then
        echo "=== Apache Status ==="
        systemctl status apache2 --no-pager
    fi
}

# Run optimization
case "${1:-all}" in
    "modules")
        enable_apache_modules
        ;;
    "mpm")
        configure_mpm_event
        test_apache_config
        restart_service apache2
        ;;
    "ssl")
        configure_ssl_settings
        test_apache_config
        restart_service apache2
        ;;
    "security")
        configure_security_headers
        configure_directory_options
        test_apache_config
        restart_service apache2
        ;;
    "compression")
        configure_compression
        test_apache_config
        restart_service apache2
        ;;
    "status")
        show_apache_status
        ;;
    "test")
        test_apache_config
        ;;
    "all")
        main
        ;;
    *)
        echo "Usage: $0 [modules|mpm|ssl|security|compression|status|test|all]"
        echo "  modules     - Enable required Apache modules"
        echo "  mpm         - Configure MPM Event"
        echo "  ssl         - Configure SSL/TLS settings"
        echo "  security    - Configure security headers and directory options"
        echo "  compression - Configure compression (Brotli/Deflate)"
        echo "  status      - Show Apache status and configuration"
        echo "  test        - Test Apache configuration"
        echo "  all         - Run full optimization (default)"
        exit 1
        ;;
esac