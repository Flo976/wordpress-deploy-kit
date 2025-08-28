#!/bin/bash

# WordPress Installation Script
# Author: Florent Didelot
# Description: Download, configure and install WordPress with wp-config.php and security settings

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
WP_DB_NAME="${WP_DB_NAME:-wordpress}"
WP_DB_USER="${WP_DB_USER:-wpuser}"
WP_DB_PASSWORD="${WP_DB_PASSWORD:-changeme}"
WP_TABLE_PREFIX="${WP_TABLE_PREFIX:-wp_}"
WP_ADMIN_USER="${WP_ADMIN_USER:-admin}"
WP_ADMIN_PASSWORD="${WP_ADMIN_PASSWORD:-admin123!}"
WP_ADMIN_EMAIL="${WP_ADMIN_EMAIL:-admin@example.local}"
WP_TITLE="${WP_TITLE:-Mon Site WordPress}"
WP_LOCALE="${WP_LOCALE:-fr_FR}"
DOMAIN="${DOMAIN:-localhost}"

# Error trap
trap 'log_error "WordPress installation failed on line $LINENO"' ERR

main() {
    log_info "Starting WordPress installation..."
    
    # Check prerequisites
    check_prerequisites
    
    # Download WordPress
    download_wordpress
    
    # Configure file permissions and ownership
    set_file_permissions
    
    # Generate wp-config.php
    generate_wp_config
    
    # Install WordPress via WP-CLI
    install_wordpress_cli
    
    # Configure WordPress settings
    configure_wordpress_settings
    
    # Install essential plugins
    install_essential_plugins
    
    # Setup WordPress security
    setup_wordpress_security
    
    # Create WordPress maintenance scripts
    create_maintenance_scripts
    
    # Verify installation
    verify_installation
    
    log_success "WordPress installation completed successfully"
    display_installation_summary
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if wp-cli is installed
    if ! command_exists wp; then
        error_exit "WP-CLI is not installed. Run optimize_php.sh first."
    fi
    
    # Check if Apache is running
    if ! service_is_active apache2; then
        error_exit "Apache is not running. Run optimize_apache.sh first."
    fi
    
    # Check if MariaDB is running and database exists
    if ! service_is_active mariadb; then
        error_exit "MariaDB is not running. Run optimize_mariadb.sh first."
    fi
    
    # Test database connection
    if ! mysql -u "$WP_DB_USER" -p"$WP_DB_PASSWORD" -e "USE $WP_DB_NAME;" >/dev/null 2>&1; then
        error_exit "Cannot connect to WordPress database. Check MariaDB configuration."
    fi
    
    log_info "Prerequisites check passed"
}

download_wordpress() {
    log_info "Downloading WordPress..."
    
    # Create WordPress directory
    create_dir "$WP_DIR" "www-data:www-data" "755"
    
    # Change to WordPress directory
    cd "$WP_DIR"
    
    # Check if WordPress is already installed
    if [[ -f "$WP_DIR/wp-config.php" ]] && wp core is-installed --allow-root 2>/dev/null; then
        log_info "WordPress is already installed, checking for updates..."
        
        # Update WordPress if needed
        if sudo -u www-data wp core check-update --allow-root >/dev/null 2>&1; then
            log_info "WordPress update available, updating..."
            sudo -u www-data wp core update --allow-root
            sudo -u www-data wp core update-db --allow-root
        else
            log_info "WordPress is up to date"
        fi
        return 0
    fi
    
    # Download WordPress core files
    log_info "Downloading WordPress core files (locale: $WP_LOCALE)..."
    
    if [[ "$WP_LOCALE" == "en_US" ]]; then
        sudo -u www-data wp core download --allow-root --force
    else
        sudo -u www-data wp core download --locale="$WP_LOCALE" --allow-root --force
    fi
    
    # Verify download
    if [[ -f "$WP_DIR/wp-load.php" ]]; then
        log_success "WordPress core files downloaded successfully"
    else
        error_exit "WordPress download failed"
    fi
}

set_file_permissions() {
    log_info "Setting WordPress file permissions and ownership..."
    
    # Set ownership
    chown -R www-data:www-data "$WP_DIR"
    
    # Set directory permissions
    find "$WP_DIR" -type d -exec chmod 755 {} \;
    
    # Set file permissions
    find "$WP_DIR" -type f -exec chmod 644 {} \;
    
    # Special permissions for wp-config.php (will be created)
    if [[ -f "$WP_DIR/wp-config.php" ]]; then
        chmod 600 "$WP_DIR/wp-config.php"
    fi
    
    # Ensure uploads directory is writable
    create_dir "$WP_DIR/wp-content/uploads" "www-data:www-data" "755"
    
    # Ensure plugins directory exists and is writable
    create_dir "$WP_DIR/wp-content/plugins" "www-data:www-data" "755"
    
    # Ensure themes directory exists and is writable
    create_dir "$WP_DIR/wp-content/themes" "www-data:www-data" "755"
    
    log_info "File permissions and ownership configured"
}

generate_wp_config() {
    log_info "Generating wp-config.php..."
    
    cd "$WP_DIR"
    
    # Generate wp-config.php using WP-CLI
    sudo -u www-data wp config create \
        --dbname="$WP_DB_NAME" \
        --dbuser="$WP_DB_USER" \
        --dbpass="$WP_DB_PASSWORD" \
        --dbhost="localhost" \
        --dbprefix="$WP_TABLE_PREFIX" \
        --locale="$WP_LOCALE" \
        --allow-root \
        --force
    
    # Generate secure salts and add custom configuration
    local salts
    salts=$(generate_wp_salts)
    
    # Create temporary config file with all settings
    local temp_config="/tmp/wp-config-temp.php"
    
    cat > "$temp_config" << EOF
<?php
/**
 * The base configuration for WordPress
 * Generated by deployment script on $(date)
 */

// ** MySQL settings ** //
define( 'DB_NAME', '$WP_DB_NAME' );
define( 'DB_USER', '$WP_DB_USER' );
define( 'DB_PASSWORD', '$WP_DB_PASSWORD' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', 'utf8mb4_unicode_ci' );

// ** Table prefix ** //
\$table_prefix = '$WP_TABLE_PREFIX';

// ** Authentication Unique Keys and Salts ** //
$salts

// ** WordPress debugging ** //
define( 'WP_DEBUG', ${WP_DEBUG:-false} );
define( 'WP_DEBUG_LOG', ${WP_DEBUG_LOG:-false} );
define( 'WP_DEBUG_DISPLAY', ${WP_DEBUG_DISPLAY:-false} );
define( 'SCRIPT_DEBUG', false );

// ** WordPress URLs ** //
define( 'WP_HOME', 'http://$DOMAIN' );
define( 'WP_SITEURL', 'http://$DOMAIN' );

// ** File system settings ** //
define( 'FS_METHOD', 'direct' );
define( 'DISALLOW_FILE_EDIT', ${WP_DISALLOW_FILE_EDIT:-true} );
define( 'DISALLOW_FILE_MODS', ${WP_DISALLOW_FILE_MODS:-false} );

// ** Cron settings ** //
define( 'DISABLE_WP_CRON', true );

// ** Security settings ** //
define( 'FORCE_SSL_ADMIN', false );
define( 'AUTOMATIC_UPDATER_DISABLED', ${WP_AUTOMATIC_UPDATER_DISABLED:-false} );

// ** Performance settings ** //
define( 'WP_MEMORY_LIMIT', '256M' );
define( 'WP_MAX_MEMORY_LIMIT', '512M' );
define( 'WP_POST_REVISIONS', 3 );
define( 'AUTOSAVE_INTERVAL', 300 );
define( 'WP_CACHE', false );

// ** Upload settings ** //
define( 'UPLOADS', 'wp-content/uploads' );

// ** Multisite settings (disabled by default) ** //
define( 'WP_ALLOW_MULTISITE', false );

// ** Additional PHP settings ** //
ini_set( 'memory_limit', '256M' );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
EOF

    # Replace the generated wp-config.php with our custom version
    sudo -u www-data cp "$temp_config" "$WP_DIR/wp-config.php"
    rm -f "$temp_config"
    
    # Set secure permissions
    chmod 600 "$WP_DIR/wp-config.php"
    
    log_success "wp-config.php generated with secure settings"
}

install_wordpress_cli() {
    log_info "Installing WordPress via WP-CLI..."
    
    cd "$WP_DIR"
    
    # Install WordPress
    local wp_url="http://$DOMAIN"
    
    # Use HTTPS if SSL is enabled
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]] || [[ -f "/etc/ssl/certs/ssl-cert-snakeoil.pem" ]]; then
        wp_url="https://$DOMAIN"
        
        # Update URLs in wp-config.php for HTTPS
        sed -i "s|http://$DOMAIN|https://$DOMAIN|g" "$WP_DIR/wp-config.php"
        
        # Enable force SSL admin
        sed -i "s|define( 'FORCE_SSL_ADMIN', false );|define( 'FORCE_SSL_ADMIN', true );|g" "$WP_DIR/wp-config.php"
    fi
    
    log_info "Installing WordPress with URL: $wp_url"
    
    sudo -u www-data wp core install \
        --url="$wp_url" \
        --title="$WP_TITLE" \
        --admin_user="$WP_ADMIN_USER" \
        --admin_password="$WP_ADMIN_PASSWORD" \
        --admin_email="$WP_ADMIN_EMAIL" \
        --allow-root
    
    # Verify installation
    if sudo -u www-data wp core is-installed --allow-root; then
        log_success "WordPress installed successfully"
    else
        error_exit "WordPress installation failed"
    fi
}

configure_wordpress_settings() {
    log_info "Configuring WordPress settings..."
    
    cd "$WP_DIR"
    
    # Update general settings
    sudo -u www-data wp option update blogname "$WP_TITLE" --allow-root
    sudo -u www-data wp option update blogdescription "Site web créé avec le script de déploiement WordPress" --allow-root
    sudo -u www-data wp option update timezone_string "Europe/Paris" --allow-root
    sudo -u www-data wp option update date_format "d/m/Y" --allow-root
    sudo -u www-data wp option update time_format "H:i" --allow-root
    sudo -u www-data wp option update start_of_week "1" --allow-root
    
    # Configure permalinks
    sudo -u www-data wp rewrite structure '/%postname%/' --allow-root
    sudo -u www-data wp rewrite flush --allow-root
    
    # Configure media settings
    sudo -u www-data wp option update thumbnail_size_w "150" --allow-root
    sudo -u www-data wp option update thumbnail_size_h "150" --allow-root
    sudo -u www-data wp option update medium_size_w "300" --allow-root
    sudo -u www-data wp option update medium_size_h "300" --allow-root
    sudo -u www-data wp option update large_size_w "1024" --allow-root
    sudo -u www-data wp option update large_size_h "1024" --allow-root
    
    # Disable search engine indexing for .local domains
    if [[ "$DOMAIN" =~ \.local$ ]]; then
        sudo -u www-data wp option update blog_public "0" --allow-root
        log_info "Search engine indexing disabled for .local domain"
    fi
    
    # Configure discussion settings
    sudo -u www-data wp option update default_comment_status "closed" --allow-root
    sudo -u www-data wp option update default_ping_status "closed" --allow-root
    sudo -u www-data wp option update comment_registration "1" --allow-root
    sudo -u www-data wp option update comments_notify "0" --allow-root
    sudo -u www-data wp option update moderation_notify "1" --allow-root
    
    log_info "WordPress settings configured"
}

install_essential_plugins() {
    log_info "Installing essential WordPress plugins..."
    
    cd "$WP_DIR"
    
    local plugins=(
        "wordpress-seo"           # Yoast SEO
        "wordfence"              # Security plugin
        "wp-super-cache"         # Caching plugin
        "updraftplus"            # Backup plugin
        "redirection"            # URL redirection management
    )
    
    for plugin in "${plugins[@]}"; do
        if ! sudo -u www-data wp plugin is-installed "$plugin" --allow-root; then
            log_info "Installing plugin: $plugin"
            sudo -u www-data wp plugin install "$plugin" --allow-root
        else
            log_info "Plugin already installed: $plugin"
        fi
    done
    
    # Activate essential plugins
    sudo -u www-data wp plugin activate wordpress-seo --allow-root
    sudo -u www-data wp plugin activate wp-super-cache --allow-root
    
    # Configure WP Super Cache
    if sudo -u www-data wp plugin is-active wp-super-cache --allow-root; then
        sudo -u www-data wp super-cache enable --allow-root 2>/dev/null || true
    fi
    
    log_info "Essential plugins installed and configured"
}

setup_wordpress_security() {
    log_info "Setting up WordPress security..."
    
    cd "$WP_DIR"
    
    # Remove default plugins if they exist
    local default_plugins=("akismet" "hello-dolly")
    for plugin in "${default_plugins[@]}"; do
        if sudo -u www-data wp plugin is-installed "$plugin" --allow-root; then
            sudo -u www-data wp plugin delete "$plugin" --allow-root
            log_info "Removed default plugin: $plugin"
        fi
    done
    
    # Remove sample content
    sudo -u www-data wp post delete 1 --force --allow-root 2>/dev/null || true  # Hello World post
    sudo -u www-data wp post delete 2 --force --allow-root 2>/dev/null || true  # Sample page
    sudo -u www-data wp comment delete 1 --force --allow-root 2>/dev/null || true  # Default comment
    
    # Create security.php file with additional security measures
    cat > "$WP_DIR/wp-content/security.php" << 'EOF'
<?php
/**
 * Additional WordPress Security Measures
 * This file is included in wp-config.php for extra security
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Hide WordPress version from RSS feeds
function remove_wp_version_rss() {
    return '';
}
add_filter('the_generator', 'remove_wp_version_rss');

// Remove WordPress version from scripts and styles
function remove_wp_version_strings($src) {
    if (strpos($src, 'ver=')) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}
add_filter('style_loader_src', 'remove_wp_version_strings', 9999);
add_filter('script_loader_src', 'remove_wp_version_strings', 9999);

// Disable XML-RPC
add_filter('xmlrpc_enabled', '__return_false');

// Remove RSD link
remove_action('wp_head', 'rsd_link');

// Remove Windows Live Writer link
remove_action('wp_head', 'wlwmanifest_link');

// Remove WordPress generator meta tag
remove_action('wp_head', 'wp_generator');

// Disable user enumeration
function disable_user_enumeration($redirect, $request) {
    if (preg_match('/\?author=(\d+)/', $request) || preg_match('/\/author\/(\d+)\//', $request)) {
        wp_redirect(home_url(), 301);
        exit;
    }
}
add_action('template_redirect', 'disable_user_enumeration');

// Limit login attempts (basic implementation)
function limit_login_attempts() {
    $ip = $_SERVER['REMOTE_ADDR'];
    $attempts_option = 'login_attempts_' . md5($ip);
    $attempts = get_transient($attempts_option);
    
    if ($attempts && $attempts >= 5) {
        wp_die('Too many login attempts. Please try again later.', 'Login Blocked', array('response' => 429));
    }
}
add_action('wp_login_failed', function($username) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $attempts_option = 'login_attempts_' . md5($ip);
    $attempts = get_transient($attempts_option) ?: 0;
    $attempts++;
    set_transient($attempts_option, $attempts, 15 * MINUTE_IN_SECONDS);
});

// Clear attempts on successful login
add_action('wp_login', function() {
    $ip = $_SERVER['REMOTE_ADDR'];
    $attempts_option = 'login_attempts_' . md5($ip);
    delete_transient($attempts_option);
});
EOF
    
    # Include security.php in wp-config.php
    if ! grep -q "security.php" "$WP_DIR/wp-config.php"; then
        sed -i "/wp-settings.php/i require_once ABSPATH . 'wp-content/security.php';" "$WP_DIR/wp-config.php"
    fi
    
    # Create .htaccess with security rules
    create_secure_htaccess
    
    # Set secure file permissions
    chmod 600 "$WP_DIR/wp-config.php"
    chmod 644 "$WP_DIR/wp-content/security.php"
    
    log_info "WordPress security measures implemented"
}

create_secure_htaccess() {
    log_info "Creating secure .htaccess file..."
    
    cat > "$WP_DIR/.htaccess" << 'EOF'
# WordPress Security .htaccess
# Generated by deployment script

# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress

# Security Headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# Disable directory browsing
Options -Indexes

# Protect sensitive files
<FilesMatch "^(wp-config\.php|\.htaccess|error_log|debug\.log)$">
    Require all denied
</FilesMatch>

# Protect wp-content
<IfModule mod_rewrite.c>
    RewriteRule ^wp-content/uploads/.*\.php$ - [R=404,L]
</IfModule>

# Disable PHP execution in uploads
<Directory "wp-content/uploads/">
    <FilesMatch "\.php$">
        Require all denied
    </FilesMatch>
</Directory>

# Limit file upload types
<FilesMatch "\.(php|phtml|php3|php4|php5|pl|py|jsp|asp|sh|cgi)$">
    Require all denied
</FilesMatch>

# Allow only specific file types in uploads
<Directory "wp-content/uploads/">
    <FilesMatch "\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|mp3|mp4|avi|mov|wmv|flv)$">
        Require all granted
    </FilesMatch>
</Directory>

# Block suspicious requests
<IfModule mod_rewrite.c>
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
</IfModule>

# Cache static files
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access plus 1 month"
    ExpiresByType image/jpeg "access plus 1 month"
    ExpiresByType image/gif "access plus 1 month"
    ExpiresByType image/png "access plus 1 month"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/pdf "access plus 1 month"
    ExpiresByType text/javascript "access plus 1 month"
    ExpiresByType text/js "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType application/x-javascript "access plus 1 month"
    ExpiresByType image/x-icon "access plus 1 year"
    ExpiresByType application/x-shockwave-flash "access plus 1 month"
</IfModule>

# Compress files
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>
EOF
    
    chown www-data:www-data "$WP_DIR/.htaccess"
    chmod 644 "$WP_DIR/.htaccess"
    
    log_info "Secure .htaccess file created"
}

create_maintenance_scripts() {
    log_info "Creating WordPress maintenance scripts..."
    
    # Create WordPress backup script
    cat > /usr/local/bin/wp-backup << 'EOF'
#!/bin/bash
# WordPress Backup Script

WP_DIR="/var/www/html"
BACKUP_DIR="/var/backups/wordpress"
DATE=$(date +%Y%m%d_%H%M%S)
SITE_NAME=$(basename "$WP_DIR")

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
mysqldump --defaults-file=/root/.my.cnf wordpress > "$BACKUP_DIR/database_$DATE.sql"

# Files backup
tar -czf "$BACKUP_DIR/files_$DATE.tar.gz" -C "$WP_DIR" .

# Combined backup
tar -czf "$BACKUP_DIR/full_backup_$DATE.tar.gz" -C "$BACKUP_DIR" "database_$DATE.sql" -C "$WP_DIR" .

# Cleanup individual files
rm -f "$BACKUP_DIR/database_$DATE.sql"

echo "WordPress backup completed: $BACKUP_DIR/full_backup_$DATE.tar.gz"

# Cleanup old backups (keep 7 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete
EOF
    
    # Create WordPress update script
    cat > /usr/local/bin/wp-update << EOF
#!/bin/bash
# WordPress Update Script

WP_DIR="$WP_DIR"
cd "\$WP_DIR"

echo "Updating WordPress core..."
sudo -u www-data wp core update --allow-root

echo "Updating WordPress database..."
sudo -u www-data wp core update-db --allow-root

echo "Updating plugins..."
sudo -u www-data wp plugin update --all --allow-root

echo "Updating themes..."
sudo -u www-data wp theme update --all --allow-root

echo "WordPress update completed"
EOF
    
    # Create WordPress health check script
    cat > /usr/local/bin/wp-health << EOF
#!/bin/bash
# WordPress Health Check Script

WP_DIR="$WP_DIR"
cd "\$WP_DIR"

echo "=== WordPress Health Check ==="
echo "WordPress Version: \$(sudo -u www-data wp core version --allow-root)"
echo "Database Status: \$(sudo -u www-data wp db check --allow-root 2>/dev/null && echo "OK" || echo "ERROR")"
echo "File Permissions: \$(sudo -u www-data wp core verify-checksums --allow-root 2>/dev/null && echo "OK" || echo "ERROR")"

echo -e "\n=== Active Plugins ==="
sudo -u www-data wp plugin list --status=active --allow-root

echo -e "\n=== Site URL ==="
sudo -u www-data wp option get siteurl --allow-root

echo -e "\n=== System Info ==="
echo "PHP Version: \$(php -v | head -1)"
echo "Apache Status: \$(systemctl is-active apache2)"
echo "MariaDB Status: \$(systemctl is-active mariadb)"
EOF
    
    # Make scripts executable
    chmod +x /usr/local/bin/wp-backup
    chmod +x /usr/local/bin/wp-update
    chmod +x /usr/local/bin/wp-health
    
    # Create backup directory
    create_dir "/var/backups/wordpress" "root:root" "700"
    
    log_info "WordPress maintenance scripts created"
}

verify_installation() {
    log_info "Verifying WordPress installation..."
    
    cd "$WP_DIR"
    
    # Check if WordPress is installed
    if ! sudo -u www-data wp core is-installed --allow-root; then
        error_exit "WordPress installation verification failed"
    fi
    
    # Check database connection
    if ! sudo -u www-data wp db check --allow-root >/dev/null 2>&1; then
        log_warn "WordPress database connection issues detected"
    fi
    
    # Check file permissions
    local config_perms
    config_perms=$(stat -c %a "$WP_DIR/wp-config.php")
    if [[ "$config_perms" != "600" ]]; then
        log_warn "wp-config.php permissions are $config_perms (should be 600)"
    fi
    
    # Check if uploads directory is writable
    if [[ ! -w "$WP_DIR/wp-content/uploads" ]]; then
        log_warn "Uploads directory is not writable"
    fi
    
    # Test HTTP response
    local wp_url="http://$DOMAIN"
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        wp_url="https://$DOMAIN"
    fi
    
    if test_http_response "$wp_url" 200; then
        log_success "WordPress HTTP response test passed"
    else
        log_warn "WordPress HTTP response test failed"
    fi
    
    log_success "WordPress installation verified"
}

display_installation_summary() {
    log_info "WordPress installation summary:"
    
    echo "=================================="
    echo "WordPress Installation Complete"
    echo "=================================="
    echo "Site URL: http://$DOMAIN"
    echo "Admin URL: http://$DOMAIN/wp-admin/"
    echo "Admin Username: $WP_ADMIN_USER"
    echo "Admin Email: $WP_ADMIN_EMAIL"
    echo "Database Name: $WP_DB_NAME"
    echo "Database User: $WP_DB_USER"
    echo "WordPress Directory: $WP_DIR"
    echo "WordPress Version: $(sudo -u www-data wp core version --allow-root 2>/dev/null || echo "Unknown")"
    echo "WordPress Locale: $WP_LOCALE"
    echo "=================================="
    echo
    echo "Maintenance Commands:"
    echo "- wp-backup    : Create full backup"
    echo "- wp-update    : Update WordPress and plugins"
    echo "- wp-health    : Check WordPress health"
    echo
    echo "Security Notes:"
    echo "- Change default admin password immediately"
    echo "- Review and configure security plugins"
    echo "- Enable SSL if not already configured"
    echo "- Regular backups are recommended"
    echo "=================================="
}

# Run installation with options
case "${1:-all}" in
    "download")
        download_wordpress
        set_file_permissions
        ;;
    "config")
        generate_wp_config
        ;;
    "install")
        install_wordpress_cli
        ;;
    "plugins")
        install_essential_plugins
        ;;
    "security")
        setup_wordpress_security
        ;;
    "verify")
        verify_installation
        ;;
    "maintenance")
        create_maintenance_scripts
        ;;
    "summary")
        display_installation_summary
        ;;
    "all")
        main
        ;;
    *)
        echo "Usage: $0 [download|config|install|plugins|security|verify|maintenance|summary|all]"
        echo "  download     - Download WordPress core files"
        echo "  config       - Generate wp-config.php"
        echo "  install      - Install WordPress via WP-CLI"
        echo "  plugins      - Install essential plugins"
        echo "  security     - Setup security measures"
        echo "  verify       - Verify installation"
        echo "  maintenance  - Create maintenance scripts"
        echo "  summary      - Display installation summary"
        echo "  all          - Run complete installation (default)"
        exit 1
        ;;
esac