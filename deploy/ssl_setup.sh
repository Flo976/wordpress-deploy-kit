#!/bin/bash

# SSL/TLS Setup Script with Let's Encrypt
# Author: Florent Didelot
# Description: Configure SSL certificates using Let's Encrypt Certbot or self-signed certificates

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
ENABLE_LETSENCRYPT="${ENABLE_LETSENCRYPT:-false}"
LE_EMAIL="${LE_EMAIL:-admin@example.local}"
DOMAIN="${DOMAIN:-localhost}"
ENABLE_HSTS="${ENABLE_HSTS:-true}"
HSTS_MAX_AGE="${HSTS_MAX_AGE:-31536000}"
ENABLE_OCSP_STAPLING="${ENABLE_OCSP_STAPLING:-true}"

# Error trap
trap 'log_error "SSL setup failed on line $LINENO"' ERR

main() {
    log_info "Starting SSL/TLS setup..."
    
    # Check prerequisites
    check_prerequisites
    
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        # Setup Let's Encrypt
        setup_letsencrypt
        obtain_letsencrypt_certificate
        configure_letsencrypt_renewal
    else
        # Setup self-signed certificates
        setup_self_signed_certificates
    fi
    
    # Configure Apache for SSL
    configure_apache_ssl
    
    # Setup SSL security features
    configure_ssl_security
    
    # Test SSL configuration
    test_ssl_configuration
    
    # Setup SSL monitoring
    setup_ssl_monitoring
    
    log_success "SSL/TLS setup completed successfully"
    display_ssl_summary
}

check_prerequisites() {
    log_info "Checking SSL prerequisites..."
    
    # Check if Apache is installed and running
    if ! service_is_active apache2; then
        error_exit "Apache is not running. Run optimize_apache.sh first."
    fi
    
    # Check if domain is not localhost for Let's Encrypt
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]] && [[ "$DOMAIN" =~ ^(localhost|.*\.local)$ ]]; then
        log_warn "Let's Encrypt cannot be used with localhost or .local domains"
        log_warn "Switching to self-signed certificates"
        ENABLE_LETSENCRYPT="false"
    fi
    
    # Check internet connectivity for Let's Encrypt
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
            log_warn "No internet connectivity detected"
            log_warn "Let's Encrypt requires internet access, switching to self-signed certificates"
            ENABLE_LETSENCRYPT="false"
        fi
    fi
    
    # Check if HTTP is accessible (required for Let's Encrypt)
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        if ! test_http_response "http://$DOMAIN" 200 10; then
            log_warn "HTTP site is not accessible, Let's Encrypt validation may fail"
        fi
    fi
    
    log_info "SSL prerequisites check completed"
}

setup_letsencrypt() {
    log_info "Setting up Let's Encrypt Certbot..."
    
    # Install snapd if not present
    if ! command_exists snap; then
        apt-get update -qq
        apt-get install -y snapd
        systemctl enable --now snapd.socket
    fi
    
    # Install certbot via snap (recommended method)
    if ! command_exists certbot; then
        log_info "Installing Certbot via snap..."
        snap install core
        snap refresh core
        snap install --classic certbot
        
        # Create symlink
        ln -sf /snap/bin/certbot /usr/bin/certbot
        
        # Verify installation
        if certbot --version >/dev/null 2>&1; then
            log_success "Certbot installed successfully"
        else
            error_exit "Certbot installation failed"
        fi
    else
        log_info "Certbot is already installed"
    fi
    
    # Install Apache plugin
    if ! snap list | grep -q certbot-apache 2>/dev/null; then
        snap set certbot trust-plugin-with-root=ok
        snap install certbot-dns-cloudflare 2>/dev/null || true
    fi
}

obtain_letsencrypt_certificate() {
    log_info "Obtaining Let's Encrypt certificate for $DOMAIN..."
    
    # Prepare certbot command
    local certbot_cmd=(
        "certbot"
        "--apache"
        "-d" "$DOMAIN"
        "--email" "$LE_EMAIL"
        "--agree-tos"
        "--non-interactive"
        "--redirect"
        "--hsts"
        "--staple-ocsp"
    )
    
    # Add www subdomain if domain doesn't start with www
    if [[ ! "$DOMAIN" =~ ^www\. ]]; then
        certbot_cmd+=("-d" "www.$DOMAIN")
    fi
    
    # Attempt certificate acquisition
    if "${certbot_cmd[@]}"; then
        log_success "Let's Encrypt certificate obtained successfully"
        
        # Verify certificate
        if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
            log_success "SSL certificate files are in place"
            
            # Show certificate info
            local cert_info
            cert_info=$(openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -text -noout | grep -A 2 "Subject:")
            log_info "Certificate details: $cert_info"
        else
            error_exit "SSL certificate files not found"
        fi
    else
        log_error "Failed to obtain Let's Encrypt certificate"
        log_info "Falling back to self-signed certificates"
        ENABLE_LETSENCRYPT="false"
        setup_self_signed_certificates
    fi
}

setup_self_signed_certificates() {
    log_info "Setting up self-signed SSL certificates..."
    
    local ssl_dir="/etc/ssl/private"
    local cert_file="/etc/ssl/certs/$DOMAIN.pem"
    local key_file="/etc/ssl/private/$DOMAIN.key"
    
    # Create SSL directory
    create_dir "$ssl_dir" "root:root" "700"
    
    # Generate self-signed certificate
    if [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]]; then
        log_info "Generating self-signed SSL certificate..."
        
        # Create OpenSSL config for SAN
        local ssl_config="/tmp/ssl_config.cnf"
        cat > "$ssl_config" << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=FR
ST=France
L=Paris
O=WordPress Deployment
OU=IT Department
CN=$DOMAIN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = www.$DOMAIN
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF

        # Generate certificate and key
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$key_file" \
            -out "$cert_file" \
            -config "$ssl_config" \
            -extensions v3_req
        
        # Clean up config
        rm -f "$ssl_config"
        
        # Set proper permissions
        chmod 600 "$key_file"
        chmod 644 "$cert_file"
        chown root:root "$key_file" "$cert_file"
        
        log_success "Self-signed SSL certificate generated"
    else
        log_info "Self-signed SSL certificate already exists"
    fi
    
    # Verify certificate
    if openssl x509 -in "$cert_file" -text -noout >/dev/null 2>&1; then
        log_success "SSL certificate validation passed"
        
        # Show certificate info
        local cert_info
        cert_info=$(openssl x509 -in "$cert_file" -subject -dates -noout)
        log_info "Certificate details: $cert_info"
    else
        error_exit "SSL certificate validation failed"
    fi
}

configure_apache_ssl() {
    log_info "Configuring Apache for SSL..."
    
    # Enable SSL module
    a2enmod ssl
    a2enmod headers
    
    # Determine certificate paths
    local cert_file
    local key_file
    
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]] && [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        cert_file="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        key_file="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        cert_file="/etc/ssl/certs/$DOMAIN.pem"
        key_file="/etc/ssl/private/$DOMAIN.key"
    fi
    
    # Create or update HTTPS virtual host
    local https_vhost="/etc/apache2/sites-available/000-default-ssl.conf"
    
    cat > "$https_vhost" << EOF
<VirtualHost *:443>
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot /var/www/html
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile $cert_file
    SSLCertificateKeyFile $key_file
EOF

    # Add intermediate certificate if Let's Encrypt
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        echo "    SSLCertificateChainFile /etc/letsencrypt/live/$DOMAIN/chain.pem" >> "$https_vhost"
    fi
    
    cat >> "$https_vhost" << EOF
    
    # SSL Security Settings
    SSLProtocol ${SSL_PROTOCOL:-TLSv1.2 TLSv1.3}
    SSLCipherSuite ${SSL_CIPHER_SUITE:-ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384}
    SSLHonorCipherOrder On
    
    # SSL Performance
    SSLSessionCache shmcb:/var/run/apache2/ssl_scache(512000)
    SSLSessionCacheTimeout 300
    
    # OCSP Stapling
    SSLUseStapling On
    SSLStaplingCache shmcb:/var/run/apache2/ssl_stapling_cache(128000)
    
    # HTTP/2 Support
    <IfModule mod_http2.c>
        Protocols h2 http/1.1
        H2Direct on
        H2Upgrade on
        H2Push on
    </IfModule>
    
    # Security Headers
    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=$HSTS_MAX_AGE; includeSubDomains; preload"
        Header always set X-Content-Type-Options nosniff
        Header always set X-Frame-Options SAMEORIGIN
        Header always set X-XSS-Protection "1; mode=block"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"
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
    
    # Security restrictions
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
EOF
    
    # Update HTTP virtual host to redirect to HTTPS
    local http_vhost="/etc/apache2/sites-available/000-default.conf"
    
    cat > "$http_vhost" << EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot /var/www/html
    
    # Redirect all HTTP traffic to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
    
    # Let's Encrypt challenge directory (if needed)
    Alias /.well-known/acme-challenge/ /var/www/html/.well-known/acme-challenge/
    <Directory "/var/www/html/.well-known/acme-challenge/">
        Options None
        AllowOverride None
        Require all granted
    </Directory>
    
    # Logging
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
    
    # Enable sites
    a2ensite 000-default
    a2ensite 000-default-ssl
    
    # Test Apache configuration
    if apache2ctl configtest; then
        log_success "Apache SSL configuration is valid"
    else
        error_exit "Apache SSL configuration test failed"
    fi
    
    # Restart Apache
    restart_service apache2
    
    log_success "Apache SSL configuration completed"
}

configure_ssl_security() {
    log_info "Configuring SSL security features..."
    
    # Create SSL security configuration
    cat > /etc/apache2/conf-available/ssl-security.conf << EOF
# SSL Security Configuration

<IfModule mod_ssl.c>
    # SSL Protocol Configuration
    SSLProtocol ${SSL_PROTOCOL:-TLSv1.2 TLSv1.3}
    
    # SSL Cipher Suite (Modern browsers)
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    
    # Honor server cipher order
    SSLHonorCipherOrder on
    
    # Disable SSL compression (CRIME attack prevention)
    SSLCompression off
    
    # Session configuration
    SSLSessionCache shmcb:/var/run/apache2/ssl_scache(512000)
    SSLSessionCacheTimeout 300
    
    # OCSP Stapling (if enabled)
    <IfDefine ENABLE_OCSP>
        SSLUseStapling On
        SSLStaplingResponderTimeout 5
        SSLStaplingReturnResponderErrors off
        SSLStaplingCache shmcb:/var/run/apache2/ssl_stapling_cache(128000)
    </IfDefine>
    
    # SSL Options
    SSLOptions +StrictRequire
    
    # Disable insecure renegotiation
    SSLInsecureRenegotiation off
</IfModule>

# Security Headers for SSL
<IfModule mod_headers.c>
    # HSTS Header (only for HTTPS)
    <If "%{HTTPS} == 'on'">
        Header always set Strict-Transport-Security "max-age=$HSTS_MAX_AGE; includeSubDomains; preload"
    </If>
    
    # Certificate Transparency
    Header always set Expect-CT "max-age=86400, enforce"
    
    # Content Security Policy for SSL
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'"
</IfModule>
EOF
    
    # Enable SSL security configuration
    a2enconf ssl-security
    
    # Define OCSP if enabled
    if [[ "$ENABLE_OCSP_STAPLING" == "true" ]]; then
        echo "Define ENABLE_OCSP" >> /etc/apache2/conf-available/ssl-security.conf
    fi
    
    log_info "SSL security features configured"
}

configure_letsencrypt_renewal() {
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        log_info "Configuring Let's Encrypt automatic renewal..."
        
        # Create renewal hook script
        local renewal_hook="/etc/letsencrypt/renewal-hooks/deploy/apache-reload.sh"
        mkdir -p "$(dirname "$renewal_hook")"
        
        cat > "$renewal_hook" << 'EOF'
#!/bin/bash
# Let's Encrypt Renewal Hook Script

# Reload Apache to use new certificate
systemctl reload apache2

# Log renewal
echo "$(date): SSL certificate renewed and Apache reloaded" >> /var/log/letsencrypt-renewal.log

# Optional: Send notification
# echo "SSL certificate for $(hostname) has been renewed" | mail -s "SSL Certificate Renewed" admin@domain.com
EOF
        
        chmod +x "$renewal_hook"
        
        # Test renewal (dry run)
        if certbot renew --dry-run >/dev/null 2>&1; then
            log_success "Let's Encrypt renewal test passed"
        else
            log_warn "Let's Encrypt renewal test failed"
        fi
        
        # Create renewal log
        touch /var/log/letsencrypt-renewal.log
        chmod 644 /var/log/letsencrypt-renewal.log
        
        log_info "Let's Encrypt automatic renewal configured"
    fi
}

test_ssl_configuration() {
    log_info "Testing SSL configuration..."
    
    # Test HTTPS response
    local https_url="https://$DOMAIN"
    if test_http_response "$https_url" 200 10; then
        log_success "HTTPS response test passed"
    else
        log_warn "HTTPS response test failed"
    fi
    
    # Test HTTP to HTTPS redirect
    local redirect_test
    redirect_test=$(curl -s -o /dev/null -w "%{http_code}" -L "http://$DOMAIN" 2>/dev/null || echo "000")
    if [[ "$redirect_test" == "200" ]]; then
        log_success "HTTP to HTTPS redirect working"
    else
        log_warn "HTTP to HTTPS redirect test failed (got $redirect_test)"
    fi
    
    # Test SSL certificate
    if command_exists openssl; then
        local ssl_test
        ssl_test=$(echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || echo "failed")
        if [[ "$ssl_test" != "failed" ]]; then
            log_success "SSL certificate test passed"
            log_info "Certificate subject: $ssl_test"
        else
            log_warn "SSL certificate test failed"
        fi
    fi
    
    # Check SSL security headers
    if command_exists curl; then
        local hsts_header
        hsts_header=$(curl -s -I "https://$DOMAIN" 2>/dev/null | grep -i "strict-transport-security" || echo "")
        if [[ -n "$hsts_header" ]]; then
            log_success "HSTS header is set"
        else
            log_warn "HSTS header not found"
        fi
    fi
    
    log_info "SSL configuration test completed"
}

setup_ssl_monitoring() {
    log_info "Setting up SSL certificate monitoring..."
    
    # Create SSL monitoring script
    cat > /usr/local/bin/ssl-monitor << EOF
#!/bin/bash
# SSL Certificate Monitoring Script

DOMAIN="$DOMAIN"
ALERT_DAYS=30
LOG_FILE="/var/log/ssl-monitor.log"

log_message() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$*" >> "\$LOG_FILE"
}

check_certificate_expiry() {
    local domain="\$1"
    local cert_file
    
    # Determine certificate file path
    if [[ -f "/etc/letsencrypt/live/\$domain/fullchain.pem" ]]; then
        cert_file="/etc/letsencrypt/live/\$domain/fullchain.pem"
    elif [[ -f "/etc/ssl/certs/\$domain.pem" ]]; then
        cert_file="/etc/ssl/certs/\$domain.pem"
    else
        log_message "ERROR: Certificate file not found for \$domain"
        return 1
    fi
    
    # Get certificate expiry date
    local expiry_date
    expiry_date=\$(openssl x509 -in "\$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
    
    if [[ -z "\$expiry_date" ]]; then
        log_message "ERROR: Could not read certificate expiry date for \$domain"
        return 1
    fi
    
    # Convert to timestamp
    local expiry_timestamp
    expiry_timestamp=\$(date -d "\$expiry_date" +%s 2>/dev/null)
    
    if [[ -z "\$expiry_timestamp" ]]; then
        log_message "ERROR: Could not parse certificate expiry date for \$domain"
        return 1
    fi
    
    # Calculate days until expiry
    local current_timestamp=\$(date +%s)
    local days_until_expiry=\$(( (expiry_timestamp - current_timestamp) / 86400 ))
    
    log_message "Certificate for \$domain expires in \$days_until_expiry days"
    
    # Check if certificate is expiring soon
    if [[ \$days_until_expiry -lt \$ALERT_DAYS ]]; then
        log_message "ALERT: Certificate for \$domain expires in \$days_until_expiry days"
        # Send email alert if configured
        # echo "SSL certificate for \$domain expires in \$days_until_expiry days" | mail -s "SSL Certificate Expiring" admin@domain.com
        return 1
    fi
    
    return 0
}

# Check main domain certificate
check_certificate_expiry "\$DOMAIN"

# Rotate log file if it gets too large
if [[ \$(stat -c%s "\$LOG_FILE" 2>/dev/null || echo 0) -gt 1048576 ]]; then
    tail -100 "\$LOG_FILE" > "\$LOG_FILE.tmp"
    mv "\$LOG_FILE.tmp" "\$LOG_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/ssl-monitor
    
    # Add SSL monitoring cron job (daily)
    local ssl_monitor_cron="0 6 * * * /usr/local/bin/ssl-monitor >/dev/null 2>&1"
    (crontab -l 2>/dev/null | grep -v "ssl-monitor" || true; echo "$ssl_monitor_cron") | crontab -
    
    # Create log file
    touch /var/log/ssl-monitor.log
    chmod 644 /var/log/ssl-monitor.log
    
    log_info "SSL certificate monitoring configured (daily at 6 AM)"
}

create_ssl_management_tools() {
    log_info "Creating SSL management tools..."
    
    # Create SSL status script
    cat > /usr/local/bin/ssl-status << EOF
#!/bin/bash
# SSL Status Script

DOMAIN="$DOMAIN"

echo "=== SSL Configuration Status ==="
echo "Domain: \$DOMAIN"
echo "Let's Encrypt: $ENABLE_LETSENCRYPT"
echo "HSTS: $ENABLE_HSTS"
echo "OCSP Stapling: $ENABLE_OCSP_STAPLING"

echo -e "\n=== Certificate Information ==="
if [[ -f "/etc/letsencrypt/live/\$DOMAIN/fullchain.pem" ]]; then
    echo "Certificate Type: Let's Encrypt"
    echo "Certificate File: /etc/letsencrypt/live/\$DOMAIN/fullchain.pem"
    openssl x509 -in "/etc/letsencrypt/live/\$DOMAIN/fullchain.pem" -noout -subject -issuer -dates 2>/dev/null
elif [[ -f "/etc/ssl/certs/\$DOMAIN.pem" ]]; then
    echo "Certificate Type: Self-signed"
    echo "Certificate File: /etc/ssl/certs/\$DOMAIN.pem"
    openssl x509 -in "/etc/ssl/certs/\$DOMAIN.pem" -noout -subject -issuer -dates 2>/dev/null
else
    echo "No certificate found"
fi

echo -e "\n=== SSL Test ==="
if command -v openssl >/dev/null 2>&1; then
    echo "Testing SSL connection..."
    timeout 10 openssl s_client -connect "\$DOMAIN:443" -servername "\$DOMAIN" </dev/null 2>/dev/null | grep -E "(subject|issuer)=" || echo "SSL connection test failed"
else
    echo "OpenSSL not available for testing"
fi

echo -e "\n=== Apache SSL Configuration ==="
if apache2ctl -M 2>/dev/null | grep -q ssl_module; then
    echo "SSL Module: Enabled"
else
    echo "SSL Module: Disabled"
fi

echo -e "\n=== HTTPS Response Test ==="
if command -v curl >/dev/null 2>&1; then
    HTTP_CODE=\$(curl -s -o /dev/null -w "%{http_code}" "https://\$DOMAIN" 2>/dev/null || echo "000")
    echo "HTTPS Response Code: \$HTTP_CODE"
    
    # Test security headers
    echo "Security Headers:"
    curl -s -I "https://\$DOMAIN" 2>/dev/null | grep -i -E "(strict-transport-security|x-content-type-options|x-frame-options)" || echo "No security headers found"
else
    echo "curl not available for testing"
fi

if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
    echo -e "\n=== Let's Encrypt Status ==="
    if command -v certbot >/dev/null 2>&1; then
        echo "Certbot Version: \$(certbot --version 2>/dev/null)"
        echo "Certificates:"
        certbot certificates 2>/dev/null | grep -A 5 "\$DOMAIN" || echo "No certificates found"
    else
        echo "Certbot not available"
    fi
fi
EOF
    
    # Create SSL renewal script
    cat > /usr/local/bin/ssl-renew << EOF
#!/bin/bash
# SSL Certificate Renewal Script

if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
    echo "Renewing Let's Encrypt certificates..."
    if certbot renew --quiet; then
        echo "Certificate renewal completed successfully"
        systemctl reload apache2
        echo "Apache reloaded"
    else
        echo "Certificate renewal failed"
        exit 1
    fi
else
    echo "Let's Encrypt is not enabled"
    echo "Using self-signed certificates - no renewal needed"
fi
EOF
    
    # Make scripts executable
    chmod +x /usr/local/bin/ssl-status
    chmod +x /usr/local/bin/ssl-renew
    
    log_info "SSL management tools created"
}

display_ssl_summary() {
    log_info "SSL/TLS setup summary:"
    
    echo "=================================="
    echo "SSL/TLS Configuration"
    echo "=================================="
    echo "Domain: $DOMAIN"
    echo "SSL/TLS: Enabled"
    
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        echo "Certificate Type: Let's Encrypt"
        echo "Automatic Renewal: Enabled"
        echo "Certificate Email: $LE_EMAIL"
    else
        echo "Certificate Type: Self-signed"
        echo "Automatic Renewal: Not applicable"
    fi
    
    echo "HSTS: $ENABLE_HSTS"
    echo "OCSP Stapling: $ENABLE_OCSP_STAPLING"
    echo "HTTP to HTTPS Redirect: Enabled"
    echo "Security Headers: Enabled"
    echo "=================================="
    echo
    echo "SSL Configuration:"
    echo "- Protocol: ${SSL_PROTOCOL:-TLSv1.2 TLSv1.3}"
    echo "- HSTS Max Age: $HSTS_MAX_AGE seconds"
    echo "- HTTP/2: Enabled"
    echo
    echo "Management Commands:"
    echo "- ssl-status     : Check SSL status and configuration"
    echo "- ssl-renew      : Renew SSL certificates"
    echo "- ssl-monitor    : Check certificate expiry"
    echo
    echo "Access URLs:"
    echo "- HTTPS: https://$DOMAIN"
    echo "- HTTP (redirects): http://$DOMAIN"
    echo
    echo "Certificate Files:"
    if [[ "$ENABLE_LETSENCRYPT" == "true" ]]; then
        echo "- Certificate: /etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        echo "- Private Key: /etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        echo "- Certificate: /etc/ssl/certs/$DOMAIN.pem"
        echo "- Private Key: /etc/ssl/private/$DOMAIN.key"
    fi
    echo "=================================="
}

# Run SSL setup with options
case "${1:-all}" in
    "letsencrypt")
        setup_letsencrypt
        obtain_letsencrypt_certificate
        configure_letsencrypt_renewal
        ;;
    "selfsigned")
        setup_self_signed_certificates
        ;;
    "apache")
        configure_apache_ssl
        restart_service apache2
        ;;
    "security")
        configure_ssl_security
        ;;
    "monitor")
        setup_ssl_monitoring
        ;;
    "tools")
        create_ssl_management_tools
        ;;
    "test")
        test_ssl_configuration
        ;;
    "status")
        /usr/local/bin/ssl-status 2>/dev/null || echo "SSL status script not available"
        ;;
    "renew")
        /usr/local/bin/ssl-renew 2>/dev/null || echo "SSL renewal script not available"
        ;;
    "all")
        main
        create_ssl_management_tools
        ;;
    *)
        echo "Usage: \$0 [letsencrypt|selfsigned|apache|security|monitor|tools|test|status|renew|all]"
        echo "  letsencrypt  - Setup Let's Encrypt certificates"
        echo "  selfsigned   - Setup self-signed certificates"
        echo "  apache       - Configure Apache for SSL"
        echo "  security     - Configure SSL security features"
        echo "  monitor      - Setup SSL monitoring"
        echo "  tools        - Create SSL management tools"
        echo "  test         - Test SSL configuration"
        echo "  status       - Show SSL status"
        echo "  renew        - Renew SSL certificates"
        echo "  all          - Run complete SSL setup (default)"
        exit 1
        ;;
esac