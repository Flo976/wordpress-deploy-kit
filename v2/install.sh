#!/usr/bin/env bash
# WordPress V2 - Installation simple et complète
# Ubuntu 24.04 LTS avec Apache2, PHP 8.4, MariaDB et Certbot

set -Eeuo pipefail


# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/env"
LOGFILE="/var/log/wordpress-install.log"

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions d'affichage
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOGFILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOGFILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOGFILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOGFILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOGFILE"
    exit 1
}

# Vérification des privilèges root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root (sudo)"
    fi
}

# Chargement du fichier d'environnement
load_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        error "Fichier d'environnement '$ENV_FILE' introuvable. Copiez env.example vers env et configurez-le."
    fi

    info "Chargement de la configuration depuis $ENV_FILE"

    # Normaliser les fins de lignes Windows, au cas où
    sed -i 's/\r$//' "$ENV_FILE"

    # Sourcing robuste : pas de process substitution, neutraliser pipefail autour du source
    set +o pipefail
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
    set -o pipefail

    # Valeurs par défaut
    WEB_ROOT="${WEB_ROOT:-/var/www/html}"
    PHP_VERSION="${PHP_VERSION:-8.4}"
    MARIADB_VERSION="${MARIADB_VERSION:-11.4}"
    ENABLE_SSL="${ENABLE_SSL:-true}"
    SSL_STAGING="${SSL_STAGING:-false}"
    ENABLE_FIREWALL="${ENABLE_FIREWALL:-true}"

    # Contrôles
    [[ -z "${DOMAIN:-}" ]] && error "DOMAIN est requis dans le fichier env"
    [[ -z "${EMAIL:-}" ]] && error "EMAIL est requis dans le fichier env"
    [[ -z "${DB_NAME:-}" ]] && error "DB_NAME est requis dans le fichier env"
    [[ -z "${DB_USER:-}" ]] && error "DB_USER est requis dans le fichier env"
    [[ -z "${DB_PASSWORD:-}" ]] && error "DB_PASSWORD est requis dans le fichier env"
    [[ -z "${DB_ROOT_PASSWORD:-}" ]] && error "DB_ROOT_PASSWORD est requis dans le fichier env"
    [[ -z "${WP_TITLE:-}" ]] && error "WP_TITLE est requis dans le fichier env"
    [[ -z "${WP_ADMIN_USER:-}" ]] && error "WP_ADMIN_USER est requis dans le fichier env"
    [[ -z "${WP_ADMIN_PASSWORD:-}" ]] && error "WP_ADMIN_PASSWORD est requis dans le fichier env"
    [[ -z "${WP_ADMIN_EMAIL:-}" ]] && error "WP_ADMIN_EMAIL est requis dans le fichier env"
}

# Mise à jour du système
update_system() {
    info "Mise à jour du système Ubuntu 24.04..."
    export DEBIAN_FRONTEND=noninteractive
    sudo apt update -y
    sudo apt upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
    sudo apt install -y software-properties-common apt-transport-https ca-certificates curl gnupg lsb-release wget unzip
    success "Système mis à jour"
}

# Installation d'Apache2
install_apache() {
    info "Installation d'Apache2..."
    sudo apt install -y apache2
    
    # Activation des modules nécessaires
    sudo a2enmod rewrite
    sudo a2enmod ssl
    sudo a2enmod headers
    sudo a2enmod expires
    sudo a2enmod deflate
    sudo a2enmod http2
    
    # Configuration de base
    sudo systemctl enable apache2
    sudo systemctl start apache2
    
    success "Apache2 installé et configuré"
}

# Installation de PHP 8.4
install_php() {
    info "Installation de PHP ${PHP_VERSION}..."
    
    # Ajout du dépôt Ondrej pour PHP 8.4
    sudo add-apt-repository -y ppa:ondrej/php
    sudo apt update -y
    
    # Installation de PHP et extensions
    sudo apt install -y \
        php${PHP_VERSION} \
        php${PHP_VERSION}-fpm \
        php${PHP_VERSION}-mysql \
        php${PHP_VERSION}-curl \
        php${PHP_VERSION}-gd \
        php${PHP_VERSION}-intl \
        php${PHP_VERSION}-mbstring \
        php${PHP_VERSION}-soap \
        php${PHP_VERSION}-xml \
        php${PHP_VERSION}-xmlrpc \
        php${PHP_VERSION}-zip \
        php${PHP_VERSION}-opcache \
        php${PHP_VERSION}-imagick \
        libapache2-mod-php${PHP_VERSION}
    
    # Configuration PHP
    PHP_INI="/etc/php/${PHP_VERSION}/apache2/php.ini"
    sudo sed -i 's/memory_limit = .*/memory_limit = 256M/' "$PHP_INI"
    sudo sed -i 's/upload_max_filesize = .*/upload_max_filesize = 64M/' "$PHP_INI"
    sudo sed -i 's/post_max_size = .*/post_max_size = 64M/' "$PHP_INI"
    sudo sed -i 's/max_execution_time = .*/max_execution_time = 300/' "$PHP_INI"
    sudo sed -i 's/max_input_vars = .*/max_input_vars = 3000/' "$PHP_INI"
    
    # Configuration OPcache
    sudo tee -a "$PHP_INI" > /dev/null << EOF

; OPcache configuration
opcache.enable=1
opcache.memory_consumption=256
opcache.max_accelerated_files=100000
opcache.validate_timestamps=0
opcache.revalidate_freq=0
opcache.save_comments=0
opcache.interned_strings_buffer=64
opcache.jit=1255
opcache.jit_buffer_size=128M
EOF
    
    sudo systemctl enable php${PHP_VERSION}-fpm
    sudo systemctl start php${PHP_VERSION}-fpm
    
    success "PHP ${PHP_VERSION} installé et configuré"
}

# Installation de MariaDB
install_mariadb() {
    info "Installation de MariaDB ${MARIADB_VERSION}..."
    
    # Ajout du dépôt MariaDB
    curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | sudo bash -s -- --mariadb-server-version="mariadb-${MARIADB_VERSION}"
    
    # Installation
    sudo apt update -y
    sudo apt install -y mariadb-server mariadb-client
    
    # Configuration sécurisée
    sudo systemctl enable mariadb
    sudo systemctl start mariadb
    
    # Sécurisation de l'installation
    sudo mysql -e "UPDATE mysql.user SET Password=PASSWORD('${DB_ROOT_PASSWORD}') WHERE User='root';"
    sudo mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    sudo mysql -e "DELETE FROM mysql.user WHERE User='';"
    sudo mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    sudo mysql -e "FLUSH PRIVILEGES;"
    
    # Création de la base et de l'utilisateur
    sudo mysql -u root -p"${DB_ROOT_PASSWORD}" -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    sudo mysql -u root -p"${DB_ROOT_PASSWORD}" -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
    sudo mysql -u root -p"${DB_ROOT_PASSWORD}" -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"
    sudo mysql -u root -p"${DB_ROOT_PASSWORD}" -e "FLUSH PRIVILEGES;"
    
    success "MariaDB ${MARIADB_VERSION} installé et configuré"
}

# Installation de WP-CLI
install_wpcli() {
    info "Installation de WP-CLI..."
    curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    sudo mv wp-cli.phar /usr/local/bin/wp
    success "WP-CLI installé"
}

# Installation de WordPress
install_wordpress() {
    info "Installation de WordPress..."
    
    # Création du répertoire web
    sudo mkdir -p "$WEB_ROOT"
    cd "$WEB_ROOT"
    
    # Suppression du contenu par défaut d'Apache
    sudo rm -f index.html
    
    # Téléchargement de WordPress
    sudo wp core download --locale="${WP_LOCALE:-fr_FR}" --allow-root
    
    # Configuration de WordPress
    sudo wp config create \
        --dbname="$DB_NAME" \
        --dbuser="$DB_USER" \
        --dbpass="$DB_PASSWORD" \
        --dbhost="localhost" \
        --locale="${WP_LOCALE:-fr_FR}" \
        --allow-root
    
    # Installation du site
    sudo wp core install \
        --url="https://$DOMAIN" \
        --title="$WP_TITLE" \
        --admin_user="$WP_ADMIN_USER" \
        --admin_password="$WP_ADMIN_PASSWORD" \
        --admin_email="$WP_ADMIN_EMAIL" \
        --skip-email \
        --allow-root
    
    # Configuration avancée
    sudo wp config set FS_METHOD direct --allow-root
    sudo wp config set DISABLE_WP_CRON true --raw --allow-root
    sudo wp config set WP_DEBUG false --raw --allow-root
    
    # Permaliens
    sudo wp rewrite structure "/%postname%/" --hard --allow-root
    
    # Permissions
    sudo chown -R www-data:www-data "$WEB_ROOT"
    sudo find "$WEB_ROOT" -type d -exec chmod 755 {} \;
    sudo find "$WEB_ROOT" -type f -exec chmod 644 {} \;
    sudo chmod 600 "$WEB_ROOT/wp-config.php"
    
    success "WordPress installé et configuré"
}

# Configuration du Virtual Host Apache
configure_apache_vhost() {
    info "Configuration du Virtual Host Apache..."
    
    sudo tee "/etc/apache2/sites-available/$DOMAIN.conf" > /dev/null << EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot $WEB_ROOT
    
    <Directory $WEB_ROOT>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Logs
    ErrorLog \${APACHE_LOG_DIR}/${DOMAIN}_error.log
    CustomLog \${APACHE_LOG_DIR}/${DOMAIN}_access.log combined
    
    # Security headers
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Cache headers
    <FilesMatch "\\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2)$">
        ExpiresActive On
        ExpiresDefault "access plus 1 year"
        Header append Cache-Control "public, immutable"
    </FilesMatch>
</VirtualHost>
EOF
    
    # Activation du site
    sudo a2ensite "$DOMAIN.conf"
    sudo a2dissite 000-default
    sudo systemctl reload apache2
    
    success "Virtual Host configuré"
}

# Installation et configuration de Certbot
install_certbot() {
    if [[ "$ENABLE_SSL" == "true" ]]; then
        info "Installation de Certbot pour SSL..."
        
        sudo apt install -y certbot python3-certbot-apache
        
        # Options pour staging/production
        CERTBOT_OPTIONS="--non-interactive --agree-tos --email $EMAIL"
        if [[ "$SSL_STAGING" == "true" ]]; then
            CERTBOT_OPTIONS="$CERTBOT_OPTIONS --staging"
            info "Mode staging activé pour les tests SSL"
        fi
        
        # Obtention du certificat
        sudo certbot --apache $CERTBOT_OPTIONS -d "$DOMAIN"
        
        # Auto-renouvellement
        sudo systemctl enable certbot.timer
        sudo systemctl start certbot.timer
        
        success "SSL configuré avec Let's Encrypt"
    else
        info "SSL désactivé dans la configuration"
    fi
}

# Configuration du pare-feu
configure_firewall() {
    if [[ "$ENABLE_FIREWALL" == "true" ]]; then
        info "Configuration du pare-feu UFW..."
        
        sudo ufw --force reset
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        
        # Ports essentiels
        sudo ufw allow ssh
        sudo ufw allow 80/tcp
        sudo ufw allow 443/tcp
        
        # Activation
        sudo ufw --force enable
        
        success "Pare-feu configuré"
    else
        info "Pare-feu désactivé dans la configuration"
    fi
}

# Configuration du cron WordPress
setup_wordpress_cron() {
    info "Configuration du cron WordPress..."
    
    # Cron système pour remplacer wp-cron.php
    CRON_COMMAND="*/5 * * * * www-data /usr/local/bin/wp cron event run --due-now --path=$WEB_ROOT --quiet"
    
    # Ajout au crontab si pas déjà présent
    if ! crontab -l 2>/dev/null | grep -Fq "$CRON_COMMAND"; then
        (crontab -l 2>/dev/null; echo "$CRON_COMMAND") | crontab -
        success "Cron WordPress configuré"
    else
        info "Cron WordPress déjà configuré"
    fi
}

# Affichage du résumé
show_summary() {
    success "Installation WordPress terminée !"
    
    cat << EOF

╔══════════════════════════════════════════════════════════════╗
║                    INSTALLATION TERMINÉE                    ║
╠══════════════════════════════════════════════════════════════╣
║ Domaine        : $DOMAIN                                     
║ URL            : https://$DOMAIN                             
║ Répertoire web : $WEB_ROOT                                   
║ Base de données: $DB_NAME                                    
║ Admin WP       : $WP_ADMIN_USER                              
║ Mot de passe   : $WP_ADMIN_PASSWORD                          
║ Email admin    : $WP_ADMIN_EMAIL                             
╠══════════════════════════════════════════════════════════════╣
║                    SERVICES INSTALLÉS                       ║
╠══════════════════════════════════════════════════════════════╣
║ • Apache2 avec HTTP/2 et modules optimisés                  
║ • PHP $PHP_VERSION avec OPcache et JIT                      
║ • MariaDB $MARIADB_VERSION avec base sécurisée              
║ • WordPress avec WP-CLI                                      
EOF

    if [[ "$ENABLE_SSL" == "true" ]]; then
        echo "║ • SSL/TLS avec Let's Encrypt"
    fi
    
    if [[ "$ENABLE_FIREWALL" == "true" ]]; then
        echo "║ • Pare-feu UFW configuré"
    fi
    
    cat << EOF
╠══════════════════════════════════════════════════════════════╣
║                   COMMANDES UTILES                          ║
╠══════════════════════════════════════════════════════════════╣
║ Mise à jour WP : wp core update --path=$WEB_ROOT --allow-root
║ État services  : systemctl status apache2 mariadb          
║ Logs Apache    : tail -f /var/log/apache2/${DOMAIN}_error.log
║ Logs install   : tail -f $LOGFILE                           
╚══════════════════════════════════════════════════════════════╝

EOF
}

# Fonction principale
main() {
    log "=== Début de l'installation WordPress V2 ==="
    
    check_root
    load_env
    update_system
    install_apache
    install_php
    install_mariadb
    install_wpcli
    install_wordpress
    configure_apache_vhost
    install_certbot
    configure_firewall
    setup_wordpress_cron
    show_summary
    
    log "=== Installation terminée avec succès ==="
}

# Gestion des erreurs
trap 'error "Une erreur est survenue à la ligne $LINENO"' ERR

# Exécution du script principal
main "$@"