#!/usr/bin/env bash
# stack-install.sh
# LAMP+FTP optimisé : PHP 8.4 FPM, Apache (HTTP/2, Brotli), MariaDB, vsftpd TLS
# Cible : Ubuntu 24.04 (noble)

set -Eeuo pipefail

### ---------- Config par défaut (surchargée par ./.env si présent) ----------
PHP_VERSION="${PHP_VERSION:-8.4}"
DOMAIN="${DOMAIN:-example.local}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

# PHP tuning
PHP_MEMORY_LIMIT="${PHP_MEMORY_LIMIT:-256M}"
PHP_UPLOAD_MAX_FILESIZE="${PHP_UPLOAD_MAX_FILESIZE:-64M}"
PHP_POST_MAX_SIZE="${PHP_POST_MAX_SIZE:-64M}"
PHP_MAX_EXECUTION_TIME="${PHP_MAX_EXECUTION_TIME:-120}"
OPCACHE_MEMORY_CONSUMPTION="${OPCACHE_MEMORY_CONSUMPTION:-256}"
OPCACHE_MAX_ACCELERATED_FILES="${OPCACHE_MAX_ACCELERATED_FILES:-100000}"
OPCACHE_VALIDATE_TIMESTAMPS="${OPCACHE_VALIDATE_TIMESTAMPS:-0}"

# PHP-FPM pool (www)
PHP_FPM_PM="${PHP_FPM_PM:-dynamic}"
PHP_FPM_PM_MAX_CHILDREN="${PHP_FPM_PM_MAX_CHILDREN:-20}"
PHP_FPM_PM_START_SERVERS="${PHP_FPM_PM_START_SERVERS:-4}"
PHP_FPM_PM_MIN_SPARE_SERVERS="${PHP_FPM_PM_MIN_SPARE_SERVERS:-2}"
PHP_FPM_PM_MAX_SPARE_SERVERS="${PHP_FPM_PM_MAX_SPARE_SERVERS:-6}"

# Apache
ENABLE_HTTP2="${ENABLE_HTTP2:-true}"
ENABLE_BROTLI="${ENABLE_BROTLI:-true}"

# MariaDB
MDB_CREATE_SAMPLE_DB="${MDB_CREATE_SAMPLE_DB:-false}"
MDB_DB_NAME="${MDB_DB_NAME:-wordpress}"
MDB_DB_USER="${MDB_DB_USER:-wpuser}"
MDB_DB_PASS="${MDB_DB_PASS:-changeme}"
# tuning
INNODB_BUFFER_POOL_SIZE="${INNODB_BUFFER_POOL_SIZE:-512M}"
INNODB_LOG_FILE_SIZE="${INNODB_LOG_FILE_SIZE:-256M}"
MDB_MAX_CONNECTIONS="${MDB_MAX_CONNECTIONS:-200}"
TMP_TABLE_SIZE="${TMP_TABLE_SIZE:-128M}"
MAX_HEAP_TABLE_SIZE="${MAX_HEAP_TABLE_SIZE:-128M}"

# FTP
FTP_USER="${FTP_USER:-ftpuser}"
FTP_PASSWORD="${FTP_PASSWORD:-changeme}"
FTP_HOME="${FTP_HOME:-$WEB_ROOT}"
FTP_PASSIVE_MIN="${FTP_PASSIVE_MIN:-40000}"
FTP_PASSIVE_MAX="${FTP_PASSIVE_MAX:-40050}"
FTP_PORT="${FTP_PORT:-21}"
FTP_TLS_CERT="${FTP_TLS_CERT:-/etc/ssl/private/vsftpd.pem}"

# Réseau/pare-feu (optionnel)
ENABLE_UFW="${ENABLE_UFW:-true}"

### ---------- Charge .env local si présent ----------
if [[ -f ./.env ]]; then
  # charge seulement les lignes KEY=VALUE (ignore commentaires)
  set -a
  # shellcheck disable=SC2046
  source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' ./.env | sed 's/\r$//')
  set +a
fi

### ---------- Helpers ----------
log() { printf "\e[1;34m[INFO]\e[0m %s\n" "$*"; }
ok()  { printf "\e[1;32m[OK]\e[0m %s\n" "$*"; }
warn(){ printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
err() { printf "\e[1;31m[ERR]\e[0m %s\n" "$*"; }

need_root() { [[ $EUID -eq 0 ]] || { err "Lancez en root (sudo)."; exit 1; }; }
is_ubuntu() { grep -qi "ubuntu" /etc/os-release || { err "Ubuntu requis."; exit 1; }; }

apt_install() {
  local pkgs=("$@")
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
}

enable_module() { a2enmod "$1" >/dev/null 2>&1 || true; }
disable_module(){ a2dismod "$1" >/dev/null 2>&1 || true; }

write_file() { # write_file /path/to/file "content"
  local f="$1"; shift
  install -d -m 0755 "$(dirname "$f")"
  printf "%s\n" "$*" >"$f"
}

replace_or_add() { # replace_or_add file regex replacement_line
  local f="$1" rx="$2" line="$3"
  if grep -qE "$rx" "$f" 2>/dev/null; then
    sed -i -E "s|$rx|$line|" "$f"
  else
    printf "%s\n" "$line" >> "$f"
  fi
}

set_ini() { # set_ini file key value
  local f="$1" key="$2" val="$3"
  if grep -qE "^[;# ]*$key *= *" "$f" 2>/dev/null; then
    sed -i -E "s|^[;# ]*($key) *=.*|\1 = $val|" "$f"
  else
    printf "%s = %s\n" "$key" "$val" >> "$f"
  fi
}

### ---------- Préchecks ----------
need_root
is_ubuntu
log "Mise à jour APT…"
apt-get update -y

### ---------- PHP 8.4 (PPA ondrej si nécessaire) ----------
if ! dpkg -l | grep -q "php$PHP_VERSION-fpm"; then
  log "Ajout du PPA ondrej/php (si absent) et installation PHP $PHP_VERSION…"
  if ! ls /etc/apt/sources.list.d | grep -qi ondrej.*php; then
    apt_install ca-certificates apt-transport-https lsb-release gnupg
    add-apt-repository -y ppa:ondrej/php
    apt-get update -y
  fi
  apt_install "php$PHP_VERSION-fpm" "php$PHP_VERSION-cli" "php$PHP_VERSION-mysql" \
              "php$PHP_VERSION-xml" "php$PHP_VERSION-curl" "php$PHP_VERSION-gd" \
              "php$PHP_VERSION-zip" "php$PHP_VERSION-mbstring" "php$PHP_VERSION-intl" \
              "php$PHP_VERSION-opcache" "php$PHP_VERSION-readline"
else
  log "PHP $PHP_VERSION déjà installé."
fi

### ---------- Apache ----------
if ! dpkg -l | grep -q '^ii  apache2 '; then
  log "Installation Apache…"
  apt_install apache2
else
  log "Apache déjà installé."
fi

# Modules & MPM
log "Activation MPM event + modules requis…"
disable_module mpm_prefork || true
enable_module mpm_event
enable_module headers
enable_module rewrite
enable_module proxy
enable_module proxy_fcgi
enable_module http2
enable_module ssl
enable_module expires

# Brotli si dispo
if apt-cache show libapache2-mod-brotli >/dev/null 2>&1; then
  apt_install libapache2-mod-brotli
  enable_module brotli
else
  warn "libapache2-mod-brotli indisponible dans ce dépôt — Brotli ignoré."
  ENABLE_BROTLI="false"
fi

# Conf FPM handler (idempotent)
log "Configuration Apache ↔ PHP-FPM…"
APACHE_FPM_CONF="/etc/apache2/conf-available/php$PHP_VERSION-fpm.conf"
write_file "$APACHE_FPM_CONF" "<FilesMatch \.php$>
    SetHandler \"proxy:unix:/run/php/php$PHP_VERSION-fpm.sock|fcgi://localhost/\"
</FilesMatch>"
a2enconf "php$PHP_VERSION-fpm" >/dev/null 2>&1 || true

# VHost 000-default (HTTP)
VHOST="/etc/apache2/sites-available/000-default.conf"
if [[ ! -f "$VHOST.bak" ]]; then cp "$VHOST" "$VHOST.bak"; fi
cat >"$VHOST" <<CONF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot $WEB_ROOT

    <Directory $WEB_ROOT>
        AllowOverride All
        Require all granted
    </Directory>

    Protocols $( [[ "$ENABLE_HTTP2" == "true" ]] && echo "h2 h2c http/1.1" || echo "http/1.1" )

    <IfModule mod_headers.c>
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set Referrer-Policy "strict-origin-when-cross-origin"
        Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"
    </IfModule>

    <IfModule mod_expires.c>
        ExpiresActive On
        ExpiresByType text/css "access plus 7 days"
        ExpiresByType application/javascript "access plus 7 days"
        ExpiresByType image/* "access plus 30 days"
    </IfModule>

    $( [[ "$ENABLE_BROTLI" == "true" ]] && cat <<'BROT'
    <IfModule mod_brotli.c>
        AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml text/css text/javascript application/javascript application/json application/xml
        BrotliCompressionQuality 5
    </IfModule>
BROT
)

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
CONF

systemctl enable --now apache2

### ---------- Tuning PHP (php.ini + FPM pool) ----------
log "Tuning PHP $PHP_VERSION…"
PHP_INI_FPM="/etc/php/$PHP_VERSION/fpm/php.ini"
PHP_INI_CLI="/etc/php/$PHP_VERSION/cli/php.ini"
POOL_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"

for ini in "$PHP_INI_FPM" "$PHP_INI_CLI"; do
  set_ini "$ini" memory_limit "$PHP_MEMORY_LIMIT"
  set_ini "$ini" upload_max_filesize "$PHP_UPLOAD_MAX_FILESIZE"
  set_ini "$ini" post_max_size "$PHP_POST_MAX_SIZE"
  set_ini "$ini" max_execution_time "$PHP_MAX_EXECUTION_TIME"
  set_ini "$ini" expose_php "Off"
  # OPcache
  set_ini "$ini" opcache.enable "1"
  set_ini "$ini" opcache.enable_cli "1"
  set_ini "$ini" opcache.memory_consumption "$OPCACHE_MEMORY_CONSUMPTION"
  set_ini "$ini" opcache.max_accelerated_files "$OPCACHE_MAX_ACCELERATED_FILES"
  set_ini "$ini" opcache.validate_timestamps "$OPCACHE_VALIDATE_TIMESTAMPS"
done

replace_or_add "$POOL_CONF" '^pm *=.*' "pm = $PHP_FPM_PM"
replace_or_add "$POOL_CONF" '^pm\.max_children *=.*' "pm.max_children = $PHP_FPM_PM_MAX_CHILDREN"
replace_or_add "$POOL_CONF" '^pm\.start_servers *=.*' "pm.start_servers = $PHP_FPM_PM_START_SERVERS"
replace_or_add "$POOL_CONF" '^pm\.min_spare_servers *=.*' "pm.min_spare_servers = $PHP_FPM_PM_MIN_SPARE_SERVERS"
replace_or_add "$POOL_CONF" '^pm\.max_spare_servers *=.*' "pm.max_spare_servers = $PHP_FPM_PM_MAX_SPARE_SERVERS"
replace_or_add "$POOL_CONF" '^catch_workers_output *=.*' "catch_workers_output = yes"
replace_or_add "$POOL_CONF" '^pm\.status_path *=.*' "pm.status_path = /status"

systemctl enable --now "php$PHP_VERSION-fpm"
systemctl reload "php$PHP_VERSION-fpm" apache2

### ---------- MariaDB ----------
if ! dpkg -l | grep -q '^ii  mariadb-server '; then
  log "Installation MariaDB…"
  apt_install mariadb-server
else
  log "MariaDB déjà installé."
fi

# Snippet tuning idempotent
log "Tuning MariaDB…"
MDB_TUNE="/etc/mysql/mariadb.conf.d/99-tuning.cnf"
write_file "$MDB_TUNE" "[mysqld]
character-set-server = utf8mb4
collation-server     = utf8mb4_0900_ai_ci

innodb_buffer_pool_size = $INNODB_BUFFER_POOL_SIZE
innodb_log_file_size    = $INNODB_LOG_FILE_SIZE
max_connections         = $MDB_MAX_CONNECTIONS
tmp_table_size          = $TMP_TABLE_SIZE
max_heap_table_size     = $MAX_HEAP_TABLE_SIZE

slow_query_log = ON
slow_query_log_file = /var/log/mysql/slow.log
performance_schema = ON
"
install -d -m 0755 /var/log/mysql
touch /var/log/mysql/slow.log
chown mysql:mysql /var/log/mysql/slow.log || true
systemctl enable --now mariadb
systemctl restart mariadb

# Création DB/User si demandé
if [[ "$MDB_CREATE_SAMPLE_DB" == "true" ]]; then
  log "Création DB/utilisateur ($MDB_DB_NAME / $MDB_DB_USER)…"
  mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`$MDB_DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS '$MDB_DB_USER'@'%' IDENTIFIED BY '$MDB_DB_PASS';
GRANT ALL PRIVILEGES ON \`$MDB_DB_NAME\`.* TO '$MDB_DB_USER'@'%';
FLUSH PRIVILEGES;
SQL
  ok "DB d’exemple prête."
fi

### ---------- vsftpd (FTPS explicite) ----------
if ! dpkg -l | grep -q '^ii  vsftpd '; then
  log "Installation vsftpd…"
  apt_install vsftpd openssl
else
  log "vsftpd déjà installé."
fi

# Cert TLS auto-signé si absent
if [[ ! -f "$FTP_TLS_CERT" ]]; then
  log "Génération d’un certificat auto-signé pour FTPS ($FTP_TLS_CERT)…"
  install -d -m 0700 "$(dirname "$FTP_TLS_CERT")"
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$FTP_TLS_CERT" -out "$FTP_TLS_CERT" \
    -subj "/C=FR/ST=NA/L=NA/O=Local/OU=FTP/CN=$DOMAIN" >/dev/null 2>&1
  chmod 600 "$FTP_TLS_CERT"
fi

# Utilisateur FTP (système) chrooté
if ! id "$FTP_USER" >/dev/null 2>&1; then
  log "Création utilisateur FTP $FTP_USER…"
  useradd -d "$FTP_HOME" -s /usr/sbin/nologin "$FTP_USER"
  echo "$FTP_USER:$FTP_PASSWORD" | chpasswd
  chown -R "$FTP_USER":"$FTP_USER" "$FTP_HOME" || true
  usermod -aG www-data $FTP_USER
  chmod -R 775 /var/www/html
  chown -R www-data:www-data /var/www/html
fi

VSFTPD_CONF="/etc/vsftpd.conf"
if [[ ! -f "$VSFTPD_CONF.bak" ]]; then cp "$VSFTPD_CONF" "$VSFTPD_CONF.bak"; fi
write_file "$VSFTPD_CONF" "listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES

pam_service_name=vsftpd
use_localtime=YES

# TLS (FTPS explicite)
ssl_enable=YES
rsa_cert_file=$FTP_TLS_CERT
rsa_private_key_file=$FTP_TLS_CERT
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO

# Port & passif
listen_port=$FTP_PORT
pasv_enable=YES
pasv_min_port=$FTP_PASSIVE_MIN
pasv_max_port=$FTP_PASSIVE_MAX

# Sécurité
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO

# Performances
seccomp_sandbox=NO
"

echo "$FTP_USER" >/etc/vsftpd.userlist
chmod 600 /etc/vsftpd.userlist

systemctl enable --now vsftpd
systemctl restart vsftpd

### ---------- Pare-feu UFW (optionnel) ----------
if [[ "$ENABLE_UFW" == "true" ]]; then
  if ! dpkg -l | grep -q '^ii  ufw '; then apt_install ufw; fi
  log "Configuration UFW…"
  ufw allow 22/tcp || true
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow $FTP_PORT/tcp || true
  ufw allow $FTP_PASSIVE_MIN:$FTP_PASSIVE_MAX/tcp || true
  yes | ufw enable || true
fi

### ---------- Récapitulatif ----------
ok "Installation & configuration terminées."
cat <<EOF

Résumé :
- Domaine         : $DOMAIN
- Racine web      : $WEB_ROOT
- PHP-FPM         : $PHP_VERSION (pm=$PHP_FPM_PM, children=$PHP_FPM_PM_MAX_CHILDREN)
- Apache          : MPM event, HTTP/2=$(echo $ENABLE_HTTP2), Brotli=$(echo $ENABLE_BROTLI)
- MariaDB         : $(mysql --version 2>/dev/null | awk '{print $1,$2,$3}' || echo 'installé') (DB exemple: $MDB_CREATE_SAMPLE_DB)
- FTP (vsftpd)    : port=$FTP_PORT, passifs=$FTP_PASSIVE_MIN-$FTP_PASSIVE_MAX, user=$FTP_USER
- TLS FTPS        : $FTP_TLS_CERT

Vérifs rapides :
  systemctl status apache2 php$PHP_VERSION-fpm mariadb vsftpd --no-pager
  curl -I http://localhost
  openssl s_client -starttls ftp -connect localhost:$FTP_PORT -tls1_2 </dev/null
EOF
