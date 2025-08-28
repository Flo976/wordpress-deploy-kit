#!/usr/bin/env bash
# deploy/install_wordpress.sh
# Installe et configure WordPress (idempotent) en lisant deploy/env

set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$BASE_DIR/env"

# --- UI helpers ---
info(){ printf "\e[1;34m[INFO]\e[0m %s\n" "$*"; }
ok(){   printf "\e[1;32m[OK]\e[0m %s\n"  "$*"; }
warn(){ printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
err(){  printf "\e[1;31m[ERR]\e[0m %s\n"  "$*"; }

need_root(){ [[ $EUID -eq 0 ]] || { err "Lance ce script en root (sudo)."; exit 1; }; }
need_root

# --- Charger env ---
if [[ ! -f "$ENV_FILE" ]]; then
  err "deploy/env introuvable. Exécute d’abord configure_basic.sh"
  exit 1
fi
set -a
# charge uniquement KEY=VALUE (ignore commentaires)
source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_FILE" | sed 's/\r$//')
set +a

# --- Variables requises / défauts ---
DOMAIN="${DOMAIN:-example.local}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

MDB_DB_NAME="${MDB_DB_NAME:-wordpress}"
MDB_DB_USER="${MDB_DB_USER:-wpuser}"
MDB_DB_PASS="${MDB_DB_PASS:-changeme}"

# Variables WP optionnelles (si absentes, on met des valeurs par défaut)
WP_LOCALE="${WP_LOCALE:-fr_FR}"
WP_TABLE_PREFIX="${WP_TABLE_PREFIX:-wp_}"
WP_ADMIN_USER="${WP_ADMIN_USER:-admin}"
WP_ADMIN_PASSWORD="${WP_ADMIN_PASSWORD:-Admin123!}"
WP_ADMIN_EMAIL="${WP_ADMIN_EMAIL:-admin@$DOMAIN}"
WP_TITLE="${WP_TITLE:-Mon Site WordPress}"

URL_SCHEME="http"  # simple et fiable ; bascule en https plus tard si tu configures TLS
SITE_URL="$URL_SCHEME://$DOMAIN"

# --- Pré-requis packages ---
info "Installation des prérequis (curl, tar, less, mariadb-client)…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends curl ca-certificates tar less mariadb-client jq

# --- WP-CLI ---
if ! command -v wp >/dev/null 2>&1; then
  info "Installation de WP-CLI…"
  curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
  chmod +x /usr/local/bin/wp
else
  info "WP-CLI déjà présent."
fi

# --- Créer WEB_ROOT ---
install -d -m 0755 "$WEB_ROOT"

# --- Créer DB et utilisateur (via socket root) ---
info "Création base et utilisateur MariaDB (si besoin)…"
if ! mysql -uroot -e "USE \`$MDB_DB_NAME\`;" >/dev/null 2>&1; then
  mysql -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`$MDB_DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER IF NOT EXISTS '$MDB_DB_USER'@'%' IDENTIFIED BY '$MDB_DB_PASS';
GRANT ALL PRIVILEGES ON \`$MDB_DB_NAME\`.* TO '$MDB_DB_USER'@'%';
FLUSH PRIVILEGES;
SQL
  ok "Base \`$MDB_DB_NAME\` et utilisateur \`$MDB_DB_USER\` prêts."
else
  info "Base \`$MDB_DB_NAME\` déjà existante — OK."
fi

# --- Télécharger WordPress si absent ---
if [[ ! -f "$WEB_ROOT/wp-settings.php" ]]; then
  info "Téléchargement de WordPress ($WP_LOCALE) dans $WEB_ROOT…"
  wp core download --locale="$WP_LOCALE" --path="$WEB_ROOT" --allow-root
else
  info "WordPress déjà présent dans $WEB_ROOT — OK."
fi

# --- Créer wp-config.php si absent ---
if [[ ! -f "$WEB_ROOT/wp-config.php" ]]; then
  info "Création wp-config.php…"
  wp config create \
    --path="$WEB_ROOT" \
    --dbname="$MDB_DB_NAME" \
    --dbuser="$MDB_DB_USER" \
    --dbpass="$MDB_DB_PASS" \
    --dbhost="127.0.0.1" \
    --dbprefix="$WP_TABLE_PREFIX" \
    --locale="$WP_LOCALE" \
    --skip-check \
    --allow-root

  # Constantes utiles
  wp config set FS_METHOD direct --path="$WEB_ROOT" --allow-root
  wp config set DISABLE_WP_CRON true --raw --path="$WEB_ROOT" --allow-root
  wp config set WP_DEBUG false --raw --path="$WEB_ROOT" --allow-root

  ok "wp-config.php créé."
else
  info "wp-config.php déjà présent — OK."
fi

# --- Installer le site si pas encore fait ---
if ! wp core is-installed --path="$WEB_ROOT" --allow-root >/dev/null 2>&1; then
  info "Installation du site WordPress…"
  wp core install \
    --path="$WEB_ROOT" \
    --url="$SITE_URL" \
    --title="$WP_TITLE" \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASSWORD" \
    --admin_email="$WP_ADMIN_EMAIL" \
    --skip-email \
    --allow-root
  ok "Site installé : $SITE_URL"
else
  info "WordPress déjà installé — OK."
fi

# --- Permaliens jolis ---
CURRENT_STRUCTURE="$(wp option get permalink_structure --path="$WEB_ROOT" --allow-root || echo '')"
if [[ "$CURRENT_STRUCTURE" != "/%postname%/" ]]; then
  info "Activation des permaliens /%postname%/…"
  wp rewrite structure "/%postname%/" --hard --path="$WEB_ROOT" --allow-root
  wp rewrite flush --hard --path="$WEB_ROOT" --allow-root
  ok "Permaliens activés."
fi

# --- Cron système (désactive WP pseudo-cron) ---
CRON_LINE="*/5 * * * * www-data /usr/local/bin/wp cron event run --due-now --path=$WEB_ROOT --quiet"
if ! crontab -l 2>/dev/null | grep -Fq "$CRON_LINE"; then
  info "Ajout cron pour wp-cron (toutes les 5 min)…"
  (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
  ok "Cron ajouté."
else
  info "Cron déjà présent — OK."
fi

# --- Droits fichiers (recommandé) ---
if id -u www-data >/dev/null 2>&1; then
  info "Ajustement des permissions (www-data)…"
  chown -R www-data:www-data "$WEB_ROOT"
  find "$WEB_ROOT" -type d -exec chmod 755 {} \;
  find "$WEB_ROOT" -type f -exec chmod 644 {} \;
  ok "Permissions appliquées."
else
  warn "Utilisateur www-data introuvable ; permissions non modifiées."
fi

# --- Résumé ---
ok "Installation WordPress terminée."
cat <<EOF

Résumé :
  Domaine         : $DOMAIN
  URL             : $SITE_URL
  Web root        : $WEB_ROOT
  DB              : $MDB_DB_NAME (user: $MDB_DB_USER)
  Admin           : $WP_ADMIN_USER / $WP_ADMIN_PASSWORD
  Locale          : $WP_LOCALE

Commandes utiles :
  wp core update --path="$WEB_ROOT" --allow-root
  wp plugin update --all --path="$WEB_ROOT" --allow-root
  wp theme update --all --path="$WEB_ROOT" --allow-root
EOF
