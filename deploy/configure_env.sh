#!/usr/bin/env bash
# =====================================================================
#  deploy.sh - Script principal de déploiement WordPress optimisé
# =====================================================================
#  Ce script installe et configure :
#   - PHP 8.4 FPM (optimisé)
#   - Apache (optimisé, MPM event, HTTP/2, Brotli)
#   - MariaDB (optimisé)
#   - WordPress (via wp-cli)
#   - Serveur FTP (vsftpd, TLS explicite)
# =====================================================================

set -Eeuo pipefail
trap 'echo "[ERROR] Échec à la ligne $LINENO"; exit 1' ERR

# --- Définition des chemins ------------------------------------------
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$BASE_DIR/env"
FUNCS_FILE="$BASE_DIR/functions.sh"

# --- Chargement des fonctions utilitaires -----------------------------
if [[ -f "$FUNCS_FILE" ]]; then
    source "$FUNCS_FILE"
else
    echo "[ERROR] Fichier $FUNCS_FILE introuvable"
    exit 1
fi

# --- Chargement des variables d’environnement -------------------------
if [[ -f "$ENV_FILE" ]]; then
    export $(grep -v '^#' "$ENV_FILE" | xargs)
else
    echo "[ERROR] Fichier $ENV_FILE introuvable."
    echo "Copiez env.example vers env puis personnalisez vos variables."
    exit 1
fi

# --- Vérifications de prérequis système -------------------------------
check_root          # doit être root
check_os "Ubuntu"   # on cible Ubuntu uniquement
check_network       # accès internet requis

# --- Fonctions principales --------------------------------------------
install_all() {
    log_info "=== DÉMARRAGE DU DÉPLOIEMENT COMPLET ==="

    bash "$BASE_DIR/optimize_apache.sh" all
    bash "$BASE_DIR/optimize_php.sh" all
    bash "$BASE_DIR/optimize_mariadb.sh" all
    bash "$BASE_DIR/install_wp.sh"
    bash "$BASE_DIR/install_ftp.sh"

    if [[ "${ENABLE_UFW:-false}" == "true" ]]; then
        bash "$BASE_DIR/hardening.sh"
    fi

    log_success "=== DÉPLOIEMENT TERMINÉ ==="
    show_summary
}

show_summary() {
    cat <<EOF

---------------------------------------------------------
 ✅ Déploiement terminé
---------------------------------------------------------
 Domaine         : ${DOMAIN:-non défini}
 URL HTTP        : http://${DOMAIN:-localhost}
 URL HTTPS       : https://${DOMAIN:-localhost}
 Admin WordPress : ${WP_ADMIN_USER:-admin}
 Base de données : ${WP_DB_NAME:-wordpress}
 Utilisateur DB  : ${WP_DB_USER:-wpuser}
 FTP utilisateur : ${FTP_USER:-ftpuser}
---------------------------------------------------------
EOF
}

# --- Parsing des arguments --------------------------------------------
ACTION="${1:-all}"

case "$ACTION" in
    "apache")
        bash "$BASE_DIR/optimize_apache.sh" all
        ;;
    "php")
        bash "$BASE_DIR/optimize_php.sh" all
        ;;
    "mariadb")
        bash "$BASE_DIR/optimize_mariadb.sh" all
        ;;
    "wp")
        bash "$BASE_DIR/install_wp.sh"
        ;;
    "ftp")
        bash "$BASE_DIR/install_ftp.sh"
        ;;
    "hardening")
        bash "$BASE_DIR/hardening.sh"
        ;;
    "all")
        install_all
        ;;
    "status")
        bash "$BASE_DIR/system_checks.sh"
        ;;
    *)
        echo "Usage: $0 [apache|php|mariadb|wp|ftp|hardening|status|all]"
        exit 1
        ;;
esac
