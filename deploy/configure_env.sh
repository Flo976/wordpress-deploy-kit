#!/usr/bin/env bash
# deploy/configure_basic.sh
# Assistant interactif pour générer/mettre à jour deploy/env
# Couvre : Domaine/Web root, MariaDB (db/user/pass), FTP (user/pass/home/ports)

set -Eeuo pipefail

# -------- UI ----------
BOLD="\e[1m"; DIM="\e[2m"; RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; RESET="\e[0m"
info(){ echo -e "${BLUE}ℹ${RESET} $*"; }
ok(){ echo -e "${GREEN}✔${RESET} $*"; }
warn(){ echo -e "${YELLOW}⚠${RESET} $*"; }
err(){ echo -e "${RED}✖${RESET} $*"; }
confirm(){ read -r -p "$1 [o/N] " r; [[ "${r,,}" == "o" || "${r,,}" == "oui" ]]; }

# -------- Paths ----------
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$BASE_DIR/env"
ENV_EXAMPLE="$BASE_DIR/env.example"

# -------- Defaults (overridable by env.example) ----------
declare -A DEF
DEF[DOMAIN]="example.local"
DEF[PUBLIC_IP]=""
DEF[WEB_ROOT]="/var/www/html"

# DB
DEF[MDB_DB_NAME]="wordpress"
DEF[MDB_DB_USER]="wpuser"
DEF[MDB_DB_PASS]="changeme"

# FTP
DEF[FTP_USER]="ftpuser"
DEF[FTP_PASSWORD]="changeme"
DEF[FTP_HOME]="${DEF[WEB_ROOT]}"
DEF[FTP_PORT]="21"
DEF[FTP_PASSIVE_MIN]="40000"
DEF[FTP_PASSIVE_MAX]="40050"

# -------- Load defaults from env.example if present ----------
if [[ -f "$ENV_EXAMPLE" ]]; then
  while IFS='=' read -r k v; do
    [[ -z "${k// }" || "${k:0:1}" == "#" ]] && continue
    v="${v%$'\r'}"
    DEF["$k"]="${v}"
  done < "$ENV_EXAMPLE"
fi

# -------- Helpers ----------
ask() { # ask "Prompt" "default" OUTVAR [silent]
  local prompt="$1" def="${2:-}" __var="$3" silent="${4:-false}" val
  if [[ "$silent" == "true" ]]; then
    read -r -s -p "$prompt [$def]: " val || true; echo
  else
    read -r -p "$prompt [$def]: " val || true
  fi
  printf -v "$__var" "%s" "${val:-$def}"
}

is_number(){ [[ "$1" =~ ^[0-9]+$ ]]; }
is_domain(){
  # accepte aussi .local/.lan pour dev
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9-]{1,63})+$ ]]
}

# -------- Questions ----------
echo -e "${BOLD}Configuration Domaine / Web:${RESET}"
ask "Domaine (DOMAIN)" "${DEF[DOMAIN]}" OUT_DOMAIN
ask "IP publique (PUBLIC_IP, optionnel)" "${DEF[PUBLIC_IP]}" OUT_PUBLIC_IP
ask "Racine Web (WEB_ROOT)" "${DEF[WEB_ROOT]}" OUT_WEB_ROOT

echo -e "\n${BOLD}Base de données (MariaDB):${RESET}"
ask "Nom de la base (MDB_DB_NAME)" "${DEF[MDB_DB_NAME]}" OUT_DB_NAME
ask "Utilisateur DB (MDB_DB_USER)" "${DEF[MDB_DB_USER]}" OUT_DB_USER
ask "Mot de passe DB (MDB_DB_PASS)" "${DEF[MDB_DB_PASS]}" OUT_DB_PASS true

echo -e "\n${BOLD}FTP (vsftpd):${RESET}"
ask "Utilisateur FTP (FTP_USER)" "${DEF[FTP_USER]}" OUT_FTP_USER
ask "Mot de passe FTP (FTP_PASSWORD)" "${DEF[FTP_PASSWORD]}" OUT_FTP_PASS true
ask "Dossier FTP (FTP_HOME)" "${DEF[FTP_HOME]}" OUT_FTP_HOME
ask "Port FTP (FTP_PORT)" "${DEF[FTP_PORT]}" OUT_FTP_PORT
ask "Port passif min (FTP_PASSIVE_MIN)" "${DEF[FTP_PASSIVE_MIN]}" OUT_PMIN
ask "Port passif max (FTP_PASSIVE_MAX)" "${DEF[FTP_PASSIVE_MAX]}" OUT_PMAX

# -------- Validation ----------
valid=true
if ! is_domain "$OUT_DOMAIN"; then err "DOMAIN invalide : $OUT_DOMAIN"; valid=false; fi
if [[ -n "$OUT_PUBLIC_IP" && ! "$OUT_PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  warn "PUBLIC_IP ne ressemble pas à une IPv4, je continue quand même."
fi
if [[ -z "$OUT_DB_NAME" || -z "$OUT_DB_USER" || -z "$OUT_DB_PASS" ]]; then
  err "Champs DB requis (nom, utilisateur, mot de passe)."; valid=false
fi
if ! is_number "$OUT_FTP_PORT"; then err "FTP_PORT doit être numérique."; valid=false; fi
if ! is_number "$OUT_PMIN" || ! is_number "$OUT_PMAX"; then
  err "Les ports passifs doivent être numériques."; valid=false
elif (( OUT_PMIN > OUT_PMAX )); then
  err "FTP_PASSIVE_MIN doit être ≤ FTP_PASSIVE_MAX."; valid=false
fi
$valid || { err "Validation échouée. Abandon."; exit 1; }

# -------- Récapitulatif ----------
echo -e "\n${BOLD}Récapitulatif :${RESET}"
cat <<EOF
DOMAIN=$OUT_DOMAIN
PUBLIC_IP=$OUT_PUBLIC_IP
WEB_ROOT=$OUT_WEB_ROOT

MDB_DB_NAME=$OUT_DB_NAME
MDB_DB_USER=$OUT_DB_USER
MDB_DB_PASS=<secret>

FTP_USER=$OUT_FTP_USER
FTP_PASSWORD=<secret>
FTP_HOME=$OUT_FTP_HOME
FTP_PORT=$OUT_FTP_PORT
FTP_PASSIVE_MIN=$OUT_PMIN
FTP_PASSIVE_MAX=$OUT_PMAX
EOF
echo

confirm "Écrire ces valeurs dans ${ENV_FILE} ?" || { warn "Annulé. Aucun fichier écrit."; exit 0; }

# -------- Écriture (avec sauvegarde) ----------
mkdir -p "$BASE_DIR"
if [[ -f "$ENV_FILE" ]]; then
  cp -f "$ENV_FILE" "${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
  info "Ancien env sauvegardé."
fi

{
  echo "# Généré par configure_basic.sh - $(date -Iseconds)"
  echo "DOMAIN=$OUT_DOMAIN"
  [[ -n "$OUT_PUBLIC_IP" ]] && echo "PUBLIC_IP=$OUT_PUBLIC_IP"
  echo "WEB_ROOT=$OUT_WEB_ROOT"

  echo "MDB_DB_NAME=$OUT_DB_NAME"
  echo "MDB_DB_USER=$OUT_DB_USER"
  echo "MDB_DB_PASS=$OUT_DB_PASS"

  echo "FTP_USER=$OUT_FTP_USER"
  echo "FTP_PASSWORD=$OUT_FTP_PASS"
  echo "FTP_HOME=$OUT_FTP_HOME"
  echo "FTP_PORT=$OUT_FTP_PORT"
  echo "FTP_PASSIVE_MIN=$OUT_PMIN"
  echo "FTP_PASSIVE_MAX=$OUT_PMAX"
} > "$ENV_FILE"

ok "Fichier écrit : $ENV_FILE"
echo -e "${DIM}Astuce : relance ce script à tout moment pour mettre à jour ces variables.${RESET}"
