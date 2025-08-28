# WordPress V2 - Installation Simple

Script d'installation automatique de WordPress sur Ubuntu 24.04 LTS avec Apache2, PHP 8.4, MariaDB et SSL.

## Fonctionnalités

- ✅ Installation complète sur Ubuntu 24.04 neuf
- ✅ Apache2 avec HTTP/2 et modules optimisés
- ✅ PHP 8.4 avec OPcache et JIT
- ✅ MariaDB LTS avec sécurisation
- ✅ WordPress avec WP-CLI
- ✅ SSL automatique avec Let's Encrypt
- ✅ Pare-feu UFW configuré
- ✅ Cron système WordPress
- ✅ Configuration sécurisée

## Installation Rapide

### 1. Préparation

```bash
# Cloner le dépôt
git clone <repository-url>
cd wordpress-deploy-kit/v2

# Copier et configurer l'environnement
cp env.example env
nano env
```

### 2. Configuration minimale (fichier `env`)

```bash
# Domaine (REQUIS)
DOMAIN=monsite.com

# Email pour SSL (REQUIS)
EMAIL=admin@monsite.com

# Base de données
DB_NAME=wordpress
DB_USER=wpuser
DB_PASSWORD=motdepasse-securise
DB_ROOT_PASSWORD=motdepasse-root-securise

# Administrateur WordPress
WP_ADMIN_USER=admin
WP_ADMIN_PASSWORD=MotDePasseAdmin123!
WP_ADMIN_EMAIL=admin@monsite.com
WP_TITLE="Mon Site WordPress"

# SSL (recommandé)
ENABLE_SSL=true
```

### 3. Installation

```bash
# Rendre le script exécutable
chmod +x install.sh

# Lancer l'installation (en root)
sudo ./install.sh
```

## Configuration Avancée

### Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|--------|
| `DOMAIN` | Nom de domaine | **REQUIS** |
| `EMAIL` | Email pour SSL | **REQUIS** |
| `ENABLE_SSL` | Activer Let's Encrypt | `true` |
| `SSL_STAGING` | Mode test SSL | `false` |
| `ENABLE_FIREWALL` | Activer UFW | `true` |
| `PHP_VERSION` | Version PHP | `8.4` |
| `MARIADB_VERSION` | Version MariaDB | `11.4` |
| `WEB_ROOT` | Répertoire web | `/var/www/html` |

### Exemple de configuration complète

```bash
# Configuration de base
DOMAIN=monsite.com
EMAIL=admin@monsite.com

# Base de données
DB_NAME=wordpress
DB_USER=wpuser
DB_PASSWORD=SuperMotDePasse123!
DB_ROOT_PASSWORD=RootPassword456!

# WordPress
WP_ADMIN_USER=administrator
WP_ADMIN_PASSWORD=AdminSecure789!
WP_ADMIN_EMAIL=webmaster@monsite.com
WP_TITLE="Mon Magnifique Site"
WP_LOCALE=fr_FR

# Sécurité et SSL
ENABLE_SSL=true
SSL_STAGING=false
ENABLE_FIREWALL=true

# Versions (optionnel)
PHP_VERSION=8.4
MARIADB_VERSION=11.4
WEB_ROOT=/var/www/html
```

## Après Installation

### Accès au site

- **URL** : `https://votre-domaine.com`
- **Admin** : `https://votre-domaine.com/wp-admin`
- **Identifiants** : ceux configurés dans le fichier `env`

### Commandes utiles

```bash
# Mise à jour WordPress
wp core update --path=/var/www/html --allow-root

# Mise à jour des plugins
wp plugin update --all --path=/var/www/html --allow-root

# État des services
systemctl status apache2 mariadb

# Logs d'erreur Apache
tail -f /var/log/apache2/[domaine]_error.log

# Logs d'installation
tail -f /var/log/wordpress-install.log

# Test SSL
openssl s_client -connect votre-domaine.com:443 -servername votre-domaine.com
```

## Dépannage

### Problèmes courants

#### 1. Erreur de DNS/domaine
```bash
# Vérifier que le domaine pointe vers le serveur
dig votre-domaine.com A
```

#### 2. Problème SSL
```bash
# Vérifier les certificats
certbot certificates

# Renouveler manuellement
certbot renew
```

#### 3. Permissions WordPress
```bash
# Rétablir les permissions
chown -R www-data:www-data /var/www/html
find /var/www/html -type d -exec chmod 755 {} \;
find /var/www/html -type f -exec chmod 644 {} \;
chmod 600 /var/www/html/wp-config.php
```

### Logs importants

- Installation : `/var/log/wordpress-install.log`
- Apache erreurs : `/var/log/apache2/[domaine]_error.log`
- Apache accès : `/var/log/apache2/[domaine]_access.log`
- MariaDB : `/var/log/mysql/error.log`
- PHP : `/var/log/php8.4-fpm.log`

## Sécurité

Le script applique automatiquement :

- ✅ Pare-feu UFW avec ports essentiels
- ✅ Sécurisation MariaDB (suppression comptes par défaut)
- ✅ Headers de sécurité Apache
- ✅ Permissions WordPress sécurisées
- ✅ SSL/TLS avec Let's Encrypt
- ✅ Désactivation de wp-cron.php (remplacé par cron système)

## Prérequis

- Ubuntu 24.04 LTS
- Accès root/sudo
- Domaine pointant vers le serveur
- Ports 80/443 ouverts
- Minimum 1 GB RAM recommandé

## Support

Pour les problèmes ou questions, consultez les logs d'installation et vérifiez la configuration réseau/DNS.