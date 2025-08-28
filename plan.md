Tu es un ingénieur DevOps. Génère un projet complet qui déploie WordPress sur Ubuntu 24.04 LTS avec :
- PHP 8.4 FPM (optimisé)
- Apache 2.4 (MPM event, HTTP/2, Brotli, TLS – optimisé)
- MariaDB (édition LTS, tuning InnoDB – optimisé)
- Serveur FTP (vsftpd, FTPS explicite, chroot)
- Un Vagrantfile pour tester localement
- Un fichier d’environnement séparé pour toutes les variables
- Script(s) idempotents, réexécutables sans casser l’existant

## Livrables attendus (arborescence)
- `deploy/`
  - `deploy.sh`               # script principal idempotent (bash strict mode)
  - `functions.sh`            # fonctions utilitaires (log, retry, ini_edit, sysctl_edit, etc.)
  - `env.example`             # modèle des variables d’env
  - `hardening.sh`            # durcissements (UFW, fail2ban optionnel, permissions WP)
  - `optimize_apache.sh`      # modules + conf MPM/HTTP2/Brotli/SSL
  - `optimize_php.sh`         # php.ini + pool FPM (pm, opcache, realpath_cache…)
  - `optimize_mariadb.sh`     # my.cnf (buffer pool, log file size, tmp table, query cache off, etc.)
  - `install_wp.sh`           # téléchargement, wp-config.php, salts, wp-cli install
  - `install_ftp.sh`          # vsftpd + TLS, user FTP, passive ports + UFW
  - `cron_setup.sh`           # désactive WP pseudo-cron et ajoute cron system
  - `ssl_setup.sh`            # (optionnel) Let’s Encrypt via Certbot si ENABLE_LETSENCRYPT=true
  - `system_checks.sh`        # prérequis CPU/RAM/disk, versions
  - `README.md`               # doc d’utilisation rapide + dépannage
- `Vagrantfile`
- `Makefile`                  # cibles: up, reprovision, ssh, destroy, logs
- `.gitignore`

## Comportement & contraintes
1) **OS cible** : Ubuntu 24.04 LTS (systemd). Tous les scripts doivent détecter l’OS et échouer proprement si non supporté.
2) **Idempotence stricte** : chaque étape teste l’état avant d’agir (fichiers marqueurs, grep dans conf, `systemctl is-enabled`, etc.).
3) **Variables d’environnement** : AUCUNE valeur en dur. Toutes les valeurs configurables passent par `deploy/env` (copie de `env.example`), chargé en `deploy.sh`.
   - Exemples de variables :
     ```
     # Infra / réseau
     HOSTNAME=wp-local
     DOMAIN=example.local
     PUBLIC_IP=
     HTTP_PORT=80
     HTTPS_PORT=443
     FTP_PORT=21
     FTP_PASSIVE_MIN=40000
     FTP_PASSIVE_MAX=40050

     # WordPress
     WP_DB_NAME=wordpress
     WP_DB_USER=wpuser
     WP_DB_PASSWORD=changeme
     WP_TABLE_PREFIX=wp_
     WP_LOCALE=fr_FR
     WP_ADMIN_USER=admin
     WP_ADMIN_PASSWORD=admin123!
     WP_ADMIN_EMAIL=admin@example.local
     WP_TITLE="Mon Site"

     # MariaDB
     MARIADB_VERSION="11.4"   # LTS recommandé
     MARIADB_ROOT_PASSWORD=supersecret
     INNODB_BUFFER_POOL_SIZE=512M
     INNODB_LOG_FILE_SIZE=256M

     # PHP-FPM (pool www)
     PHP_VERSION=8.4
     PHP_FPM_PM=dynamic
     PHP_FPM_PM_MAX_CHILDREN=20
     PHP_FPM_PM_START_SERVERS=4
     PHP_FPM_PM_MIN_SPARE_SERVERS=2
     PHP_FPM_PM_MAX_SPARE_SERVERS=6
     OPCACHE_MEMORY_CONSUMPTION=256
     OPCACHE_MAX_ACCELERATED_FILES=100000
     OPCACHE_VALIDATE_TIMESTAMPS=0

     # Apache
     APACHE_MPM_EVENT_MAX_REQUEST_WORKERS=256
     APACHE_MPM_EVENT_THREADS_PER_CHILD=25
     ENABLE_BROTLI=true
     ENABLE_HTTP2=true

     # FTP
     FTP_USER=ftpuser
     FTP_PASSWORD=changeme
     FTP_HOME=/var/www/html

     # SSL / Let’s Encrypt (optionnel)
     ENABLE_LETSENCRYPT=false
     LE_EMAIL=admin@example.local

     # Sécurité
     ENABLE_UFW=true
     ENABLE_FAIL2BAN=false
     ```
4) **WordPress** :
   - Télécharge la dernière version stable (fr), crée la base, l’utilisateur, et `wp-config.php` avec `AUTH_*/SECURE_*_SALT` aléatoires.
   - Force `FS_METHOD=direct`, met `DISABLE_WP_CRON=true`, crée une tâche cron `*/5 * * * *` pour `wp cron event run --due-now`.
   - Propriétés/permissions : répertoire WP possédé par `www-data:www-data`, 750/640 (ou 755/644 pour compat compatibilité), upload dir writable.

5) **Apache** :
   - Modules : `headers`, `rewrite`, `proxy_fcgi`, `http2`, `ssl`, `brotli` (si ENABLE_BROTLI), `expires`.
   - MPM event activé, prefork désactivé. `php-fpm` via `SetHandler "proxy:unix:/run/php/php8.4-fpm.sock|fcgi://localhost/"`
   - Vhost `:80` → redirection 301 vers `https` si Let’s Encrypt actif. Vhost `:443` HTTP/2, ciphers solides, HSTS (si domaine non .local), OCSP stapling.
   - Compression Brotli (ou Deflate fallback si disabled).
   - En-têtes de sécurité de base (X-Content-Type-Options, X-Frame-Options SAMEORIGIN, Referrer-Policy strict-origin-when-cross-origin, Permissions-Policy minimale).

6) **PHP 8.4 FPM** :
   - Tuning `php.ini` (memory_limit >= 256M, upload_max_filesize/post_max_size 64M min, realpath_cache_size 256k, realpath_cache_ttl 600).
   - OPcache activé, valeurs depuis env. `opcache.jit=1255` si stable en 8.4 (sinon commenter proprement).
   - Pool FPM `www.conf` réglé via env (pm, max_children…). `catch_workers_output = yes`, `pm.status_path=/status`.
   - Un endpoint `/fpm-status` protégé par `Require local` (ou BasicAuth optionnel).

7) **MariaDB** :
   - Installe la version LTS indiquée (11.4 par défaut) depuis le repo officiel.
   - `my.cnf` : `innodb_buffer_pool_size`, `innodb_log_file_size`, `max_connections` (200), `tmp_table_size`/`max_heap_table_size` (128M), `slow_query_log=ON`, `performance_schema=ON`, `character-set-server=utf8mb4`, `collation-server=utf8mb4_0900_ai_ci`. Pas de query cache.
   - Sécurisation initiale (équivalent `mysql_secure_installation`) non interactive via env.

8) **FTP (vsftpd)** :
   - FTPS explicite (TLS), ports passifs depuis env, chroot utilisateur FTP sur `FTP_HOME`.
   - UFW ouvre `FTP_PORT` + range passif si `ENABLE_UFW=true`.
   - Le user FTP mappe sur un user système dédié limité au répertoire web (no shell).

9) **Sécurité & hardening** :
   - UFW (ALLOW 22,80,443,21 + passifs), fail2ban optionnel (jails sshd/apache-auth).
   - Désactive `server_tokens`, liste d’index, expose_php=Off, limite méthodes HTTP.
   - Journalisation centralisée, rotation log d’Apache/PHP-FPM/MariaDB.

10) **Vagrantfile (test local)** :
   - Box : `ubuntu/jammy64` ou `bento/ubuntu-24.04`.
   - Provision `shell` lançant `deploy/deploy.sh` après avoir copié `deploy/env.example` → `deploy/env`.
   - Ports forward :
     - 8080→80 (HTTP), 8443→443 (HTTPS), 2121→21 (FTP), 40000-40050→idem (passif), 33060→3306 (MariaDB)
   - Synced folder hôte→VM paramétrable via variable d’env `VAGRANT_HOST_PATH` (sinon fallback à `./`), ex:
     ```ruby
     host_path = ENV.fetch("VAGRANT_HOST_PATH", File.dirname(__FILE__))
     config.vm.synced_folder host_path, "/vagrant", type: "virtualbox"
     ```
   - RAM/CPU configurables via `ENV["VAGRANT_RAM"]` (4096 par défaut) et `ENV["VAGRANT_CPUS"]` (2 par défaut).

11) **Makefile** :
   - `make up` (vagrant up), `make reprovision`, `make ssh`, `make destroy`, `make logs` (journaux apache/php-fpm/mysql combinés via `journalctl`).

12) **Qualité & tests** :
   - `deploy/system_checks.sh` vérifie versions (`php -v`, `apache2 -v`, `mysql --version`), sockets FPM, modules Apache actifs, ports ouverts, UFW rules.
   - Healthchecks HTTP : `curl -I http://localhost:80` (302→443 si SSL), `curl -kI https://localhost:443`, `curl -I http://localhost:8080` côté hôte via forwarded ports.
   - `wp core is-installed` doit retourner 0. Création d’un article de test via wp-cli.
   - FTP : test de connexion `lftp` (ou `openssl s_client -starttls ftp -connect localhost:21`) et listage passif.

13) **Documentation** :
   - `deploy/README.md` : 
     - Prérequis (Vagrant, VirtualBox, 8 GB RAM recommandés)
     - Utilisation rapide (copier `env.example`→`env`, éditer, `make up`)
     - Dépannage (ports en conflit, UFW, certificats)
     - Restauration/mise à jour (réexécution idempotente, sauvegarde DB)

## Style & exigences de code
- Bash strict mode (`set -Eeuo pipefail`), `trap` pour logs d’erreur, fonctions réutilisables dans `functions.sh`.
- Aucune variable secrète commitée. `env.example` documente chaque variable.
- Tous les scripts doivent être POSIX-friendly (bash) et commentés.
- Proposer des valeurs par défaut sûres si une variable est absente tout en loggant un avertissement.
- Utiliser `crudini` (si besoin) ou `sed` sûr pour éditer ini/conf.
- Redémarrer/enabler proprement les services (`systemctl enable --now`).
- Tout ce qui touche SSL/HTTP/2/Brotli doit être conditionnel selon les variables.
- Sortie finale du `deploy.sh` : récapitulatif (URL WP, user admin, versions installées, services actifs).

## À rendre maintenant
1) Tous les fichiers listés, complets et prêts à l’emploi.
2) Un `README.md` clair dans `deploy/`.
3) Des commentaires TODO si un point dépend de l’environnement (ex: DNS public).

Vérifie que l’ensemble est exécutable, cohérent et idempotent. Fournis le code complet de chaque fichier demandé.
