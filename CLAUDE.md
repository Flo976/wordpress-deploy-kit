# WordPress on Azure - DevOps Project

This project deploys WordPress on Ubuntu 24.04 LTS with optimized components.

## Project Structure

```
deploy/
├── deploy.sh               # Main idempotent deployment script (bash strict mode)
├── functions.sh            # Utility functions (log, retry, ini_edit, sysctl_edit, etc.)
├── env.example             # Environment variables template
├── hardening.sh            # Security hardening (UFW, fail2ban, WP permissions)
├── optimize_apache.sh      # Apache modules + MPM/HTTP2/Brotli/SSL config
├── optimize_php.sh         # php.ini + FPM pool (pm, opcache, realpath_cache)
├── optimize_mariadb.sh     # my.cnf (buffer pool, log file size, tmp table, etc.)
├── install_wp.sh           # WordPress download, wp-config.php, salts, wp-cli install
├── install_ftp.sh          # vsftpd + TLS, FTP user, passive ports + UFW
├── cron_setup.sh           # Disable WP pseudo-cron, add system cron
├── ssl_setup.sh            # Let's Encrypt via Certbot (if ENABLE_LETSENCRYPT=true)
├── system_checks.sh        # CPU/RAM/disk prerequisites, version checks
└── README.md               # Quick usage doc + troubleshooting
Vagrantfile                 # Local testing environment
Makefile                    # Targets: up, reprovision, ssh, destroy, logs
.gitignore
```

## Technology Stack

- **OS**: Ubuntu 24.04 LTS
- **Web Server**: Apache 2.4 with MPM event, HTTP/2, Brotli compression
- **PHP**: PHP 8.4 FPM (optimized)
- **Database**: MariaDB LTS edition with InnoDB tuning
- **FTP**: vsftpd with explicit FTPS and chroot
- **SSL**: Optional Let's Encrypt integration

## Key Features

### Idempotent Deployment
- All scripts test state before acting (marker files, grep in configs, systemctl checks)
- Safe to re-run without breaking existing installations
- Bash strict mode with error trapping

### Environment-Driven Configuration
- No hardcoded values in scripts
- All configuration via `deploy/env` file
- Extensive variable support for customization

### Security Hardening
- UFW firewall configuration
- Optional fail2ban integration
- Secure file permissions and ownership
- Security headers and SSL/TLS configuration

### Performance Optimization
- PHP OPcache with JIT compilation
- MariaDB InnoDB tuning
- Apache HTTP/2 and Brotli compression
- Optimized PHP-FPM pool settings

## Environment Variables

Key configuration variables (see `deploy/env.example`):

```bash
# Infrastructure
HOSTNAME=wp-local
DOMAIN=example.local
HTTP_PORT=80
HTTPS_PORT=443

# WordPress
WP_DB_NAME=wordpress
WP_DB_USER=wpuser
WP_ADMIN_USER=admin
WP_LOCALE=fr_FR

# Performance Tuning
PHP_FPM_PM_MAX_CHILDREN=20
INNODB_BUFFER_POOL_SIZE=512M
APACHE_MPM_EVENT_MAX_REQUEST_WORKERS=256

# Security
ENABLE_UFW=true
ENABLE_LETSENCRYPT=false
```

## Quick Start

1. Copy environment template: `cp deploy/env.example deploy/env`
2. Edit variables in `deploy/env`
3. Run deployment: `./deploy/deploy.sh`

For local testing with Vagrant:
```bash
make up      # Start VM and deploy
make ssh     # SSH into VM
make destroy # Clean up
```

## Testing & Validation

The deployment includes automated checks for:
- Service status and versions
- HTTP/HTTPS connectivity
- WordPress installation
- FTP functionality
- Security configurations

## Makefile Targets

- `make up` - Start Vagrant VM
- `make reprovision` - Re-run provisioning
- `make ssh` - SSH into VM
- `make destroy` - Destroy VM
- `make logs` - View combined service logs

## Requirements

- Ubuntu 24.04 LTS target system
- For local testing: Vagrant + VirtualBox
- Minimum 4GB RAM recommended
- Root or sudo access on target system