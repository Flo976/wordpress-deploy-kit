# WordPress Deployment Documentation

This comprehensive deployment system automates the installation and configuration of a production-ready WordPress environment on Ubuntu 24.04 LTS.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Testing with Vagrant](#testing-with-vagrant)
- [Management Commands](#management-commands)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Performance Optimization](#performance-optimization)
- [Backup and Recovery](#backup-and-recovery)
- [Monitoring](#monitoring)
- [Contributing](#contributing)

## 🔍 Overview

This deployment system provides a complete, production-ready WordPress stack with:

- **Web Server**: Apache 2.4 with MPM Event, HTTP/2, Brotli compression
- **PHP**: PHP 8.4 FPM with OPcache and performance tuning
- **Database**: MariaDB LTS with InnoDB optimization
- **FTP**: vsftpd with explicit FTPS and chroot security
- **SSL/TLS**: Let's Encrypt integration with security headers
- **Security**: UFW firewall, fail2ban, system hardening
- **Monitoring**: Comprehensive logging and health checks
- **Automation**: Fully automated, idempotent deployment

## ✨ Features

### 🔒 Security
- UFW firewall configuration
- fail2ban intrusion prevention
- SSH hardening
- SSL/TLS with Let's Encrypt
- Security headers (HSTS, CSP, etc.)
- File permission hardening
- WordPress security enhancements

### ⚡ Performance
- PHP 8.4 with OPcache JIT
- Apache HTTP/2 and Brotli compression
- MariaDB InnoDB tuning
- Caching optimization
- Performance monitoring

### 🛠 Automation
- Idempotent deployment scripts
- Environment-driven configuration
- Automated cron jobs
- System health monitoring
- Backup automation
- Update management

### 🧪 Testing
- Vagrant development environment
- Automated testing scripts
- Health check validation
- Performance benchmarking

## 🖥 System Requirements

### Target System
- **OS**: Ubuntu 24.04 LTS Server
- **RAM**: 4GB minimum (8GB recommended)
- **CPU**: 2 cores minimum (4 cores recommended)
- **Storage**: 20GB minimum (50GB recommended)
- **Network**: Internet connection for package installation

### Local Development (Vagrant)
- **RAM**: 8GB minimum
- **Storage**: 10GB free space
- **Software**: VirtualBox 6.1+, Vagrant 2.2+

### Required Access
- Root or sudo access on target system
- SSH access (for remote deployment)
- Domain name with DNS pointing to server (for SSL)

## 🚀 Quick Start

### 1. Local Testing with Vagrant

```bash
# Clone the repository
git clone <repository-url>
cd wp-azure

# Start local environment
make up

# Access WordPress
# http://localhost:8080
# Admin: admin / vagrant123!
```

### 2. Production Deployment

```bash
# Copy environment template
cp deploy/env.example deploy/env

# Edit configuration
vim deploy/env

# Run deployment
sudo ./deploy/deploy.sh
```

### 3. Using Makefile (Vagrant)

```bash
make help       # Show all available commands
make up         # Start and provision VM
make ssh        # SSH into VM
make logs       # View service logs
make destroy    # Clean up VM
```

## ⚙️ Configuration

### Environment Variables

Copy `deploy/env.example` to `deploy/env` and configure:

#### Basic Configuration
```bash
# Infrastructure
HOSTNAME=wp-server
DOMAIN=example.com
HTTP_PORT=80
HTTPS_PORT=443

# WordPress
WP_DB_NAME=wordpress
WP_DB_USER=wpuser
WP_DB_PASSWORD=secure_password
WP_ADMIN_USER=admin
WP_ADMIN_PASSWORD=strong_password
WP_ADMIN_EMAIL=admin@example.com
WP_TITLE="Mon Site WordPress"
WP_LOCALE=fr_FR
```

#### Database Configuration
```bash
# MariaDB
MARIADB_VERSION="11.4"
MARIADB_ROOT_PASSWORD=very_secure_password
INNODB_BUFFER_POOL_SIZE=512M
MAX_CONNECTIONS=200
```

#### PHP Configuration
```bash
# PHP-FPM
PHP_VERSION=8.4
PHP_MEMORY_LIMIT=256M
PHP_FPM_PM_MAX_CHILDREN=20
OPCACHE_MEMORY_CONSUMPTION=256
OPCACHE_JIT=1255
```

#### Security Configuration
```bash
# Firewall and Security
ENABLE_UFW=true
ENABLE_FAIL2BAN=false
ENABLE_LETSENCRYPT=true
LE_EMAIL=admin@example.com

# FTP
FTP_USER=ftpuser
FTP_PASSWORD=secure_ftp_password
```

### Configuration Validation

```bash
# Validate configuration without deploying
./deploy.sh --dry-run
```

## 🚀 Deployment

### Full Deployment

```bash
# Run complete deployment
sudo ./deploy/deploy.sh
```

### Component-Based Deployment

```bash
# Deploy specific components
./deploy.sh --component system_checks
./deploy.sh --component optimize_apache
./deploy.sh --component install_wp
```

### Deployment Phases

1. **Pre-checks**: System validation and prerequisites
2. **Infrastructure**: MariaDB, PHP, Apache installation
3. **Services**: FTP server configuration
4. **Application**: WordPress installation
5. **Security**: SSL setup and hardening
6. **Maintenance**: Cron jobs and monitoring
7. **Validation**: Final testing and verification

### Deployment Logs

Monitor deployment progress:
```bash
# View real-time logs
tail -f /var/log/wordpress-deployment.log

# View specific service logs
journalctl -f -u apache2
journalctl -f -u mariadb
journalctl -f -u php8.4-fpm
```

## 🧪 Testing with Vagrant

### Quick Start
```bash
# Start development environment
vagrant up

# Access services
# WordPress: http://localhost:8080
# Admin: http://localhost:8080/wp-admin/
# FTP: ftp://localhost:2121
# MySQL: localhost:33060
```

### Vagrant Commands
```bash
vagrant up           # Start VM
vagrant ssh          # Connect to VM
vagrant halt         # Stop VM
vagrant reload       # Restart VM
vagrant destroy      # Delete VM
vagrant provision    # Re-run provisioning
```

### Development Tools
```bash
# Install additional development tools
vagrant provision --provision-with development-tools

# Access phpMyAdmin (if installed)
# http://localhost:8080/phpmyadmin
```

### Custom Configuration
Set environment variables to customize the VM:

```bash
export VAGRANT_RAM=8192        # 8GB RAM
export VAGRANT_CPUS=4          # 4 CPU cores
export VAGRANT_IP=192.168.56.20
vagrant up
```

## 🛠 Management Commands

### WordPress Management
```bash
wp-health           # WordPress health check
wp-backup           # Create full backup
wp-update           # Update WordPress and plugins
wp-maintenance      # Database cleanup and optimization
```

### System Monitoring
```bash
system-monitor      # System resource monitoring
security-status     # Security configuration status
cron-status         # Cron jobs status
ssl-status          # SSL certificate status
```

### Service Management
```bash
# Apache
systemctl status apache2
systemctl reload apache2
apache2ctl configtest

# PHP-FPM
systemctl status php8.4-fpm
systemctl reload php8.4-fmp

# MariaDB
systemctl status mariadb
mysql -u root -p
```

### Log Management
```bash
# View logs
tail -f /var/log/apache2/access.log
tail -f /var/log/mysql/error.log
tail -f /var/log/php/error.log

# Clear logs
cron-logs wp 10          # Last 10 WordPress cron logs
cron-logs security 20    # Last 20 security logs
```

## 🔧 Troubleshooting

### Common Issues

#### Deployment Fails
```bash
# Check logs
tail -100 /var/log/wordpress-deployment.log

# Verify system requirements
./deploy/system_checks.sh

# Check disk space
df -h

# Check memory usage
free -h
```

#### WordPress Not Accessible
```bash
# Check Apache status
systemctl status apache2

# Check Apache configuration
apache2ctl configtest

# Check ports
netstat -tlnp | grep :80

# Check firewall
ufw status
```

#### Database Connection Issues
```bash
# Check MariaDB status
systemctl status mariadb

# Test database connection
mysql -u wpuser -p wordpress

# Check MariaDB logs
tail -50 /var/log/mysql/error.log
```

#### SSL Certificate Problems
```bash
# Check certificate status
ssl-status

# Renew Let's Encrypt certificate
ssl-renew

# Check certificate expiry
openssl x509 -in /etc/letsencrypt/live/domain.com/fullchain.pem -noout -dates
```

#### Performance Issues
```bash
# Check system resources
htop
iotop

# Check slow queries
tail -50 /var/log/mysql/slow.log

# Check PHP-FPM status
curl http://localhost/fmp-status

# Run performance benchmark
ab -n 100 -c 10 http://localhost/
```

### Debug Mode

Enable debug mode for troubleshooting:
```bash
# Edit environment file
vim deploy/env

# Enable debug
WP_DEBUG=true
WP_DEBUG_LOG=true
DEV_MODE=true

# Re-run deployment
sudo ./deploy/deploy.sh
```

### Recovery Procedures

#### Restore from Backup
```bash
# List available backups
ls -la /var/backups/wordpress/

# Restore WordPress files
tar -xzf /var/backups/wordpress/files_YYYYMMDD.tar.gz -C /var/www/html/

# Restore database
mysql -u root -p wordpress < /var/backups/mariadb/database_YYYYMMDD.sql
```

#### Reset WordPress
```bash
# Download fresh WordPress
cd /var/www/html
sudo -u www-data wp core download --force --allow-root

# Reset file permissions
./deploy/install_wp.sh permissions
```

## 🔐 Security Considerations

### Initial Security Steps
1. **Change Default Passwords**: Update all default passwords immediately
2. **Update System**: Ensure all packages are up to date
3. **Configure Firewall**: Verify UFW rules are appropriate
4. **Review Users**: Remove unnecessary user accounts
5. **SSH Keys**: Use SSH key authentication instead of passwords

### Ongoing Security Maintenance
- **Regular Updates**: Keep WordPress, plugins, and system updated
- **Monitor Logs**: Review security logs regularly
- **Backup Verification**: Test backup restoration procedures
- **SSL Certificate**: Monitor certificate expiry dates
- **Security Scanning**: Run regular security scans

### Security Monitoring
```bash
# Check failed login attempts
security-monitor

# Review firewall logs
journalctl -u ufw

# Check fail2ban status (if enabled)
fail2ban-client status
```

### Hardening Checklist
- [ ] Changed all default passwords
- [ ] Configured SSH key authentication
- [ ] Enabled UFW firewall
- [ ] Configured fail2ban (optional)
- [ ] Setup SSL/TLS certificates
- [ ] Configured security headers
- [ ] Disabled unnecessary services
- [ ] Set up log monitoring
- [ ] Configured automatic updates
- [ ] Created backup strategy

## ⚡ Performance Optimization

### Monitoring Performance
```bash
# System resources
htop
iostat -x 1

# WordPress performance
wp-health

# Database performance
mysql -e "SHOW PROCESSLIST;"
mysql -e "SHOW ENGINE INNODB STATUS\G"
```

### Optimization Tips

#### PHP Optimization
- Adjust `PHP_FPM_PM_MAX_CHILDREN` based on available RAM
- Enable OPcache JIT for PHP 8.0+
- Monitor PHP-FPM pool status at `/fpm-status`

#### Database Optimization
- Adjust `INNODB_BUFFER_POOL_SIZE` to 70-80% of available RAM
- Enable slow query log to identify bottlenecks
- Regular database optimization with `wp-maintenance`

#### Web Server Optimization
- Enable HTTP/2 and Brotli compression
- Configure proper caching headers
- Use CDN for static assets

#### WordPress Optimization
- Install caching plugin (WP Super Cache included)
- Optimize images before upload
- Minimize plugins and themes
- Regular database cleanup

### Performance Testing
```bash
# HTTP load testing
ab -n 1000 -c 50 http://localhost/

# Database performance
mysqlslap --user=root --password --host=localhost --auto-generate-sql --auto-generate-sql-load-type=mixed --number-of-queries=1000 --concurrency=10
```

## 💾 Backup and Recovery

### Automated Backups
Backups are automatically configured if `ENABLE_BACKUPS=true`:
- **WordPress files**: Daily backup to `/var/backups/wordpress/`
- **Database**: Daily backup to `/var/backups/mariadb/`
- **Retention**: 7 days by default

### Manual Backup
```bash
# Create WordPress backup
wp-backup

# Create database backup
mariadb-backup

# Create system configuration backup
tar -czf /var/backups/config_$(date +%Y%m%d).tar.gz /etc/apache2/ /etc/php/ /etc/mysql/
```

### Backup Verification
```bash
# List backups
ls -la /var/backups/wordpress/
ls -la /var/backups/mariadb/

# Test database restore (dry run)
mysql -u root -p --execute="CREATE DATABASE test_restore;"
mysql -u root -p test_restore < /var/backups/mariadb/database_latest.sql
mysql -u root -p --execute="DROP DATABASE test_restore;"
```

### Recovery Procedures
1. **Stop services**: `systemctl stop apache2 php8.4-fmp`
2. **Restore files**: Extract backup archives
3. **Restore database**: Import SQL backup
4. **Fix permissions**: Run permission fix script
5. **Start services**: `systemctl start apache2 php8.4-fpm`
6. **Test functionality**: Verify site accessibility

## 📊 Monitoring

### Service Monitoring
```bash
# Service status
systemctl status apache2 mariadb php8.4-fpm vsftpd

# Resource usage
free -h
df -h
top
```

### Log Monitoring
Key log locations:
- **Deployment**: `/var/log/wordpress-deployment.log`
- **Apache**: `/var/log/apache2/`
- **PHP**: `/var/log/php/`
- **MariaDB**: `/var/log/mysql/`
- **Security**: `/var/log/security-audit.log`
- **WordPress Cron**: `/var/log/wp-cron.log`

### Health Checks
```bash
# Overall health
wp-deployment-status

# WordPress specific
wp-health

# Security status
security-status

# System monitoring
system-monitor
```

### Alerting
Configure email alerts by editing monitoring scripts:
```bash
vim /usr/local/bin/system-monitor
vim /usr/local/bin/security-monitor

# Set ALERT_EMAIL variable
ALERT_EMAIL="admin@example.com"
```

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Test changes with Vagrant: `make up`
4. Validate scripts: `make validate`
5. Create pull request

### Testing Guidelines
- Test all changes in Vagrant environment
- Ensure idempotent script behavior
- Validate on fresh Ubuntu 24.04 installation
- Document configuration changes
- Update tests for new features

### Code Standards
- Use bash strict mode: `set -Eeuo pipefail`
- Add error trapping and logging
- Follow existing naming conventions
- Document environment variables
- Include help messages in scripts

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

### Getting Help
1. Check this documentation
2. Review troubleshooting section
3. Check deployment logs
4. Search existing issues
5. Create new issue with details

### Information to Include
When requesting support, provide:
- OS version: `lsb_release -a`
- Deployment logs: `/var/log/wordpress-deployment.log`
- System information: `wp-deployment-status`
- Error messages and steps to reproduce

---

## 📞 Quick Reference

### Essential Commands
```bash
# Deployment
sudo ./deploy/deploy.sh              # Full deployment
./deploy.sh --dry-run               # Validate only
./deploy.sh --component install_wp  # Single component

# Vagrant
make up          # Start VM
make ssh         # Connect to VM
make destroy     # Delete VM
make logs        # View logs

# Management
wp-health        # WordPress health check
security-status  # Security status
system-monitor   # System monitoring
cron-status      # Cron jobs status
```

### Important Paths
```bash
/var/www/html/                    # WordPress root
/var/log/wordpress-deployment.log # Deployment log
/var/backups/wordpress/           # WordPress backups
/var/backups/mariadb/            # Database backups
deploy/env                       # Environment config
```

### Default Credentials (Vagrant)
- **WordPress**: admin / vagrant123!
- **FTP**: ftpuser / vagrant123
- **MySQL**: wpuser / vagrant123

### Service URLs (Vagrant)
- **WordPress**: http://localhost:8080
- **Admin**: http://localhost:8080/wp-admin/
- **FTP**: ftp://localhost:2121
- **MySQL**: localhost:33060