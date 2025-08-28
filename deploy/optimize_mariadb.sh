#!/bin/bash

# MariaDB LTS Optimization Script
# Author: Florent Didelot
# Description: Install and configure MariaDB LTS with InnoDB tuning for WordPress

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
MARIADB_VERSION="${MARIADB_VERSION:-11.4}"
MARIADB_ROOT_PASSWORD="${MARIADB_ROOT_PASSWORD:-supersecret}"
INNODB_BUFFER_POOL_SIZE="${INNODB_BUFFER_POOL_SIZE:-512M}"
INNODB_LOG_FILE_SIZE="${INNODB_LOG_FILE_SIZE:-256M}"
MAX_CONNECTIONS="${MAX_CONNECTIONS:-200}"
TMP_TABLE_SIZE="${TMP_TABLE_SIZE:-128M}"
MAX_HEAP_TABLE_SIZE="${MAX_HEAP_TABLE_SIZE:-128M}"
QUERY_CACHE_TYPE="${QUERY_CACHE_TYPE:-0}"

# Error trap
trap 'log_error "MariaDB optimization failed on line $LINENO"' ERR

main() {
    log_info "Starting MariaDB $MARIADB_VERSION optimization..."
    
    # Check if MariaDB is installed
    if ! command_exists mysql && ! command_exists mariadb; then
        log_info "MariaDB not installed, installing MariaDB $MARIADB_VERSION..."
        install_mariadb
    fi
    
    # Backup existing configuration
    backup_mariadb_configs
    
    # Configure MariaDB
    configure_mariadb
    
    # Secure MariaDB installation
    secure_mariadb_installation
    
    # Create WordPress database and user
    create_wordpress_database
    
    # Optimize performance settings
    configure_performance_settings
    
    # Configure logging
    configure_logging
    
    # Configure security settings
    configure_security_settings
    
    # Setup monitoring
    setup_monitoring
    
    # Test configuration
    test_mariadb_config
    
    # Restart MariaDB
    restart_service mariadb
    
    log_success "MariaDB $MARIADB_VERSION optimization completed successfully"
}

install_mariadb() {
    log_info "Installing MariaDB $MARIADB_VERSION LTS..."
    
    # Add MariaDB official repository
    local mariadb_version_major=$(echo "$MARIADB_VERSION" | cut -d. -f1-2)
    
    # Install prerequisites
    apt-get update -qq
    apt-get install -y software-properties-common dirmngr apt-transport-https
    
    # Add MariaDB GPG key
    curl -o /tmp/mariadb_release_signing_key.asc 'https://mariadb.org/mariadb_release_signing_key.asc'
    apt-key add /tmp/mariadb_release_signing_key.asc
    rm /tmp/mariadb_release_signing_key.asc
    
    # Add MariaDB repository
    cat > /etc/apt/sources.list.d/mariadb.list << EOF
# MariaDB ${mariadb_version_major} repository list
deb [arch=amd64,arm64,ppc64el,s390x] https://ftp.osuosl.org/pub/mariadb/repo/${mariadb_version_major}/ubuntu jammy main
deb-src https://ftp.osuosl.org/pub/mariadb/repo/${mariadb_version_major}/ubuntu jammy main
EOF
    
    # Update package lists
    apt-get update -qq
    
    # Set debconf selections for non-interactive install
    debconf-set-selections <<< "mariadb-server mysql-server/root_password password $MARIADB_ROOT_PASSWORD"
    debconf-set-selections <<< "mariadb-server mysql-server/root_password_again password $MARIADB_ROOT_PASSWORD"
    
    # Install MariaDB packages
    local mariadb_packages=(
        "mariadb-server"
        "mariadb-client"
        "mariadb-common"
        "mariadb-backup"
        "galera-4"
        "libmariadb3"
        "mariadb-client-core"
    )
    
    log_info "Installing MariaDB packages: ${mariadb_packages[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${mariadb_packages[@]}"
    
    # Enable and start MariaDB
    enable_start_service mariadb
    
    # Verify installation
    if mysql --version >/dev/null 2>&1; then
        log_success "MariaDB installed successfully"
        mysql --version | log_info "$(cat)"
    else
        error_exit "MariaDB installation failed"
    fi
}

backup_mariadb_configs() {
    log_info "Backing up MariaDB configuration files..."
    
    local backup_dir="/etc/mysql/backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup configuration files
    [[ -f /etc/mysql/my.cnf ]] && cp /etc/mysql/my.cnf "$backup_dir/"
    [[ -d /etc/mysql/conf.d ]] && cp -r /etc/mysql/conf.d "$backup_dir/"
    [[ -d /etc/mysql/mariadb.conf.d ]] && cp -r /etc/mysql/mariadb.conf.d "$backup_dir/"
    
    log_info "MariaDB configs backed up to: $backup_dir"
}

configure_mariadb() {
    log_info "Configuring MariaDB main configuration..."
    
    # Create custom configuration file
    local custom_config="/etc/mysql/mariadb.conf.d/99-wordpress.cnf"
    
    # Calculate InnoDB buffer pool size (75% of RAM if not specified)
    if [[ "$INNODB_BUFFER_POOL_SIZE" == "auto" ]]; then
        local ram_mb
        ram_mb=$(free -m | awk '/^Mem:/{print $2}')
        local buffer_pool_mb=$((ram_mb * 75 / 100))
        INNODB_BUFFER_POOL_SIZE="${buffer_pool_mb}M"
        log_info "Auto-calculated InnoDB buffer pool size: $INNODB_BUFFER_POOL_SIZE"
    fi
    
    cat > "$custom_config" << EOF
# WordPress Optimized MariaDB Configuration
# Generated on $(date)

[mysqld]
# Basic settings
user = mysql
pid-file = /run/mysqld/mysqld.pid
basedir = /usr
datadir = /var/lib/mysql
tmpdir = /tmp
lc-messages-dir = /usr/share/mysql
lc-messages = en_US

# Character set and collation
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# Network settings
bind-address = 127.0.0.1
port = 3306
max_connections = ${MAX_CONNECTIONS}
max_allowed_packet = ${MAX_ALLOWED_PACKET:-64M}
thread_stack = 256K
thread_cache_size = 50
open_files_limit = 65535

# Query cache (disabled for better performance)
query_cache_type = ${QUERY_CACHE_TYPE}
query_cache_size = ${QUERY_CACHE_SIZE:-0}

# InnoDB settings
default_storage_engine = InnoDB
innodb_buffer_pool_size = ${INNODB_BUFFER_POOL_SIZE}
innodb_buffer_pool_instances = $(( $(echo "$INNODB_BUFFER_POOL_SIZE" | sed 's/[^0-9]//g') / 128 ))
innodb_log_file_size = ${INNODB_LOG_FILE_SIZE}
innodb_log_files_in_group = ${INNODB_LOG_FILES_IN_GROUP:-2}
innodb_log_buffer_size = 64M
innodb_flush_method = O_DIRECT
innodb_flush_log_at_trx_commit = 2
innodb_file_per_table = ON
innodb_open_files = 400

# InnoDB performance
innodb_read_io_threads = 8
innodb_write_io_threads = 8
innodb_thread_concurrency = 0
innodb_purge_threads = 4
innodb_adaptive_flushing = ON
innodb_adaptive_hash_index = ON
innodb_change_buffering = all

# Temporary tables
tmp_table_size = ${TMP_TABLE_SIZE}
max_heap_table_size = ${MAX_HEAP_TABLE_SIZE}

# MyISAM settings (for system tables)
key_buffer_size = 32M
myisam_recover_options = BACKUP,FORCE

# Logging
log_error = /var/log/mysql/error.log
slow_query_log = ${SLOW_QUERY_LOG:-ON}
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = ${LONG_QUERY_TIME:-2}
log_queries_not_using_indexes = OFF

# Binary logging (for replication and backup)
log_bin = /var/log/mysql/mysql-bin.log
binlog_format = ROW
expire_logs_days = 7
max_binlog_size = 100M

# Performance Schema
performance_schema = ${PERFORMANCE_SCHEMA:-ON}
performance_schema_max_table_instances = 12500
performance_schema_max_table_handles = 4000

# Security
sql_mode = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION
local_infile = 0

# WordPress specific optimizations
max_connect_errors = 100000
table_open_cache = 4000
table_definition_cache = 2000
table_open_cache_instances = 8

# Connection timeout
connect_timeout = 60
wait_timeout = 600
interactive_timeout = 600

# Sort and group
sort_buffer_size = 4M
join_buffer_size = 4M
read_buffer_size = 2M
read_rnd_buffer_size = 16M

[mysql]
default-character-set = utf8mb4

[mysqldump]
quick
quote-names
max_allowed_packet = 64M

[isamchk]
key_buffer_size = 32M
sort_buffer_size = 32M
read_buffer_size = 16M
write_buffer_size = 16M

EOF

    log_info "MariaDB configuration created with InnoDB buffer pool: $INNODB_BUFFER_POOL_SIZE"
}

secure_mariadb_installation() {
    log_info "Securing MariaDB installation..."
    
    # Create secure installation script
    local secure_script="/tmp/mariadb_secure_install.sql"
    
    cat > "$secure_script" << EOF
-- Secure MariaDB installation
UPDATE mysql.user SET Password=PASSWORD('${MARIADB_ROOT_PASSWORD}') WHERE User='root';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF

    # Execute secure installation
    if mysql -u root -p"$MARIADB_ROOT_PASSWORD" < "$secure_script" 2>/dev/null; then
        log_success "MariaDB security configuration applied"
    else
        # Try without password (first time setup)
        if mysql -u root < "$secure_script" 2>/dev/null; then
            log_success "MariaDB initial security configuration applied"
        else
            log_warn "Could not apply security configuration (may already be secured)"
        fi
    fi
    
    # Clean up
    rm -f "$secure_script"
    
    # Create root password file for future operations
    cat > /root/.my.cnf << EOF
[client]
user = root
password = ${MARIADB_ROOT_PASSWORD}
EOF
    
    chmod 600 /root/.my.cnf
    log_info "MariaDB root credentials configured"
}

create_wordpress_database() {
    log_info "Creating WordPress database and user..."
    
    local db_name="${WP_DB_NAME:-wordpress}"
    local db_user="${WP_DB_USER:-wpuser}"
    local db_password="${WP_DB_PASSWORD:-changeme}"
    
    # Create database and user script
    local db_script="/tmp/create_wp_database.sql"
    
    cat > "$db_script" << EOF
-- Create WordPress database and user
CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${db_password}';
GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost';
FLUSH PRIVILEGES;

-- Show created database and user
SELECT User, Host FROM mysql.user WHERE User = '${db_user}';
SHOW DATABASES LIKE '${db_name}';
EOF

    # Execute database creation
    if mysql -u root -p"$MARIADB_ROOT_PASSWORD" < "$db_script"; then
        log_success "WordPress database '$db_name' and user '$db_user' created"
    else
        error_exit "Failed to create WordPress database"
    fi
    
    # Clean up
    rm -f "$db_script"
}

configure_performance_settings() {
    log_info "Configuring MariaDB performance settings..."
    
    # Create performance tuning configuration
    local perf_config="/etc/mysql/mariadb.conf.d/90-performance.cnf"
    
    cat > "$perf_config" << EOF
# MariaDB Performance Tuning Configuration

[mysqld]
# Connection handling
back_log = 100
max_connections = ${MAX_CONNECTIONS}
max_user_connections = 0
max_connect_errors = 100000

# Thread handling
thread_handling = pool-of-threads
thread_pool_size = $(nproc)
thread_pool_max_threads = 2000
thread_pool_stall_limit = 500
thread_pool_idle_timeout = 60

# Buffer sizes
join_buffer_size = 4M
sort_buffer_size = 4M
read_buffer_size = 2M
read_rnd_buffer_size = 16M
bulk_insert_buffer_size = 32M

# Table cache
table_open_cache = 4000
table_definition_cache = 2000
table_open_cache_instances = 8

# Query optimization
optimizer_search_depth = 62
optimizer_use_condition_selectivity = 4
optimizer_switch = 'index_merge=on,index_merge_union=on,index_merge_sort_union=on,index_merge_intersection=on'

# Aria storage engine (for temporary tables)
aria_pagecache_buffer_size = 128M
aria_sort_buffer_size = 256M

# Optimizer statistics
histogram_size = 254
histogram_type = DOUBLE_PREC_HB

EOF

    log_info "Performance tuning configuration applied"
}

configure_logging() {
    log_info "Configuring MariaDB logging..."
    
    # Create log directory
    create_dir "/var/log/mysql" "mysql:mysql" "750"
    
    # Create logging configuration
    local log_config="/etc/mysql/mariadb.conf.d/95-logging.cnf"
    
    cat > "$log_config" << EOF
# MariaDB Logging Configuration

[mysqld]
# Error log
log_error = /var/log/mysql/error.log

# General query log (disabled by default for performance)
general_log = ${MYSQL_GENERAL_LOG:-OFF}
general_log_file = /var/log/mysql/mysql.log

# Slow query log
slow_query_log = ${MYSQL_SLOW_QUERY_LOG:-ON}
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = ${LONG_QUERY_TIME:-2}
log_queries_not_using_indexes = OFF
min_examined_row_limit = 1000

# Binary log (for backups and replication)
log_bin = /var/log/mysql/mysql-bin.log
binlog_format = ROW
binlog_expire_logs_seconds = 604800  # 7 days
max_binlog_size = 100M
binlog_cache_size = 32K
binlog_stmt_cache_size = 32K

# Log warnings
log_warnings = 2

EOF

    # Create log files with proper permissions
    touch /var/log/mysql/error.log
    touch /var/log/mysql/slow.log
    chown mysql:mysql /var/log/mysql/*.log
    chmod 640 /var/log/mysql/*.log
    
    # Configure log rotation
    cat > /etc/logrotate.d/mariadb << EOF
/var/log/mysql/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    sharedscripts
    copytruncate
    postrotate
        if test -x /usr/bin/mysqladmin && test -x /usr/bin/mysql && \
           /usr/bin/mysql --defaults-file=/root/.my.cnf -e 'select 1' > /dev/null 2>&1
        then
            /usr/bin/mysqladmin --defaults-file=/root/.my.cnf flush-logs
        fi
    endscript
}
EOF
    
    log_info "MariaDB logging configured"
}

configure_security_settings() {
    log_info "Configuring MariaDB security settings..."
    
    local security_config="/etc/mysql/mariadb.conf.d/98-security.cnf"
    
    cat > "$security_config" << EOF
# MariaDB Security Configuration

[mysqld]
# Network security
bind-address = 127.0.0.1
skip-networking = 0
skip-name-resolve = 1

# Disable LOCAL INFILE
local_infile = 0

# SQL modes for strict operation
sql_mode = STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION

# Disable symbolic links
symbolic-links = 0

# Secure file privileges
secure_file_priv = /var/lib/mysql-files/

# Plugin settings
plugin_load_add = server_audit

# Audit plugin configuration (if enabled)
server_audit_logging = OFF
server_audit_output_type = file
server_audit_file_path = /var/log/mysql/audit.log
server_audit_file_rotate_size = 100M
server_audit_file_rotations = 9

# Connection limits
max_connections = ${MAX_CONNECTIONS}
max_user_connections = 50
max_connect_errors = 100000

# Password validation (if plugin is available)
# validate_password_policy = MEDIUM
# validate_password_length = 8

EOF

    # Create secure file directory
    create_dir "/var/lib/mysql-files" "mysql:mysql" "750"
    
    log_info "MariaDB security settings configured"
}

setup_monitoring() {
    log_info "Setting up MariaDB monitoring..."
    
    # Create monitoring user for status checks
    local monitor_script="/tmp/create_monitor_user.sql"
    local monitor_password
    monitor_password=$(generate_password 16)
    
    cat > "$monitor_script" << EOF
-- Create monitoring user
CREATE USER IF NOT EXISTS 'monitor'@'localhost' IDENTIFIED BY '${monitor_password}';
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'monitor'@'localhost';
FLUSH PRIVILEGES;
EOF

    mysql -u root -p"$MARIADB_ROOT_PASSWORD" < "$monitor_script"
    rm -f "$monitor_script"
    
    # Create monitoring script
    cat > /usr/local/bin/mariadb-status << 'EOF'
#!/bin/bash
# MariaDB Status Monitoring Script

MYSQL_USER="monitor"
MYSQL_PASS="MONITOR_PASSWORD_PLACEHOLDER"

echo "=== MariaDB Status ==="
echo "Uptime: $(mysql -u$MYSQL_USER -p$MYSQL_PASS -e "SHOW STATUS LIKE 'Uptime';" -s --skip-column-names | awk '{print $2}') seconds"
echo "Connections: $(mysql -u$MYSQL_USER -p$MYSQL_PASS -e "SHOW STATUS LIKE 'Threads_connected';" -s --skip-column-names | awk '{print $2}')"
echo "Questions: $(mysql -u$MYSQL_USER -p$MYSQL_PASS -e "SHOW STATUS LIKE 'Questions';" -s --skip-column-names | awk '{print $2}')"
echo "Slow queries: $(mysql -u$MYSQL_USER -p$MYSQL_PASS -e "SHOW STATUS LIKE 'Slow_queries';" -s --skip-column-names | awk '{print $2}')"

echo -e "\n=== InnoDB Status ==="
mysql -u$MYSQL_USER -p$MYSQL_PASS -e "SHOW ENGINE INNODB STATUS\G" | grep -A 20 "BUFFER POOL AND MEMORY"

echo -e "\n=== Process List ==="
mysql -u$MYSQL_USER -p$MYSQL_PASS -e "SHOW PROCESSLIST;"
EOF

    # Replace password placeholder
    sed -i "s/MONITOR_PASSWORD_PLACEHOLDER/$monitor_password/" /usr/local/bin/mariadb-status
    
    chmod +x /usr/local/bin/mariadb-status
    
    # Save monitor credentials
    echo "monitor_password=$monitor_password" >> /root/.mariadb_monitor
    chmod 600 /root/.mariadb_monitor
    
    log_info "MariaDB monitoring setup completed"
}

test_mariadb_config() {
    log_info "Testing MariaDB configuration..."
    
    # Test configuration syntax
    if mysqld --help --verbose >/dev/null 2>&1; then
        log_success "MariaDB configuration syntax is valid"
    else
        error_exit "MariaDB configuration syntax error"
    fi
    
    # Test connection
    if mysql -u root -p"$MARIADB_ROOT_PASSWORD" -e "SELECT 1;" >/dev/null 2>&1; then
        log_success "MariaDB connection test passed"
    else
        error_exit "MariaDB connection test failed"
    fi
    
    # Test WordPress database
    local db_name="${WP_DB_NAME:-wordpress}"
    local db_user="${WP_DB_USER:-wpuser}"
    local db_password="${WP_DB_PASSWORD:-changeme}"
    
    if mysql -u "$db_user" -p"$db_password" -e "USE $db_name; SELECT 1;" >/dev/null 2>&1; then
        log_success "WordPress database access test passed"
    else
        log_warn "WordPress database access test failed"
    fi
    
    # Check key variables
    log_info "Checking MariaDB variables..."
    mysql -u root -p"$MARIADB_ROOT_PASSWORD" -e "
        SELECT 
            @@innodb_buffer_pool_size as buffer_pool_size,
            @@max_connections as max_connections,
            @@query_cache_type as query_cache_type,
            @@slow_query_log as slow_query_log;
    " 2>/dev/null || log_warn "Could not query MariaDB variables"
}

show_mariadb_status() {
    log_info "MariaDB status and configuration:"
    
    echo "=== MariaDB Version ==="
    mysql --version
    echo
    
    echo "=== MariaDB Service Status ==="
    if service_is_active mariadb; then
        systemctl status mariadb --no-pager
        echo
    fi
    
    echo "=== MariaDB Variables ==="
    mysql -u root -p"$MARIADB_ROOT_PASSWORD" -e "
        SHOW VARIABLES WHERE Variable_name IN (
            'version', 'innodb_buffer_pool_size', 'max_connections',
            'query_cache_type', 'slow_query_log', 'character_set_server'
        );
    " 2>/dev/null || echo "Could not query MariaDB variables"
    echo
    
    echo "=== Database Status ==="
    mysql -u root -p"$MARIADB_ROOT_PASSWORD" -e "SHOW DATABASES;" 2>/dev/null || echo "Could not list databases"
    echo
    
    echo "=== Connection Status ==="
    mysql -u root -p"$MARIADB_ROOT_PASSWORD" -e "SHOW STATUS LIKE 'Threads_connected';" 2>/dev/null || echo "Could not get connection status"
}

create_backup_script() {
    log_info "Creating MariaDB backup script..."
    
    local backup_script="/usr/local/bin/mariadb-backup"
    local db_name="${WP_DB_NAME:-wordpress}"
    
    cat > "$backup_script" << EOF
#!/bin/bash
# MariaDB Backup Script for WordPress

BACKUP_DIR="/var/backups/mariadb"
DB_NAME="$db_name"
DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="\$BACKUP_DIR/\${DB_NAME}_\$DATE.sql"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"

# Create backup directory
mkdir -p "\$BACKUP_DIR"

# Dump database
if mysqldump --defaults-file=/root/.my.cnf "\$DB_NAME" > "\$BACKUP_FILE"; then
    echo "Database backup created: \$BACKUP_FILE"
    
    # Compress backup
    gzip "\$BACKUP_FILE"
    echo "Backup compressed: \$BACKUP_FILE.gz"
    
    # Remove old backups
    find "\$BACKUP_DIR" -name "*.sql.gz" -mtime +\$RETENTION_DAYS -delete
    echo "Old backups cleaned up (retention: \$RETENTION_DAYS days)"
else
    echo "ERROR: Database backup failed"
    exit 1
fi
EOF

    chmod +x "$backup_script"
    
    # Create backup directory
    create_dir "/var/backups/mariadb" "root:root" "700"
    
    log_info "MariaDB backup script created at: $backup_script"
}

# Run optimization with options
case "${1:-all}" in
    "install")
        install_mariadb
        ;;
    "config")
        configure_mariadb
        configure_performance_settings
        test_mariadb_config
        restart_service mariadb
        ;;
    "secure")
        secure_mariadb_installation
        configure_security_settings
        test_mariadb_config
        restart_service mariadb
        ;;
    "database")
        create_wordpress_database
        ;;
    "monitor")
        setup_monitoring
        ;;
    "backup")
        create_backup_script
        ;;
    "status")
        show_mariadb_status
        ;;
    "test")
        test_mariadb_config
        ;;
    "all")
        main
        create_backup_script
        ;;
    *)
        echo "Usage: $0 [install|config|secure|database|monitor|backup|status|test|all]"
        echo "  install   - Install MariaDB LTS"
        echo "  config    - Configure MariaDB performance settings"
        echo "  secure    - Secure MariaDB installation"
        echo "  database  - Create WordPress database and user"
        echo "  monitor   - Setup monitoring"
        echo "  backup    - Create backup script"
        echo "  status    - Show MariaDB status and configuration"
        echo "  test      - Test MariaDB configuration"
        echo "  all       - Run full optimization (default)"
        exit 1
        ;;
esac