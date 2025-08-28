# -*- mode: ruby -*-
# vi: set ft=ruby :

# WordPress Deployment Vagrantfile
# Author: Florent Didelot
# Description: Local testing environment for WordPress deployment

# Configurable variables via environment
VAGRANT_BOX = ENV.fetch("VAGRANT_BOX", "bento/ubuntu-24.04")
VAGRANT_RAM = ENV.fetch("VAGRANT_RAM", "4096").to_i
VAGRANT_CPUS = ENV.fetch("VAGRANT_CPUS", "2").to_i
VAGRANT_IP = ENV.fetch("VAGRANT_IP", "192.168.56.10")
VAGRANT_HOST_PATH = ENV.fetch("VAGRANT_HOST_PATH", File.dirname(__FILE__))

Vagrant.configure("2") do |config|
  # Base box configuration
  config.vm.box = VAGRANT_BOX
  config.vm.box_check_update = true
  
  # Network configuration
  config.vm.network "private_network", ip: VAGRANT_IP
  
  # Port forwarding for services
  config.vm.network "forwarded_port", guest: 80, host: 8080, auto_correct: true, host_ip: "127.0.0.1"
  config.vm.network "forwarded_port", guest: 443, host: 8443, auto_correct: true, host_ip: "127.0.0.1"
  config.vm.network "forwarded_port", guest: 21, host: 2121, auto_correct: true, host_ip: "127.0.0.1"
  config.vm.network "forwarded_port", guest: 3306, host: 33060, auto_correct: true, host_ip: "127.0.0.1"
  
  # FTP passive ports range
  (40000..40050).each do |port|
    config.vm.network "forwarded_port", guest: port, host: port, auto_correct: true, host_ip: "127.0.0.1"
  end
  
  # SSH configuration
  config.vm.network "forwarded_port", guest: 22, host: 2222, auto_correct: true, id: "ssh"
  config.ssh.forward_agent = true
  config.ssh.insert_key = false
  
  # Synced folder configuration
  config.vm.synced_folder VAGRANT_HOST_PATH, "/vagrant", 
    type: "virtualbox",
    owner: "vagrant",
    group: "vagrant",
    mount_options: ["dmode=755,fmode=644"]
  
  # Disable default synced folder
  config.vm.synced_folder ".", "/vagrant", disabled: true unless VAGRANT_HOST_PATH == File.dirname(__FILE__)
  
  # VM provider configuration
  config.vm.provider "virtualbox" do |vb|
    # VM settings
    vb.name = "wordpress-deployment"
    vb.memory = VAGRANT_RAM
    vb.cpus = VAGRANT_CPUS
    
    # Performance optimizations
    vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
    vb.customize ["modifyvm", :id, "--audio", "none"]
    vb.customize ["modifyvm", :id, "--clipboard-mode", "bidirectional"]
    vb.customize ["modifyvm", :id, "--draganddrop", "bidirectional"]
    
    # Enable nested virtualization if supported
    vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
    
    # Increase video memory for better GUI performance
    vb.customize ["modifyvm", :id, "--vram", "128"]
    
end
  
  # VM hostname
  config.vm.hostname = "wp-local"
  
  # Hosts file entries
  config.vm.provision "shell", inline: <<-SHELL
    echo "127.0.0.1 wp-local example.local" >> /etc/hosts
    echo "#{VAGRANT_IP} wp-local example.local" >> /etc/hosts
  SHELL
  
  # System preparation
  config.vm.provision "shell", name: "system-preparation", inline: <<-SHELL
    echo "=== System Preparation ==="
    
    # Update package lists
    apt-get update -qq
    
    # Install basic tools
    apt-get install -y curl wget vim git htop tree
    
    # Set timezone to Europe/Paris
    timedatectl set-timezone Europe/Paris
    
    # Configure locale
    locale-gen fr_FR.UTF-8
    update-locale LANG=fr_FR.UTF-8
    
    # Increase system limits for development
    cat >> /etc/security/limits.conf << EOF
    
    # Development limits
    vagrant soft nofile 65536
    vagrant hard nofile 65536
    vagrant soft nproc 32768
    vagrant hard nproc 32768
    EOF
    
    echo "System preparation completed"
  SHELL
  
  # Environment setup
  config.vm.provision "shell", name: "environment-setup", inline: <<-SHELL
    echo "=== Environment Setup ==="
    
    # Create environment file if it doesn't exist
    if [ ! -f /vagrant/deploy/env ]; then
      echo "Creating environment file from template..."
      cp /vagrant/deploy/env.example /vagrant/deploy/env
      
      # Configure for local development
      sed -i 's/DOMAIN=example.local/DOMAIN=wp-local/' /vagrant/deploy/env
      sed -i 's/HOSTNAME=wp-local/HOSTNAME=wp-local/' /vagrant/deploy/env
      sed -i 's/ENABLE_LETSENCRYPT=false/ENABLE_LETSENCRYPT=false/' /vagrant/deploy/env
      sed -i 's/WP_ADMIN_PASSWORD=admin123!/WP_ADMIN_PASSWORD=vagrant123!/' /vagrant/deploy/env
      sed -i 's/WP_ADMIN_EMAIL=admin@example.local/WP_ADMIN_EMAIL=admin@wp-local/' /vagrant/deploy/env
      sed -i 's/MARIADB_ROOT_PASSWORD=supersecret/MARIADB_ROOT_PASSWORD=vagrant123/' /vagrant/deploy/env
      sed -i 's/WP_DB_PASSWORD=changeme/WP_DB_PASSWORD=vagrant123/' /vagrant/deploy/env
      sed -i 's/FTP_PASSWORD=changeme/FTP_PASSWORD=vagrant123/' /vagrant/deploy/env
      
      echo "Environment file configured for local development"
    else
      echo "Environment file already exists"
    fi
    
    # Make scripts executable
    chmod +x /vagrant/deploy/*.sh
    
    echo "Environment setup completed"
  SHELL
  
  # Main deployment
  config.vm.provision "shell", name: "wordpress-deployment", inline: <<-SHELL
    echo "=== WordPress Deployment ==="
    
    # Change to deployment directory
    cd /vagrant/deploy
    
    # Run deployment
    ./deploy.sh
    
    echo "WordPress deployment completed"
    echo ""
    echo "=== Access Information ==="
    echo "WordPress Site: http://localhost:8080"
    echo "WordPress Admin: http://localhost:8080/wp-admin/"
    echo "Admin User: admin"
    echo "Admin Password: vagrant123!"
    echo ""
    echo "FTP Access:"
    echo "  Host: localhost"
    echo "  Port: 2121"
    echo "  User: ftpuser"
    echo "  Password: vagrant123"
    echo ""
    echo "Database Access:"
    echo "  Host: localhost"
    echo "  Port: 33060"
    echo "  Database: wordpress"
    echo "  User: wpuser"
    echo "  Password: vagrant123"
    echo ""
    echo "SSH Access: vagrant ssh"
    echo "VM IP: #{VAGRANT_IP}"
    echo ""
  SHELL
  
  # Optional: Install development tools
  config.vm.provision "shell", name: "development-tools", run: "never", inline: <<-SHELL
    echo "=== Installing Development Tools ==="
    
    # Install Node.js and npm
    curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
    apt-get install -y nodejs
    
    # Install Composer
    curl -sS https://getcomposer.org/installer | php
    mv composer.phar /usr/local/bin/composer
    chmod +x /usr/local/bin/composer
    
    # Install phpMyAdmin
    apt-get install -y phpmyadmin
    
    # Configure phpMyAdmin for Apache
    ln -sf /usr/share/phpmyadmin /var/www/html/phpmyadmin
    
    echo "Development tools installed"
    echo "phpMyAdmin: http://localhost:8080/phpmyadmin"
  SHELL
  
  # Cleanup and optimization
  config.vm.provision "shell", name: "cleanup", inline: <<-SHELL
    echo "=== Cleanup and Optimization ==="
    
    # Clean package cache
    apt-get autoremove -y
    apt-get autoclean
    
    # Clear logs
    find /var/log -type f -name "*.log" -exec truncate -s 0 {} \\;
    
    # Clear bash history
    cat /dev/null > ~/.bash_history
    history -c
    
    echo "Cleanup completed"
  SHELL
  
  # Display final information
  config.vm.provision "shell", name: "final-info", inline: <<-SHELL
    echo ""
    echo "=============================================================================="
    echo "                    WORDPRESS VAGRANT ENVIRONMENT READY"
    echo "=============================================================================="
    echo "VM Information:"
    echo "  Hostname: wp-local"
    echo "  IP Address: #{VAGRANT_IP}"
    echo "  RAM: #{VAGRANT_RAM}MB"
    echo "  CPUs: #{VAGRANT_CPUS}"
    echo ""
    echo "Service Access:"
    echo "  WordPress: http://localhost:8080"
    echo "  HTTPS: http://localhost:8443 (self-signed)"
    echo "  FTP: ftp://localhost:2121"
    echo "  MySQL: localhost:33060"
    echo ""
    echo "Credentials:"
    echo "  WordPress Admin: admin / vagrant123!"
    echo "  FTP: ftpuser / vagrant123"
    echo "  MySQL: wpuser / vagrant123"
    echo ""
    echo "Management Commands:"
    echo "  vagrant ssh              - SSH into VM"
    echo "  vagrant halt             - Stop VM"
    echo "  vagrant reload           - Restart VM"
    echo "  vagrant destroy          - Delete VM"
    echo "  vagrant provision        - Re-run provisioning"
    echo ""
    echo "Inside VM:"
    echo "  wp-health               - WordPress health check"
    echo "  system-monitor          - System monitoring"
    echo "  security-status         - Security status"
    echo "=============================================================================="
  SHELL
end

# Multi-machine configuration (optional)
# Uncomment below for multi-VM setup (web + db separation)
=begin
Vagrant.configure("2") do |config|
  # Web server VM
  config.vm.define "web" do |web|
    web.vm.box = VAGRANT_BOX
    web.vm.hostname = "wp-web"
    web.vm.network "private_network", ip: "192.168.56.11"
    web.vm.network "forwarded_port", guest: 80, host: 8080
    web.vm.network "forwarded_port", guest: 443, host: 8443
    
    web.vm.provider "virtualbox" do |vb|
      vb.name = "wordpress-web"
      vb.memory = 2048
      vb.cpus = 2
    end
  end
  
  # Database server VM
  config.vm.define "db" do |db|
    db.vm.box = VAGRANT_BOX
    db.vm.hostname = "wp-db"
    db.vm.network "private_network", ip: "192.168.56.12"
    db.vm.network "forwarded_port", guest: 3306, host: 33060
    
    db.vm.provider "virtualbox" do |vb|
      vb.name = "wordpress-db"
      vb.memory = 2048
      vb.cpus = 1
    end
  end
end
=end