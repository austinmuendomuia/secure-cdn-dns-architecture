#!/bin/bash

echo "Starting Server Deployment..."

# 1. Update and install required stack (PHP & MariaDB)
sudo apt update
sudo apt install -y php-fpm php-mysql mariadb-server git

# 2. Secure Firewall (UFW)
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

# 3. Setup Web Root & Clone Repo
sudo rm -rf /var/www/html/*
sudo git clone https://github.com/austinmuendomuia/secure-cdn-dns-architecture.git /var/www/html

# 4. Fix permissions so Allan can push/pull/edit code without sudo
sudo chown -R staffonly:www-data /var/www/html
sudo chmod -R 775 /var/www/html

echo "Deployment Complete!"
