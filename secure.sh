#!/bin/bash

# Update and upgrade system
apt update
apt upgrade -y

# Set a strong password for the root account
echo "Enter a new password for the root account:"
passwd

# Use SSH keys for authentication
echo "Generating SSH key pair..."
ssh-keygen -t rsa -b 4096 -C "root@mysystem"
echo "Please add the following public key to your authorized_keys file:"
cat ~/.ssh/id_rsa.pub
echo "Disabling password-based authentication in SSH config..."
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

# Configure firewall
echo "Setting up firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# Enable security alerts
echo "Enabling security alerts..."
echo "Please enter your email address to receive security alerts:"
read email
echo "security_alerts@mysystem ALL=(ALL) NOPASSWD: /usr/bin/logwatch" >> /etc/sudoers
echo "root" > /etc/aliases/$email
newaliases

# Monitor system logs
echo "Setting up logwatch cron job to run daily at midnight..."
(crontab -l 2>/dev/null; echo "0 0 * * * /usr/sbin/logwatch --output mail --mailto $email") | crontab -

# Harden access to system files
echo "Hardening access to system files..."
chmod 700 /etc/ssh
chmod 600 /etc/ssh/*

# Enable security measures for services
echo "Enabling security measures for services..."
echo "Enabling SSL/TLS for email service..."
apt install -y ssl-cert
make-ssl-cert generate-default-snakeoil --force-overwrite
postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem'
postconf -e 'smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key'
systemctl restart postfix
echo "Installing and configuring fail2ban..."
apt install -y fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
systemctl start fail2ban
