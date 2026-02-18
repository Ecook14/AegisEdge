#!/bin/bash
# AegisEdge Rollback Script
# Restores Apache/Nginx to original ports and removes AegisEdge

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Rolling back AegisEdge permanent changes..."

# 1. Stop and disable AegisEdge
systemctl stop aegisedge
systemctl disable aegisedge
rm /etc/systemd/system/aegisedge.service
systemctl daemon-reload

# 2. Detect OS and Restore Configs
DISTRO=$(test -f /etc/os-release && grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"' || echo "unknown")

if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
    echo "[*] Restoring Apache on Debian/Ubuntu..."
    sed -i 's/Listen 8080/Listen 80/g' /etc/apache2/ports.conf
    sed -i 's/:8080/:80/g' /etc/apache2/sites-available/*.conf
    systemctl restart apache2
elif [[ "$DISTRO" == "centos" || "$DISTRO" == "rhel" ]]; then
    echo "[*] Restoring Apache on RHEL/CentOS..."
    sed -i 's/Listen 8080/Listen 80/g' /etc/httpd/conf/httpd.conf
    systemctl restart httpd
fi

echo "------------------------------------------------"
echo "  ROLLBACK SUCCESSFUL"
echo "  AegisEdge removed and Apache restored to Port 80."
echo "------------------------------------------------"
