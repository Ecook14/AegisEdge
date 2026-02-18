#!/bin/bash
# AegisEdge Smart Takeover Orchestrator
# Use: sudo bash takeover.sh

if [[ $EUID -ne 0 ]]; then
   echo "CRITICAL: This script must be run as root/sudo." 
   exit 1
fi

echo "------------------------------------------------"
echo "  AegisEdge Smart Takeover Engine Initializing  "
echo "------------------------------------------------"

# 1. Detect Environment
DISTRO=$(test -f /etc/os-release && grep ^ID= /etc/os-release | cut -d= -f2 | tr -d '"' || echo "unknown")
PANEL="none"
if [ -d "/usr/local/psa" ]; then PANEL="plesk"; fi
if [ -d "/var/cpanel" ]; then PANEL="whm"; fi

echo "[+] Distro: $DISTRO"
echo "[+] Panel:  $PANEL"

# 2. Build Decision
TAKEOVER_MODE="HOT" # Default to Hot-Takeover for safety
if [[ "$PANEL" == "none" ]]; then
    echo "[?] NO Control Panel detected. Would you like a Permanent Port Migration (L7 Nginx-style)?"
    echo "    1) YES (Apache moves to 8080, AegisEdge takes 80/443 directly)"
    echo "    2) NO (Use Transparent Hot-Takeover/NAT - Recommended for first time)"
    read -p "Select [1-2]: " choice
    if [[ "$choice" == "1" ]]; then
        TAKEOVER_MODE="CLEAN"
    fi
fi

# 3. Execution Phase
echo "[*] Executing $TAKEOVER_MODE deployment..."

if [[ "$TAKEOVER_MODE" == "CLEAN" ]]; then
    echo "[!] Performing Permanent Port Migration..."
    # UBUNTU/DEBIAN Example
    if [[ "$DISTRO" == "ubuntu" || "$DISTRO" == "debian" ]]; then
        sed -i 's/Listen 80/Listen 8080/g' /etc/apache2/ports.conf
        sed -i 's/:80/:8080/g' /etc/apache2/sites-available/*.conf
        systemctl restart apache2
    # RHEL/CENTOS Example
    elif [[ "$DISTRO" == "centos" || "$DISTRO" == "rhel" ]]; then
        sed -i 's/Listen 80/Listen 8080/g' /etc/httpd/conf/httpd.conf
        systemctl restart httpd
    fi
    echo "[+] Web Server moved to port 8080."
    export AEGISEDGE_HOT_TAKEOVER=false
    export AEGISEDGE_UPSTREAM="http://127.0.0.1:8080"
else
    echo "[+] Using Transparent Hot-Takeover (Ghost Mode)."
    export AEGISEDGE_HOT_TAKEOVER=true
    export AEGISEDGE_UPSTREAM="http://127.0.0.1:80"
fi

# 4. Binary & Service Setup
echo "[*] Compiling AegisEdge binary..."
go build -o /opt/aegisedge/aegisedge main.go config.go 2>/dev/null || (mkdir -p /opt/aegisedge && go build -o /opt/aegisedge/aegisedge main.go config.go)

# Write persistent .env
cat <<EOF > /opt/aegisedge/.env
AEGISEDGE_HOT_TAKEOVER=$AEGISEDGE_HOT_TAKEOVER
AEGISEDGE_UPSTREAM=$AEGISEDGE_UPSTREAM
AEGISEDGE_HYPERVISOR_MODE=true
AEGISEDGE_PORTS=80,443
EOF

# 5. Service Activation
echo "[*] Starting AegisEdge Service..."
cp scripts/install.sh /opt/aegisedge/
bash /opt/aegisedge/install.sh >/dev/null 2>&1

echo "------------------------------------------------"
echo "  SUCCESS: AegisEdge is now protecting this VPS "
echo "  Mode:    $TAKEOVER_MODE"
echo "  Log:     journalctl -u aegisedge -f"
echo "------------------------------------------------"
