#!/bin/bash
# Universal AegisEdge Installer for Linux VPS
# (Supports WHM, Plesk, Baremetal)

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Installing AegisEdge as a system service..."

# 1. Build the binary
go build -o aegisedge main.go config.go

# 2. Move to standard path
mkdir -p /opt/aegisedge
cp aegisedge /opt/aegisedge/
cp config.json /opt/aegisedge/
cp .env /opt/aegisedge/ 2>/dev/null || touch /opt/aegisedge/.env

# 3. Create Systemd Service
cat <<EOF > /etc/systemd/system/aegisedge.service
[Unit]
Description=AegisEdge Smart Security Proxy
After=network.target apache2.service httpd.service nginx.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/aegisedge
ExecStart=/opt/aegisedge/aegisedge
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 4. Reload and Start
systemctl daemon-reload
systemctl enable aegisedge
systemctl start aegisedge

echo "------------------------------------------------"
echo "AegisEdge is now INSTALLED and PROTECTING."
echo "Status: $(systemctl is-active aegisedge)"
echo "Mode: Hot-Takeover enabled (No changes to Apache needed)"
echo "------------------------------------------------"
