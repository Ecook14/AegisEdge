#!/bin/bash
# AegisEdge OS Hardening Script
# Usage: sudo ./harden.sh

echo "[*] Hardening Networking Stack..."

# 1. ICMP (Ping) Rate Limiting
# Allow 1 ping per second with a burst of 5, then drop everything else.
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# 2. SYN Flood Protection
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sysctl -w net.ipv4.tcp_synack_retries=2

# 3. Spoofing Protection
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# 4. Port 80 Protection
# Ensure port 80 is only accessible via AegisEdge if running locally
# (Example rule: block port 80 for everyone except localhost)
# iptables -A INPUT -p tcp --dport 80 ! -s 127.0.0.1 -j DROP

echo "[+] OS Hardening Applied Successfully."
