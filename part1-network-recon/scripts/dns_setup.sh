#!/bin/bash
# ============================================================
# BIND9 DNS Server Setup Script for Capstone Part 1 — Task 5
# ============================================================
# USAGE: chmod +x dns_setup.sh && sudo ./dns_setup.sh
# Run this on your Kali Linux VM
# ============================================================

set -euo pipefail

echo "============================================"
echo "  BIND9 DNS Server Setup for lab.local"
echo "============================================"

# Step 1: Install BIND9
echo "[*] Installing BIND9..."
apt-get update -qq
apt-get install -y bind9 bind9utils bind9-doc dnsutils

# Step 2: Copy zone files
echo "[*] Copying zone files..."
cp dns-config/db.lab.local /etc/bind/db.lab.local
cp dns-config/db.192.168.56 /etc/bind/db.192.168.56
cp dns-config/named.conf.local /etc/bind/named.conf.local

# Step 3: Set correct permissions
echo "[*] Setting permissions..."
chown bind:bind /etc/bind/db.lab.local
chown bind:bind /etc/bind/db.192.168.56
chmod 644 /etc/bind/db.lab.local
chmod 644 /etc/bind/db.192.168.56

# Step 4: Check configuration syntax
echo "[*] Checking BIND9 configuration..."
named-checkconf
echo "[✓] named-checkconf passed"

echo "[*] Checking zone file syntax..."
named-checkzone lab.local /etc/bind/db.lab.local
named-checkzone 56.168.192.in-addr.arpa /etc/bind/db.192.168.56
echo "[✓] Zone files validated"

# Step 5: Restart BIND9 (service name is 'named' on newer Kali, 'bind9' on older)
echo "[*] Restarting BIND9..."
if systemctl list-unit-files | grep -q "named.service"; then
    systemctl restart named
    systemctl enable named
else
    systemctl restart bind9
    systemctl enable bind9
fi

# Step 6: Configure local DNS resolution
echo "[*] Setting Kali to use local DNS..."
# Backup existing resolv.conf
cp /etc/resolv.conf /etc/resolv.conf.bak
echo "nameserver 127.0.0.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# Step 7: Verify DNS is working
echo ""
echo "[*] Verifying DNS setup..."
echo "--- Testing A record ---"
dig A lab.local @127.0.0.1 +short

echo "--- Testing MX record ---"
dig MX lab.local @127.0.0.1 +short

echo "--- Testing NS record ---"
dig NS lab.local @127.0.0.1 +short

echo "--- Testing TXT record ---"
dig TXT lab.local @127.0.0.1 +short

echo "--- Testing CNAME record ---"
dig CNAME www.lab.local @127.0.0.1 +short

echo ""
echo "============================================"
echo "  BIND9 Setup Complete!"
echo "============================================"
echo ""
echo "You can now run the DNS enumeration tasks:"
echo "  dig ANY lab.local @127.0.0.1"
echo "  dig axfr lab.local @127.0.0.1"
echo "  dig -x 192.168.56.102 @127.0.0.1"
