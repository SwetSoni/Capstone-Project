#!/bin/bash
# ============================================================
# Part 1 — Network Reconnaissance & Vulnerability Assessment
# Complete scanning script for Tasks 2–6
# ============================================================
# USAGE: chmod +x recon_scan.sh && sudo ./recon_scan.sh
# NOTE: Must be run as root (sudo) on Kali Linux
# ============================================================

set -euo pipefail

# ===================== CONFIGURATION ========================
TARGET_NETWORK="192.168.56.0/24"
OUTPUT_DIR="./outputs"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DNS_DOMAIN="lab.local"
DNS_SERVER_IP="192.168.56.10"     # Kali Linux (DNS server)
PUBLIC_DOMAIN="tesla.com"          # Public domain used for passive OSINT demonstration

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "  Capstone Part 1 — Reconnaissance Script"
echo "  Target: $TARGET_NETWORK"
echo "  Started: $(date)"
echo "============================================"

# ============================================================
# TASK 3: Active Host Discovery (Ping Sweep)
# ============================================================
echo ""
echo "[TASK 3] Active Host Discovery — Ping Sweep"
echo "============================================"

# Command explanation:
# -sn  : Ping scan only (no port scan) — we only want to discover live hosts
# -PE  : Send ICMP Echo Request probes
# -PS22,80,443 : Send TCP SYN probes to ports 22,80,443 (catches hosts blocking ICMP)
# -PA80 : Send TCP ACK probe to port 80 (bypasses stateless firewalls)
# -oN  : Save output in normal format for documentation
# -oG  : Save output in grepable format for easy parsing

PING_SWEEP_CMD="nmap -sn -PE -PS22,80,443 -PA80 $TARGET_NETWORK"
echo "[*] Running: $PING_SWEEP_CMD"
echo ""

nmap -sn -PE -PS22,80,443 -PA80 $TARGET_NETWORK \
  -oN "$OUTPUT_DIR/task3_ping_sweep_${TIMESTAMP}.nmap" \
  -oG "$OUTPUT_DIR/task3_ping_sweep_${TIMESTAMP}.gnmap"

echo ""
echo "[*] Extracting live hosts..."
LIVE_HOSTS=$(grep "Up" "$OUTPUT_DIR/task3_ping_sweep_${TIMESTAMP}.gnmap" | awk '{print $2}')
echo "$LIVE_HOSTS"
echo "$LIVE_HOSTS" > "$OUTPUT_DIR/task3_live_hosts.txt"
echo "[✓] Live hosts saved to $OUTPUT_DIR/task3_live_hosts.txt"

# ============================================================
# TASK 4: Port Scanning and Service Enumeration
# ============================================================
echo ""
echo "[TASK 4] Port Scanning & Service Enumeration"
echo "============================================"

for HOST in $LIVE_HOSTS; do
  echo ""
  echo "────────────────────────────────────────"
  echo "[*] Scanning host: $HOST"
  echo "────────────────────────────────────────"

  # Task 4a: TCP SYN (half-open) scan on ports 1-1024
  # -sS : TCP SYN scan (half-open) — sends SYN, receives SYN/ACK, sends RST
  #        instead of completing the 3-way handshake. Stealthier because the
  #        connection is never fully established, so many logging mechanisms
  #        that only log completed connections will miss it.
  # -p 1-1024 : Scan well-known ports only (as specified in the task)
  # -T3 : Normal timing — balanced between speed and reliability
  # --reason : Show why a port is in a particular state

  SYN_CMD="nmap -sS -p 1-1024 -T3 --reason $HOST"
  echo "[*] Running TCP SYN scan: $SYN_CMD"

  nmap -sS -p 1-1024 -T3 --reason $HOST \
    -oN "$OUTPUT_DIR/task4a_syn_scan_${HOST}_${TIMESTAMP}.nmap" \
    -oG "$OUTPUT_DIR/task4a_syn_scan_${HOST}_${TIMESTAMP}.gnmap"

  # Task 4b: Service version detection
  # -sV : Probe open ports to determine service/version info
  # --version-intensity 5 : Set version detection probe intensity (default)

  VERSION_CMD="nmap -sV --version-intensity 5 -p 1-1024 $HOST"
  echo "[*] Running service version scan: $VERSION_CMD"

  nmap -sV --version-intensity 5 -p 1-1024 $HOST \
    -oN "$OUTPUT_DIR/task4b_version_scan_${HOST}_${TIMESTAMP}.nmap"

  # Task 4c: OS fingerprinting (on each host)
  # -O : Enable OS detection using TCP/IP stack fingerprinting
  # --osscan-guess : Make Nmap guess more aggressively if no perfect match

  OS_CMD="nmap -O --osscan-guess $HOST"
  echo "[*] Running OS fingerprinting: $OS_CMD"

  nmap -O --osscan-guess $HOST \
    -oN "$OUTPUT_DIR/task4c_os_scan_${HOST}_${TIMESTAMP}.nmap"

done

echo ""
echo "[✓] Port scanning and service enumeration complete."

# ============================================================
# TASK 5: DNS Enumeration
# ============================================================
echo ""
echo "[TASK 5] DNS Enumeration"
echo "============================================"

# Task 5a: Retrieve all DNS record types
echo "[*] Querying DNS records for $DNS_DOMAIN from $DNS_SERVER_IP"

echo "--- A Record ---" | tee "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
dig A $DNS_DOMAIN @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"

echo "" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
echo "--- MX Record ---" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
dig MX $DNS_DOMAIN @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"

echo "" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
echo "--- NS Record ---" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
dig NS $DNS_DOMAIN @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"

echo "" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
echo "--- TXT Record ---" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
dig TXT $DNS_DOMAIN @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"

echo "" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
echo "--- CNAME Record ---" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
dig CNAME www.$DNS_DOMAIN @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"

echo "" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
echo "--- ANY Record (all types) ---" | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"
dig ANY $DNS_DOMAIN @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5a_dns_records_${TIMESTAMP}.txt"

# Task 5b: Zone transfer (AXFR)
echo ""
echo "[*] Attempting zone transfer (AXFR)..."
echo "--- Zone Transfer (AXFR) ---" | tee "$OUTPUT_DIR/task5b_axfr_${TIMESTAMP}.txt"
dig axfr $DNS_DOMAIN @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5b_axfr_${TIMESTAMP}.txt"

# Task 5c: Additional DNS enumeration — Reverse DNS lookup
echo ""
echo "[*] Performing reverse DNS lookups on live hosts..."
echo "--- Reverse DNS Lookups ---" | tee "$OUTPUT_DIR/task5c_reverse_dns_${TIMESTAMP}.txt"
for HOST in $LIVE_HOSTS; do
  echo "Reverse lookup for $HOST:" | tee -a "$OUTPUT_DIR/task5c_reverse_dns_${TIMESTAMP}.txt"
  dig -x $HOST @$DNS_SERVER_IP | tee -a "$OUTPUT_DIR/task5c_reverse_dns_${TIMESTAMP}.txt"
  echo "" | tee -a "$OUTPUT_DIR/task5c_reverse_dns_${TIMESTAMP}.txt"
done

# Task 5c: Additional — Subdomain brute-force using dnsenum
echo ""
echo "[*] Running dnsenum for subdomain enumeration..."
echo "--- DNSenum Subdomain Brute-force ---" | tee "$OUTPUT_DIR/task5c_dnsenum_${TIMESTAMP}.txt"
dnsenum --dnsserver $DNS_SERVER_IP --enum $DNS_DOMAIN 2>&1 | tee -a "$OUTPUT_DIR/task5c_dnsenum_${TIMESTAMP}.txt" || echo "[!] dnsenum finished (may show warnings for local domain)"

echo ""
echo "[✓] DNS enumeration complete."

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================"
echo "  Scan Complete — $(date)"
echo "============================================"
echo ""
echo "Output files saved in: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
echo ""
echo "NEXT STEPS:"
echo "  1. Run OpenVAS/Nessus vulnerability scan (Task 6) via the web UI"
echo "  2. Export the vulnerability report and save to $OUTPUT_DIR/"
echo "  3. Compile findings into the README.md penetration-test report (Task 7)"
