# Penetration Test Report — Network Reconnaissance and Vulnerability Assessment

**Engagement:** Capstone Project — Part 1  
**Assessor:** Swet Soni  
**Date:** August 2026  
**Classification:** CONFIDENTIAL

---

## Executive Summary

A security assessment was conducted against the 192.168.56.0/24 lab network to identify live hosts, enumerate exposed services, and detect known vulnerabilities. The assessment identified 3 live hosts with 12 open ports on the primary target (192.168.56.20) and 3 vulnerabilities rated High or Critical. Immediate remediation is recommended for the critical findings to reduce the organisation's attack surface.

---

## Table of Contents

1. [Scope and Rules of Engagement](#1-scope-and-rules-of-engagement)
2. [Lab Setup](#2-lab-setup)
3. [Methodology](#3-methodology)
4. [Task 2 — Passive OSINT](#4-task-2--passive-osint)
5. [Task 3 — Active Host Discovery](#5-task-3--active-host-discovery)
6. [Task 4 — Port Scanning and Service Enumeration](#6-task-4--port-scanning-and-service-enumeration)
7. [Task 5 — DNS Enumeration](#7-task-5--dns-enumeration)
8. [Task 6 — Automated Vulnerability Scan](#8-task-6--automated-vulnerability-scan)
9. [Findings Table](#9-findings-table)
10. [Risk Heat Map](#10-risk-heat-map)
11. [Remediation Priority List](#11-remediation-priority-list)

---

## 1. Scope and Rules of Engagement

> Full scope document: [scope.md](scope.md)

| Parameter | Detail |
|-----------|--------|
| **Target Range** | 192.168.56.0/24 |
| **In Scope** | Passive OSINT, active host discovery, port scanning, DNS enumeration, automated vulnerability scanning |
| **Out of Scope** | Exploitation, post-exploitation, scanning outside 192.168.56.0/24 |
| **Scanning Hours** | 24/7 (isolated lab environment) |
| **Rate Limits** | Nmap default timing (-T3); HTTP rate-limited to 50 conn/sec |

---

## 2. Lab Setup

| VM Name | Role | IP Address | OS / Image |
|---------|------|------------|------------|
| Kali Linux | Attack / Scanner host | 192.168.56.10 | Kali Linux 2024+ |
| Metasploitable 2 | Intentionally vulnerable target | 192.168.56.20 | Ubuntu 8.04 (Metasploitable 2) |
| DNS Server (BIND9) | Local authoritative DNS | 192.168.56.10 | Kali Linux (same host) |

---

## 3. Methodology

This assessment follows the **Penetration Testing Execution Standard (PTES)** framework:

| PTES Phase | Capstone Task | Description |
|------------|--------------|-------------|
| Pre-engagement | Task 1 — Scope Definition | Defined target range, authorised techniques, and rules of engagement |
| Intelligence Gathering (Passive) | Task 2 — Passive OSINT | Collected publicly available information using passive DNS tools and Shodan |
| Intelligence Gathering (Active) | Task 3 — Host Discovery | Identified live hosts via Nmap ping sweep |
| Intelligence Gathering (Active) | Task 4 — Port Scanning | Enumerated open ports, services, versions, and operating systems |
| Intelligence Gathering (Active) | Task 5 — DNS Enumeration | Queried DNS records, attempted zone transfers, performed subdomain brute-force |
| Vulnerability Analysis | Task 6 — Automated Scan | Ran Nessus Essentials vulnerability scan to identify CVEs |

---

## 4. Task 2 — Passive OSINT

### (a) DNS Record Collection

**Target Domain:** `tesla.com`

**Tools Used:** `dig`, Shodan (free-tier web interface)

```bash
dig A tesla.com
dig MX tesla.com
dig NS tesla.com
dig TXT tesla.com
dig CNAME www.tesla.com
```

```
; <<>> DiG 9.20.26-1-Debian <<>> A tesla.com
;; ANSWER SECTION:
tesla.com.       5    IN   A   2.18.53.207
tesla.com.       5    IN   A   2.18.55.207
tesla.com.       5    IN   A   2.18.52.207
tesla.com.       5    IN   A   23.7.244.207
tesla.com.       5    IN   A   2.18.50.207
tesla.com.       5    IN   A   2.18.49.207
tesla.com.       5    IN   A   23.40.100.207
tesla.com.       5    IN   A   2.18.54.207
tesla.com.       5    IN   A   2.18.48.207
tesla.com.       5    IN   A   2.18.51.207
;; Query time: 160 msec
;; SERVER: 192.168.174.2#53(192.168.174.2) (UDP)
;; WHEN: Sat Aug 15 12:44:10 IST 2026

; <<>> DiG 9.20.26-1-Debian <<>> MX tesla.com
;; ANSWER SECTION:
tesla.com.       5    IN   MX  10 tesla-com.mail.protection.outlook.com.
;; Query time: 48 msec
;; SERVER: 192.168.174.2#53(192.168.174.2) (UDP)
;; WHEN: Sat Aug 15 12:44:10 IST 2026

; <<>> DiG 9.20.26-1-Debian <<>> NS tesla.com
;; ANSWER SECTION:
tesla.com.       5    IN   NS  a1-12.akam.net.
tesla.com.       5    IN   NS  a12-64.akam.net.
tesla.com.       5    IN   NS  a28-65.akam.net.
tesla.com.       5    IN   NS  a7-66.akam.net.
tesla.com.       5    IN   NS  edns69.ultradns.com.
tesla.com.       5    IN   NS  a10-67.akam.net.
tesla.com.       5    IN   NS  a9-67.akam.net.
;; Query time: 40 msec
;; SERVER: 192.168.174.2#53(192.168.174.2) (UDP)
;; WHEN: Sat Aug 15 12:44:10 IST 2026

; <<>> DiG 9.20.26-1-Debian <<>> TXT tesla.com
;; ANSWER SECTION:
(No TXT records returned — ANSWER: 0)
;; Query time: 428 msec
;; SERVER: 192.168.174.2#53(192.168.174.2) (UDP)
;; WHEN: Sat Aug 15 12:44:11 IST 2026

; <<>> DiG 9.20.26-1-Debian <<>> CNAME www.tesla.com
;; ANSWER SECTION:
www.tesla.com.   5    IN   CNAME www.tesla.com.edgekey.net.
;; Query time: 24 msec
;; SERVER: 192.168.174.2#53(192.168.174.2) (UDP)
;; WHEN: Sat Aug 15 12:44:11 IST 2026
```

> Full dig output saved at `outputs/task2_osint_dns.txt`

### (b) Shodan Query

**Query Used:** `port:80 product:Apache country:US` (matching Apache httpd found on Metasploitable 2 in our lab)

**Platform:** [Shodan Free Tier](https://www.shodan.io/) — web interface search

```
Query: port:80 product:Apache country:US
Date: Saturday 15 August 2026 02:02:02 PM IST
Method: Manual search performed via Shodan web interface.

Sample Result:
  IP: 8.8.8.8
  Hostnames: workplanapi.sb.one.alliantgroup.com; dns.google
  City: Mountain View
  Country: United States
  Organization: Google LLC
  Updated: 2026-08-15T05:44:00.182417
  Open Ports: 53/tcp, 53/udp, 443/tcp
  HTTP Title: Google Public DNS
  Cert Issuer: C=US, CN=WR2, O=Google Trust Services
  Cert Subject: CN=dns.google
  SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
```

> Full Shodan search results saved at `outputs/task2_osint_shodan.txt`. The search demonstrates the technique — finding publicly exposed servers and their configurations, including SSL/TLS versions, certificate details, and open ports.

### (c) OSINT Findings Classification

| # | Finding | Source | Data Exposed | Sensitivity | Attacker Inference |
|---|---------|--------|-------------|-------------|-------------------|
| 1 | A records: 10 IPs (2.18.53.207, 23.7.244.207, 23.40.100.207, etc.) | dig | Server IP addresses behind CDN | **Medium** | 10 A records confirm Akamai CDN/load balancing; attacker can attempt origin IP discovery behind CDN |
| 2 | MX record: tesla-com.mail.protection.outlook.com | dig | Mail infrastructure (Microsoft 365) | **Medium** | Reveals Tesla uses Microsoft 365 for email; enables targeted phishing using O365-themed lures |
| 3 | NS records: akam.net, ultradns.com (7 nameservers) | dig | DNS infrastructure providers | **Medium** | Identifies Akamai + UltraDNS as DNS providers; enables DNS-level attacks or social engineering against providers |
| 4 | TXT records: no results returned (ANSWER: 0) | dig | DNS resolver may have filtered/blocked TXT response | **Low** | Empty TXT response could indicate DNS filtering; attacker may try different resolvers to obtain SPF/DKIM data |
| 5 | CNAME: www.tesla.com → www.tesla.com.edgekey.net | dig | CDN provider (Akamai EdgeKey) | **Low** | Confirms Akamai CDN; attacker knows to look for origin bypass techniques |
| 6 | Shodan: Google Public DNS (8.8.8.8) — ports 53, 443 with TLS 1.2/1.3 | Shodan | Server infrastructure, SSL versions, certificate details | **Medium** | Reveals supported SSL/TLS versions and certificate chain; attacker can identify deprecated protocol support or certificate misconfigurations |
| 7 | Shodan: Multiple Apache servers on port 80 (US) | Shodan | Outdated web server versions exposed to internet | **High** | Various Apache versions found publicly; attacker can match version-specific CVEs to exposed servers (similar to our lab's Apache 2.2.8) |

---

## 5. Task 3 — Active Host Discovery

### Command Used

```bash
nmap -sn -PE -PS22,80,443 -PA80 192.168.56.0/24
```

### Flag Justification

| Flag | Purpose |
|------|---------|
| `-sn` | Ping scan only — disables port scanning; we only want to discover which hosts are alive on the network |
| `-PE` | Sends ICMP Echo Request probes — the most common ping method to detect live hosts |
| `-PS22,80,443` | Sends TCP SYN probes to ports 22, 80, and 443 — catches hosts that block ICMP but have these common services open |
| `-PA80` | Sends TCP ACK probe to port 80 — bypasses stateless firewalls that drop SYN packets but allow ACK |

### Scan Output

```
# Nmap 7.95 scan initiated Wed Aug 12 21:55:07 2026 as: nmap -sn -PE -PS22,80,443 -PA80 192.168.56.0/24
Nmap scan report for 192.168.56.1
Host is up (0.0011s latency).
MAC Address: 00:50:56:C0:00:02 (VMware)
Nmap scan report for 192.168.56.20
Host is up (0.0029s latency).
MAC Address: 00:0C:29:FA:DD:2A (VMware)
Nmap scan report for 192.168.56.10
Host is up.
# Nmap done at Wed Aug 12 21:55:10 2026 -- 256 IP addresses (3 hosts up) scanned in 3.03 seconds
```

### Live Hosts Discovered

| # | IP Address | Host Type | MAC Address |
|---|------------|-----------|-------------|
| 1 | 192.168.56.1 | VMware Host Gateway | 00:50:56:C0:00:02 |
| 2 | 192.168.56.10 | Kali Linux (Scanner) | Local |
| 3 | 192.168.56.20 | Metasploitable 2 (Target) | 00:0C:29:FA:DD:2A |

### Why Host Discovery Precedes Port Scanning (PTES)

In the PTES Intelligence Gathering phase, host discovery is performed before port scanning because it establishes the attack surface by identifying which IP addresses on the target network have live, responsive systems. Scanning ports on every address in a /24 subnet (254 hosts × 1,024 ports = 260,096 probes) is time-consuming and noisy. By first determining which hosts are alive, the assessor narrows the scope to only active targets, reducing scan time, network noise, and the likelihood of triggering intrusion detection alerts. This phased approach also follows the principle of progressive enumeration — moving from broad discovery to targeted deep scanning.

---

## 6. Task 4 — Port Scanning and Service Enumeration

### (a) TCP SYN (Half-Open) Scan

**Command:**

```bash
nmap -sS -p 1-1024 -T3 --reason 192.168.56.20
```

| Flag | Purpose |
|------|---------|
| `-sS` | TCP SYN scan (half-open) — sends a SYN packet to each port; if a SYN/ACK is received (port open), Nmap sends RST to tear down the connection instead of completing the handshake |
| `-p 1-1024` | Scan well-known ports 1 through 1024 as specified in the task requirements |
| `-T3` | Normal timing template — balanced between speed and reliability; avoids overwhelming the target |
| `--reason` | Display the reason each port is in a particular state — provides evidence for the report |

#### SYN Scan vs TCP Connect Scan — Packet-Level Difference

A **TCP SYN scan** (`-sS`) is stealthier than a **TCP Connect scan** (`-sT`) because of how each handles the TCP three-way handshake at the packet level:

| Step | TCP Connect (`-sT`) | TCP SYN (`-sS`) |
|------|---------------------|-----------------|
| 1 | Scanner sends **SYN** | Scanner sends **SYN** |
| 2 | Target responds **SYN/ACK** (port open) | Target responds **SYN/ACK** (port open) |
| 3 | Scanner sends **ACK** → **connection fully established** | Scanner sends **RST** → **connection torn down** |
| 4 | Scanner closes with FIN/RST | No full connection ever existed |

The TCP Connect scan completes the full three-way handshake (SYN → SYN/ACK → ACK), which means the operating system's TCP stack establishes a legitimate connection. This connection is recorded in the target's application-layer logs (e.g., Apache access log, SSH auth log) because the service accepts the connection.

The SYN scan never completes the handshake — it sends RST after receiving SYN/ACK. Because the connection is never fully established, most application-layer logging mechanisms do not record it. Only packet-level monitoring (IDS/IPS, raw packet capture) will detect the half-open scan. This makes the SYN scan significantly less visible to basic log-based detection.

#### SYN Scan Output

```
# Nmap 7.95 scan initiated Wed Aug 12 21:56:22 2026 as: nmap -sS -p 1-1024 -T3 --reason 192.168.56.20
Nmap scan report for 192.168.56.20
Host is up, received arp-response (0.0029s latency).
Not shown: 1012 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack ttl 64
22/tcp  open  ssh          syn-ack ttl 64
23/tcp  open  telnet       syn-ack ttl 64
25/tcp  open  smtp         syn-ack ttl 64
53/tcp  open  domain       syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
111/tcp open  rpcbind      syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
512/tcp open  exec         syn-ack ttl 64
513/tcp open  login        syn-ack ttl 64
514/tcp open  shell        syn-ack ttl 64
MAC Address: 00:0C:29:FA:DD:2A (VMware)
# Nmap done at Wed Aug 12 21:56:22 2026 -- 1 IP address (1 host up) scanned in 0.42 seconds
```

### (b) Service Version Detection

**Command:**

```bash
nmap -sV --version-intensity 5 -p 1-1024 192.168.56.20
```

| Flag | Purpose |
|------|---------|
| `-sV` | Probe open ports to determine the service name and version running on each port |
| `--version-intensity 5` | Default probe intensity level — sends the most common version detection probes |

```
# Nmap 7.95 scan initiated Wed Aug 12 21:56:22 2026 as: nmap -sV --version-intensity 5 -p 1-1024 192.168.56.20
Nmap scan report for 192.168.56.20
Host is up (0.0022s latency).
Not shown: 1012 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp  open  telnet      Linux telnetd
25/tcp  open  smtp        Postfix smtpd
53/tcp  open  domain      ISC BIND 9.4.2
80/tcp  open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp open  rpcbind
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp open  exec        netkit-rsh rexecd
513/tcp open  login       OpenBSD or Solaris rlogind
514/tcp open  shell       Netkit rshd
MAC Address: 00:0C:29:FA:DD:2A (VMware)
Service Info: Host:  metasploitable.localdomain; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
# Nmap done at Wed Aug 12 21:56:34 2026 -- 1 IP address (1 host up) scanned in 11.98 seconds
```

### (c) OS Fingerprinting

**Command:**

```bash
nmap -O --osscan-guess 192.168.56.20
```

| Flag | Purpose |
|------|---------|
| `-O` | Enable OS detection using TCP/IP stack fingerprinting based on responses to specially crafted probes |
| `--osscan-guess` | Make Nmap guess more aggressively when no perfect OS match is found |

```
# Nmap 7.95 scan initiated Wed Aug 12 21:56:35 2026 as: nmap -O --osscan-guess 192.168.56.20
Nmap scan report for 192.168.56.20
Host is up (0.0030s latency).
Not shown: 977 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
23/tcp   open  telnet
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
512/tcp  open  exec
513/tcp  open  login
514/tcp  open  shell
1099/tcp open  rmiregistry
1524/tcp open  ingreslock
2049/tcp open  nfs
2121/tcp open  ccproxy-ftp
3306/tcp open  mysql
5432/tcp open  postgresql
5900/tcp open  vnc
6000/tcp open  X11
6667/tcp open  irc
8009/tcp open  ajp13
8180/tcp open  unknown
MAC Address: 00:0C:29:FA:DD:2A (VMware)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
# Nmap done at Wed Aug 12 21:56:36 2026 -- 1 IP address (1 host up) scanned in 1.70 seconds
```

### Results Summary Table

| Host | Port | State | Service | Version | OS |
|------|------|-------|---------|---------|-----|
| 192.168.56.20 | 21 | open | ftp | vsftpd 2.3.4 | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 22 | open | ssh | OpenSSH 4.7p1 Debian 8ubuntu1 | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 23 | open | telnet | Linux telnetd | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 25 | open | smtp | Postfix smtpd | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 53 | open | domain | ISC BIND 9.4.2 | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 80 | open | http | Apache httpd 2.2.8 ((Ubuntu) DAV/2) | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 111 | open | rpcbind | — | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 139 | open | netbios-ssn | Samba smbd 3.X - 4.X | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 445 | open | netbios-ssn | Samba smbd 3.X - 4.X | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 512 | open | exec | netkit-rsh rexecd | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 513 | open | login | OpenBSD or Solaris rlogind | Linux 2.6.9 - 2.6.33 |
| 192.168.56.20 | 514 | open | shell | Netkit rshd | Linux 2.6.9 - 2.6.33 |


---

## 7. Task 5 — DNS Enumeration

### DNS Server Configuration

A local BIND9 DNS server was configured on the Kali host (192.168.56.10) to serve the `lab.local` domain authoritatively.

**Configuration files included in this repository:**
- [`dns-config/named.conf.local`](dns-config/named.conf.local) — BIND9 zone declaration
- [`dns-config/db.lab.local`](dns-config/db.lab.local) — Forward zone file with A, MX, NS, TXT, and CNAME records
- [`dns-config/db.192.168.56`](dns-config/db.192.168.56) — Reverse zone file for PTR records

### (a) DNS Record Retrieval

```bash
# A Record
dig A lab.local @192.168.56.10

# MX Record
dig MX lab.local @192.168.56.10

# NS Record
dig NS lab.local @192.168.56.10

# TXT Record
dig TXT lab.local @192.168.56.10

# CNAME Record
dig CNAME www.lab.local @192.168.56.10

# ALL Records
dig ANY lab.local @192.168.56.10
```

```
; <<>> DiG 9.20.26-1-Debian <<>> A lab.local @192.168.56.10
;; ANSWER SECTION:
lab.local.              604800  IN      A       192.168.56.10

; <<>> DiG 9.20.26-1-Debian <<>> MX lab.local @192.168.56.10
;; ANSWER SECTION:
lab.local.              604800  IN      MX      10 mail.lab.local.
;; ADDITIONAL SECTION:
mail.lab.local.         604800  IN      A       192.168.56.10

; <<>> DiG 9.20.26-1-Debian <<>> NS lab.local @192.168.56.10
;; ANSWER SECTION:
lab.local.              604800  IN      NS      ns1.lab.local.
;; ADDITIONAL SECTION:
ns1.lab.local.          604800  IN      A       192.168.56.10

; <<>> DiG 9.20.26-1-Debian <<>> TXT lab.local @192.168.56.10
;; ANSWER SECTION:
lab.local.              604800  IN      TXT     "v=spf1 mx a ip4:192.168.56.0/24 -all"
lab.local.              604800  IN      TXT     "Lab domain for Capstone security assessment"

; <<>> DiG 9.20.26-1-Debian <<>> CNAME www.lab.local @192.168.56.10
;; ANSWER SECTION:
www.lab.local.          604800  IN      CNAME   webserver.lab.local.

; <<>> DiG 9.20.26-1-Debian <<>> ANY lab.local @192.168.56.10
;; ANSWER SECTION:
lab.local.              604800  IN      TXT     "v=spf1 mx a ip4:192.168.56.0/24 -all"
lab.local.              604800  IN      TXT     "Lab domain for Capstone security assessment"
lab.local.              604800  IN      MX      10 mail.lab.local.
lab.local.              604800  IN      SOA     ns1.lab.local. admin.lab.local. 2024081201 604800 86400 2419200 604800
lab.local.              604800  IN      NS      ns1.lab.local.
lab.local.              604800  IN      A       192.168.56.10
```

### (b) Zone Transfer (AXFR)

**Command:**

```bash
dig axfr lab.local @192.168.56.10
```

```
; <<>> DiG 9.20.26-1-Debian <<>> axfr lab.local @192.168.56.10
lab.local.              604800  IN      SOA     ns1.lab.local. admin.lab.local. 2024081201 604800 86400 2419200 604800
lab.local.              604800  IN      TXT     "v=spf1 mx a ip4:192.168.56.0/24 -all"
lab.local.              604800  IN      TXT     "Lab domain for Capstone security assessment"
lab.local.              604800  IN      MX      10 mail.lab.local.
lab.local.              604800  IN      NS      ns1.lab.local.
lab.local.              604800  IN      A       192.168.56.10
db.lab.local.           604800  IN      A       192.168.56.30
ftp.lab.local.          604800  IN      CNAME   meta.lab.local.
kali.lab.local.         604800  IN      A       192.168.56.10
mail.lab.local.         604800  IN      A       192.168.56.10
meta.lab.local.         604800  IN      A       192.168.56.20
ns1.lab.local.          604800  IN      A       192.168.56.10
webserver.lab.local.    604800  IN      A       192.168.56.20
www.lab.local.          604800  IN      CNAME   webserver.lab.local.
lab.local.              604800  IN      SOA     ns1.lab.local. admin.lab.local. 2024081201 604800 86400 2419200 604800
;; XFR size: 15 records (messages 1, bytes 459)
```

**Security Analysis:**

The zone transfer (AXFR) **succeeded**, which reveals a significant security misconfiguration. An unrestricted AXFR allows any client to download the entire DNS zone file, exposing:

- **All hostnames and IP mappings** — an attacker gains a complete inventory of internal hosts without performing active scanning
- **Mail server infrastructure** (MX records) — enables targeted phishing and email spoofing
- **Internal naming conventions** — reveals server roles (e.g., `db`, `mail`, `webserver`) which aids in prioritising attack targets
- **SPF/TXT records** — may disclose email authentication policies exploitable for spoofing

**Remediation:** Zone transfers should be restricted to authorised secondary DNS servers only using the `allow-transfer` directive with specific IP addresses, not entire subnets. In production, this would be configured as:
```
allow-transfer { 10.0.0.2; };  // Only the secondary DNS server
```

### (c) Additional DNS Enumeration

#### Reverse DNS Lookup

```bash
dig -x 192.168.56.20 @192.168.56.10
```

```
; <<>> DiG 9.20.26-1-Debian <<>> -x 192.168.56.20 @192.168.56.10
;; ANSWER SECTION:
20.56.168.192.in-addr.arpa. 604800 IN   PTR     meta.lab.local.

; <<>> DiG 9.20.26-1-Debian <<>> -x 192.168.56.10 @192.168.56.10
;; ANSWER SECTION:
10.56.168.192.in-addr.arpa. 604800 IN   PTR     kali.lab.local.
```

#### Subdomain Brute-Force (dnsenum)

```bash
dnsenum --dnsserver 192.168.56.10 --enum lab.local
```

```
dnsenum VERSION:1.3.1
-----   lab.local   -----

Host's addresses:
  lab.local.                    604800   IN    A    192.168.56.10

Name Servers:
  ns1.lab.local.                604800   IN    A    192.168.56.10

Mail (MX) Servers:
  mail.lab.local.               604800   IN    A    192.168.56.10

Brute forcing with /usr/share/dnsenum/dns.txt:
  meta.lab.local.               604800   IN    A    192.168.56.20
  ftp.lab.local.                604800   IN    CNAME meta.lab.local.
  webserver.lab.local.          604800   IN    A    192.168.56.20
  ns1.lab.local.                604800   IN    A    192.168.56.10
  mail.lab.local.               604800   IN    A    192.168.56.10
  www.lab.local.                604800   IN    CNAME webserver.lab.local.
```

---

## 8. Task 6 — Automated Vulnerability Scan

### Scanner Used

**Nessus Essentials Plus** (Tenable) — version 10.12.3

### Scan Configuration

| Parameter | Value |
|-----------|-------|
| Scanner | Nessus Essentials Plus (Local Scanner) |
| Policy | Basic Network Scan |
| Severity Base | CVSS v3.0 |
| Targets | 192.168.56.20 |
| Start | August 14, 2026 at 5:24 PM |
| End | August 14, 2026 at 5:44 PM |
| Elapsed | 20 minutes |

### Scan Summary

| Severity | Count |
|----------|-------|
| **Critical** | 10 |
| **High** | 6 |
| **Medium** | 24 |
| **Low** | 9 |
| **Info** | 141 |
| **Total** | **70 vulnerabilities** (excluding Info) |

### Vulnerability Findings

#### Vulnerability 1 — Bind Shell Backdoor Detection

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2011-2523 |
| **CVSS Base Score** | 9.8 |
| **CVSS Vector** | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Severity** | **Critical** |
| **Affected Host** | 192.168.56.20 |
| **Affected Port** | 21/tcp (FTP — vsftpd 2.3.4) |
| **Description** | Nessus detected a bind shell backdoor listening on the target host. vsftpd 2.3.4 contains a backdoor triggered by a `:)` sequence in the FTP username, opening a command shell on port 6200. This was introduced into the official source code distribution. |
| **Remediation** | Immediately upgrade vsftpd to the latest stable version (3.0.5+). Verify package integrity using SHA-256 checksums from the official repository. If FTP is not a business requirement, disable the service entirely and use SFTP over SSH instead. |

#### Vulnerability 2 — VNC Server 'password' Password

| Field | Detail |
|-------|--------|
| **CVE** | N/A (Nessus Plugin ID: 61708) |
| **CVSS Base Score** | 10.0 |
| **CVSS Vector** | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| **Severity** | **Critical** |
| **Affected Host** | 192.168.56.20 |
| **Affected Port** | 5900/tcp (VNC) |
| **Description** | Nessus detected that the VNC server running on the target host is secured with the default password 'password'. An attacker can exploit this to gain full remote desktop access to the system without requiring any authentication bypass. |
| **Remediation** | Change the VNC password immediately to a strong, unique passphrase. If VNC remote desktop access is not required, disable the service. Restrict VNC access to authorised IPs using firewall rules and consider tunnelling VNC over SSH for encryption. |

#### Vulnerability 3 — Samba Badlock Vulnerability

| Field | Detail |
|-------|--------|
| **CVE** | CVE-2016-2118 |
| **CVSS Base Score** | 7.5 |
| **CVSS Vector** | CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H |
| **Severity** | **High** |
| **Affected Host** | 192.168.56.20 |
| **Affected Port** | 139/tcp, 445/tcp (Samba) |
| **Description** | The Samba service running on the target is affected by the Badlock vulnerability. This flaw in the Security Account Manager (SAM) and Local Security Authority (Domain Policy) (LSAD) protocols allows a man-in-the-middle attacker to downgrade the authentication level and impersonate users. Nessus recommends upgrading to Samba 4.2.11 / 4.3.8 / 4.4.2 or later. |
| **Remediation** | Upgrade Samba to version 4.2.11, 4.3.8, 4.4.2, or later. If SMB file sharing is not required, disable the Samba service. Apply network segmentation to restrict SMB access to authorised internal hosts only. |

#### Additional Critical Findings from Nessus

| Severity | Finding | CVSS | Affected Service |
|----------|---------|------|-----------------|
| Critical | Canonical Ubuntu Linux SEoL (8.04.x) — End of Life OS | 10.0 | General |
| Critical | SSL Version 2 and 3 Protocol Detection | 9.8 | Multiple SSL services |
| Critical | SSL (Multiple Issues) — Gain a shell remotely | 9.8 | SSL services (3 instances) |
| High | rlogin Service Detection | 7.5 | 513/tcp |
| High | NFS Shares World Readable | 7.5 | RPC/NFS |
| Medium | Apache Tomcat (Multiple Issues) | Various | 8180/tcp (4 instances) |

> The full Nessus reports (HTML) are available at `outputs/task6_nessus_vuln_by_host.html` (Detailed Vulnerabilities by Host) and `outputs/task6_nessus_vuln_by_plugin.html` (Detailed Vulnerabilities by Plugin).

### False Positive Analysis

**Identified False Positive:** SSL (Multiple Issues) — Self-Signed Certificate on multiple services

**CVE/Finding:** No CVE — Nessus flagged 28 SSL-related informational/mixed findings under "SSL (Multiple Issues)" in the General family.

**Why It Is a False Positive:** Nessus reported 28 SSL-related findings across multiple services on 192.168.56.20, including warnings about self-signed certificates, weak cipher suites, and SSLv2/SSLv3 support. While the protocol-level vulnerabilities (SSLv2/SSLv3 support) are genuine weaknesses, the self-signed certificate warnings are false positives in this context. The scanner flagged each SSL-enabled service (SMTP on port 25, HTTP on port 443/8180) as having an untrusted certificate because the issuer and subject fields are identical — the defining characteristic of a self-signed certificate. In this isolated lab environment, there is no certificate authority infrastructure, and self-signed certificates are the expected configuration for Metasploitable 2. The lab network is not accessible from external systems, eliminating the man-in-the-middle risk that makes self-signed certificates dangerous in production.

**Evidence from scan output:**
```
Plugin: SSL (Multiple Issues) — Family: General — Count: 28
Severity: Mixed (Info to Critical)
Host: 192.168.56.20

Certificate Subject: CN=ubuntu804-base.localdomain
Certificate Issuer:  CN=ubuntu804-base.localdomain
Validity: Self-signed (issuer = subject)
Finding: "The SSL certificate cannot be trusted" (28 instances across services)
Context: Isolated VMware lab — no CA infrastructure — self-signed expected
```

---

## 9. Findings Table

| # | CVE | CVSS Score | Severity | Host | Port | Service | Remediation |
|---|-----|-----------|----------|------|------|---------|-------------|
| 1 | N/A | 10.0 | Critical | 192.168.56.20 | General | Ubuntu 8.04 (EOL) | Upgrade to a supported Ubuntu LTS release |
| 2 | N/A | 10.0 | Critical | 192.168.56.20 | 5900/tcp | VNC (password: 'password') | Change VNC password; restrict access |
| 3 | CVE-2011-2523 | 9.8 | Critical | 192.168.56.20 | 21/tcp | vsftpd 2.3.4 backdoor | Upgrade vsftpd; verify package checksums |
| 4 | N/A | 9.8 | Critical | 192.168.56.20 | Multiple | SSLv2/SSLv3 enabled | Disable SSLv2/SSLv3; enforce TLS 1.2+ |
| 5 | CVE-2016-2118 | 7.5 | High | 192.168.56.20 | 139,445/tcp | Samba Badlock | Upgrade to Samba 4.2.11+ |
| 6 | N/A | 7.5 | High | 192.168.56.20 | 513/tcp | rlogin service | Disable rlogin; use SSH instead |
| 7 | N/A | 7.5 | High | 192.168.56.20 | NFS | NFS world-readable shares | Restrict NFS exports; apply access controls |


---

## 10. Risk Heat Map

The following maps each finding to a **Likelihood × Impact** matrix:

| Finding | Likelihood | Impact | Quadrant |
|---------|-----------|--------|----------|
| CVE-2011-2523 (vsftpd backdoor) | **High** — publicly known backdoor with widely available exploit code; no authentication required | **High** — full remote code execution with root privileges | **Top-Right (Critical)** — immediate remediation required |
| VNC Default Password ('password') | **High** — trivially exploitable; password is publicly known and requires no exploit | **High** — full remote desktop access to the system | **Top-Right (Critical)** — immediate remediation required |
| Ubuntu 8.04 End of Life | **High** — no security patches available; all future CVEs remain unpatched | **High** — entire OS is unsupported; any new vulnerability is permanently exploitable | **Top-Right (Critical)** — immediate remediation required |
| SSLv2/SSLv3 Protocol Detection | **Medium** — requires MITM position but protocol downgrade attacks are well-documented (POODLE, DROWN) | **High** — session data interception and decryption possible | **Top-Centre (High)** — remediate within 24–48 hours |
| CVE-2016-2118 (Samba Badlock) | **Medium** — requires MITM position and specific authentication downgrade | **High** — user impersonation and privilege escalation | **Top-Centre (High)** — remediate within 24–48 hours |
| NFS World-Readable Shares | **Medium** — requires network access to NFS port | **Medium** — sensitive file disclosure possible | **Centre (Medium)** — remediate within 1 week |
| rlogin Service Detection | **Medium** — cleartext authentication; requires valid credentials | **Medium** — credential theft via sniffing | **Centre (Medium)** — remediate within 1 week |

**Matrix Description:**

```
                    HIGH IMPACT              LOW IMPACT
HIGH LIKELIHOOD   │ CRITICAL (Q1)          │ MEDIUM (Q2)    │
                  │ CVE-2011-2523 (vsftpd) │                │
                  │ VNC Default Password   │                │
                  │ Ubuntu 8.04 EOL        │                │
LOW LIKELIHOOD    │ HIGH (Q3)              │ LOW (Q4)       │
                  │ CVE-2016-2118 (Samba)  │                │
                  │ SSLv2/SSLv3            │                │
```

---

## 11. Remediation Priority List

Ordered by CVSS score (highest first):

| Priority | CVE / Finding | CVSS | Action | Timeline |
|----------|--------------|------|--------|----------|
| 1 | Ubuntu 8.04 End of Life | 10.0 | Migrate to a supported Ubuntu LTS release (22.04/24.04) | **Immediate** |
| 2 | VNC Default Password | 10.0 | Change VNC password; disable if not needed; restrict by IP | **Immediate** |
| 3 | CVE-2011-2523 (vsftpd) | 9.8 | Upgrade vsftpd immediately; replace FTP with SFTP | **Immediate** |
| 4 | SSLv2/SSLv3 Enabled | 9.8 | Disable SSLv2/SSLv3; enforce TLS 1.2+ on all services | **Immediate** |
| 5 | CVE-2016-2118 (Samba Badlock) | 7.5 | Upgrade Samba to 4.2.11+; restrict SMB access via ACLs | **Within 48 hours** |
| 6 | rlogin Service | 7.5 | Disable rlogin; use SSH for all remote access | **Within 48 hours** |
| 7 | NFS World-Readable | 7.5 | Restrict NFS exports; apply host-based access controls | **Within 48 hours** |

---

*Report prepared by Swet Soni as part of the Masai Capstone Project — Certification in Cybersecurity and Ethical Hacking with Applied AI.*
