# Capstone Project — Cybersecurity and Ethical Hacking with Applied AI

**Author:** Swet Soni  
**Date:** August 2026

---

## Project Overview

This repository contains the final capstone project for the Certification in Cybersecurity and Ethical Hacking with Applied AI. The project covers the complete security lifecycle: network reconnaissance, defensive security operations, secure application development, and Python-based security automation.

---

## Repository Structure

| Part | Directory | Description |
|------|-----------|-------------|
| **Part 1** | [`part1-network-recon/`](part1-network-recon/) | Network Reconnaissance and Vulnerability Assessment |
| **Part 2** | [`part2-defense-soc/`](part2-defense-soc/) | Network Defense Architecture and SOC Operations |
| **Part 3** | [`part3-secure-app/`](part3-secure-app/) | Secure Application Development |
| **Part 4** | [`part4-automation-ai/`](part4-automation-ai/) | Security Automation and AI-Powered Threat Detection |

---

## Part 1 — Network Reconnaissance and Vulnerability Assessment

A penetration-test-style assessment of the 192.168.56.0/24 lab network following the PTES framework. Includes passive OSINT, active host discovery, port scanning, DNS enumeration, and automated vulnerability scanning with Nessus Essentials.

**Key Deliverables:**
- Formal pentest report in [`part1-network-recon/README.md`](part1-network-recon/README.md)
- Pre-engagement scope document in [`part1-network-recon/scope.md`](part1-network-recon/scope.md)
- BIND9 DNS configuration in [`part1-network-recon/dns-config/`](part1-network-recon/dns-config/)
- All scan outputs (Nmap, Nessus) in [`part1-network-recon/outputs/`](part1-network-recon/outputs/)

## Part 2 — Network Defense Architecture and SOC Operations

A detailed defense and SOC operations portfolio piece encompassing iptables firewall configurations, Zero Trust policy enforcement, SIEM correlation rules, and comprehensive incident response workflows.

**Key Deliverables:**
- Defense architecture & incident response report in [`part2-defense-soc/README.md`](part2-defense-soc/README.md)

## Part 3 — Secure Application Development

A Flask web application hardened against OWASP Top 10 vulnerabilities with STRIDE threat modelling, cryptographic password hashing, and a CI/CD security pipeline using GitHub Actions and Bandit SAST.

**Key Deliverables:**
- Application code and security remediations in [`part3-secure-app/`](part3-secure-app/)
- STRIDE threat model and OWASP analysis in [`part3-secure-app/README.md`](part3-secure-app/README.md)
- GitHub Actions CI/CD workflow in [`part3-secure-app/.github/workflows/security.yml`](part3-secure-app/.github/workflows/security.yml)

## Part 4 — Security Automation and AI-Powered Threat Detection

Python-based security tools: a socket-based port scanner, a log analysis pipeline with VirusTotal enrichment, and a machine-learning threat detector trained on a labelled security dataset.

**Key Deliverables:**
- Port scanner in [`part4-automation-ai/port_scanner.py`](part4-automation-ai/port_scanner.py)
- Log enricher with VirusTotal integration in [`part4-automation-ai/log_enricher.py`](part4-automation-ai/log_enricher.py)
- ML threat detector in [`part4-automation-ai/threat_detector.py`](part4-automation-ai/threat_detector.py)
- Documentation and evaluation results in [`part4-automation-ai/README.md`](part4-automation-ai/README.md)

---

## Lab Environment

| VM | Role | IP Address | OS |
|----|------|------------|-----|
| Kali Linux | Scanner / DNS Server | 192.168.56.10 | Kali Linux 2024+ |
| Metasploitable 2 | Vulnerable Target | 192.168.56.20 | Ubuntu 8.04 |

**Network:** VMware Host-Only (VMnet2) — 192.168.56.0/24

---

## Tools Used

- **Reconnaissance:** Nmap 7.95, dig (BIND9 utils), dnsenum, Shodan
- **Vulnerability Scanning:** Nessus Essentials Plus 10.12.3
- **DNS Server:** BIND9 (authoritative for lab.local)
- **Secure App:** Python 3, Flask, bcrypt, Bandit (SAST)
- **Automation:** Python 3, scikit-learn, requests, VirusTotal API v3

---

*Report prepared by Swet Soni as part of the Masai Capstone Project — Certification in Cybersecurity and Ethical Hacking with Applied AI.*
