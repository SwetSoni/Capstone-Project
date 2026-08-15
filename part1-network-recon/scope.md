# Pre-Engagement Scope Definition

## Lab Setup Note

| VM Name            | Role                     | IP Address      | OS / Image          |
|--------------------|--------------------------|-----------------|---------------------|
| Kali Linux         | Attack / Scanner host    | 192.168.56.10   | Kali Linux 2024+    |
| Metasploitable 2   | Intentionally vulnerable | 192.168.56.20   | Ubuntu 8.04 (Metasploitable 2) |
| DNS Server (BIND9) | Local authoritative DNS  | 192.168.56.10   | Kali Linux (same host) |


---

## (a) Target IP Range

| Parameter      | Value                |
|----------------|----------------------|
| Target Network | 192.168.56.0/24      |
| Subnet Mask    | 255.255.255.0        |
| Usable Hosts   | 192.168.56.1 – 192.168.56.254 |
| Total IPs      | 256 (254 usable)     |

The engagement is strictly limited to the **192.168.56.0/24** private, host-only virtual-machine lab network. No external or production systems are in scope.

---

## (b) Techniques In Scope

| #  | Technique                        | Tools                          | Description                                                                 |
|----|----------------------------------|--------------------------------|-----------------------------------------------------------------------------|
| 1  | Passive OSINT                    | dig, host, Shodan, dnsdumpster | Gather publicly available information about a demonstration domain/device class |
| 2  | Active Host Discovery            | Nmap (ping sweep)              | Identify live hosts on 192.168.56.0/24 using ICMP, ARP, and TCP probes     |
| 3  | Port Scanning (TCP SYN)          | Nmap (-sS)                     | Half-open scan on ports 1–1024 of discovered hosts                         |
| 4  | Service Version Detection        | Nmap (-sV)                     | Identify service names and version numbers on open ports                   |
| 5  | OS Fingerprinting                | Nmap (-O)                      | Determine the operating system of at least one target host                 |
| 6  | DNS Enumeration                  | dig, dnsenum, gobuster         | Retrieve DNS records, attempt zone transfer (AXFR), brute-force subdomains |
| 7  | Automated Vulnerability Scanning | Nessus Essentials              | Full vulnerability scan to identify CVEs on live hosts                     |

---

## (c) Techniques Out of Scope

| #  | Technique                    | Justification                                                              |
|----|------------------------------|----------------------------------------------------------------------------|
| 1  | Exploitation                 | No exploitation of vulnerabilities is authorised in this engagement        |
| 2  | Post-Exploitation            | No payload delivery, privilege escalation, or lateral movement permitted   |
| 3  | Social Engineering           | No phishing, pretexting, or social attacks are authorised                  |
| 4  | Physical Security Testing    | Not applicable to virtual lab environment                                  |
| 5  | Scanning outside 192.168.56.0/24 | Any IP outside the defined subnet is strictly prohibited              |
| 6  | Denial of Service (DoS)      | No intentional disruption of services, even within the lab                 |

---

## (d) Rules of Engagement

| Rule                    | Detail                                                                                      |
|-------------------------|---------------------------------------------------------------------------------------------|
| **Scanning Hours**      | Scanning is permitted 24/7 as this is an isolated lab network with no production dependencies |
| **Rate Limits**         | Nmap scans will use default timing (-T3) or cautious timing (-T2) to avoid overwhelming targets; no aggressive (-T5) scans without justification |
| **Contact Point**       | In case of accidental disruption or unexpected behaviour, immediately halt all scans and document the incident. Lab owner: Swet Soni |
| **Data Handling**       | All scan outputs will be stored locally and in the private/public GitHub repository. No sensitive credentials or real-world PII will be included |
| **Tool Authorisation**  | Only tools installed on Kali Linux and explicitly listed in the "In Scope" section are authorised |
| **Incident Procedure**  | If a scan causes a target VM to crash or become unresponsive: (1) stop all active scans, (2) restart the affected VM, (3) document the incident with timestamp and cause |

---

**Authorised by:** Swet Soni  
**Date:** August 12, 2026  
**Signature:** _This document serves as written authorisation for the assessment described above._
