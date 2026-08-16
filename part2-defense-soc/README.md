# Part 2 — Network Defense Architecture and SOC Operations

**Engagement:** Capstone Project — Part 2  
**Assessor:** Swet Soni  
**Date:** August 2026  
**Classification:** CONFIDENTIAL

---

## Task 1 — iptables Rule-Set

```bash
#!/bin/bash
# ============================================================
# iptables Firewall Rule-Set — Capstone Part 2, Task 1
# Network Topology:
#   Internet-facing zone: Web server 10.0.1.10 (HTTP/HTTPS)
#   Internal zone: App server 10.0.2.20 (8080), DB server 10.0.3.30 (5432)
#   Management zone: Admin workstation 10.0.4.40 (SSH to all servers)
# ============================================================

# ---- Flush existing rules and set default DROP policies ----
# Clear all existing rules to start with a clean slate
iptables -F
iptables -X
iptables -Z

# Default DROP policy on all chains — deny everything unless explicitly allowed
iptables -P INPUT DROP     # Drop all inbound traffic by default
iptables -P FORWARD DROP   # Drop all forwarded/routed traffic by default
iptables -P OUTPUT DROP    # Drop all outbound traffic by default

# ---- Allow loopback interface ----
# Permit all traffic on the loopback interface (localhost communication)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# ---- Allow established and related connections ----
# Stateful inspection: allow return traffic for connections we initiated or accepted
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT    # Return traffic for accepted inbound connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT  # Return traffic for forwarded connections
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT   # Return traffic for outbound connections

# ---- Rate-limit inbound HTTP/HTTPS — 50 new connections/sec per source IP ----
# Uses hashlimit module with srcip mode for per-source-IP rate limiting
iptables -A FORWARD -d 10.0.1.10 -p tcp --dport 80 -m state --state NEW \
  -m hashlimit --hashlimit-name web_rate_http --hashlimit 50/second \
  --hashlimit-burst 100 --hashlimit-mode srcip -j ACCEPT  # Rate-limit HTTP: max 50 new conn/sec per source IP

iptables -A FORWARD -d 10.0.1.10 -p tcp --dport 443 -m state --state NEW \
  -m hashlimit --hashlimit-name web_rate_https --hashlimit 50/second \
  --hashlimit-burst 100 --hashlimit-mode srcip -j ACCEPT  # Rate-limit HTTPS: max 50 new conn/sec per source IP

# ---- Allow SSH from admin workstation (10.0.4.40) to all three servers ----
# Only the admin workstation can SSH into the servers; all other SSH sources are denied by default DROP
iptables -A FORWARD -s 10.0.4.40 -d 10.0.1.10 -p tcp --dport 22 -m state --state NEW -j ACCEPT  # Admin SSH to web server
iptables -A FORWARD -s 10.0.4.40 -d 10.0.2.20 -p tcp --dport 22 -m state --state NEW -j ACCEPT  # Admin SSH to app server
iptables -A FORWARD -s 10.0.4.40 -d 10.0.3.30 -p tcp --dport 22 -m state --state NEW -j ACCEPT  # Admin SSH to DB server

# ---- Allow inter-zone traffic: web server → app server (port 8080) ----
# Web server needs to forward requests to the application server
iptables -A FORWARD -s 10.0.1.10 -d 10.0.2.20 -p tcp --dport 8080 -m state --state NEW -j ACCEPT  # Web → App on port 8080

# ---- Allow inter-zone traffic: app server → DB server (port 5432) ----
# Application server needs to query the PostgreSQL database
iptables -A FORWARD -s 10.0.2.20 -d 10.0.3.30 -p tcp --dport 5432 -m state --state NEW -j ACCEPT  # App → DB on port 5432

# ---- Log and drop all other traffic ----
# Log all dropped packets with the [FW-DROP] prefix before the final DROP
iptables -A INPUT -j LOG --log-prefix "[FW-DROP] " --log-level 4    # Log dropped inbound packets
iptables -A FORWARD -j LOG --log-prefix "[FW-DROP] " --log-level 4  # Log dropped forwarded packets
iptables -A OUTPUT -j LOG --log-prefix "[FW-DROP] " --log-level 4   # Log dropped outbound packets

# Final explicit DROP (defence in depth — these match the default policy but are explicit)
iptables -A INPUT -j DROP     # Drop all remaining inbound traffic
iptables -A FORWARD -j DROP   # Drop all remaining forwarded traffic
iptables -A OUTPUT -j DROP    # Drop all remaining outbound traffic
```

---

## Task 2 — Stateful Inspection Explanation

Stateful inspection provides fundamentally stronger security than simple packet filtering because it tracks the complete lifecycle of each network connection, maintaining awareness of whether a packet belongs to a legitimate, previously established communication flow.

Simple packet filtering operates on individual packets in isolation — it examines source/destination IP addresses, ports, and protocol flags, but has no memory of previous packets. This means it cannot distinguish between a legitimate response packet and a crafted malicious packet that merely mimics the correct IP/port combination. For example, if a firewall allows outbound traffic to port 80 and inbound traffic from port 80, an attacker could craft arbitrary packets with a source port of 80 to bypass the filter, even if no legitimate connection was ever initiated.

Stateful inspection eliminates this weakness by maintaining a state table that records each connection's status (NEW, ESTABLISHED, RELATED). When the firewall sees the initial SYN packet, it records the connection as NEW. After the three-way handshake completes, the connection moves to ESTABLISHED. Return packets are only permitted if they match an existing entry in the state table.

Concrete attack scenario — TCP SYN Flood: In a SYN flood attack, an attacker sends thousands of SYN packets with spoofed source IPs to exhaust the target's connection table. A simple packet filter allows all SYN packets to port 80 indiscriminately. A stateful firewall, however, tracks the number of half-open (NEW) connections and can enforce limits. When the state table detects an abnormal volume of NEW connections that never transition to ESTABLISHED (because the spoofed sources never complete the handshake), the stateful firewall can drop subsequent SYN packets from the offending sources, effectively mitigating the flood while still allowing legitimate connections to complete.

(208 words)

---

## Task 3 — Zero Trust Policy Statement

Paragraph 1 — Zero Trust Principle

The company shall adopt a Zero Trust security architecture, replacing the current implicit trust model where any device on the internal network is automatically trusted. Under Zero Trust, no user, device, or application is inherently trusted regardless of its network location — every access request must be explicitly verified, authenticated, and authorised before granting the minimum level of access required to perform the task. The foundational principle is "never trust, always verify": all traffic between network zones is treated as potentially hostile, and access decisions are made dynamically based on the identity of the requester, the health of the device, the sensitivity of the resource being accessed, and the context of the request (time, location, behaviour patterns). This means that even an admin workstation on the internal management zone (10.0.4.40) must prove its identity and device compliance before being granted SSH access to any server.

Paragraph 2 — Three Concrete Policy Changes

First, the company must implement Network Access Control (NAC) at every zone boundary. Currently, any device connected to the internal network gains implicit access. Under Zero Trust, each device must pass a health check (OS patches current, antivirus active, no known vulnerabilities) before being admitted to the network; devices that fail the check are quarantined to a remediation VLAN. Second, the company must enforce Multi-Factor Authentication (MFA) for all administrative and privileged access. The current SSH access from the admin workstation (10.0.4.40) relies solely on password or key-based authentication. Under Zero Trust, every SSH session must require a second factor (TOTP, hardware token, or push notification) to prevent credential theft from granting immediate access. Third, the company must deploy micro-segmentation via VLANs to isolate each zone (Internet-facing, Internal, Management) into separate broadcast domains with explicit inter-VLAN routing rules. The current flat trust model allows lateral movement between zones; micro-segmentation ensures that even if the web server (10.0.1.10) is compromised, the attacker cannot reach the database server (10.0.3.30) without passing through a policy enforcement point that validates the request against Zero Trust rules.

---

## Task 4 — SIEM Correlation Rule

Rule Specification

Rule Name: SSH Brute-Force Followed by Successful Login and Lateral Movement
Rule ID: CORR-001
Description: Detects a brute-force SSH attack pattern where multiple failed SSH login attempts from a single source IP are followed by a successful login, and then the compromised host initiates outbound connections to an unknown external IP on a suspicious port (4444, commonly used by reverse shells).

Data Sources

1. SSH authentication logs — /var/log/auth.log (via Wazuh agent) — Fields: timestamp, source_ip, username, auth_result (success/failure)
2. Syslog / system logs — /var/log/syslog (via Wazuh agent) — Fields: timestamp, source_ip, event_type
3. Firewall logs — iptables logs with [FW-DROP] prefix — Fields: timestamp, source_ip, dest_ip, dest_port, action
4. Network connection logs — netflow / connection tracking — Fields: timestamp, source_ip, dest_ip, dest_port, direction (inbound/outbound)

Correlation Logic

```
CONDITION 1 (Brute-Force Phase):
  IF   count(ssh_auth_failure) >= 5
  FROM same source_ip
  WITHIN 2-minute sliding window
  THEN flag source_ip as "brute_force_suspect"

CONDITION 2 (Compromise Phase):
  IF   ssh_auth_success == true
  FROM source_ip IN "brute_force_suspect"
  WITHIN 1 minute AFTER Condition 1
  THEN flag destination_host as "potentially_compromised"
       SET compromised_host_ip = destination_host_ip

CONDITION 3 (Lateral Movement / C2 Phase):
  IF   outbound_connection detected
  FROM compromised_host_ip
  TO   external_ip NOT IN whitelist
  ON   port IN [4444, 4445, 5555, 8888, 1337]  // Known reverse shell ports
  WITHIN 5 minutes AFTER Condition 2
  THEN TRIGGER ALERT "SSH Brute-Force → Compromise → Lateral Movement Detected"

FULL CORRELATION:
  Condition 1 AND Condition 2 AND Condition 3 must occur in sequence
  within a 10-minute total window
```

Alert Severity

Severity: SEV-1 (Critical)
Justification: The three-stage pattern (brute-force → successful login → suspicious outbound connection) indicates a completed compromise with active command-and-control or data exfiltration. This requires immediate human intervention.

Recommended Automated Containment Actions

1. Block source IP at firewall — Immediately upon Condition 3 — iptables rule: `iptables -I INPUT -s 203.0.113.5 -j DROP`
2. Isolate compromised host — Immediately upon Condition 3 — Move 10.0.2.20 to quarantine VLAN or disable network interface
3. Disable compromised SSH account — Immediately upon Condition 2 — `passwd -l <username>` or disable in LDAP/AD
4. Notify SOC team — Upon alert generation — Email/Slack/PagerDuty alert to on-call analyst
5. Capture forensic snapshot — Within 5 minutes of alert — Initiate memory dump and log preservation on 10.0.2.20

---

## Task 5 — Incident Response Walkthrough

### Phase 1: Preparation

- Incident response plan is documented and accessible to all SOC analysts, including this SIEM correlation rule and escalation procedures for SSH brute-force scenarios.
- Forensic toolkit is pre-staged on a dedicated forensics workstation: includes tools for memory acquisition (LiME), disk imaging (dd/dcfldd), log collection scripts, and chain-of-custody forms.
- Network segmentation is in place (per the iptables rule-set in Task 1) with the ability to quarantine hosts by moving them to an isolated VLAN.
- Baseline system snapshots of all servers (10.0.1.10, 10.0.2.20, 10.0.3.30) are maintained for comparison during the eradication phase — these include known-good file hashes, scheduled processes, and authorised user accounts.
- Communication channels are established: the SOC team has a dedicated Slack channel and PagerDuty on-call rotation for SEV-1 incidents.

### Phase 2: Detection and Analysis

- SIEM alert triggered: The correlation rule (CORR-001) fires when it detects 47 failed SSH attempts from 203.0.113.5 within 5 minutes (02:00–02:05), followed by a successful SSH login at 02:06, followed by three outbound connections from 10.0.2.20 to an unknown external IP on port 4444 at 02:07.
- Alert triage: The SOC analyst reviews the alert, confirms the source IP (203.0.113.5) is not in any known whitelist, and verifies the outbound connections to port 4444 — a port commonly associated with Metasploit reverse shell payloads.
- Log correlation: The analyst cross-references SSH auth logs (/var/log/auth.log) with firewall logs and netflow data to confirm the timeline: brute-force → successful login → outbound C2 connection — confirming this is a genuine attack, not a false positive.
- Scope assessment: The analyst checks whether 10.0.2.20 (application server) has connections to other internal hosts, particularly 10.0.3.30 (database server on port 5432), to determine if lateral movement has extended further.
- Severity confirmed as SEV-1: The attack has progressed through three stages (initial access, persistence, command and control), requiring immediate containment.

### Phase 3: Containment

- Short-term containment: Immediately block inbound traffic from 203.0.113.5 at the perimeter firewall: `iptables -I INPUT -s 203.0.113.5 -j DROP` and `iptables -I FORWARD -s 203.0.113.5 -j DROP`.
- Isolate compromised host: Move 10.0.2.20 to a quarantine VLAN or disable its network interface (`ifdown eth0`) to sever the C2 channel on port 4444 without powering off the machine (preserving volatile memory evidence).
- Block outbound C2: Add a firewall rule to block outbound traffic to the external C2 IP identified in the alert: `iptables -I OUTPUT -d <C2_IP> -j DROP`.
- Disable compromised account: Lock the SSH account used for the successful login at 02:06: `passwd -l <username>` and revoke any SSH keys associated with that account.
- Long-term containment: Rebuild 10.0.2.20 from a known-good image after forensic evidence collection is complete; rotate all credentials that 10.0.2.20 had access to, including the database credentials for 10.0.3.30.

### Phase 4: Eradication

- Collect forensic artefacts from 10.0.2.20 before any cleanup: memory dump (using LiME), full disk image (using dcfldd), auth logs, bash history, crontabs, network connections, and running processes (see Task 6 forensics table).
- Identify root cause: Analyse the SSH auth logs to determine which username was compromised and whether the password was weak (brute-force viable) or if credential stuffing was used.
- Remove attacker persistence: Check for backdoors, rogue SSH keys (~/.ssh/authorized_keys), crontab entries, modified system binaries, and new user accounts created after 02:06.
- Patch the vulnerability: If SSH was brute-forced due to weak password policy, enforce strong password requirements and implement fail2ban or SSH key-only authentication.
- Verify eradication: Compare the compromised system's file hashes against the baseline snapshot to identify all modified files; scan with rootkit detection tools (rkhunter, chkrootkit).

### Phase 5: Recovery

- Restore from clean baseline: Rebuild 10.0.2.20 from the known-good image or a verified backup taken before the compromise (before 02:00).
- Harden SSH configuration: Disable password authentication in /etc/ssh/sshd_config (set PasswordAuthentication no), enforce key-based authentication only, and install fail2ban with a threshold of 3 failed attempts before banning.
- Rotate all credentials: Change all passwords and API keys that 10.0.2.20 had access to, including the PostgreSQL credentials for 10.0.3.30:5432.
- Gradual reconnection: Reconnect 10.0.2.20 to the production network only after verification; monitor it intensively for 72 hours for any signs of re-compromise.
- Verify service functionality: Confirm that the application server on port 8080 is operating correctly and that the web server (10.0.1.10) can reach it as expected.

### Phase 6: Post-Incident

- MTTD (Mean Time to Detect): The brute-force started at 02:00 and the SIEM alert would trigger at approximately 02:07 (when the outbound C2 connection meets Condition 3). MTTD = 7 minutes. Target MTTD for SEV-1: 5 minutes or less. The scenario missed the MTTD target by 2 minutes, suggesting the correlation rule's time windows should be tightened (reduce the Condition 1 threshold from 5 failures to 3 for faster detection).
- MTTR (Mean Time to Respond/Remediate): If the SOC analyst acts on the alert within 5 minutes of detection (by 02:12), containment is achieved within 12 minutes of attack start. Target MTTR for SEV-1: 30 minutes or less. This meets the MTTR target if the automated containment actions (IP block, host isolation) execute within 1–2 minutes of the alert.
- Lessons learned: (a) SSH should have been configured with key-only authentication from the start, eliminating brute-force as an attack vector; (b) the absence of fail2ban allowed 47 attempts before the successful login; (c) outbound connections to port 4444 should have been blocked by the firewall's default egress policy.
- Rule tuning: Lower the brute-force threshold from 5 to 3 failed attempts to trigger Condition 1 earlier; add port 4444 to a blocklist of suspicious outbound ports.
- Post-incident report: Document the full timeline, root cause, impact assessment, and remediation actions; share with management and update the incident response playbook.

---

## Task 6 — Digital Forensics Artefact List

Artefact | Location on Disk/Memory | What It Reveals
--- | --- | ---
SSH Authentication Logs | /var/log/auth.log and /var/log/secure | Records all SSH login attempts (successful and failed) with timestamps, source IPs, and usernames — reveals the brute-force timeline, the compromised username, and the exact time of successful login (02:06)
Bash Command History | ~/.bash_history for the compromised user and /root/.bash_history if privilege escalation occurred | Records all commands executed by the attacker after gaining access — reveals post-compromise activities such as reconnaissance commands, file downloads, privilege escalation attempts, and lateral movement commands
Active Network Connections (Volatile) | Memory / output of netstat -tulpn or ss -tulpn | Shows all active TCP/UDP connections at the time of capture — reveals the C2 connection to the external IP on port 4444 and any other connections the attacker established (e.g., data exfiltration channels)
Running Processes (Volatile) | Memory / output of ps auxf and /proc/ filesystem | Lists all processes running at the time of capture — reveals attacker tools, reverse shells, cryptocurrency miners, or other malicious processes that may not persist across reboots
Crontab Entries | /var/spool/cron/crontabs/, /etc/cron.d/, /etc/crontab | Records scheduled tasks — reveals persistence mechanisms the attacker may have installed (e.g., a cron job that re-establishes the C2 connection on reboot or at regular intervals)
SSH Authorized Keys | ~/.ssh/authorized_keys for all user accounts | Lists public keys authorised for passwordless SSH login — reveals whether the attacker planted their own SSH key for persistent backdoor access that survives password changes
System Log (syslog) | /var/log/syslog and /var/log/messages | Records system-level events including service starts/stops, kernel messages, and network interface changes — reveals if the attacker restarted services, loaded kernel modules, or modified network configuration
File System Timeline (MAC times) | File metadata via find / -newer /tmp/timestamp -ls or forensic tools (Autopsy, Sleuth Kit) | Shows Modified/Accessed/Created timestamps for all files — reveals which files the attacker created, modified, or accessed during the compromise window (after 02:06), including any downloaded tools or modified configuration files

---

*Report prepared by Swet Soni as part of the Masai Capstone Project — Certification in Cybersecurity and Ethical Hacking with Applied AI.*
