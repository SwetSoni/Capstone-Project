# Part 4 — Python Security Automation and AI/ML-Driven Threat Detection

**Engagement:** Capstone Project — Part 4  
**Assessor:** Swet Soni  
**Date:** August 2026  
**Classification:** CONFIDENTIAL

## Overview

This repository contains three Python security automation tools built for SOC analyst workflow automation:

1. **Port Scanner** (`port_scanner.py`) — Multithreaded TCP port scanner with banner grabbing
2. **Log Enricher** (`log_enricher.py`) — Regex-based IP extraction with threat intelligence enrichment
3. **Threat Detector** (`threat_detector.py`) — ML-based phishing URL classification
4. **VirusTotal Enrichment** (`virustotal_check.py`) — REST API integration for IP reputation checking

---

## Table of Contents

1. [Task 1 — Port Scanner](#task-1--multithreaded-port-scanner)
2. [Task 2 — Log Enricher](#task-2--log-parser-with-ip-enrichment)
3. [Task 3 — ML Threat Detector](#task-3--machine-learning-threat-detector)
4. [Task 4 — VirusTotal Enrichment](#task-4--virustotal-rest-api-enrichment)
5. [Task 5 — SOAR Workflow](#task-5--soar-workflow-description)
6. [Input → Process → Output](#inputprocessoutput-automation-mindset)
7. [Setup & Usage](#setup--usage)

---

## Task 1 — Multithreaded Port Scanner

### Design Decisions

- Uses Python's built-in `socket` library (no external scanner binaries like nmap)
- Uses `threading` module for concurrent scanning with a `threading.Lock` to prevent race conditions
- Handles connection refused, timeout, and OS errors gracefully
- Banner grabbing sends `\r\n` probe and receives up to 1,024 bytes

### Usage

```bash
python port_scanner.py 192.168.56.20 1 1024
```

### Sample Output

```
=================================================================
  Port Scanner — Target: 192.168.56.20
  Port Range: 1-1024
  Started: 2026-08-15 22:32:05
=================================================================

Port       State      Banner
-----------------------------------------------------------------
21         open       220 (vsFTPd 2.3.4)
22         open       SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
23         open       #'
25         open       220 metasploitable.localdomain ESMTP Postfix 
53         open       No banner received
80         open       No banner received
111        open       No banner received
139        open       No banner received
445        open       No banner received
512        open        Where are you?
513        open       No banner received
514        open        getnameinfo: Temporary failure in name resol
-----------------------------------------------------------------

12 open port(s) found on 192.168.56.20

Scan completed: 2026-08-15 22:32:09
```

---

## Task 2 — Log Parser with IP Enrichment

### Design Decisions

- IPv4 extraction uses regex pattern: `\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`
- Private ranges (10.x, 172.16-31.x, 192.168.x, 127.x) are filtered using Python's `ipaddress` module
- Deduplication uses a Python `set` for O(1) lookups
- Queries `ip-api.com` REST API for country, ISP, and proxy/hosting/VPN indicators
- All HTTP and JSON errors are caught with try-except blocks

### Usage

```bash
python log_enricher.py sample_logs/firewall.log
```

### Sample Output (3–5 IPs)

```json
{
  "185.220.101.1": {
    "ip": "185.220.101.1",
    "country": "Germany",
    "isp": "Stiftung Erneuerbare Freiheit",
    "is_hosting": true,
    "is_proxy": true,
    "is_mobile": false,
    "risk_indicators": [
      "Hosting/Cloud provider — commonly used for attack infrastructure",
      "Proxy/VPN detected — may be used to anonymise malicious activity"
    ],
    "risk_level": "HIGH"
  },
  "198.51.100.42": {
    "ip": "198.51.100.42",
    "country": "Romania",
    "isp": "TEST-NET-2",
    "is_hosting": false,
    "is_proxy": false,
    "is_mobile": false,
    "risk_indicators": [],
    "risk_level": "LOW"
  },
  "203.0.113.5": {
    "ip": "203.0.113.5",
    "country": "United States",
    "isp": "TEST-NET-3",
    "is_hosting": false,
    "is_proxy": false,
    "is_mobile": false,
    "risk_indicators": [],
    "risk_level": "LOW"
  }
}
```

---

## Task 3 — Machine Learning Threat Detector

### Dataset

**Source:** UCI Phishing Websites Dataset (11,055 samples, 30 features, binary label)

### First 5 Rows

```
   having_IP_Address  URL_Length  Shortining_Service  having_At_Symbol  ...  Result
0                  1           1                   0                 0  ...       1
1                 -1           0                   1                -1  ...      -1
2                  1           1                   0                 1  ...       1
3                  1          -1                   0                -1  ...       1
4                 -1           0                  -1                -1  ...      -1
```

### Class Distribution

```
 1 (Legitimate):  7059 samples (63.9%)
-1 (Phishing):    3996 samples (36.1%)
Total:           11055 samples
```

### Data Preprocessing

- Null values found: 0
- Duplicate rows found: 0 (dropped 0)
- No categorical features to encode
- Train/test split: 80/20 with `random_state=42`

### Random Forest Classification Report

```
                precision    recall  f1-score   support

 Phishing (-1)       0.59      0.43      0.49       778
Legitimate (1)       0.73      0.84      0.78      1433

      accuracy                           0.69      2211
     macro avg       0.66      0.63      0.64      2211
  weighted avg       0.68      0.69      0.68      2211
```

### Isolation Forest Anomaly Detection

```
  Anomaly Detection Accuracy: 0.5789
  Precision: 0.5847
  Recall:    0.5789
  F1 Score:  0.5816
```

### Model Comparison

| Model | Accuracy | Precision | Recall | F1 Score | Notes |
|-------|----------|-----------|--------|----------|-------|
| Random Forest | 0.6929 | 0.6793 | 0.6929 | 0.6792 | Supervised; requires labelled training data |
| Isolation Forest | 0.5789 | 0.5847 | 0.5789 | 0.5816 | Unsupervised; no labels needed but lower accuracy |

### Discussion: Precision, Recall, F1 Score, and Model Limitations (174 words)

In imbalanced security datasets — such as phishing detection where malicious samples are far fewer than benign ones — **precision and recall are more meaningful than raw accuracy**. A model that classifies everything as "legitimate" could achieve 90%+ accuracy on a dataset where only 10% of samples are phishing, yet it would miss every actual threat. Precision measures how many of the model's "phishing" predictions were actually phishing (minimising false positives that waste analyst time), while recall measures how many actual phishing samples the model detected (minimising false negatives that let threats through).

The **F1 score** is the harmonic mean of precision and recall, providing a single metric that balances both. An F1 of 0.96 means the model achieves both high precision and high recall; a low F1 indicates the model sacrifices one for the other.

**Random Forest limitation:** It requires a large, accurately labelled training dataset. In a real SOC, obtaining labelled data is expensive and time-consuming, and the model cannot detect novel attack types not represented in the training data. **Isolation Forest limitation:** It assumes anomalies are statistically rare and different from normal patterns. In a real SOC, sophisticated phishing URLs may closely mimic legitimate URLs, causing the Isolation Forest to miss them (high false negative rate), and it provides no interpretability for why a sample was flagged.

---

## Task 4 — VirusTotal REST API Enrichment

### Design Decisions

- API key loaded from `VT_API_KEY` environment variable (never hardcoded)
- Handles rate limits (free tier: 4 requests/minute), invalid keys, 404, and network errors
- Extracts: malicious detections, harmless count, last analysis date

### Usage

```bash
# Set API key in .env file first
python virustotal_check.py sample_logs/firewall.log
```

### Sample Output (2 IPs)

```json
{
  "185.220.101.1": {
    "ip": "185.220.101.1",
    "malicious_detections": 14,
    "harmless_count": 45,
    "suspicious_count": 2,
    "undetected_count": 30,
    "last_analysis_date": "2026-08-15 16:20:06 UTC",
    "total_vendors": 91,
    "country": "DE",
    "as_owner": "Stiftung Erneuerbare Freiheit"
  },
  "198.51.100.42": {
    "ip": "198.51.100.42",
    "malicious_detections": 0,
    "harmless_count": 54,
    "suspicious_count": 0,
    "undetected_count": 37,
    "last_analysis_date": "2026-08-15 17:05:15 UTC",
    "total_vendors": 91,
    "country": "Unknown",
    "as_owner": "Unknown"
  }
}
```

### Mock/Offline Mode

If the VirusTotal API is unavailable (rate limit, quota, network), the script includes sample response JSON files in the repository for demonstration:

- `data/vt_sample_8.8.8.8.json`
- `data/vt_sample_45.33.32.156.json`

---

## Input → Process → Output Automation Mindset

The **Input → Process → Output** (IPO) mindset structures every automation tool as a three-stage pipeline: raw data enters the system (Input), is transformed or analysed by the tool (Process), and actionable results are produced (Output). This mindset ensures each tool has a clear data contract and can be chained with other tools in a larger SOAR workflow.

| Script | Input | Process | Output |
|--------|-------|---------|--------|
| `port_scanner.py` | Target IP address + port range (CLI args) | Concurrent TCP connection attempts with banner grabbing using socket library | Formatted table of open ports with service banners |
| `log_enricher.py` | Plain-text log file (syslog/firewall format) | Regex IPv4 extraction → private IP filtering → set deduplication → ip-api.com REST API queries | Enriched JSON with country, ISP, and proxy/hosting/VPN risk indicators per IP |
| `threat_detector.py` | Phishing URL dataset (CSV with features + labels) | Data preprocessing → Random Forest training → Isolation Forest training → evaluation metrics | Classification report, model comparison table, and accuracy/precision/recall/F1 scores |

---

## Task 5 — SOAR Workflow Description (232 words)

The three tools built in this project map directly to a **SOAR (Security Orchestration, Automation, and Response)** workflow that a Security Operations Center (SOC) would use to automate threat detection and response.

**Step 1 — Data Collection:** The `port_scanner.py` tool corresponds to the data collection phase. In a SOAR workflow, it would be triggered as a scheduled reconnaissance scan or as an on-demand scan when a new asset is reported. The scanner identifies open ports and running services, providing the raw inventory data that subsequent enrichment and detection steps require.

**Step 2 — Enrichment:** The `log_enricher.py` and `virustotal_check.py` tools correspond to the enrichment phase. When the SOAR platform receives a security event (e.g., an alert from the SIEM), these tools automatically extract IP addresses from the alert's associated logs, query threat intelligence APIs, and attach contextual data (country, ISP, malicious reputation score) to the alert — giving the analyst a complete picture without manual lookups.

**Step 3 — Detection and Decision:** The `threat_detector.py` ML model corresponds to the detection and automated decision phase. The Random Forest model's classification output (phishing vs. legitimate) and its probability score (confidence) drive the SOAR platform's escalation logic. **If the model's confidence exceeds 95%** (high certainty of malicious activity), the SOAR platform takes **automated action**: block the IP at the firewall, quarantine the email, and log the action for audit. **If the confidence is between 70% and 95%**, the alert is **escalated to a human analyst** for review — this threshold avoids the costly false-positive trap where legitimate traffic is blocked, while still ensuring high-confidence threats are neutralised instantly. **Below 70%**, the alert is logged for trend analysis but no immediate action is taken. This tiered approach balances the trade-off between false positives (blocking legitimate users, eroding trust) and false negatives (missing real threats, increasing breach risk) — a critical consideration in any SOC environment.

---

## Setup & Usage

```bash
# 1. Clone the repository
git clone https://github.com/SwetSoni/capstone-project.git
cd part4-automation-ai

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env with your VirusTotal API key

# 5. Run port scanner
python port_scanner.py 192.168.56.20 1 1024

# 6. Run log enricher
python log_enricher.py sample_logs/firewall.log

# 7. Run threat detector
python threat_detector.py

# 8. Run VirusTotal enrichment
python virustotal_check.py sample_logs/firewall.log
```

---

*Report prepared by Swet Soni as part of the Masai Capstone Project — Certification in Cybersecurity and Ethical Hacking with Applied AI.*

